#include "http_transport.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <curl/curl.h>

typedef struct ResponseBuffer
{
	char	   *data;
	size_t		length;
	size_t		maximum;
	bool		too_large;
	bool		out_of_memory;
} ResponseBuffer;

typedef struct HeaderBuffer
{
	PgOAuthHttpResponse *response;
	const ResponseBuffer *body;
	bool		too_large;
	bool		out_of_memory;
} HeaderBuffer;

#define PG_OAUTH_MAX_FRESHNESS_HEADER_SIZE 4096

static size_t
append_response(char *contents, size_t size, size_t count, void *user_data)
{
	ResponseBuffer *buffer = user_data;
	size_t		bytes;
	char	   *resized;

	if (size != 0 && count > SIZE_MAX / size)
	{
		buffer->too_large = true;
		return 0;
	}
	bytes = size * count;
	if (bytes > buffer->maximum - buffer->length)
	{
		buffer->too_large = true;
		return 0;
	}
	resized = realloc(buffer->data, buffer->length + bytes + 1);
	if (resized == NULL)
	{
		buffer->out_of_memory = true;
		return 0;
	}
	buffer->data = resized;
	memcpy(buffer->data + buffer->length, contents, bytes);
	buffer->length += bytes;
	buffer->data[buffer->length] = '\0';
	return bytes;
}

static bool
append_header_value(char **target, const char *value, size_t length)
{
	size_t		current = *target != NULL ? strlen(*target) : 0;
	size_t		separator = current > 0 ? 1 : 0;
	char	   *resized;

	/*
	 * Check the sum first: with current at the limit, subtracting the
	 * separator from the remaining room would wrap around.
	 */
	if (current + separator > PG_OAUTH_MAX_FRESHNESS_HEADER_SIZE ||
		length > PG_OAUTH_MAX_FRESHNESS_HEADER_SIZE - current - separator)
		return false;
	resized = realloc(*target, current + separator + length + 1);
	if (resized == NULL)
		return false;
	if (separator != 0)
		resized[current++] = ',';
	memcpy(resized + current, value, length);
	resized[current + length] = '\0';
	*target = resized;
	return true;
}

static size_t
capture_header(char *contents, size_t size, size_t count, void *user_data)
{
	HeaderBuffer *headers = user_data;
	size_t		bytes;
	const char *colon;
	const char *value;
	const char *end;
	char	  **target = NULL;

	if (size != 0 && count > SIZE_MAX / size)
	{
		headers->too_large = true;
		return 0;
	}
	bytes = size * count;

	/*
	 * A status line starts a new response. libcurl reports each interim (1xx)
	 * response's header block before the final one, and RFC 9110 section 15.2
	 * says only the final response describes the representation, so earlier
	 * freshness fields are discarded.
	 */
	if (bytes >= 5 && strncasecmp(contents, "HTTP/", 5) == 0)
	{
		free(headers->response->cache_control);
		free(headers->response->date);
		free(headers->response->expires);
		free(headers->response->age);
		headers->response->cache_control = NULL;
		headers->response->date = NULL;
		headers->response->expires = NULL;
		headers->response->age = NULL;
		return bytes;
	}

	/*
	 * Fields after the body are trailers (RFC 9110 section 6.5.1): they must
	 * not influence caching decisions made from the header section.
	 */
	if (headers->body != NULL && headers->body->length != 0)
		return bytes;
	colon = memchr(contents, ':', bytes);
	if (colon == NULL)
		return bytes;
	if ((size_t) (colon - contents) == strlen("Cache-Control") &&
		strncasecmp(contents, "Cache-Control", strlen("Cache-Control")) == 0)
		target = &headers->response->cache_control;
	else if ((size_t) (colon - contents) == strlen("Date") &&
			 strncasecmp(contents, "Date", strlen("Date")) == 0)
		target = &headers->response->date;
	else if ((size_t) (colon - contents) == strlen("Expires") &&
			 strncasecmp(contents, "Expires", strlen("Expires")) == 0)
		target = &headers->response->expires;
	else if ((size_t) (colon - contents) == strlen("Age") &&
			 strncasecmp(contents, "Age", strlen("Age")) == 0)
		target = &headers->response->age;
	if (target == NULL)
		return bytes;

	value = colon + 1;
	end = contents + bytes;
	while (value < end && (*value == ' ' || *value == '\t'))
		value++;
	while (end > value &&
		   (end[-1] == '\r' || end[-1] == '\n' || end[-1] == ' ' ||
			end[-1] == '\t'))
		end--;
	if (!append_header_value(target, value, (size_t) (end - value)))
	{
		if (*target != NULL || (size_t) (end - value) >
			PG_OAUTH_MAX_FRESHNESS_HEADER_SIZE)
			headers->too_large = true;
		else
			headers->out_of_memory = true;
		return 0;
	}
	return bytes;
}

static PgOAuthHttpError
parse_url(const char *value, size_t max_url_size, bool allow_insecure_http,
		  CURLU **validated_url, char **parsed_host)
{
	CURLU	   *url;
	char	   *host = NULL;
	char	   *part = NULL;
	size_t		length;
	size_t		scheme_length;
	size_t		authority_length;
	bool		https;
	PgOAuthHttpError error = PG_OAUTH_HTTP_INVALID_URL;

	if (value == NULL || validated_url == NULL || parsed_host == NULL)
		return PG_OAUTH_HTTP_INVALID_ARGUMENT;
	*validated_url = NULL;
	*parsed_host = NULL;
	length = strlen(value);
	if (length == 0 || length > max_url_size)
		return error;
	for (size_t i = 0; i < length; i++)
	{
		unsigned char byte = (unsigned char) value[i];

		if (byte <= 0x20 || byte >= 0x7f || byte == '\\')
			return error;
	}
	https = length > strlen("https://") &&
		memcmp(value, "https://", strlen("https://")) == 0;
	scheme_length = strlen("https://");
	if (!https)
	{
		bool		http = length > strlen("http://") &&
			memcmp(value, "http://", strlen("http://")) == 0;

		if (!http)
			return error;
		if (!allow_insecure_http)
			return PG_OAUTH_HTTP_INSECURE_URL;
		scheme_length = strlen("http://");
	}
	authority_length = strcspn(value + scheme_length, "/?#");
	if (authority_length == 0 || strchr(value, '#') != NULL ||
		memchr(value + scheme_length, '@', authority_length) != NULL)
		return error;

	url = curl_url();
	if (url == NULL)
		return PG_OAUTH_HTTP_OUT_OF_MEMORY;
	if (curl_url_set(url, CURLUPART_URL, value, 0) != CURLUE_OK ||
		curl_url_get(url, CURLUPART_HOST, &host, 0) != CURLUE_OK ||
		host == NULL || host[0] == '\0')
		goto done;
	if (curl_url_get(url, CURLUPART_USER, &part, 0) == CURLUE_OK)
		goto done;
	curl_free(part);
	part = NULL;
	if (curl_url_get(url, CURLUPART_PASSWORD, &part, 0) == CURLUE_OK)
		goto done;
	curl_free(part);
	part = NULL;
	if (curl_url_get(url, CURLUPART_FRAGMENT, &part, 0) == CURLUE_OK)
		goto done;
	*validated_url = url;
	*parsed_host = host;
	url = NULL;
	host = NULL;
	error = PG_OAUTH_HTTP_OK;

done:
	curl_free(part);
	curl_free(host);
	curl_url_cleanup(url);
	return error;
}

static bool
host_in_list(const char *host, const char *list)
{
	const char *entry = list;
	size_t		host_length = strlen(host);

	if (list == NULL || list[0] == '\0')
		return false;
	while (*entry != '\0')
	{
		const char *end = strchr(entry, ',');
		const char *trimmed_end = end != NULL ? end : entry + strlen(entry);

		while (*entry == ' ' || *entry == '\t')
			entry++;
		while (trimmed_end > entry &&
			   (trimmed_end[-1] == ' ' || trimmed_end[-1] == '\t'))
			trimmed_end--;
		if ((size_t) (trimmed_end - entry) == host_length &&
			strncasecmp(entry, host, host_length) == 0)
			return true;
		if (end == NULL)
			break;
		entry = end + 1;
	}
	return false;
}

PgOAuthHttpError
pg_oauth_http_url_host(const char *url, size_t max_url_size,
					   bool allow_insecure_http, char **host)
{
	CURLU	   *parsed_url = NULL;
	char	   *curl_host = NULL;
	PgOAuthHttpError error;

	if (host == NULL)
		return PG_OAUTH_HTTP_INVALID_ARGUMENT;
	*host = NULL;
	error = parse_url(url, max_url_size, allow_insecure_http, &parsed_url,
					  &curl_host);
	if (error == PG_OAUTH_HTTP_OK)
	{
		size_t		host_length = strlen(curl_host);

		*host = malloc(host_length + 1);
		if (*host == NULL)
			error = PG_OAUTH_HTTP_OUT_OF_MEMORY;
		else
			memcpy(*host, curl_host, host_length + 1);
	}
	curl_free(curl_host);
	curl_url_cleanup(parsed_url);
	return error;
}

static PgOAuthHttpError
validate_request_url(const char *value, const PgOAuthHttpPolicy *policy,
					 CURLU **validated_url)
{
	char	   *host = NULL;
	PgOAuthHttpError error;

	error = parse_url(value, policy->max_url_size, policy->allow_insecure_http,
					  validated_url, &host);
	if (error != PG_OAUTH_HTTP_OK)
		return error;
	if (strcasecmp(host, policy->allowed_host) != 0 &&
		!host_in_list(host, policy->additional_allowed_hosts))
	{
		curl_free(host);
		curl_url_cleanup(*validated_url);
		*validated_url = NULL;
		return PG_OAUTH_HTTP_HOST_NOT_ALLOWED;
	}
	curl_free(host);
	return PG_OAUTH_HTTP_OK;
}

static bool
json_content_type(const char *content_type)
{
	static const char json[] = "application/json";
	static const char jwks[] = "application/jwk-set+json";
	const char *start;
	size_t		length;

	if (content_type == NULL)
		return false;
	start = content_type;
	while (*start == ' ' || *start == '\t')
		start++;
	length = strcspn(start, ";");
	while (length > 0 && (start[length - 1] == ' ' || start[length - 1] == '\t'))
		length--;
	return (length == sizeof(json) - 1 &&
			strncasecmp(start, json, length) == 0) ||
		(length == sizeof(jwks) - 1 && strncasecmp(start, jwks, length) == 0);
}

void
pg_oauth_http_response_clear(PgOAuthHttpResponse *response)
{
	if (response == NULL)
		return;
	free(response->body);
	free(response->cache_control);
	free(response->date);
	free(response->expires);
	free(response->age);
	memset(response, 0, sizeof(*response));
}

PgOAuthHttpError
pg_oauth_http_get_json(const char *url, const PgOAuthHttpPolicy *policy,
					   PgOAuthHttpResponse *response)
{
	CURLU	   *validated_url = NULL;
	CURL	   *handle = NULL;
	CURLM	   *multi = NULL;
	bool		added_to_multi = false;
	struct curl_slist *headers = NULL;
	ResponseBuffer buffer = {0};
	HeaderBuffer header_buffer;
	CURLcode	result;
	const curl_version_info_data *curl_info;
	char	   *content_type = NULL;
	PgOAuthHttpError error;

	if (response == NULL)
		return PG_OAUTH_HTTP_INVALID_ARGUMENT;
	memset(response, 0, sizeof(*response));
	header_buffer = (HeaderBuffer)
	{
		.response = response,
			.body = &buffer
	};
	if (url == NULL || policy == NULL || policy->max_url_size == 0 ||
		policy->max_response_size == 0 || policy->allowed_host == NULL ||
		policy->allowed_host[0] == '\0' || policy->connect_timeout_ms <= 0 ||
		policy->total_timeout_ms <= 0 ||
		policy->connect_timeout_ms > policy->total_timeout_ms)
		return PG_OAUTH_HTTP_INVALID_ARGUMENT;
	error = validate_request_url(url, policy, &validated_url);
	if (error != PG_OAUTH_HTTP_OK)
		return error;
	handle = curl_easy_init();
	if (handle == NULL)
	{
		error = PG_OAUTH_HTTP_OUT_OF_MEMORY;
		goto done;
	}
	/* Synchronous DNS or unbounded resolver cleanup can outlive auth timeout. */
	curl_info = curl_version_info(CURLVERSION_NOW);
	if (policy->cancel_requested != NULL &&
		(curl_info == NULL ||
		 (curl_info->features & CURL_VERSION_ASYNCHDNS) == 0 ||
		 curl_info->version_num < 0x075700))
	{
		error = PG_OAUTH_HTTP_NETWORK_FAILURE;
		goto done;
	}
#if LIBCURL_VERSION_NUM < 0x075700
	if (policy->cancel_requested != NULL)
	{
		error = PG_OAUTH_HTTP_NETWORK_FAILURE;
		goto done;
	}
#endif
	headers = curl_slist_append(NULL, "Accept: application/json");
	if (headers == NULL)
	{
		error = PG_OAUTH_HTTP_OUT_OF_MEMORY;
		goto done;
	}
	buffer.maximum = policy->max_response_size;
#define SETOPT(option, value) \
	do { if (curl_easy_setopt(handle, (option), (value)) != CURLE_OK) { \
		error = PG_OAUTH_HTTP_NETWORK_FAILURE; goto done; } } while (0)
	SETOPT(CURLOPT_CURLU, validated_url);
	SETOPT(CURLOPT_HTTPHEADER, headers);
	SETOPT(CURLOPT_HTTPGET, 1L);
	SETOPT(CURLOPT_FOLLOWLOCATION, 0L);
	SETOPT(CURLOPT_MAXREDIRS, 0L);
#if LIBCURL_VERSION_NUM >= 0x075500
	SETOPT(CURLOPT_PROTOCOLS_STR,
		   policy->allow_insecure_http ? "http,https" : "https");
	SETOPT(CURLOPT_REDIR_PROTOCOLS_STR,
		   policy->allow_insecure_http ? "http,https" : "https");
#else
	/* The string options replaced these bitmasks in libcurl 7.85.0. */
	SETOPT(CURLOPT_PROTOCOLS,
		   (long) (CURLPROTO_HTTPS |
				   (policy->allow_insecure_http ? CURLPROTO_HTTP : 0)));
	SETOPT(CURLOPT_REDIR_PROTOCOLS,
		   (long) (CURLPROTO_HTTPS |
				   (policy->allow_insecure_http ? CURLPROTO_HTTP : 0)));
#endif
	SETOPT(CURLOPT_SSL_VERIFYPEER, 1L);
	SETOPT(CURLOPT_SSL_VERIFYHOST, 2L);
	SETOPT(CURLOPT_SSLVERSION, (long) CURL_SSLVERSION_TLSv1_2);
	SETOPT(CURLOPT_NOSIGNAL, 1L);
#if LIBCURL_VERSION_NUM >= 0x075700

	/*
	 * Authentication failure ends this backend; avoid waiting for DNS
	 * cleanup.
	 */
	if (policy->cancel_requested != NULL)
		SETOPT(CURLOPT_QUICK_EXIT, 1L);
#endif
	SETOPT(CURLOPT_NETRC, (long) CURL_NETRC_IGNORED);
	SETOPT(CURLOPT_PROXY, "");
	SETOPT(CURLOPT_CONNECTTIMEOUT_MS, policy->connect_timeout_ms);
	SETOPT(CURLOPT_TIMEOUT_MS, policy->total_timeout_ms);
	SETOPT(CURLOPT_MAXFILESIZE_LARGE, (curl_off_t) policy->max_response_size);
	SETOPT(CURLOPT_WRITEFUNCTION, append_response);
	SETOPT(CURLOPT_WRITEDATA, &buffer);
	SETOPT(CURLOPT_HEADERFUNCTION, capture_header);
	SETOPT(CURLOPT_HEADERDATA, &header_buffer);
	if (policy->ca_file != NULL)
		SETOPT(CURLOPT_CAINFO, policy->ca_file);
#undef SETOPT

	/*
	 * curl_multi_poll bounds each wait so the backend can notice an
	 * interrupt. Keep the callback free of PostgreSQL error unwinding: the
	 * caller checks interrupts only after this function and the cache owner
	 * have cleaned up.
	 */
	multi = curl_multi_init();
	if (multi == NULL)
	{
		error = PG_OAUTH_HTTP_OUT_OF_MEMORY;
		goto done;
	}
	if (curl_multi_add_handle(multi, handle) != CURLM_OK)
	{
		error = PG_OAUTH_HTTP_NETWORK_FAILURE;
		goto done;
	}
	added_to_multi = true;
	{
		int			running = 0;
		CURLMsg    *message;
		int			messages_left;

		for (;;)
		{
			if (policy->cancel_requested != NULL &&
				policy->cancel_requested(policy->cancel_context))
			{
				error = PG_OAUTH_HTTP_INTERRUPTED;
				goto done;
			}
			if (curl_multi_perform(multi, &running) != CURLM_OK)
			{
				error = PG_OAUTH_HTTP_NETWORK_FAILURE;
				goto done;
			}
			if (running == 0)
				break;
			if (curl_multi_poll(multi, NULL, 0, 50, NULL) != CURLM_OK)
			{
				error = PG_OAUTH_HTTP_NETWORK_FAILURE;
				goto done;
			}
		}
		if (policy->cancel_requested != NULL &&
			policy->cancel_requested(policy->cancel_context))
		{
			error = PG_OAUTH_HTTP_INTERRUPTED;
			goto done;
		}
		message = curl_multi_info_read(multi, &messages_left);
		if (message == NULL || message->msg != CURLMSG_DONE)
		{
			error = PG_OAUTH_HTTP_NETWORK_FAILURE;
			goto done;
		}
		result = message->data.result;
	}
	if (result != CURLE_OK)
	{
		if (buffer.too_large || header_buffer.too_large ||
			result == CURLE_FILESIZE_EXCEEDED)
			error = PG_OAUTH_HTTP_RESPONSE_TOO_LARGE;
		else if (buffer.out_of_memory || header_buffer.out_of_memory)
			error = PG_OAUTH_HTTP_OUT_OF_MEMORY;
		else if (result == CURLE_OPERATION_TIMEDOUT)
			error = PG_OAUTH_HTTP_TIMEOUT;
		else if (result == CURLE_PEER_FAILED_VERIFICATION ||
				 result == CURLE_SSL_CONNECT_ERROR ||
				 result == CURLE_SSL_CACERT_BADFILE ||
				 result == CURLE_SSL_CERTPROBLEM)
			error = PG_OAUTH_HTTP_TLS_FAILURE;
		else
			error = PG_OAUTH_HTTP_NETWORK_FAILURE;
		goto done;
	}

	/*
	 * RFC 8414 section 3.2 and RFC 7517 section 5 define the document as the
	 * body of a 200 response. Other 2xx codes (203, 204, 206) can carry no
	 * body or a partial or transformed one, so they are not trusted.
	 */
	if (curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &response->status) !=
		CURLE_OK || response->status != 200)
	{
		error = PG_OAUTH_HTTP_STATUS;
		goto done;
	}
	if (curl_easy_getinfo(handle, CURLINFO_CONTENT_TYPE, &content_type) !=
		CURLE_OK || !json_content_type(content_type))
	{
		error = PG_OAUTH_HTTP_CONTENT_TYPE;
		goto done;
	}
	if (buffer.data == NULL)
	{
		buffer.data = malloc(1);
		if (buffer.data == NULL)
		{
			error = PG_OAUTH_HTTP_OUT_OF_MEMORY;
			goto done;
		}
		buffer.data[0] = '\0';
	}
	response->body = buffer.data;
	response->body_length = buffer.length;
	buffer.data = NULL;
	error = PG_OAUTH_HTTP_OK;

done:
	free(buffer.data);
	if (error != PG_OAUTH_HTTP_OK)
		pg_oauth_http_response_clear(response);
	curl_slist_free_all(headers);
	if (added_to_multi)
		(void) curl_multi_remove_handle(multi, handle);
	if (multi != NULL)
		curl_multi_cleanup(multi);
	curl_easy_cleanup(handle);
	curl_url_cleanup(validated_url);
	return error;
}

const char *
pg_oauth_http_error_code(PgOAuthHttpError error)
{
	switch (error)
	{
		case PG_OAUTH_HTTP_OK:
			return "http_ok";
		case PG_OAUTH_HTTP_INVALID_ARGUMENT:
			return "http_invalid_argument";
		case PG_OAUTH_HTTP_INVALID_URL:
			return "http_invalid_url";
		case PG_OAUTH_HTTP_INSECURE_URL:
			return "http_insecure_url";
		case PG_OAUTH_HTTP_HOST_NOT_ALLOWED:
			return "http_host_not_allowed";
		case PG_OAUTH_HTTP_TIMEOUT:
			return "http_timeout";
		case PG_OAUTH_HTTP_INTERRUPTED:
			return "http_interrupted";
		case PG_OAUTH_HTTP_TLS_FAILURE:
			return "http_tls_failure";
		case PG_OAUTH_HTTP_RESPONSE_TOO_LARGE:
			return "http_response_too_large";
		case PG_OAUTH_HTTP_STATUS:
			return "http_status";
		case PG_OAUTH_HTTP_CONTENT_TYPE:
			return "http_content_type";
		case PG_OAUTH_HTTP_NETWORK_FAILURE:
			return "http_network_failure";
		case PG_OAUTH_HTTP_OUT_OF_MEMORY:
			return "http_out_of_memory";
	}
	return "http_unknown_error";
}
