#include "metadata.h"

#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <jansson.h>

static bool
valid_url_octets(const char *value, size_t length)
{
	for (size_t i = 0; i < length; i++)
	{
		unsigned char byte = (unsigned char) value[i];

		if (byte <= 0x20 || byte >= 0x7f || byte == '\\')
			return false;
	}
	return true;
}

static PgOAuthMetadataError
validate_url(const char *value, size_t length, size_t maximum,
			 bool allow_http, bool issuer)
{
	CURLU	   *url = NULL;
	char	   *host = NULL;
	char	   *part = NULL;
	CURLUcode	result;
	bool		https;
	size_t		scheme_length;
	size_t		authority_length;
	PgOAuthMetadataError error = PG_OAUTH_METADATA_INVALID_JWKS_URI;

	if (length == 0 || length > maximum ||
		!valid_url_octets(value, length) || strchr(value, '#') != NULL)
		return error;
	https = length > strlen("https://") &&
		memcmp(value, "https://", strlen("https://")) == 0;
	scheme_length = strlen("https://");
	if (!https)
	{
		bool		http = length > strlen("http://") &&
			memcmp(value, "http://", strlen("http://")) == 0;

		if (!http)
			return error;
		scheme_length = strlen("http://");
		if (!allow_http)
			return PG_OAUTH_METADATA_INSECURE_URI;
	}
	authority_length = strcspn(value + scheme_length, "/?#");
	if (authority_length == 0 ||
		memchr(value + scheme_length, '@', authority_length) != NULL)
		return error;
	if (issuer && strchr(value, '?') != NULL)
		return error;

	url = curl_url();
	if (url == NULL)
		return error;
	result = curl_url_set(url, CURLUPART_URL, value, 0);
	if (result != CURLUE_OK ||
		curl_url_get(url, CURLUPART_HOST, &host, 0) != CURLUE_OK ||
		host == NULL || host[0] == '\0')
		goto done;
	if (curl_url_get(url, CURLUPART_USER, &part, 0) == CURLUE_OK)
		goto done;
	if (part != NULL)
	{
		curl_free(part);
		part = NULL;
	}
	if (curl_url_get(url, CURLUPART_PASSWORD, &part, 0) == CURLUE_OK)
		goto done;
	if (part != NULL)
	{
		curl_free(part);
		part = NULL;
	}
	if (curl_url_get(url, CURLUPART_FRAGMENT, &part, 0) == CURLUE_OK)
		goto done;
	error = PG_OAUTH_METADATA_OK;

done:
	curl_free(part);
	curl_free(host);
	curl_url_cleanup(url);
	return error;
}

void
pg_oauth_metadata_clear(PgOAuthMetadata *metadata)
{
	if (metadata == NULL)
		return;
	free(metadata->jwks_uri);
	memset(metadata, 0, sizeof(*metadata));
}

PgOAuthMetadataError
pg_oauth_metadata_parse(const char *document, size_t document_length,
						const char *expected_issuer,
						const PgOAuthMetadataPolicy *policy,
						PgOAuthMetadata *metadata)
{
	json_error_t json_error;
	json_t	   *root = NULL;
	json_t	   *issuer;
	json_t	   *jwks_uri;
	const char *issuer_value;
	const char *jwks_uri_value;
	size_t		expected_length;
	size_t		issuer_length;
	size_t		jwks_uri_length;
	PgOAuthMetadataError error;

	if (metadata == NULL)
		return PG_OAUTH_METADATA_INVALID_ARGUMENT;
	memset(metadata, 0, sizeof(*metadata));
	if (document == NULL || expected_issuer == NULL || policy == NULL ||
		policy->max_document_size == 0 || policy->max_url_size == 0)
		return PG_OAUTH_METADATA_INVALID_ARGUMENT;
	if (document_length == 0)
		return PG_OAUTH_METADATA_EMPTY;
	if (document_length > policy->max_document_size)
		return PG_OAUTH_METADATA_TOO_LARGE;
	expected_length = strlen(expected_issuer);
	error = validate_url(expected_issuer, expected_length,
						 policy->max_url_size, policy->allow_insecure_http, true);
	if (error != PG_OAUTH_METADATA_OK)
		return PG_OAUTH_METADATA_INVALID_ISSUER;

	root = json_loadb(document, document_length, JSON_REJECT_DUPLICATES,
					  &json_error);
	if (root == NULL || !json_is_object(root))
	{
		error = PG_OAUTH_METADATA_INVALID_JSON;
		goto done;
	}
	issuer = json_object_get(root, "issuer");
	if (!json_is_string(issuer))
	{
		error = PG_OAUTH_METADATA_INVALID_ISSUER;
		goto done;
	}
	issuer_value = json_string_value(issuer);
	issuer_length = json_string_length(issuer);
	if (issuer_length != expected_length ||
		memcmp(issuer_value, expected_issuer, expected_length) != 0)
	{
		error = PG_OAUTH_METADATA_ISSUER_MISMATCH;
		goto done;
	}

	jwks_uri = json_object_get(root, "jwks_uri");
	if (!json_is_string(jwks_uri))
	{
		error = PG_OAUTH_METADATA_INVALID_JWKS_URI;
		goto done;
	}
	jwks_uri_value = json_string_value(jwks_uri);
	jwks_uri_length = json_string_length(jwks_uri);
	error = validate_url(jwks_uri_value, jwks_uri_length,
						 policy->max_url_size, policy->allow_insecure_http, false);
	if (error != PG_OAUTH_METADATA_OK)
		goto done;
	metadata->jwks_uri = malloc(jwks_uri_length + 1);
	if (metadata->jwks_uri == NULL)
	{
		error = PG_OAUTH_METADATA_INVALID_ARGUMENT;
		goto done;
	}
	memcpy(metadata->jwks_uri, jwks_uri_value, jwks_uri_length + 1);

done:
	json_decref(root);
	if (error != PG_OAUTH_METADATA_OK)
		pg_oauth_metadata_clear(metadata);
	return error;
}

const char *
pg_oauth_metadata_error_code(PgOAuthMetadataError error)
{
	switch (error)
	{
		case PG_OAUTH_METADATA_OK:
			return "metadata_ok";
		case PG_OAUTH_METADATA_INVALID_ARGUMENT:
			return "metadata_invalid_argument";
		case PG_OAUTH_METADATA_EMPTY:
			return "metadata_empty";
		case PG_OAUTH_METADATA_TOO_LARGE:
			return "metadata_too_large";
		case PG_OAUTH_METADATA_INVALID_JSON:
			return "metadata_invalid_json";
		case PG_OAUTH_METADATA_INVALID_ISSUER:
			return "metadata_invalid_issuer";
		case PG_OAUTH_METADATA_ISSUER_MISMATCH:
			return "metadata_issuer_mismatch";
		case PG_OAUTH_METADATA_INVALID_JWKS_URI:
			return "metadata_invalid_jwks_uri";
		case PG_OAUTH_METADATA_INSECURE_URI:
			return "metadata_insecure_uri";
	}
	return "metadata_unknown_error";
}
