#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#include "http_transport.h"

static void
fail(const char *message)
{
	fprintf(stderr, "http_transport_test: %s\n", message);
	exit(EXIT_FAILURE);
}

static bool
cancel_after_checks(void *context)
{
	int		   *checks = context;

	return ++* checks >= 3;
}

static bool
never_cancel(void *context)
{
	(void) context;
	return false;
}

static void
expect(const char *url, PgOAuthHttpPolicy *policy, PgOAuthHttpError expected,
	   const char *message)
{
	PgOAuthHttpResponse response;

	if (pg_oauth_http_get_json(url, policy, &response) != expected)
		fail(message);
	if (expected != PG_OAUTH_HTTP_OK && response.body != NULL)
		fail("failed request retained response bytes");
	pg_oauth_http_response_clear(&response);
}

int
main(int argc, char **argv)
{
	PgOAuthHttpPolicy policy = {
		.max_url_size = 2048,
		.max_response_size = 1024,
		.connect_timeout_ms = 500,
		.total_timeout_ms = 500,
		.allowed_host = "localhost",
		.ca_file = NULL,
		.allow_insecure_http = true,
	};
	PgOAuthHttpResponse response;
	char		url[4096];

	if (argc == 2 &&
		(strcmp(argv[1], "--dns-failure") == 0 ||
		 strcmp(argv[1], "--dns-cancel") == 0))
	{
		const curl_version_info_data *info;

		if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
			fail("libcurl initialization failed");
		info = curl_version_info(CURLVERSION_NOW);
		if (info != NULL && info->ares != NULL)
			return 77;
		policy.allowed_host = "resolver-probe.invalid";
		if (strcmp(argv[1], "--dns-cancel") == 0)
		{
			int			checks = 0;

			policy.connect_timeout_ms = 5000;
			policy.total_timeout_ms = 5000;
			policy.cancel_requested = cancel_after_checks;
			policy.cancel_context = &checks;
			expect("http://resolver-probe.invalid/jwks", &policy,
				   PG_OAUTH_HTTP_INTERRUPTED,
				   "DNS lookup cancellation did not deny the request");
		}
		else
		{
			policy.cancel_requested = never_cancel;
			expect("http://resolver-probe.invalid/jwks", &policy,
				   PG_OAUTH_HTTP_NETWORK_FAILURE,
				   "DNS lookup failure did not deny the request");
		}
		curl_global_cleanup();
		return EXIT_SUCCESS;
	}

	if (argc != 4)
		fail("expected HTTP base URL, HTTPS base URL, and CA file");
	snprintf(url, sizeof(url), "%s/ok", argv[1]);
	if (pg_oauth_http_get_json(url, &policy, &response) != PG_OAUTH_HTTP_OK)
		fail("valid bounded HTTP development response failed");
	if (response.body_length != 11 || strcmp(response.body, "{\"ok\":true}") != 0 ||
		response.status != 200)
		fail("successful response was returned incorrectly");
	pg_oauth_http_response_clear(&response);
	snprintf(url, sizeof(url), "%s/fresh", argv[1]);
	if (pg_oauth_http_get_json(url, &policy, &response) != PG_OAUTH_HTTP_OK ||
		response.cache_control == NULL ||
		strcmp(response.cache_control, "public,max-age=120") != 0 ||
		response.age == NULL || strcmp(response.age, "20") != 0 ||
		response.expires == NULL)
		fail("bounded freshness headers were not preserved");
	pg_oauth_http_response_clear(&response);
	snprintf(url, sizeof(url), "%s/large-freshness-header", argv[1]);
	expect(url, &policy, PG_OAUTH_HTTP_RESPONSE_TOO_LARGE,
		   "oversized freshness header was accepted");
	snprintf(url, sizeof(url), "%s/underflow-freshness-header", argv[1]);
	expect(url, &policy, PG_OAUTH_HTTP_RESPONSE_TOO_LARGE,
		   "freshness header limit was bypassed by a second value");
	snprintf(url, sizeof(url), "%s/interim-freshness-header", argv[1]);
	if (pg_oauth_http_get_json(url, &policy, &response) != PG_OAUTH_HTTP_OK ||
		response.cache_control != NULL || response.age != NULL)
		fail("interim response headers were merged into the final response");
	pg_oauth_http_response_clear(&response);
	snprintf(url, sizeof(url), "%s/trailer-freshness-header", argv[1]);
	if (pg_oauth_http_get_json(url, &policy, &response) != PG_OAUTH_HTTP_OK ||
		response.cache_control != NULL)
		fail("trailer fields were merged into the response headers");
	pg_oauth_http_response_clear(&response);
	snprintf(url, sizeof(url), "%s/jwks", argv[1]);
	if (pg_oauth_http_get_json(url, &policy, &response) != PG_OAUTH_HTTP_OK)
		fail("standards JWKS media type was rejected");
	pg_oauth_http_response_clear(&response);

	policy.allow_insecure_http = false;
	expect(url, &policy, PG_OAUTH_HTTP_INSECURE_URL,
		   "HTTP was accepted without development opt-in");
	policy.allow_insecure_http = true;
	snprintf(url, sizeof(url), "%s/redirect", argv[1]);
	expect(url, &policy, PG_OAUTH_HTTP_STATUS, "redirect was followed");
	snprintf(url, sizeof(url), "%s/large", argv[1]);
	policy.max_response_size = 32;
	expect(url, &policy, PG_OAUTH_HTTP_RESPONSE_TOO_LARGE,
		   "oversized response was accepted");
	policy.max_response_size = 1024;
	snprintf(url, sizeof(url), "%s/text", argv[1]);
	expect(url, &policy, PG_OAUTH_HTTP_CONTENT_TYPE,
		   "non-JSON content type was accepted");
	{
		static const char *const statuses[] = {"201", "203", "204", "206"};

		for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++)
		{
			snprintf(url, sizeof(url), "%s/status-%s", argv[1], statuses[i]);
			expect(url, &policy, PG_OAUTH_HTTP_STATUS,
				   "a 2xx response other than 200 was accepted");
		}
	}
	snprintf(url, sizeof(url), "%s/error", argv[1]);
	expect(url, &policy, PG_OAUTH_HTTP_STATUS, "HTTP error status was accepted");
	snprintf(url, sizeof(url), "%s/slow", argv[1]);
	policy.connect_timeout_ms = 50;
	policy.total_timeout_ms = 100;
	expect(url, &policy, PG_OAUTH_HTTP_TIMEOUT, "request timeout was ignored");
	{
		int			checks = 0;

		policy.total_timeout_ms = 500;
		policy.cancel_requested = cancel_after_checks;
		policy.cancel_context = &checks;
		expect(url, &policy, PG_OAUTH_HTTP_INTERRUPTED,
			   "cancelled request did not stop and release its response");
		if (checks < 3)
			fail("cancel callback was not polled during a stalled request");
		policy.cancel_requested = NULL;
		policy.cancel_context = NULL;
	}
	policy.connect_timeout_ms = 500;
	policy.total_timeout_ms = 500;

	snprintf(url, sizeof(url), "%s/ok", argv[1]);
	policy.allowed_host = "example.invalid";
	expect(url, &policy, PG_OAUTH_HTTP_HOST_NOT_ALLOWED,
		   "non-allowlisted host was requested");
	policy.allowed_host = "localhost";
	policy.additional_allowed_hosts = "example.invalid, LOCALHOST";
	expect(url, &policy, PG_OAUTH_HTTP_OK,
		   "exact additional allowlist host was rejected");
	policy.additional_allowed_hosts = NULL;
	expect("http://localhost.attacker.invalid/jwks", &policy,
		   PG_OAUTH_HTTP_HOST_NOT_ALLOWED, "hostname suffix bypass was accepted");
	expect("file:///etc/passwd", &policy, PG_OAUTH_HTTP_INVALID_URL,
		   "non-HTTP protocol was accepted");
	expect("https://user:secret@localhost/jwks", &policy,
		   PG_OAUTH_HTTP_INVALID_URL, "URL credentials were accepted");

	policy.allow_insecure_http = false;
	snprintf(url, sizeof(url), "%s/ok", argv[2]);
	expect(url, &policy, PG_OAUTH_HTTP_TLS_FAILURE,
		   "untrusted TLS certificate was accepted");
	policy.ca_file = argv[3];
	if (pg_oauth_http_get_json(url, &policy, &response) != PG_OAUTH_HTTP_OK)
		fail("trusted TLS response failed");
	pg_oauth_http_response_clear(&response);

	if (strstr(pg_oauth_http_error_code(PG_OAUTH_HTTP_TLS_FAILURE), "localhost") != NULL)
		fail("stable transport error exposed request data");
	return EXIT_SUCCESS;
}
