#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "issuer_key.h"

static void fail(const char *message);

typedef struct LocalCache
{
	PgOAuthCache cache;
	PgOAuthCacheEntry entries[8];
} LocalCache;

static PgOAuthCacheIoLookup
local_lookup(void *context, const void *key, size_t key_length,
			 int64_t now_ms, bool allow_stale, void *output, size_t output_size)
{
	LocalCache *local = context;
	PgOAuthCacheIoLookup result = {0};
	size_t		index;

	result.freshness = pg_oauth_cache_lookup(&local->cache, key, key_length,
											 now_ms, allow_stale, &index);
	result.copy_result = PG_OAUTH_CACHE_COPY_NOT_FOUND;
	if (result.freshness != PG_OAUTH_CACHE_MISS)
		result.copy_result = pg_oauth_cache_copy_payload(&local->cache, index,
														 output, output_size, &result.payload_length);
	return result;
}

static PgOAuthCacheRefreshResult
local_begin(void *context, const void *key, size_t key_length, int64_t now_ms,
			bool unknown_kid, int64_t cooldown_ms, PgOAuthCacheRefresh *refresh)
{
	LocalCache *local = context;

	return pg_oauth_cache_begin_refresh(&local->cache, key, key_length, now_ms,
										unknown_kid, cooldown_ms, refresh);
}

static bool
local_complete(void *context, const PgOAuthCacheRefresh *refresh,
			   int64_t now_ms, bool success, bool cacheable,
			   bool revalidation_required, int64_t ttl_ms, int64_t stale_grace_ms,
			   const void *payload, size_t payload_length)
{
	LocalCache *local = context;

	return pg_oauth_cache_complete_refresh(&local->cache, refresh, now_ms,
										   success, cacheable, revalidation_required, ttl_ms, stale_grace_ms,
										   payload, payload_length);
}

static PgOAuthIssuerKeyCachePolicy
cache_policy(LocalCache *local, PgOAuthCacheIo *io)
{
	PgOAuthIssuerKeyCachePolicy value = {
		.io = io,
		.key_policy = {
			.policy_name = "default",
			.required_scopes = "postgresql.connect",
			.audiences = "postgresql",
			.allowed_token_types = PG_OAUTH_TOKEN_TYPE_AT_JWT,
			.identity_claim = "sub",
			.role_claim = "",
			.allowed_jwks_hosts = "",
			.ca_file = "",
			.allowed_algorithms = PG_OAUTH_ALGORITHM_RS256,
			.clock_skew_ms = 60000,
			.max_token_size = 16384,
			.max_metadata_size = 65536,
			.max_jwks_size = 65536,
			.max_jwks_keys = 16,
			.minimum_rsa_bits = 2048,
			.maximum_rsa_bits = 8192,
			.jwks_stale_grace_ms = 0,
			.allow_insecure_http = true,
		},
		.metadata_freshness = {300000, 3600000},
		.jwks_freshness = {300000, 3600000},
		.jwks_stale_grace_ms = 0,
		.unknown_kid_refresh_cooldown_ms = 30000,
		.refresh_wait_timeout_ms = 0,
	};

	memset(local, 0, sizeof(*local));
	if (!pg_oauth_cache_init(&local->cache, local->entries, 8))
		fail("could not initialize local cache");
	io->context = local;
	io->lookup = local_lookup;
	io->begin_refresh = local_begin;
	io->complete_refresh = local_complete;
	return value;
}

static void
fail(const char *message)
{
	fprintf(stderr, "issuer_key_test: %s\n", message);
	exit(EXIT_FAILURE);
}

static PgOAuthIssuerKeyPolicy
policy(void)
{
	PgOAuthIssuerKeyPolicy value = {
		.metadata_http = {
			.max_url_size = 2048,
			.max_response_size = 65536,
			.connect_timeout_ms = 500,
			.total_timeout_ms = 1000,
			.allowed_host = "localhost",
			.allow_insecure_http = true,
		},
		.metadata = {
			.max_document_size = 65536,
			.max_url_size = 2048,
			.allow_insecure_http = true,
		},
		.jwks_http = {
			.max_url_size = 2048,
			.max_response_size = 65536,
			.connect_timeout_ms = 500,
			.total_timeout_ms = 1000,
			.allowed_host = "localhost",
			.allow_insecure_http = true,
		},
		.jwks = {
			.max_jwks_size = 65536,
			.max_keys = 16,
			.max_key_id_size = 1024,
			.allowed_algorithms = PG_OAUTH_ALGORITHM_RS256,
			.minimum_rsa_bits = 2048,
			.maximum_rsa_bits = 8192,
		},
	};

	return value;
}

static void
make_url(char *output, size_t size, const char *base, const char *path)
{
	if (snprintf(output, size, "%s%s", base, path) < 0)
		fail("could not construct test URL");
}

int
main(int argc, char **argv)
{
	PgOAuthIssuerKeyPolicy selected_policy = policy();
	PgOAuthIssuerKeyResult result;
	PgOAuthIssuerKeyError error;
	PgOAuthIssuerKeyCachePolicy selected_cache_policy;
	PgOAuthCacheIo cache_io;
	LocalCache	local_cache;
	char		url[4096];

	if (argc != 2)
		fail("expected mock issuer base URL");
	selected_cache_policy = cache_policy(&local_cache, &cache_io);
	make_url(url, sizeof(url), argv[1], "/metadata-cache");
	error = pg_oauth_issuer_key_fetch_cached(url, argv[1], "test-key",
											 PG_OAUTH_ALGORITHM_RS256, &selected_policy, &selected_cache_policy,
											 1000, 1, &result);
	if (error != PG_OAUTH_ISSUER_KEY_OK)
		fail("cold cached issuer retrieval failed");
	pg_oauth_issuer_key_result_clear(&result);
	error = pg_oauth_issuer_key_fetch_cached(url, argv[1], "test-key",
											 PG_OAUTH_ALGORITHM_RS256, &selected_policy, &selected_cache_policy,
											 1001, 1, &result);
	if (error != PG_OAUTH_ISSUER_KEY_OK)
		fail("fresh cached issuer retrieval failed");
	pg_oauth_issuer_key_result_clear(&result);
	selected_cache_policy.key_policy.audiences = "different-resource";
	error = pg_oauth_issuer_key_fetch_cached(url, argv[1], "test-key",
											 PG_OAUTH_ALGORITHM_RS256, &selected_policy, &selected_cache_policy,
											 1002, 1, &result);
	if (error != PG_OAUTH_ISSUER_KEY_OK)
		fail("policy-separated issuer retrieval failed");
	pg_oauth_issuer_key_result_clear(&result);
	selected_cache_policy.key_policy.audiences = "postgresql";
	error = pg_oauth_issuer_key_fetch_cached(url, argv[1], "test-key",
											 PG_OAUTH_ALGORITHM_RS256, &selected_policy, &selected_cache_policy,
											 2501, 2, &result);
	if (error != PG_OAUTH_ISSUER_KEY_OK)
		fail("expired JWKS refresh failed");
	pg_oauth_issuer_key_result_clear(&result);
	error = pg_oauth_issuer_key_fetch_cached(url, argv[1], "unknown-key",
											 PG_OAUTH_ALGORITHM_RS256, &selected_policy, &selected_cache_policy,
											 2600, 2, &result);
	if (error != PG_OAUTH_ISSUER_KEY_JWKS_INVALID ||
		result.jwks_error != PG_OAUTH_JWKS_KEY_NOT_FOUND)
		fail("unknown cached key did not perform one bounded refresh");
	pg_oauth_issuer_key_result_clear(&result);
	error = pg_oauth_issuer_key_fetch_cached(url, argv[1], "unknown-key",
											 PG_OAUTH_ALGORITHM_RS256, &selected_policy, &selected_cache_policy,
											 2601, 2, &result);
	if (error != PG_OAUTH_ISSUER_KEY_CACHE)
		fail("unknown-key refresh cooldown did not fail closed");
	pg_oauth_issuer_key_result_clear(&result);

	selected_cache_policy = cache_policy(&local_cache, &cache_io);
	selected_cache_policy.jwks_stale_grace_ms = 5000;
	selected_cache_policy.key_policy.jwks_stale_grace_ms = 5000;
	make_url(url, sizeof(url), argv[1], "/metadata-stale");
	error = pg_oauth_issuer_key_fetch_cached(url, argv[1], "test-key",
											 PG_OAUTH_ALGORITHM_RS256, &selected_policy, &selected_cache_policy,
											 1000, 1, &result);
	if (error != PG_OAUTH_ISSUER_KEY_OK)
		fail("initial stale-policy retrieval failed");
	pg_oauth_issuer_key_result_clear(&result);
	error = pg_oauth_issuer_key_fetch_cached(url, argv[1], "test-key",
											 PG_OAUTH_ALGORITHM_RS256, &selected_policy, &selected_cache_policy,
											 2501, 2, &result);
	if (error != PG_OAUTH_ISSUER_KEY_OK || result.selected.jwk == NULL)
		fail("eligible stale JWKS was not used during refresh outage");
	pg_oauth_issuer_key_result_clear(&result);
	make_url(url, sizeof(url), argv[1], "/metadata");
	error = pg_oauth_issuer_key_fetch(url, argv[1], "test-key",
									  PG_OAUTH_ALGORITHM_RS256, &selected_policy, &result);
	if (error != PG_OAUTH_ISSUER_KEY_OK || result.selected.jwk == NULL ||
		result.selected.algorithm != PG_OAUTH_ALGORITHM_RS256)
		fail("valid issuer-bound key retrieval failed");
	pg_oauth_issuer_key_result_clear(&result);

	make_url(url, sizeof(url), argv[1], "/metadata-http-error");
	error = pg_oauth_issuer_key_fetch(url, argv[1], "test-key",
									  PG_OAUTH_ALGORITHM_RS256, &selected_policy, &result);
	if (error != PG_OAUTH_ISSUER_KEY_METADATA_HTTP ||
		result.http_error != PG_OAUTH_HTTP_STATUS)
		fail("metadata HTTP failure lost its typed cause");
	pg_oauth_issuer_key_result_clear(&result);

	make_url(url, sizeof(url), argv[1], "/metadata-wrong-issuer");
	error = pg_oauth_issuer_key_fetch(url, argv[1], "test-key",
									  PG_OAUTH_ALGORITHM_RS256, &selected_policy, &result);
	if (error != PG_OAUTH_ISSUER_KEY_METADATA_INVALID ||
		result.metadata_error != PG_OAUTH_METADATA_ISSUER_MISMATCH)
		fail("wrong metadata issuer was not rejected precisely");
	if (result.selected.jwks != NULL)
		fail("metadata failure retained a selected key");
	pg_oauth_issuer_key_result_clear(&result);

	make_url(url, sizeof(url), argv[1], "/metadata-jwks-http-error");
	error = pg_oauth_issuer_key_fetch(url, argv[1], "test-key",
									  PG_OAUTH_ALGORITHM_RS256, &selected_policy, &result);
	if (error != PG_OAUTH_ISSUER_KEY_JWKS_HTTP ||
		result.http_error != PG_OAUTH_HTTP_STATUS)
		fail("JWKS HTTP failure lost its typed cause");
	pg_oauth_issuer_key_result_clear(&result);

	make_url(url, sizeof(url), argv[1], "/metadata-bad-host");
	error = pg_oauth_issuer_key_fetch(url, argv[1], "test-key",
									  PG_OAUTH_ALGORITHM_RS256, &selected_policy, &result);
	if (error != PG_OAUTH_ISSUER_KEY_JWKS_HTTP ||
		result.http_error != PG_OAUTH_HTTP_HOST_NOT_ALLOWED)
		fail("metadata-selected non-allowlisted JWKS host was requested");
	pg_oauth_issuer_key_result_clear(&result);

	selected_policy.jwks_http.additional_allowed_hosts = "127.0.0.1";
	error = pg_oauth_issuer_key_fetch(url, argv[1], "test-key",
									  PG_OAUTH_ALGORITHM_RS256, &selected_policy, &result);
	if (error != PG_OAUTH_ISSUER_KEY_OK)
		fail("explicitly allowlisted cross-host JWKS was rejected");
	pg_oauth_issuer_key_result_clear(&result);
	selected_policy.jwks_http.additional_allowed_hosts = NULL;

	make_url(url, sizeof(url), argv[1], "/metadata-bad-jwks");
	error = pg_oauth_issuer_key_fetch(url, argv[1], "test-key",
									  PG_OAUTH_ALGORITHM_RS256, &selected_policy, &result);
	if (error != PG_OAUTH_ISSUER_KEY_JWKS_INVALID ||
		result.jwks_error != PG_OAUTH_JWKS_INVALID_JSON)
		fail("malformed retrieved JWKS was not rejected precisely");
	pg_oauth_issuer_key_result_clear(&result);

	make_url(url, sizeof(url), argv[1], "/metadata");
	error = pg_oauth_issuer_key_fetch(url, argv[1], "unknown-key",
									  PG_OAUTH_ALGORITHM_RS256, &selected_policy, &result);
	if (error != PG_OAUTH_ISSUER_KEY_JWKS_INVALID ||
		result.jwks_error != PG_OAUTH_JWKS_KEY_NOT_FOUND)
		fail("unknown key identifier was accepted or retried");
	pg_oauth_issuer_key_result_clear(&result);

	/*
	 * Cold cache, unknown key identifiers. The first fetch publishes the
	 * well-formed document even though it lacks the key, one more refresh
	 * starts the cooldown, and everything after that is suppressed without a
	 * request (the mock server counts them).
	 */
	selected_cache_policy = cache_policy(&local_cache, &cache_io);
	make_url(url, sizeof(url), argv[1], "/metadata-flood");
	for (int attempt = 0; attempt < 4; attempt++)
	{
		char		key_id[32];

		snprintf(key_id, sizeof(key_id), "unknown-%d", attempt);
		error = pg_oauth_issuer_key_fetch_cached(url, argv[1], key_id,
												 PG_OAUTH_ALGORITHM_RS256, &selected_policy,
												 &selected_cache_policy, 1000 + attempt, 1, &result);
		if (attempt < 2 && (error != PG_OAUTH_ISSUER_KEY_JWKS_INVALID ||
							result.jwks_error != PG_OAUTH_JWKS_KEY_NOT_FOUND))
			fail("cold unknown key was not denied as not found");
		if (attempt >= 2 && error != PG_OAUTH_ISSUER_KEY_CACHE)
			fail("unknown-key flood was not suppressed by the cooldown");
		pg_oauth_issuer_key_result_clear(&result);
	}
	error = pg_oauth_issuer_key_fetch_cached(url, argv[1], "test-key",
											 PG_OAUTH_ALGORITHM_RS256, &selected_policy, &selected_cache_policy,
											 1010, 1, &result);
	if (error != PG_OAUTH_ISSUER_KEY_OK || result.selected.jwk == NULL)
		fail("valid key was not served from the document published by a denied token");
	pg_oauth_issuer_key_result_clear(&result);

	/*
	 * A real key identifier with the wrong algorithm must publish as well.
	 * The policy has to allow both algorithms, otherwise selection rejects
	 * the token's algorithm as an invalid argument before it looks at any
	 * key.
	 */
	selected_cache_policy = cache_policy(&local_cache, &cache_io);
	selected_policy.jwks.allowed_algorithms =
		PG_OAUTH_ALGORITHM_RS256 | PG_OAUTH_ALGORITHM_ES256;
	selected_cache_policy.key_policy.allowed_algorithms =
		PG_OAUTH_ALGORITHM_RS256 | PG_OAUTH_ALGORITHM_ES256;
	error = pg_oauth_issuer_key_fetch_cached(url, argv[1], "test-key",
											 PG_OAUTH_ALGORITHM_ES256, &selected_policy, &selected_cache_policy,
											 1000, 1, &result);
	if (error != PG_OAUTH_ISSUER_KEY_JWKS_INVALID ||
		result.jwks_error != PG_OAUTH_JWKS_ALGORITHM_MISMATCH)
		fail("cold algorithm mismatch was not denied precisely");
	pg_oauth_issuer_key_result_clear(&result);
	error = pg_oauth_issuer_key_fetch_cached(url, argv[1], "test-key",
											 PG_OAUTH_ALGORITHM_RS256, &selected_policy, &selected_cache_policy,
											 1001, 1, &result);
	if (error != PG_OAUTH_ISSUER_KEY_OK)
		fail("valid key was not served after an algorithm-mismatch denial");
	pg_oauth_issuer_key_result_clear(&result);
	selected_policy.jwks.allowed_algorithms = PG_OAUTH_ALGORITHM_RS256;

	/* Documents that fail validation are never retained: each call refetches. */
	selected_cache_policy = cache_policy(&local_cache, &cache_io);
	make_url(url, sizeof(url), argv[1], "/metadata-bad-cached");
	for (int attempt = 0; attempt < 2; attempt++)
	{
		error = pg_oauth_issuer_key_fetch_cached(url, argv[1], "test-key",
												 PG_OAUTH_ALGORITHM_RS256, &selected_policy,
												 &selected_cache_policy, 1000 + attempt, 1, &result);
		if (error != PG_OAUTH_ISSUER_KEY_JWKS_INVALID ||
			result.jwks_error != PG_OAUTH_JWKS_INVALID_JSON)
			fail("malformed JWKS was not rejected when cached lookups are enabled");
		pg_oauth_issuer_key_result_clear(&result);
	}
	selected_cache_policy = cache_policy(&local_cache, &cache_io);
	make_url(url, sizeof(url), argv[1], "/metadata-private-jwks");
	for (int attempt = 0; attempt < 2; attempt++)
	{
		error = pg_oauth_issuer_key_fetch_cached(url, argv[1], "test-key",
												 PG_OAUTH_ALGORITHM_RS256, &selected_policy,
												 &selected_cache_policy, 1000 + attempt, 1, &result);
		if (error != PG_OAUTH_ISSUER_KEY_JWKS_INVALID ||
			result.jwks_error != PG_OAUTH_JWKS_INVALID_KEY)
			fail("JWKS with private key material was not rejected");
		pg_oauth_issuer_key_result_clear(&result);
	}

	if (strstr(pg_oauth_issuer_key_error_code(
											  PG_OAUTH_ISSUER_KEY_JWKS_INVALID), "test-key") != NULL)
		fail("stable pipeline error exposed key input");
	return EXIT_SUCCESS;
}
