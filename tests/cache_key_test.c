#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cache_key.h"

static void
fail(const char *message)
{
	fprintf(stderr, "cache_key_test: %s\n", message);
	exit(EXIT_FAILURE);
}

static PgOAuthCacheKeyPolicy
policy(void)
{
	PgOAuthCacheKeyPolicy value = {
		.resource = PG_OAUTH_CACHE_RESOURCE_JWKS,
		.issuer = "https://issuer.example/",
		.metadata_url = "https://issuer.example/.well-known/openid-configuration",
		.jwks_url = "https://issuer.example/jwks",
		.policy_name = "default",
		.required_scopes = "connect:postgres",
		.audiences = "postgres://primary",
		.allowed_token_types = PG_OAUTH_TOKEN_TYPE_AT_JWT,
		.identity_claim = "sub",
		.role_claim = "",
		.allowed_jwks_hosts = "",
		.ca_file = "",
		.allowed_algorithms = 1,
		.clock_skew_ms = 60000,
		.max_token_size = 16384,
		.max_metadata_size = 65536,
		.max_jwks_size = 65536,
		.max_jwks_keys = 16,
		.minimum_rsa_bits = 2048,
		.maximum_rsa_bits = 8192,
		.jwks_stale_grace_ms = 0,
		.metadata_default_ttl_ms = 300000,
		.jwks_default_ttl_ms = 300000,
		.cache_max_ttl_ms = 3600000,
		.cache_min_ttl_ms = 30000,
		.unknown_kid_refresh_cooldown_ms = 30000,
		.allow_insecure_http = false,
	};

	return value;
}

static PgOAuthCacheKey
build(PgOAuthCacheKeyPolicy *value)
{
	PgOAuthCacheKey key;

	if (pg_oauth_cache_key_build(value, &key) != PG_OAUTH_CACHE_KEY_OK)
		fail("valid cache key policy was rejected");
	return key;
}

static void
different(const PgOAuthCacheKey *original, PgOAuthCacheKeyPolicy *changed,
		  const char *message)
{
	PgOAuthCacheKey other = build(changed);

	if (original->length == other.length &&
		memcmp(original->data, other.data, original->length) == 0)
		fail(message);
}

int
main(void)
{
	PgOAuthCacheKeyPolicy value = policy();
	PgOAuthCacheKey original = build(&value);
	PgOAuthCacheKey second = build(&value);
	char		oversized[PG_OAUTH_CACHE_MAX_KEY_SIZE + 1];
	char		unterminated[PG_OAUTH_CACHE_MAX_KEY_SIZE];

	if (original.length == 0 || original.length > PG_OAUTH_CACHE_MAX_KEY_SIZE ||
		original.length != second.length ||
		memcmp(original.data, second.data, original.length) != 0)
		fail("cache key encoding was not deterministic");

#define CHECK_STRING(field, replacement) \
	do { value = policy(); value.field = (replacement); \
		different(&original, &value, #field " did not separate cache trust"); } while (0)
#define CHECK_NUMBER(field) \
	do { value = policy(); value.field++; \
		different(&original, &value, #field " did not separate cache trust"); } while (0)
	CHECK_STRING(issuer, "https://other.example/");
	CHECK_STRING(metadata_url, "https://issuer.example/metadata");
	CHECK_STRING(jwks_url, "https://keys.example/jwks");
	CHECK_STRING(policy_name, "production");
	CHECK_STRING(required_scopes, "connect:postgres read:metadata");
	CHECK_STRING(audiences, "postgres://secondary");
	CHECK_NUMBER(allowed_token_types);
	value = policy();
	value.allow_missing_token_type = true;
	different(&original, &value, "missing-type policy did not separate cache trust");
	CHECK_STRING(identity_claim, "uid");
	CHECK_STRING(role_claim, "postgres_roles");
	CHECK_STRING(allowed_jwks_hosts, "keys.example");
	CHECK_STRING(ca_file, "/etc/postgresql/oauth-ca.pem");
	CHECK_NUMBER(allowed_algorithms);
	CHECK_NUMBER(clock_skew_ms);
	CHECK_NUMBER(max_token_size);
	CHECK_NUMBER(max_metadata_size);
	CHECK_NUMBER(max_jwks_size);
	CHECK_NUMBER(max_jwks_keys);
	CHECK_NUMBER(minimum_rsa_bits);
	CHECK_NUMBER(maximum_rsa_bits);
	CHECK_NUMBER(jwks_stale_grace_ms);
	CHECK_NUMBER(metadata_default_ttl_ms);
	CHECK_NUMBER(jwks_default_ttl_ms);
	CHECK_NUMBER(cache_max_ttl_ms);
	CHECK_NUMBER(cache_min_ttl_ms);
	CHECK_NUMBER(unknown_kid_refresh_cooldown_ms);
	value = policy();
	value.allow_insecure_http = true;
	different(&original, &value, "HTTP policy did not separate cache trust");
	value = policy();
	value.resource = PG_OAUTH_CACHE_RESOURCE_METADATA;
	value.jwks_url = NULL;
	different(&original, &value, "resource type did not separate cache trust");
#undef CHECK_NUMBER
#undef CHECK_STRING

	/* Length prefixes prevent delimiter and field-boundary ambiguity. */
	value = policy();
	value.issuer = "a|b";
	value.metadata_url = "c";
	second = build(&value);
	value.issuer = "a";
	value.metadata_url = "b|c";
	different(&second, &value, "length framing allowed a field-boundary collision");

	memset(oversized, 'x', sizeof(oversized) - 1);
	oversized[sizeof(oversized) - 1] = '\0';
	value = policy();
	value.issuer = oversized;
	memset(&second, 0xa5, sizeof(second));
	if (pg_oauth_cache_key_build(&value, &second) !=
		PG_OAUTH_CACHE_KEY_TOO_LARGE || second.length != 0)
		fail("oversized key was accepted or retained partial bytes");
	memset(unterminated, 'x', sizeof(unterminated));
	value = policy();
	value.issuer = unterminated;
	memset(&second, 0x5a, sizeof(second));
	if (pg_oauth_cache_key_build(&value, &second) !=
		PG_OAUTH_CACHE_KEY_TOO_LARGE || second.length != 0 || second.data[0] != 0)
		fail("unterminated key field was not rejected within its bound");
	value = policy();
	value.allowed_algorithms = 0;
	if (pg_oauth_cache_key_build(&value, &second) !=
		PG_OAUTH_CACHE_KEY_INVALID_ARGUMENT)
		fail("incomplete trust policy was accepted");
	if (strstr(pg_oauth_cache_key_error_code(PG_OAUTH_CACHE_KEY_TOO_LARGE),
			   "issuer") != NULL)
		fail("stable cache-key error exposed policy contents");
	return EXIT_SUCCESS;
}
