#ifndef PG_OAUTH_VALIDATOR_CACHE_KEY_H
#define PG_OAUTH_VALIDATOR_CACHE_KEY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cache_state.h"
#include "jwt_envelope.h"

typedef enum PgOAuthCacheResource
{
	PG_OAUTH_CACHE_RESOURCE_METADATA = 1,
	PG_OAUTH_CACHE_RESOURCE_JWKS = 2
} PgOAuthCacheResource;

typedef enum PgOAuthCacheKeyError
{
	PG_OAUTH_CACHE_KEY_OK = 0,
	PG_OAUTH_CACHE_KEY_INVALID_ARGUMENT,
	PG_OAUTH_CACHE_KEY_TOO_LARGE
} PgOAuthCacheKeyError;

typedef struct PgOAuthCacheKeyPolicy
{
	PgOAuthCacheResource resource;
	const char *issuer;
	const char *metadata_url;
	const char *jwks_url;
	const char *policy_name;
	const char *required_scopes;
	const char *audiences;
	uint8_t		allowed_token_types;
	bool		allow_missing_token_type;
	const char *identity_claim;
	const char *role_claim;
	const char *allowed_jwks_hosts;
	const char *ca_file;
	uint32_t	allowed_algorithms;
	uint32_t	clock_skew_ms;
	uint32_t	max_token_size;
	uint32_t	max_metadata_size;
	uint32_t	max_jwks_size;
	uint32_t	max_jwks_keys;
	uint32_t	minimum_rsa_bits;
	uint32_t	maximum_rsa_bits;
	uint64_t	jwks_stale_grace_ms;
	uint64_t	metadata_default_ttl_ms;
	uint64_t	jwks_default_ttl_ms;
	uint64_t	cache_max_ttl_ms;
	uint64_t	cache_min_ttl_ms;
	uint64_t	unknown_kid_refresh_cooldown_ms;
	bool		allow_insecure_http;
} PgOAuthCacheKeyPolicy;

typedef struct PgOAuthCacheKey
{
	unsigned char data[PG_OAUTH_CACHE_MAX_KEY_SIZE];
	size_t		length;
} PgOAuthCacheKey;

extern PgOAuthCacheKeyError pg_oauth_cache_key_build(
													 const PgOAuthCacheKeyPolicy *policy, PgOAuthCacheKey *key);
extern const char *pg_oauth_cache_key_error_code(PgOAuthCacheKeyError error);

#endif
