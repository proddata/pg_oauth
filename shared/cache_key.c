#include "cache_key.h"

#include <limits.h>
#include <string.h>

#define PG_OAUTH_CACHE_KEY_VERSION 6

static bool
append_bytes(PgOAuthCacheKey *key, const void *value, size_t length)
{
	if (length > sizeof(key->data) - key->length)
		return false;
	memcpy(key->data + key->length, value, length);
	key->length += length;
	return true;
}

static bool
append_u8(PgOAuthCacheKey *key, uint8_t value)
{
	return append_bytes(key, &value, sizeof(value));
}

static bool
append_u32(PgOAuthCacheKey *key, uint32_t value)
{
	unsigned char encoded[4] = {
		(unsigned char) (value >> 24),
		(unsigned char) (value >> 16),
		(unsigned char) (value >> 8),
		(unsigned char) value,
	};

	return append_bytes(key, encoded, sizeof(encoded));
}

static bool
append_u64(PgOAuthCacheKey *key, uint64_t value)
{
	unsigned char encoded[8];

	for (size_t i = 0; i < sizeof(encoded); i++)
		encoded[i] = (unsigned char) (value >> (56 - i * 8));
	return append_bytes(key, encoded, sizeof(encoded));
}

static bool
append_string(PgOAuthCacheKey *key, const char *value)
{
	size_t		length = 0;

	if (value == NULL)
		return false;
	while (length < sizeof(key->data) && value[length] != '\0')
		length++;
	if (length == sizeof(key->data) || length > UINT32_MAX ||
		!append_u32(key, (uint32_t) length))
		return false;
	return append_bytes(key, value, length);
}

PgOAuthCacheKeyError
pg_oauth_cache_key_build(const PgOAuthCacheKeyPolicy *policy,
						 PgOAuthCacheKey *key)
{
	static const unsigned char magic[] = {'P', 'G', 'O', 'C'};

	if (key == NULL)
		return PG_OAUTH_CACHE_KEY_INVALID_ARGUMENT;
	memset(key, 0, sizeof(*key));
	if (policy == NULL ||
		(policy->resource != PG_OAUTH_CACHE_RESOURCE_METADATA &&
		 policy->resource != PG_OAUTH_CACHE_RESOURCE_JWKS) ||
		policy->issuer == NULL || policy->issuer[0] == '\0' ||
		policy->metadata_url == NULL || policy->metadata_url[0] == '\0' ||
		(policy->resource == PG_OAUTH_CACHE_RESOURCE_JWKS &&
		 (policy->jwks_url == NULL || policy->jwks_url[0] == '\0')) ||
		policy->policy_name == NULL || policy->required_scopes == NULL ||
		policy->audiences == NULL || policy->allowed_token_types == 0 ||
		(policy->allowed_token_types & ~PG_OAUTH_TOKEN_TYPES_ALL) != 0 ||
		policy->identity_claim == NULL || policy->role_claim == NULL ||
		policy->allowed_jwks_hosts == NULL ||
		policy->ca_file == NULL ||
		policy->allowed_algorithms == 0 || policy->max_token_size == 0 ||
		policy->max_metadata_size == 0 || policy->max_jwks_size == 0 ||
		policy->max_jwks_keys == 0 || policy->minimum_rsa_bits == 0 ||
		policy->maximum_rsa_bits < policy->minimum_rsa_bits)
		return PG_OAUTH_CACHE_KEY_INVALID_ARGUMENT;

	if (!append_bytes(key, magic, sizeof(magic)) ||
		!append_u8(key, PG_OAUTH_CACHE_KEY_VERSION) ||
		!append_u8(key, (uint8_t) policy->resource) ||
		!append_string(key, policy->issuer) ||
		!append_string(key, policy->metadata_url) ||
		!append_string(key, policy->jwks_url != NULL ? policy->jwks_url : "") ||
		!append_string(key, policy->policy_name) ||
		!append_string(key, policy->required_scopes) ||
		!append_string(key, policy->audiences) ||
		!append_u8(key, policy->allowed_token_types) ||
		!append_u8(key, policy->allow_missing_token_type ? 1 : 0) ||
		!append_string(key, policy->identity_claim) ||
		!append_string(key, policy->role_claim) ||
		!append_string(key, policy->allowed_jwks_hosts) ||
		!append_string(key, policy->ca_file) ||
		!append_u32(key, policy->allowed_algorithms) ||
		!append_u32(key, policy->clock_skew_ms) ||
		!append_u32(key, policy->max_token_size) ||
		!append_u32(key, policy->max_metadata_size) ||
		!append_u32(key, policy->max_jwks_size) ||
		!append_u32(key, policy->max_jwks_keys) ||
		!append_u32(key, policy->minimum_rsa_bits) ||
		!append_u32(key, policy->maximum_rsa_bits) ||
		!append_u64(key, policy->jwks_stale_grace_ms) ||
		!append_u64(key, policy->metadata_default_ttl_ms) ||
		!append_u64(key, policy->jwks_default_ttl_ms) ||
		!append_u64(key, policy->cache_max_ttl_ms) ||
		!append_u64(key, policy->cache_min_ttl_ms) ||
		!append_u64(key, policy->unknown_kid_refresh_cooldown_ms) ||
		!append_u8(key, policy->allow_insecure_http ? 1 : 0))
	{
		memset(key, 0, sizeof(*key));
		return PG_OAUTH_CACHE_KEY_TOO_LARGE;
	}
	return PG_OAUTH_CACHE_KEY_OK;
}

const char *
pg_oauth_cache_key_error_code(PgOAuthCacheKeyError error)
{
	switch (error)
	{
		case PG_OAUTH_CACHE_KEY_OK:
			return "cache_key_ok";
		case PG_OAUTH_CACHE_KEY_INVALID_ARGUMENT:
			return "cache_key_invalid_argument";
		case PG_OAUTH_CACHE_KEY_TOO_LARGE:
			return "cache_key_too_large";
	}
	return "cache_key_unknown_error";
}
