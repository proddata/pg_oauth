#include "postgres.h"

#include <string.h>

#include "validator_policy.h"

bool
pg_oauth_metadata_url_build(const char *issuer, char *out, size_t size)
{
	static const char with_slash[] = ".well-known/openid-configuration";
	static const char without_slash[] = "/.well-known/openid-configuration";
	size_t		length;
	const char *suffix;
	size_t		suffix_length;

	if (out == NULL || size == 0)
		return false;
	out[0] = '\0';
	if (issuer == NULL)
		return false;
	length = strlen(issuer);
	if (length == 0 || length > PG_OAUTH_MAX_URL_SIZE)
		return false;
	suffix = issuer[length - 1] == '/' ? with_slash : without_slash;
	suffix_length = strlen(suffix);
	if (suffix_length > PG_OAUTH_MAX_URL_SIZE - length ||
		length + suffix_length + 1 > size)
		return false;
	memcpy(out, issuer, length);
	memcpy(out + length, suffix, suffix_length + 1);
	return true;
}

void
pg_oauth_validator_policy_assemble(const PgOAuthValidationPolicy *policy,
								   const char *metadata_host,
								   const char *requested_role,
								   int64_t wall_time, bool (*cancel) (void *),
								   PgOAuthValidatorPolicy *out)
{
	memset(out, 0, sizeof(*out));
	out->envelope.max_token_size = (size_t) policy->max_token_size;
	out->envelope.max_header_size = 4096;
	out->envelope.max_payload_size = (size_t) policy->max_token_size;
	out->envelope.allowed_algorithms = policy->allowed_algorithms;
	out->envelope.allowed_token_types = policy->allowed_token_types;
	out->envelope.allow_missing_token_type = policy->allow_missing_token_type;
	out->issuer_key.metadata_http = (PgOAuthHttpPolicy)
	{
		PG_OAUTH_MAX_URL_SIZE, PG_OAUTH_MAX_DOCUMENT_SIZE,
			PG_OAUTH_HTTP_CONNECT_TIMEOUT_MS, PG_OAUTH_HTTP_TOTAL_TIMEOUT_MS,
			metadata_host, NULL,
			policy->ca_file[0] != '\0' ? policy->ca_file : NULL,
			policy->allow_insecure_http,
			cancel, NULL
	};
	out->issuer_key.metadata = (PgOAuthMetadataPolicy)
	{
		PG_OAUTH_MAX_DOCUMENT_SIZE, PG_OAUTH_MAX_URL_SIZE,
			policy->allow_insecure_http
	};
	out->issuer_key.jwks_http = (PgOAuthHttpPolicy)
	{
		PG_OAUTH_MAX_URL_SIZE, PG_OAUTH_MAX_DOCUMENT_SIZE,
			PG_OAUTH_HTTP_CONNECT_TIMEOUT_MS, PG_OAUTH_HTTP_TOTAL_TIMEOUT_MS,
			metadata_host, policy->allowed_jwks_hosts,
			policy->ca_file[0] != '\0' ? policy->ca_file : NULL,
			policy->allow_insecure_http,
			cancel, NULL
	};
	out->issuer_key.jwks = (PgOAuthJwksPolicy)
	{
		PG_OAUTH_MAX_DOCUMENT_SIZE, 16, 1024, policy->allowed_algorithms,
			2048, 8192
	};
	out->claims = (PgOAuthClaimsPolicy)
	{
		.issuer = policy->issuer,
			.audiences = policy->audiences,
			.required_scopes = policy->required_scopes,
			.identity_claim = policy->identity_claim,
			.role_claim = policy->role_claim,
			.requested_role = requested_role,
			.current_time = wall_time,
			.clock_skew_seconds = (uint32) (policy->clock_skew_ms / 1000),
			.max_identity_size = NAMEDATALEN - 1,
			.max_subject_size = PG_OAUTH_MAX_IDENTITY_SIZE,
			.max_audiences = 16,
			.max_scopes = 64,
			.max_roles = 64,
			.max_role_size = NAMEDATALEN - 1
	};
	out->identity = (PgOAuthIdentityPolicy)
	{
		.max_subject_size = NAMEDATALEN - 1,
			.max_authn_id_size = NAMEDATALEN - 1
	};
}

void
pg_oauth_cache_policy_assemble(const PgOAuthValidationPolicy *policy,
							   const PgOAuthCacheIo *io,
							   PgOAuthIssuerKeyCachePolicy *out)
{
	memset(out, 0, sizeof(*out));
	out->io = io;
	out->key_policy = (PgOAuthCacheKeyPolicy)
	{
		.policy_name = policy->name,
			.required_scopes = policy->required_scopes,
			.audiences = policy->audiences,
			.allowed_token_types = policy->allowed_token_types,
			.allow_missing_token_type = policy->allow_missing_token_type,
			.identity_claim = policy->identity_claim,
			.role_claim = policy->role_claim,
			.allowed_jwks_hosts = policy->allowed_jwks_hosts,
			.ca_file = policy->ca_file,
			.allowed_algorithms = policy->allowed_algorithms,
			.clock_skew_ms = (uint32) policy->clock_skew_ms,
			.max_token_size = (uint32) policy->max_token_size,
			.max_metadata_size = PG_OAUTH_MAX_DOCUMENT_SIZE,
			.max_jwks_size = PG_OAUTH_MAX_DOCUMENT_SIZE,
			.max_jwks_keys = 16,
			.minimum_rsa_bits = 2048,
			.maximum_rsa_bits = 8192,
			.jwks_stale_grace_ms = (uint64) policy->jwks_stale_grace_ms,
			.metadata_default_ttl_ms = (uint64) policy->metadata_default_ttl_ms,
			.jwks_default_ttl_ms = (uint64) policy->jwks_default_ttl_ms,
			.cache_max_ttl_ms = (uint64) policy->cache_max_ttl_ms,
			.unknown_kid_refresh_cooldown_ms =
			(uint64) policy->unknown_kid_refresh_cooldown_ms,
			.allow_insecure_http = policy->allow_insecure_http,
	};
	out->metadata_freshness = (PgOAuthHttpFreshnessPolicy)
	{
		policy->metadata_default_ttl_ms, policy->cache_max_ttl_ms
	};
	out->jwks_freshness = (PgOAuthHttpFreshnessPolicy)
	{
		policy->jwks_default_ttl_ms, policy->cache_max_ttl_ms
	};
	out->jwks_stale_grace_ms = policy->jwks_stale_grace_ms;
	out->unknown_kid_refresh_cooldown_ms = policy->unknown_kid_refresh_cooldown_ms;
	out->refresh_wait_timeout_ms = policy->refresh_wait_timeout_ms;
}
