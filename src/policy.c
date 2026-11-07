/*
 * Builds the immutable validation policy from administrator configuration
 * (GUCs) and the matched pg_hba.conf rule.
 *
 * Security policy is explicit here rather than inherited from a library
 * default: audience and the required scopes have no default, the algorithm
 * allowlist is exact and duplicate-free, and every bound is range-checked.
 * Any invalid or incomplete setting returns a specific error and no policy,
 * so authentication fails closed instead of running with a weaker one.
 */
#include "postgres.h"

#include <ctype.h>
#include <string.h>

#include "policy.h"

#define PG_OAUTH_MAX_AUDIENCES 16
#define PG_OAUTH_MAX_AUTHN_CLAIM_LENGTH 128
#define PG_OAUTH_MAX_JWKS_HOSTS 16
#define PG_OAUTH_MAX_HOST_LENGTH 253
#define PG_OAUTH_MAX_CLOCK_SKEW_MS (5 * 60 * 1000)
#define PG_OAUTH_MIN_TOKEN_SIZE 1024
#define PG_OAUTH_MAX_TOKEN_SIZE (64 * 1024)

static bool
is_nonempty(const char *value)
{
	return value != NULL && value[0] != '\0';
}

/* Only the two RFC 9068 spellings are access-token types. */
static bool
parse_token_types(const char *value, uint8_t *types)
{
	const char *entry = value;
	uint8_t		result = 0;

	if (!is_nonempty(value) || strlen(value) > 64)
		return false;
	while (*entry != '\0')
	{
		const char *end = strchr(entry, ',');
		size_t		length = end != NULL ? (size_t) (end - entry) : strlen(entry);
		uint8_t		type;

		while (length > 0 && isspace((unsigned char) *entry))
		{
			entry++;
			length--;
		}
		while (length > 0 && isspace((unsigned char) entry[length - 1]))
			length--;
		if (length == strlen("at+jwt") &&
			memcmp(entry, "at+jwt", length) == 0)
			type = PG_OAUTH_TOKEN_TYPE_AT_JWT;
		else if (length == strlen("application/at+jwt") &&
				 memcmp(entry, "application/at+jwt", length) == 0)
			type = PG_OAUTH_TOKEN_TYPE_APPLICATION_AT_JWT;
		else
			return false;
		if ((result & type) != 0)
			return false;
		result |= type;
		if (end == NULL)
			break;
		entry = end + 1;
		if (*entry == '\0')
			return false;
	}
	*types = result;
	return result != 0;
}

static bool
validate_audiences(const char *value)
{
	const char *entry = value;
	int			count = 0;

	while (*entry != '\0')
	{
		const char *end = strchr(entry, ',');
		const char *trimmed_end = end != NULL ? end : entry + strlen(entry);

		while (*entry != '\0' && isspace((unsigned char) *entry))
			entry++;
		while (trimmed_end > entry &&
			   isspace((unsigned char) trimmed_end[-1]))
			trimmed_end--;

		if (trimmed_end == entry || ++count > PG_OAUTH_MAX_AUDIENCES)
			return false;

		for (const char *cursor = entry; cursor < trimmed_end; cursor++)
		{
			if (iscntrl((unsigned char) *cursor))
				return false;
		}

		if (end == NULL)
			break;
		entry = end + 1;
		if (*entry == '\0')
			return false;
	}

	return count > 0;
}

/*
 * Parse the administrator's algorithm allowlist. Matching is exact and
 * case-sensitive; unknown names, duplicates, and empty entries are rejected
 * so that a typo cannot silently narrow or widen what is accepted.
 */
static bool
parse_algorithms(const char *value, uint32 *algorithms)
{
	const char *entry = value;
	uint32		result = 0;

	if (!is_nonempty(value))
		return false;

	while (*entry != '\0')
	{
		const char *end = strchr(entry, ',');
		size_t		length = end != NULL ? (size_t) (end - entry) : strlen(entry);
		uint32		algorithm;

		while (length > 0 && isspace((unsigned char) *entry))
		{
			entry++;
			length--;
		}
		while (length > 0 && isspace((unsigned char) entry[length - 1]))
			length--;

		if (length == 5 && memcmp(entry, "RS256", length) == 0)
			algorithm = PG_OAUTH_ALGORITHM_RS256;
		else if (length == 5 && memcmp(entry, "ES256", length) == 0)
			algorithm = PG_OAUTH_ALGORITHM_ES256;
		else if (length == 5 && memcmp(entry, "EdDSA", length) == 0)
			algorithm = PG_OAUTH_ALGORITHM_EDDSA;
		else
			return false;

		if ((result & algorithm) != 0)
			return false;
		result |= algorithm;

		if (end == NULL)
			break;
		entry = end + 1;
		if (*entry == '\0')
			return false;
	}

	*algorithms = result;
	return result != 0;
}

static bool
validate_claim_name(const char *claim)
{
	size_t		length;

	if (!is_nonempty(claim))
		return false;

	length = strlen(claim);
	if (length > PG_OAUTH_MAX_AUTHN_CLAIM_LENGTH)
		return false;

	for (size_t i = 0; i < length; i++)
	{
		if (iscntrl((unsigned char) claim[i]) ||
			isspace((unsigned char) claim[i]))
			return false;
	}

	return true;
}

static bool
validate_jwks_hosts(const char *value)
{
	const char *entry;
	int			count = 0;

	if (value == NULL || value[0] == '\0')
		return true;
	entry = value;
	while (*entry != '\0')
	{
		const char *end = strchr(entry, ',');
		const char *trimmed_end = end != NULL ? end : entry + strlen(entry);
		size_t		length;

		while (*entry != '\0' && isspace((unsigned char) *entry))
			entry++;
		while (trimmed_end > entry &&
			   isspace((unsigned char) trimmed_end[-1]))
			trimmed_end--;
		length = (size_t) (trimmed_end - entry);
		if (length == 0 || length > PG_OAUTH_MAX_HOST_LENGTH ||
			++count > PG_OAUTH_MAX_JWKS_HOSTS || entry[0] == '.' ||
			entry[0] == '-' || trimmed_end[-1] == '.' || trimmed_end[-1] == '-')
			return false;
		for (const char *cursor = entry; cursor < trimmed_end; cursor++)
		{
			if (!(isalnum((unsigned char) *cursor) || *cursor == '.' ||
				  *cursor == '-'))
				return false;
		}
		if (end == NULL)
			break;
		entry = end + 1;
		if (*entry == '\0')
			return false;
	}
	return true;
}

/*
 * `openid` only asks the provider for an ID token (OpenID Connect Core 1.0,
 * section 3.1.2.1); it says nothing about access to PostgreSQL. A rule whose
 * required scopes are all `openid` would authorize any correctly signed token
 * for the audience, so it is refused (FEATURES.md security invariants).
 * Entries are separated by the same single space the claims check uses.
 */
static bool
scopes_are_only_openid(const char *scopes)
{
	bool		seen = false;

	while (*scopes != '\0')
	{
		size_t		length = strcspn(scopes, " ");

		if (length != 0)
		{
			if (length != strlen("openid") ||
				strncmp(scopes, "openid", length) != 0)
				return false;
			seen = true;
		}
		scopes += length;
		if (*scopes == ' ')
			scopes++;
	}
	return seen;
}

PgOAuthPolicyError
pg_oauth_policy_build(const PgOAuthPolicyConfig *config,
					  const PgOAuthHbaPolicy *hba,
					  PgOAuthValidationPolicy *policy)
{
	uint32		algorithms;
	uint8_t		token_types;

	if (config == NULL || hba == NULL || policy == NULL)
		return PG_OAUTH_POLICY_INVALID_ARGUMENT;

	memset(policy, 0, sizeof(*policy));

	if (!is_nonempty(hba->issuer))
		return PG_OAUTH_POLICY_MISSING_ISSUER;
	if (!is_nonempty(hba->required_scopes))
		return PG_OAUTH_POLICY_MISSING_SCOPES;
	if (scopes_are_only_openid(hba->required_scopes))
		return PG_OAUTH_POLICY_OPENID_ONLY_SCOPES;
	if (hba->policy_name != NULL && hba->policy_name[0] != '\0' &&
		strcmp(hba->policy_name, "default") != 0)
		return PG_OAUTH_POLICY_UNKNOWN_POLICY;
	if (!is_nonempty(config->audiences))
		return PG_OAUTH_POLICY_MISSING_AUDIENCE;
	if (!validate_audiences(config->audiences))
		return PG_OAUTH_POLICY_INVALID_AUDIENCES;
	if (!parse_algorithms(config->allowed_algorithms, &algorithms))
		return PG_OAUTH_POLICY_INVALID_ALGORITHMS;
	if (!parse_token_types(config->allowed_token_types, &token_types))
		return PG_OAUTH_POLICY_INVALID_TOKEN_TYPE;
	if (!validate_claim_name(config->identity_claim))
		return PG_OAUTH_POLICY_INVALID_AUTHN_CLAIM;
	if (config->role_claim == NULL ||
		(config->role_claim[0] != '\0' &&
		 !validate_claim_name(config->role_claim)))
		return PG_OAUTH_POLICY_INVALID_ROLE_CLAIM;
	/* Delegated mapping and the validator's role check must agree. */
	if (hba->delegate_ident_mapping != (config->role_claim[0] != '\0'))
		return PG_OAUTH_POLICY_DELEGATION_MISMATCH;
	if (!validate_jwks_hosts(config->allowed_jwks_hosts))
		return PG_OAUTH_POLICY_INVALID_JWKS_HOSTS;
	if (config->ca_file == NULL || strlen(config->ca_file) > 2048)
		return PG_OAUTH_POLICY_INVALID_CA_FILE;
	for (const char *cursor = config->ca_file; *cursor != '\0'; cursor++)
	{
		if (iscntrl((unsigned char) *cursor))
			return PG_OAUTH_POLICY_INVALID_CA_FILE;
	}
	if (config->clock_skew_ms < 0 ||
		config->clock_skew_ms > PG_OAUTH_MAX_CLOCK_SKEW_MS)
		return PG_OAUTH_POLICY_INVALID_CLOCK_SKEW;
	if (config->max_token_size < PG_OAUTH_MIN_TOKEN_SIZE ||
		config->max_token_size > PG_OAUTH_MAX_TOKEN_SIZE)
		return PG_OAUTH_POLICY_INVALID_TOKEN_SIZE;
	if (config->metadata_default_ttl_ms < 1000 ||
		config->metadata_default_ttl_ms > 3600000 ||
		config->jwks_default_ttl_ms < 1000 ||
		config->jwks_default_ttl_ms > 3600000 ||
		config->cache_max_ttl_ms < config->metadata_default_ttl_ms ||
		config->cache_max_ttl_ms < config->jwks_default_ttl_ms ||
		config->cache_max_ttl_ms > 86400000 ||
		config->cache_min_ttl_ms < 0 ||
		config->cache_min_ttl_ms > 300000 ||
		config->cache_min_ttl_ms > config->cache_max_ttl_ms ||
		config->jwks_stale_grace_ms < 0 ||
		config->jwks_stale_grace_ms > 3600000 ||
		config->unknown_kid_refresh_cooldown_ms < 1000 ||
		config->unknown_kid_refresh_cooldown_ms > 300000 ||
		config->refresh_wait_timeout_ms < 0 ||
		config->refresh_wait_timeout_ms > 5000)
		return PG_OAUTH_POLICY_INVALID_CACHE_POLICY;

	policy->name = "default";
	policy->issuer = hba->issuer;
	policy->required_scopes = hba->required_scopes;
	policy->audiences = config->audiences;
	policy->allowed_token_types = token_types;
	policy->allow_missing_token_type = config->allow_missing_token_type;
	policy->identity_claim = config->identity_claim;
	policy->role_claim = config->role_claim;
	policy->allowed_jwks_hosts = config->allowed_jwks_hosts;
	policy->ca_file = config->ca_file;
	policy->allowed_algorithms = algorithms;
	policy->clock_skew_ms = config->clock_skew_ms;
	policy->max_token_size = config->max_token_size;
	policy->metadata_default_ttl_ms = config->metadata_default_ttl_ms;
	policy->jwks_default_ttl_ms = config->jwks_default_ttl_ms;
	policy->cache_max_ttl_ms = config->cache_max_ttl_ms;
	policy->cache_min_ttl_ms = config->cache_min_ttl_ms;
	policy->jwks_stale_grace_ms = config->jwks_stale_grace_ms;
	policy->unknown_kid_refresh_cooldown_ms =
		config->unknown_kid_refresh_cooldown_ms;
	policy->refresh_wait_timeout_ms = config->refresh_wait_timeout_ms;
	policy->allow_insecure_http = config->allow_insecure_http;

	return PG_OAUTH_POLICY_OK;
}

/* Stable, non-sensitive diagnostic codes; never include configuration values. */
const char *
pg_oauth_policy_error_code(PgOAuthPolicyError error)
{
	switch (error)
	{
		case PG_OAUTH_POLICY_OK:
			return "policy_ok";
		case PG_OAUTH_POLICY_INVALID_ARGUMENT:
			return "policy_invalid_argument";
		case PG_OAUTH_POLICY_MISSING_ISSUER:
			return "policy_missing_issuer";
		case PG_OAUTH_POLICY_MISSING_SCOPES:
			return "policy_missing_scopes";
		case PG_OAUTH_POLICY_MISSING_AUDIENCE:
			return "policy_missing_audience";
		case PG_OAUTH_POLICY_INVALID_AUDIENCES:
			return "policy_invalid_audiences";
		case PG_OAUTH_POLICY_INVALID_ALGORITHMS:
			return "policy_invalid_algorithms";
		case PG_OAUTH_POLICY_INVALID_TOKEN_TYPE:
			return "policy_invalid_token_type";
		case PG_OAUTH_POLICY_INVALID_AUTHN_CLAIM:
			return "policy_invalid_authn_claim";
		case PG_OAUTH_POLICY_INVALID_ROLE_CLAIM:
			return "policy_invalid_role_claim";
		case PG_OAUTH_POLICY_DELEGATION_MISMATCH:
			return "policy_delegation_mismatch";
		case PG_OAUTH_POLICY_INVALID_JWKS_HOSTS:
			return "policy_invalid_jwks_hosts";
		case PG_OAUTH_POLICY_INVALID_CA_FILE:
			return "policy_invalid_ca_file";
		case PG_OAUTH_POLICY_INVALID_CLOCK_SKEW:
			return "policy_invalid_clock_skew";
		case PG_OAUTH_POLICY_INVALID_TOKEN_SIZE:
			return "policy_invalid_token_size";
		case PG_OAUTH_POLICY_INVALID_CACHE_POLICY:
			return "policy_invalid_cache_policy";
		case PG_OAUTH_POLICY_UNKNOWN_POLICY:
			return "policy_unknown_policy";
		case PG_OAUTH_POLICY_OPENID_ONLY_SCOPES:
			return "policy_openid_only_scopes";
	}
	return "policy_unknown_error";
}
