#include "postgres.h"

#include <ctype.h>
#include <limits.h>
#include <string.h>

#include <openssl/evp.h>

#include "pam_credential.h"
#include "pam_policy.h"

typedef enum ArgumentKind
{
	ARGUMENT_STRING,
	ARGUMENT_NUMBER,
	ARGUMENT_BOOLEAN
} ArgumentKind;

typedef struct ArgumentSpec
{
	const char *name;
	ArgumentKind kind;
	size_t		offset;			/* into PgOAuthPamPolicy */
} ArgumentSpec;

#define SPEC(name, kind, field) \
	{name, kind, offsetof(PgOAuthPamPolicy, field)}

/* Arguments mirror the OAuth validator's settings; units are in the name. */
static const ArgumentSpec specs[] = {
	SPEC("issuer", ARGUMENT_STRING, hba.issuer),
	SPEC("audience", ARGUMENT_STRING, config.audiences),
	SPEC("scope", ARGUMENT_STRING, hba.required_scopes),
	SPEC("algorithms", ARGUMENT_STRING, config.allowed_algorithms),
	SPEC("token_types", ARGUMENT_STRING, config.allowed_token_types),
	SPEC("allow_missing_token_type", ARGUMENT_BOOLEAN, config.allow_missing_token_type),
	SPEC("identity_claim", ARGUMENT_STRING, config.identity_claim),
	SPEC("role_claim", ARGUMENT_STRING, config.role_claim),
	SPEC("clock_skew_ms", ARGUMENT_NUMBER, config.clock_skew_ms),
	SPEC("max_token_size", ARGUMENT_NUMBER, config.max_token_size),
	SPEC("jwks_hosts", ARGUMENT_STRING, config.allowed_jwks_hosts),
	SPEC("ca_file", ARGUMENT_STRING, config.ca_file),
	SPEC("metadata_default_ttl_ms", ARGUMENT_NUMBER, config.metadata_default_ttl_ms),
	SPEC("jwks_default_ttl_ms", ARGUMENT_NUMBER, config.jwks_default_ttl_ms),
	SPEC("cache_max_ttl_ms", ARGUMENT_NUMBER, config.cache_max_ttl_ms),
	SPEC("jwks_stale_grace_ms", ARGUMENT_NUMBER, config.jwks_stale_grace_ms),
	SPEC("unknown_kid_refresh_cooldown_ms", ARGUMENT_NUMBER, config.unknown_kid_refresh_cooldown_ms),
	SPEC("refresh_wait_timeout_ms", ARGUMENT_NUMBER, config.refresh_wait_timeout_ms),
	SPEC("allow_insecure_http", ARGUMENT_BOOLEAN, config.allow_insecure_http),
};

#define SPEC_COUNT (sizeof(specs) / sizeof(specs[0]))

/* Defaults equal the OAuth validator's GUC defaults. */
static void
set_defaults(PgOAuthPamPolicy *policy)
{
	memset(policy, 0, sizeof(*policy));
	policy->config.allowed_algorithms = "RS256,ES256";
	policy->config.allowed_token_types = "at+jwt,application/at+jwt";
	policy->config.identity_claim = "sub";
	policy->config.role_claim = "";
	policy->config.allowed_jwks_hosts = "";
	policy->config.ca_file = "";
	policy->config.clock_skew_ms = 60000;
	policy->config.max_token_size = 16384;
	policy->config.metadata_default_ttl_ms = 300000;
	policy->config.jwks_default_ttl_ms = 300000;
	policy->config.cache_max_ttl_ms = 3600000;
	policy->config.jwks_stale_grace_ms = 0;
	policy->config.unknown_kid_refresh_cooldown_ms = 30000;
	policy->config.refresh_wait_timeout_ms = 5000;
}

/* Canonical unsigned decimal: digits only, no sign, space or leading zeros. */
static bool
parse_number(const char *value, int *number)
{
	long		result = 0;
	size_t		length = strlen(value);

	if (length == 0 || length > 9 || (length > 1 && value[0] == '0'))
		return false;
	for (size_t i = 0; i < length; i++)
	{
		if (value[i] < '0' || value[i] > '9')
			return false;
		result = result * 10 + (value[i] - '0');
	}
	*number = (int) result;
	return true;
}

static PgOAuthPamPolicyError
apply(PgOAuthPamPolicy *policy, const ArgumentSpec *spec, const char *value)
{
	char	   *field = (char *) policy + spec->offset;

	switch (spec->kind)
	{
		case ARGUMENT_STRING:
			*(const char **) field = value;
			return PG_OAUTH_PAM_POLICY_OK;
		case ARGUMENT_NUMBER:
			return parse_number(value, (int *) field) ?
				PG_OAUTH_PAM_POLICY_OK : PG_OAUTH_PAM_POLICY_INVALID_NUMBER;
		case ARGUMENT_BOOLEAN:
			if (strcmp(value, "on") == 0)
				*(bool *) field = true;
			else if (strcmp(value, "off") == 0)
				*(bool *) field = false;
			else
				return PG_OAUTH_PAM_POLICY_INVALID_BOOLEAN;
			return PG_OAUTH_PAM_POLICY_OK;
	}
	return PG_OAUTH_PAM_POLICY_INVALID_ARGUMENT;
}

PgOAuthPamPolicyError
pg_oauth_pam_policy_parse(int argc, const char **argv, PgOAuthPamPolicy *policy)
{
	bool		seen[SPEC_COUNT] = {false};

	if (policy == NULL)
		return PG_OAUTH_PAM_POLICY_INVALID_ARGUMENT;
	set_defaults(policy);
	if (argc < 0 || (argc > 0 && argv == NULL))
		return PG_OAUTH_PAM_POLICY_INVALID_ARGUMENT;
	if (argc > PG_OAUTH_PAM_MAX_ARGUMENTS)
		return PG_OAUTH_PAM_POLICY_TOO_MANY_ARGUMENTS;

	for (int i = 0; i < argc; i++)
	{
		const char *argument = argv[i];
		const char *equals;
		size_t		name_length;
		const char *value;
		size_t		spec_index = SPEC_COUNT;
		PgOAuthPamPolicyError error;

		if (argument == NULL)
			return PG_OAUTH_PAM_POLICY_INVALID_ARGUMENT;

		/*
		 * Bound before scanning; the name is short, the value is bounded
		 * below.
		 */
		if (strnlen(argument, PG_OAUTH_PAM_MAX_VALUE_LENGTH + 64) >
			PG_OAUTH_PAM_MAX_VALUE_LENGTH + 64)
			return PG_OAUTH_PAM_POLICY_VALUE_TOO_LONG;
		for (const char *cursor = argument; *cursor != '\0'; cursor++)
		{
			if (iscntrl((unsigned char) *cursor))
				return PG_OAUTH_PAM_POLICY_MALFORMED_ARGUMENT;
		}
		equals = strchr(argument, '=');
		if (equals == NULL || equals == argument)
			return PG_OAUTH_PAM_POLICY_MALFORMED_ARGUMENT;
		name_length = (size_t) (equals - argument);
		value = equals + 1;
		if (strlen(value) > PG_OAUTH_PAM_MAX_VALUE_LENGTH)
			return PG_OAUTH_PAM_POLICY_VALUE_TOO_LONG;

		for (size_t s = 0; s < SPEC_COUNT; s++)
		{
			if (strlen(specs[s].name) == name_length &&
				memcmp(specs[s].name, argument, name_length) == 0)
			{
				spec_index = s;
				break;
			}
		}
		if (spec_index == SPEC_COUNT)
			return PG_OAUTH_PAM_POLICY_UNKNOWN_ARGUMENT;
		if (seen[spec_index])
			return PG_OAUTH_PAM_POLICY_DUPLICATE_ARGUMENT;
		seen[spec_index] = true;
		error = apply(policy, &specs[spec_index], value);
		if (error != PG_OAUTH_PAM_POLICY_OK)
			return error;
	}

	/* The shared builder owns every semantic rule (ranges, lists, claims). */
	policy->hba.policy_name = NULL;

	/*
	 * PAM has no HBA switch for delegation: a non-empty role_claim argument
	 * is the single explicit opt-in. The builder still requires the two to
	 * agree.
	 */
	policy->hba.delegate_ident_mapping = policy->config.role_claim != NULL &&
		policy->config.role_claim[0] != '\0';
	policy->build_error = pg_oauth_policy_build(&policy->config, &policy->hba,
												&policy->validation);
	if (policy->build_error != PG_OAUTH_POLICY_OK)
	{
		memset(&policy->validation, 0, sizeof(policy->validation));
		return PG_OAUTH_PAM_POLICY_INVALID_POLICY;
	}
	if (policy->validation.max_token_size > PG_OAUTH_PAM_MAX_CREDENTIAL)
	{
		memset(&policy->validation, 0, sizeof(policy->validation));
		return PG_OAUTH_PAM_POLICY_TOKEN_SIZE_TOO_LARGE;
	}
	return PG_OAUTH_PAM_POLICY_OK;
}

static bool
digest_field(EVP_MD_CTX *context, const char *name, const void *value, size_t length)
{
	uint64_t	name_length = strlen(name);
	uint64_t	value_length = length;

	return EVP_DigestUpdate(context, &name_length, sizeof(name_length)) == 1 &&
		EVP_DigestUpdate(context, name, (size_t) name_length) == 1 &&
		EVP_DigestUpdate(context, &value_length, sizeof(value_length)) == 1 &&
		(length == 0 || EVP_DigestUpdate(context, value, length) == 1);
}

#define DIGEST_STRING(name, value) \
	digest_field(context, name, (value), strlen(value))
#define DIGEST_INT(name, value) \
	(digest_integer = (int64_t) (value), \
	 digest_field(context, name, &digest_integer, sizeof(digest_integer)))

bool
pg_oauth_pam_policy_digest(const PgOAuthPamPolicy *policy, uint8_t out[32])
{
	const PgOAuthValidationPolicy *v;
	EVP_MD_CTX *context;
	unsigned int length = 0;
	int64_t		digest_integer;
	bool		ok;

	if (policy == NULL || out == NULL || policy->validation.issuer == NULL)
		return false;
	v = &policy->validation;
	context = EVP_MD_CTX_new();
	if (context == NULL)
		return false;
	ok = EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1 &&
		DIGEST_STRING("issuer", v->issuer) &&
		DIGEST_STRING("audience", v->audiences) &&
		DIGEST_STRING("scope", v->required_scopes) &&
		DIGEST_STRING("identity_claim", v->identity_claim) &&
		DIGEST_STRING("role_claim", v->role_claim) &&
		DIGEST_STRING("jwks_hosts", v->allowed_jwks_hosts) &&
		DIGEST_STRING("ca_file", v->ca_file) &&
		DIGEST_INT("algorithms", v->allowed_algorithms) &&
		DIGEST_INT("token_types", v->allowed_token_types) &&
		DIGEST_INT("allow_missing_token_type", v->allow_missing_token_type) &&
		DIGEST_INT("clock_skew_ms", v->clock_skew_ms) &&
		DIGEST_INT("max_token_size", v->max_token_size) &&
		DIGEST_INT("metadata_default_ttl_ms", v->metadata_default_ttl_ms) &&
		DIGEST_INT("jwks_default_ttl_ms", v->jwks_default_ttl_ms) &&
		DIGEST_INT("cache_max_ttl_ms", v->cache_max_ttl_ms) &&
		DIGEST_INT("jwks_stale_grace_ms", v->jwks_stale_grace_ms) &&
		DIGEST_INT("unknown_kid_refresh_cooldown_ms", v->unknown_kid_refresh_cooldown_ms) &&
		DIGEST_INT("refresh_wait_timeout_ms", v->refresh_wait_timeout_ms) &&
		DIGEST_INT("allow_insecure_http", v->allow_insecure_http) &&
		EVP_DigestFinal_ex(context, out, &length) == 1 && length == 32;
	EVP_MD_CTX_free(context);
	return ok;
}

const char *
pg_oauth_pam_policy_error_code(PgOAuthPamPolicyError error)
{
	switch (error)
	{
		case PG_OAUTH_PAM_POLICY_OK:
			return "ok";
		case PG_OAUTH_PAM_POLICY_INVALID_ARGUMENT:
			return "policy_invalid_argument";
		case PG_OAUTH_PAM_POLICY_TOO_MANY_ARGUMENTS:
			return "policy_too_many_arguments";
		case PG_OAUTH_PAM_POLICY_MALFORMED_ARGUMENT:
			return "policy_malformed_argument";
		case PG_OAUTH_PAM_POLICY_UNKNOWN_ARGUMENT:
			return "policy_unknown_argument";
		case PG_OAUTH_PAM_POLICY_DUPLICATE_ARGUMENT:
			return "policy_duplicate_argument";
		case PG_OAUTH_PAM_POLICY_VALUE_TOO_LONG:
			return "policy_value_too_long";
		case PG_OAUTH_PAM_POLICY_INVALID_NUMBER:
			return "policy_invalid_number";
		case PG_OAUTH_PAM_POLICY_INVALID_BOOLEAN:
			return "policy_invalid_boolean";
		case PG_OAUTH_PAM_POLICY_INVALID_POLICY:
			return "policy_invalid";
		case PG_OAUTH_PAM_POLICY_TOKEN_SIZE_TOO_LARGE:
			return "policy_token_size_too_large";
	}
	return "policy_internal_error";
}
