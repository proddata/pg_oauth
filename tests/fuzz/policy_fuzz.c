/*
 * Fuzz the native validator's configuration parsers: building a validation
 * policy from the GUC values and the matched HBA rule, and deriving the
 * metadata URL from the issuer.
 *
 * Input layout: nine selector bytes choose the numeric settings from a table of
 * boundary values (so both sides of every limit are reached), one flag byte sets
 * the booleans and the size of a small metadata URL buffer, and the rest is
 * split on newlines into the string settings. A missing string takes a valid
 * default, so accepted policies are reachable from small inputs.
 *
 * Besides memory safety the contract is checked: any error leaves a zeroed
 * policy (callbacks initialise to denial), and any accepted policy is complete
 * and bounded. A scope list consisting only of "openid" is checked
 * independently of the parser: it must never produce a policy.
 */
#include "postgres.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "policy.h"
#include "validator_policy.h"

#define FUZZ_MAX_INPUT 16384
#define STRING_FIELDS 10
#define NUMERIC_FIELDS 9

#define REQUIRE(condition) \
	do { \
		if (!(condition)) \
			abort(); \
	} while (0)

static const int boundary_values[] = {
	0, 1, 999, 1000, 5000, 5001, 300000, 300001, 3600000, 3600001, 86400000,
	86400001, -1, INT_MAX
};

#define BOUNDARY_COUNT (sizeof(boundary_values) / sizeof(boundary_values[0]))

static int
pick(uint8_t selector, int typical)
{
	size_t		index = selector % (BOUNDARY_COUNT + 1);

	return index == BOUNDARY_COUNT ? typical : boundary_values[index];
}

/* Every token of the scope list is "openid" (and there is at least one). */
static bool
only_openid(const char *scopes)
{
	bool		any = false;
	const char *cursor = scopes;

	while (*cursor != '\0')
	{
		const char *end = strchr(cursor, ' ');
		size_t		length = end != NULL ? (size_t) (end - cursor) : strlen(cursor);

		if (length > 0)
		{
			if (length != strlen("openid") || memcmp(cursor, "openid", length) != 0)
				return false;
			any = true;
		}
		cursor += length;
		if (*cursor == ' ')
			cursor++;
	}
	return any;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const PgOAuthValidationPolicy zero;
	static const char suffix[] = ".well-known/openid-configuration";
	static const char *const defaults[STRING_FIELDS] = {
		"https://idp.example/", "connect:postgres", "", "postgres://primary",
		"RS256,ES256", "at+jwt,application/at+jwt", "sub", "", "", ""
	};
	char		buffer[FUZZ_MAX_INPUT + 1];
	const char *fields[STRING_FIELDS];
	size_t		count = 0;
	PgOAuthPolicyConfig config;
	PgOAuthHbaPolicy hba;
	PgOAuthValidationPolicy policy;
	char		url[PG_OAUTH_METADATA_URL_BUFFER];
	char		small[64];
	uint8_t		flags;
	char	   *cursor;

	if (size < NUMERIC_FIELDS + 1 || size > FUZZ_MAX_INPUT)
		return 0;
	memcpy(buffer, data + NUMERIC_FIELDS + 1, size - NUMERIC_FIELDS - 1);
	buffer[size - NUMERIC_FIELDS - 1] = '\0';
	flags = data[NUMERIC_FIELDS];

	for (cursor = buffer; count < STRING_FIELDS;)
	{
		fields[count++] = cursor;
		cursor = strchr(cursor, '\n');
		if (cursor == NULL)
			break;
		*cursor++ = '\0';
	}
	for (size_t i = count; i < STRING_FIELDS; i++)
		fields[i] = defaults[i];

	memset(&config, 0, sizeof(config));
	hba.issuer = fields[0];
	hba.required_scopes = fields[1];
	hba.policy_name = fields[2];
	config.audiences = fields[3];
	config.allowed_algorithms = fields[4];
	config.allowed_token_types = fields[5];
	config.identity_claim = fields[6];
	config.role_claim = fields[7];
	config.allowed_jwks_hosts = fields[8];
	config.ca_file = fields[9];
	/* Delegation must agree with the role claim; the flag may break that. */
	hba.delegate_ident_mapping = (config.role_claim[0] != '\0') != ((flags & 1) != 0);
	config.allow_insecure_http = (flags & 2) != 0;
	config.allow_missing_token_type = (flags & 4) != 0;
	config.clock_skew_ms = pick(data[0], 60000);
	config.max_token_size = pick(data[1], 16384);
	config.metadata_default_ttl_ms = pick(data[2], 300000);
	config.jwks_default_ttl_ms = pick(data[3], 300000);
	config.cache_max_ttl_ms = pick(data[4], 3600000);
	config.cache_min_ttl_ms = pick(data[5], 30000);
	config.jwks_stale_grace_ms = pick(data[6], 0);
	config.unknown_kid_refresh_cooldown_ms = pick(data[7], 30000);
	config.refresh_wait_timeout_ms = pick(data[8], 2000);

	memset(&policy, 0x5a, sizeof(policy));
	if (pg_oauth_policy_build(&config, &hba, &policy) != PG_OAUTH_POLICY_OK)
		REQUIRE(memcmp(&policy, &zero, sizeof(zero)) == 0);
	else
	{
		REQUIRE(!only_openid(hba.required_scopes));
		REQUIRE(policy.issuer != NULL && policy.issuer[0] != '\0');
		REQUIRE(policy.required_scopes != NULL && policy.required_scopes[0] != '\0');
		REQUIRE(policy.audiences != NULL && policy.audiences[0] != '\0');
		REQUIRE(policy.identity_claim != NULL && policy.identity_claim[0] != '\0');
		REQUIRE(policy.role_claim != NULL && policy.ca_file != NULL);
		REQUIRE(policy.allowed_algorithms != 0);
		REQUIRE(policy.allowed_token_types >= 1 &&
				policy.allowed_token_types <= PG_OAUTH_TOKEN_TYPES_ALL);
		REQUIRE((policy.role_claim[0] != '\0') == hba.delegate_ident_mapping);
		REQUIRE(policy.clock_skew_ms >= 0);
		REQUIRE(policy.max_token_size > 0);
		REQUIRE(policy.cache_min_ttl_ms >= 0 &&
				policy.cache_min_ttl_ms <= policy.cache_max_ttl_ms);
		REQUIRE(policy.metadata_default_ttl_ms <= policy.cache_max_ttl_ms &&
				policy.jwks_default_ttl_ms <= policy.cache_max_ttl_ms);
		REQUIRE(policy.jwks_stale_grace_ms >= 0 && policy.refresh_wait_timeout_ms >= 0);
	}

	/* Metadata URL derivation from an arbitrary issuer string. */
	memset(url, 0x5a, sizeof(url));
	if (pg_oauth_metadata_url_build(hba.issuer, url, sizeof(url)))
	{
		size_t		issuer_length = strlen(hba.issuer);
		size_t		length = strlen(url);

		REQUIRE(issuer_length > 0 && issuer_length <= PG_OAUTH_MAX_URL_SIZE);
		REQUIRE(length < sizeof(url));
		REQUIRE(memcmp(url, hba.issuer, issuer_length) == 0);
		REQUIRE(length == issuer_length + strlen(suffix) +
				(hba.issuer[issuer_length - 1] == '/' ? 0 : 1));
		REQUIRE(strcmp(url + length - strlen(suffix), suffix) == 0);
	}
	else
		REQUIRE(url[0] == '\0');

	/* A buffer too small for the result must fail and leave an empty string. */
	memset(small, 0x5a, sizeof(small));
	if (pg_oauth_metadata_url_build(hba.issuer, small, 1 + (flags >> 3) % sizeof(small)))
		REQUIRE(memchr(small, '\0', sizeof(small)) != NULL);
	else
		REQUIRE(small[0] == '\0');
	return 0;
}
