#include "postgres.h"

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ascii.h"
#include "policy.h"
#include "validator_policy.h"

#undef fprintf

static void
fail(const char *message)
{
	fprintf(stderr, "policy_test: %s\n", message);
	exit(EXIT_FAILURE);
}

static PgOAuthPolicyConfig
valid_config(void)
{
	PgOAuthPolicyConfig config = {
		.audiences = "https://postgres.example/",
		.allowed_algorithms = "RS256,ES256",
		.allowed_token_types = "at+jwt,application/at+jwt",
		.identity_claim = "sub",
		.role_claim = "",
		.allowed_jwks_hosts = "",
		.ca_file = "",
		.clock_skew_ms = 60000,
		.max_token_size = 16384,
		.metadata_default_ttl_ms = 300000,
		.jwks_default_ttl_ms = 300000,
		.cache_max_ttl_ms = 3600000,
		.cache_min_ttl_ms = 30000,
		.jwks_stale_grace_ms = 0,
		.unknown_kid_refresh_cooldown_ms = 30000,
		.refresh_wait_timeout_ms = 5000,
	};

	return config;
}

static PgOAuthHbaPolicy
valid_hba(void)
{
	PgOAuthHbaPolicy hba = {
		.issuer = "https://issuer.example/",
		.required_scopes = "connect:postgres",
		.policy_name = "default",
	};

	return hba;
}

static void
expect_error(PgOAuthPolicyConfig *config, PgOAuthHbaPolicy *hba,
			 PgOAuthPolicyError expected, const char *message)
{
	PgOAuthValidationPolicy policy;

	if (pg_oauth_policy_build(config, hba, &policy) != expected)
		fail(message);
}

int
main(void)
{
	PgOAuthPolicyConfig config = valid_config();
	PgOAuthHbaPolicy hba = valid_hba();
	PgOAuthValidationPolicy policy;

	/*
	 * Honour the environment's locale (run with LC_ALL=<a single-byte
	 * locale>) to prove that classification of untrusted bytes does not
	 * depend on it.
	 */
	setlocale(LC_CTYPE, "");

	if (pg_oauth_policy_build(&config, &hba, &policy) != PG_OAUTH_POLICY_OK)
		fail("valid default policy was rejected");
	if (strcmp(policy.name, "default") != 0 ||
		strcmp(policy.issuer, hba.issuer) != 0 ||
		strcmp(policy.required_scopes, hba.required_scopes) != 0 ||
		policy.allowed_algorithms !=
		(PG_OAUTH_ALGORITHM_RS256 | PG_OAUTH_ALGORITHM_ES256))
		fail("valid policy was built incorrectly");

	config = valid_config();
	config.audiences = "";
	expect_error(&config, &hba, PG_OAUTH_POLICY_MISSING_AUDIENCE,
				 "empty audiences were accepted");

	config = valid_config();
	config.audiences = "audience-a,,audience-b";
	expect_error(&config, &hba, PG_OAUTH_POLICY_INVALID_AUDIENCES,
				 "empty audience entry was accepted");

	config = valid_config();
	config.allowed_algorithms = "none";
	expect_error(&config, &hba, PG_OAUTH_POLICY_INVALID_ALGORITHMS,
				 "unsupported algorithm was accepted");

	config = valid_config();
	config.allowed_algorithms = "EdDSA";
	if (pg_oauth_policy_build(&config, &hba, &policy) != PG_OAUTH_POLICY_OK ||
		policy.allowed_algorithms != PG_OAUTH_ALGORITHM_EDDSA)
		fail("EdDSA-only allowlist was not built");

	config = valid_config();
	config.allowed_algorithms = "RS256, EdDSA";
	if (pg_oauth_policy_build(&config, &hba, &policy) != PG_OAUTH_POLICY_OK ||
		policy.allowed_algorithms !=
		(PG_OAUTH_ALGORITHM_RS256 | PG_OAUTH_ALGORITHM_EDDSA))
		fail("mixed RS256/EdDSA allowlist was not built");

	{
		static const char *const rejected[] = {
			"EdDSA,EdDSA", "eddsa", "EDDSA", "Ed25519", "Ed448", "EdDSA,",
			",EdDSA", "EdDSA ES512"
		};

		for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++)
		{
			config = valid_config();
			config.allowed_algorithms = rejected[i];
			expect_error(&config, &hba, PG_OAUTH_POLICY_INVALID_ALGORITHMS,
						 "malformed or unreviewed EdDSA allowlist entry was accepted");
		}
	}

	config = valid_config();
	config.allowed_algorithms = "RS256,RS256";
	expect_error(&config, &hba, PG_OAUTH_POLICY_INVALID_ALGORITHMS,
				 "duplicate algorithm was accepted");

	config = valid_config();
	config.allowed_token_types = "application/at+jwt";
	if (pg_oauth_policy_build(&config, &hba, &policy) != PG_OAUTH_POLICY_OK)
		fail("standard access-token media type was rejected");
	if (policy.allowed_token_types != PG_OAUTH_TOKEN_TYPE_APPLICATION_AT_JWT)
		fail("token-type allowlist was built incorrectly");

	config = valid_config();
	config.allowed_token_types = "JWT";
	expect_error(&config, &hba, PG_OAUTH_POLICY_INVALID_TOKEN_TYPE,
				 "non-access-token type was accepted");
	{
		static const char *const rejected[] = {
			"", "at+jwt,", ",at+jwt", "at+jwt,,application/at+jwt",
			"at+jwt,at+jwt", "JWT,at+jwt", "at+jwt,id+jwt"
		};

		for (size_t i = 0; i < lengthof(rejected); i++)
		{
			config = valid_config();
			config.allowed_token_types = rejected[i];
			expect_error(&config, &hba, PG_OAUTH_POLICY_INVALID_TOKEN_TYPE,
						 "invalid token-type allowlist was accepted");
		}
	}
	config = valid_config();
	config.allow_missing_token_type = true;
	if (pg_oauth_policy_build(&config, &hba, &policy) != PG_OAUTH_POLICY_OK ||
		!policy.allow_missing_token_type)
		fail("explicit missing-type policy was not built");

	config = valid_config();
	config.identity_claim = "display name";
	expect_error(&config, &hba, PG_OAUTH_POLICY_INVALID_AUTHN_CLAIM,
				 "unsafe identity claim name was accepted");

	config = valid_config();
	config.role_claim = "role list";
	expect_error(&config, &hba, PG_OAUTH_POLICY_INVALID_ROLE_CLAIM,
				 "unsafe role claim name was accepted");

	config = valid_config();
	config.allowed_jwks_hosts = "keys.example, cdn.example";
	if (pg_oauth_policy_build(&config, &hba, &policy) != PG_OAUTH_POLICY_OK ||
		strcmp(policy.allowed_jwks_hosts, config.allowed_jwks_hosts) != 0)
		fail("valid additional JWKS hosts were rejected");

	config = valid_config();
	config.allowed_jwks_hosts = "keys.example:443";
	expect_error(&config, &hba, PG_OAUTH_POLICY_INVALID_JWKS_HOSTS,
				 "JWKS host containing a port was accepted");

	config = valid_config();
	config.allowed_jwks_hosts = "keys.example,,cdn.example";
	expect_error(&config, &hba, PG_OAUTH_POLICY_INVALID_JWKS_HOSTS,
				 "empty JWKS host entry was accepted");

	config = valid_config();
	config.clock_skew_ms = 300001;
	expect_error(&config, &hba, PG_OAUTH_POLICY_INVALID_CLOCK_SKEW,
				 "excessive clock skew was accepted");

	config = valid_config();
	config.max_token_size = 1023;
	expect_error(&config, &hba, PG_OAUTH_POLICY_INVALID_TOKEN_SIZE,
				 "undersized token limit was accepted");

#define EXPECT_CACHE_ERROR(field, value, message) \
	do { config = valid_config(); config.field = (value); \
		expect_error(&config, &hba, PG_OAUTH_POLICY_INVALID_CACHE_POLICY, \
			(message)); } while (0)
	EXPECT_CACHE_ERROR(metadata_default_ttl_ms, 999,
					   "undersized metadata fallback TTL was accepted");
	EXPECT_CACHE_ERROR(metadata_default_ttl_ms, 3600001,
					   "oversized metadata fallback TTL was accepted");
	EXPECT_CACHE_ERROR(jwks_default_ttl_ms, 999,
					   "undersized JWKS fallback TTL was accepted");
	EXPECT_CACHE_ERROR(jwks_default_ttl_ms, 3600001,
					   "oversized JWKS fallback TTL was accepted");
	EXPECT_CACHE_ERROR(cache_max_ttl_ms, 299999,
					   "maximum TTL shorter than a fallback was accepted");
	EXPECT_CACHE_ERROR(cache_max_ttl_ms, 86400001,
					   "oversized cache maximum TTL was accepted");
	EXPECT_CACHE_ERROR(cache_min_ttl_ms, -1,
					   "negative minimum cache retention was accepted");
	EXPECT_CACHE_ERROR(cache_min_ttl_ms, 300001,
					   "oversized minimum cache retention was accepted");
	EXPECT_CACHE_ERROR(jwks_stale_grace_ms, -1,
					   "negative JWKS stale grace was accepted");
	EXPECT_CACHE_ERROR(jwks_stale_grace_ms, 3600001,
					   "oversized JWKS stale grace was accepted");
	EXPECT_CACHE_ERROR(unknown_kid_refresh_cooldown_ms, 999,
					   "undersized unknown-kid cooldown was accepted");
	EXPECT_CACHE_ERROR(unknown_kid_refresh_cooldown_ms, 300001,
					   "oversized unknown-kid cooldown was accepted");
	EXPECT_CACHE_ERROR(refresh_wait_timeout_ms, -1,
					   "negative refresh wait timeout was accepted");
	EXPECT_CACHE_ERROR(refresh_wait_timeout_ms, 5001,
					   "oversized refresh wait timeout was accepted");
#undef EXPECT_CACHE_ERROR

	config = valid_config();
	config.metadata_default_ttl_ms = 1000;
	config.jwks_default_ttl_ms = 1000;
	config.cache_max_ttl_ms = 1000;
	config.cache_min_ttl_ms = 1000;
	config.jwks_stale_grace_ms = 3600000;
	config.unknown_kid_refresh_cooldown_ms = 1000;
	if (pg_oauth_policy_build(&config, &hba, &policy) != PG_OAUTH_POLICY_OK)
		fail("valid lower and upper cache-policy boundaries were rejected");

	/* The minimum retention may be disabled, or as long as the maximum. */
	config = valid_config();
	config.cache_min_ttl_ms = 0;
	if (pg_oauth_policy_build(&config, &hba, &policy) != PG_OAUTH_POLICY_OK ||
		policy.cache_min_ttl_ms != 0)
		fail("disabled minimum cache retention was rejected");
	config.cache_min_ttl_ms = 300000;
	if (pg_oauth_policy_build(&config, &hba, &policy) != PG_OAUTH_POLICY_OK ||
		policy.cache_min_ttl_ms != 300000)
		fail("maximum minimum cache retention was rejected");
	/* ...but never longer than the maximum lifetime it falls back under. */
	config = valid_config();
	config.metadata_default_ttl_ms = 1000;
	config.jwks_default_ttl_ms = 1000;
	config.cache_max_ttl_ms = 1000;
	config.cache_min_ttl_ms = 2000;
	expect_error(&config, &hba, PG_OAUTH_POLICY_INVALID_CACHE_POLICY,
				 "minimum retention above the maximum lifetime was accepted");

	config = valid_config();
	hba = valid_hba();
	hba.issuer = "";
	expect_error(&config, &hba, PG_OAUTH_POLICY_MISSING_ISSUER,
				 "empty issuer was accepted");

	hba = valid_hba();
	hba.required_scopes = "";
	expect_error(&config, &hba, PG_OAUTH_POLICY_MISSING_SCOPES,
				 "empty required scopes were accepted");

	/* `openid` only requests an ID token; it never authorizes a connection. */
	hba = valid_hba();
	hba.required_scopes = "openid";
	expect_error(&config, &hba, PG_OAUTH_POLICY_OPENID_ONLY_SCOPES,
				 "openid-only required scopes were accepted");
	hba.required_scopes = "openid openid";
	expect_error(&config, &hba, PG_OAUTH_POLICY_OPENID_ONLY_SCOPES,
				 "repeated openid-only required scopes were accepted");
	hba.required_scopes = "openid connect:postgres";
	if (pg_oauth_policy_build(&config, &hba, &policy) != PG_OAUTH_POLICY_OK)
		fail("openid with a connection scope was rejected");
	hba.required_scopes = "connect:postgres openid";
	if (pg_oauth_policy_build(&config, &hba, &policy) != PG_OAUTH_POLICY_OK)
		fail("a connection scope followed by openid was rejected");
	hba.required_scopes = "openid2";
	if (pg_oauth_policy_build(&config, &hba, &policy) != PG_OAUTH_POLICY_OK)
		fail("a scope that merely starts with openid was rejected");
	hba.required_scopes = "OpenID";
	if (pg_oauth_policy_build(&config, &hba, &policy) != PG_OAUTH_POLICY_OK)
		fail("scope comparison must be case-sensitive");

	hba = valid_hba();
	hba.policy_name = "unknown";
	expect_error(&config, &hba, PG_OAUTH_POLICY_UNKNOWN_POLICY,
				 "unknown named policy was accepted");

	hba = valid_hba();
	hba.delegate_ident_mapping = true;
	expect_error(&config, &hba, PG_OAUTH_POLICY_DELEGATION_MISMATCH,
				 "HBA delegation without claim-roles policy was accepted");

	config = valid_config();
	config.role_claim = "roles";
	hba = valid_hba();
	expect_error(&config, &hba, PG_OAUTH_POLICY_DELEGATION_MISMATCH,
				 "claim-roles policy without HBA delegation was accepted");
	hba.delegate_ident_mapping = true;
	if (pg_oauth_policy_build(&config, &hba, &policy) != PG_OAUTH_POLICY_OK ||
		strcmp(policy.role_claim, "roles") != 0)
		fail("explicit delegated role policy was rejected");

	/*
	 * Bytes at or above 0x80 are ordinary: a valid UTF-8 path may contain
	 * 0x80-0x9f (controls in ISO-8859-1), and a host name may not contain a
	 * Latin-1 letter such as 0xe9 (alphanumeric in ISO-8859-1). The result
	 * must be the same in every locale.
	 */
	config = valid_config();
	hba = valid_hba();
	config.ca_file = "/etc/ssl/caf\xe2\x80\xa6.pem";
	if (pg_oauth_policy_build(&config, &hba, &policy) != PG_OAUTH_POLICY_OK)
		fail("a valid UTF-8 path was rejected as containing control characters");
	config = valid_config();
	config.allowed_jwks_hosts = "caf\xe9.example";
	expect_error(&config, &hba, PG_OAUTH_POLICY_INVALID_JWKS_HOSTS,
				 "a non-ASCII host name was accepted");

	/*
	 * Character classes for untrusted bytes must not depend on the database
	 * locale: exactly the ASCII controls, ASCII white space and ASCII
	 * alphanumerics, and nothing at or above 0x80 (valid UTF-8 uses those).
	 */
	for (int byte = 0; byte < 256; byte++)
	{
		bool		control = byte < 0x20 || byte == 0x7f;
		bool		space = byte == ' ' || (byte >= 9 && byte <= 13);
		bool		alnum = (byte >= '0' && byte <= '9') ||
			(byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z');

		if (pg_oauth_ascii_iscntrl((unsigned char) byte) != control ||
			pg_oauth_ascii_isspace((unsigned char) byte) != space ||
			pg_oauth_ascii_isalnum((unsigned char) byte) != alnum)
			fail("an ASCII character class depends on more than the ASCII table");
	}

	/* Every error has its own stable, non-empty, prefixed diagnostic code. */
	for (int a = PG_OAUTH_POLICY_OK; a <= PG_OAUTH_POLICY_OPENID_ONLY_SCOPES; a++)
	{
		const char *code = pg_oauth_policy_error_code((PgOAuthPolicyError) a);

		if (code == NULL || strncmp(code, "policy_", 7) != 0 ||
			strcmp(code, "policy_unknown_error") == 0)
			fail("a policy error has no stable diagnostic code");
		for (int b = a + 1; b <= PG_OAUTH_POLICY_OPENID_ONLY_SCOPES; b++)
		{
			if (strcmp(code, pg_oauth_policy_error_code((PgOAuthPolicyError) b)) == 0)
				fail("two policy errors share a diagnostic code");
		}
	}
	if (strcmp(pg_oauth_policy_error_code((PgOAuthPolicyError) 9999),
			   "policy_unknown_error") != 0)
		fail("an out-of-range policy error was not reported as unknown");

	/*
	 * The configured issuer is an identifier, not a discovery URL: the
	 * well-known suffix is always appended, with no doubled slash. An issuer
	 * that already is the well-known URL therefore gets it twice, which is
	 * documented in configuration.md so operators do not configure it.
	 */
	{
		static const struct
		{
			const char *issuer;
			const char *expected;	/* NULL: rejected */
		}			cases[] = {
			{"https://idp.example", "https://idp.example/.well-known/openid-configuration"},
			{"https://idp.example/", "https://idp.example/.well-known/openid-configuration"},
			{"https://idp.example/realms/a", "https://idp.example/realms/a/.well-known/openid-configuration"},
			{"https://idp.example/realms/a/", "https://idp.example/realms/a/.well-known/openid-configuration"},
			{"https://idp.example/.well-known/openid-configuration",
			"https://idp.example/.well-known/openid-configuration/.well-known/openid-configuration"},
			{"", NULL},
		};
		char		url[PG_OAUTH_MAX_URL_SIZE + 1];

		for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
		{
			bool		built = pg_oauth_metadata_url_build(cases[i].issuer, url, sizeof(url));

			if (cases[i].expected == NULL ? built :
				(!built || strcmp(url, cases[i].expected) != 0))
				fail("the metadata URL was derived from the issuer incorrectly");
		}
		if (pg_oauth_metadata_url_build("https://idp.example", url, 20) ||
			url[0] != '\0')
			fail("a metadata URL was truncated into a small buffer");
	}
	return EXIT_SUCCESS;
}
