/* Unit tests for strict PAM stack-argument policy parsing (ADR 0008). */
#include "postgres.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pam_credential.h"
#include "pam_policy.h"

#define require(condition) \
	do { \
		if (!(condition)) \
		{ \
			/* postgres.h redirects fprintf to a symbol the test does not link. */ \
			fputs(__FILE__ ": requirement failed: " #condition "\n", stderr); \
			exit(EXIT_FAILURE); \
		} \
	} while (0)

#define REQUIRED "issuer=https://idp.example/", "audience=postgres://primary", "scope=connect:postgres"

static PgOAuthPamPolicyError
parse(int argc, const char **argv, PgOAuthPamPolicy *policy)
{
	memset(policy, 0x5a, sizeof(*policy));
	return pg_oauth_pam_policy_parse(argc, argv, policy);
}

#define PARSE(policy, ...) \
	parse((int) (sizeof((const char *[]){__VA_ARGS__}) / sizeof(const char *)), \
		  (const char *[]){__VA_ARGS__}, policy)

static void
denied_at(int line, PgOAuthPamPolicyError actual, PgOAuthPamPolicyError expected,
		  const PgOAuthPamPolicy *policy)
{
	static const PgOAuthValidationPolicy zero;

	if (actual != expected)
	{
		/* Identify the failing case without formatting through postgres.h. */
		fputs("unexpected result: got ", stderr);
		fputs(pg_oauth_pam_policy_error_code(actual), stderr);
		fputs(" expected ", stderr);
		fputs(pg_oauth_pam_policy_error_code(expected), stderr);
		fputs(line >= 100 ? " (line >= 100)\n" : " (early)\n", stderr);
		exit(line);
	}
	require(memcmp(&policy->validation, &zero, sizeof(zero)) == 0);
}

#define denied(actual, expected, policy) denied_at(__LINE__, actual, expected, policy)

int
main(void)
{
	PgOAuthPamPolicy p;
	char		long_value[PG_OAUTH_PAM_MAX_VALUE_LENGTH + 64];
	const char *many[PG_OAUTH_PAM_MAX_ARGUMENTS + 1];

	/* Accepted: required arguments with documented defaults. */
	require(PARSE(&p, REQUIRED) == PG_OAUTH_PAM_POLICY_OK);
	require(strcmp(p.validation.issuer, "https://idp.example/") == 0);
	require(strcmp(p.validation.audiences, "postgres://primary") == 0);
	require(strcmp(p.validation.required_scopes, "connect:postgres") == 0);
	require(strcmp(p.validation.identity_claim, "sub") == 0 && p.validation.role_claim[0] == '\0');
	require(p.validation.max_token_size == 16384 && p.validation.clock_skew_ms == 60000);
	require(p.validation.allowed_algorithms == (PG_OAUTH_ALGORITHM_RS256 | PG_OAUTH_ALGORITHM_ES256));
	require(!p.validation.allow_insecure_http && !p.validation.allow_missing_token_type);
	require(!p.hba.delegate_ident_mapping);

	/* Accepted: every optional argument, in any order. */
	require(PARSE(&p, "algorithms=RS256,ES256,EdDSA", "scope=a b", "audience=x,y",
				  "issuer=https://idp.example/", "token_types=at+jwt", "allow_missing_token_type=on",
				  "identity_claim=email", "clock_skew_ms=300000", "max_token_size=65530",
				  "jwks_hosts=keys.example", "ca_file=/etc/ssl/ca.pem",
				  "metadata_default_ttl_ms=1000", "jwks_default_ttl_ms=1000", "cache_max_ttl_ms=1000",
				  "jwks_stale_grace_ms=0", "unknown_kid_refresh_cooldown_ms=1000",
				  "refresh_wait_timeout_ms=0", "allow_insecure_http=off") == PG_OAUTH_PAM_POLICY_OK);
	require(p.validation.max_token_size == 65530 && p.validation.allow_missing_token_type);
	require(p.validation.allowed_algorithms & PG_OAUTH_ALGORITHM_EDDSA);

	/* Delegated roles: role_claim is the single explicit opt-in. */
	require(PARSE(&p, REQUIRED) == PG_OAUTH_PAM_POLICY_OK);
	require(p.validation.role_claim[0] == '\0' && !p.hba.delegate_ident_mapping);
	require(PARSE(&p, REQUIRED, "role_claim=pg_roles") == PG_OAUTH_PAM_POLICY_OK);
	require(strcmp(p.validation.role_claim, "pg_roles") == 0 && p.hba.delegate_ident_mapping);
	require(strcmp(p.validation.identity_claim, "sub") == 0);
	require(PARSE(&p, REQUIRED, "role_claim=pg_roles", "identity_claim=email") == PG_OAUTH_PAM_POLICY_OK);
	require(PARSE(&p, REQUIRED, "role_claim=") == PG_OAUTH_PAM_POLICY_OK);
	require(p.validation.role_claim[0] == '\0' && !p.hba.delegate_ident_mapping);
	denied(PARSE(&p, REQUIRED, "role_claim=has space"), PG_OAUTH_PAM_POLICY_INVALID_POLICY, &p);
	denied(PARSE(&p, REQUIRED, "role_claim=pg_roles", "role_claim=other"), PG_OAUTH_PAM_POLICY_DUPLICATE_ARGUMENT, &p);
	{
		char		long_claim[11 + 129 + 1] = "role_claim=";

		memset(long_claim + 11, 'c', 129);
		long_claim[11 + 129] = '\0';
		denied(PARSE(&p, REQUIRED, long_claim), PG_OAUTH_PAM_POLICY_INVALID_POLICY, &p);
	}

	/* Boundaries of the PAM credential limit. */
	require(PARSE(&p, REQUIRED, "max_token_size=1024") == PG_OAUTH_PAM_POLICY_OK);
	denied(PARSE(&p, REQUIRED, "max_token_size=1023"), PG_OAUTH_PAM_POLICY_INVALID_POLICY, &p);
	denied(PARSE(&p, REQUIRED, "max_token_size=65531"), PG_OAUTH_PAM_POLICY_TOKEN_SIZE_TOO_LARGE, &p);
	denied(PARSE(&p, REQUIRED, "max_token_size=65536"), PG_OAUTH_PAM_POLICY_TOKEN_SIZE_TOO_LARGE, &p);
	denied(PARSE(&p, REQUIRED, "max_token_size=65537"), PG_OAUTH_PAM_POLICY_INVALID_POLICY, &p);

	/* Missing required arguments (never defaulted). */
	denied(PARSE(&p, "audience=postgres://primary", "scope=a"), PG_OAUTH_PAM_POLICY_INVALID_POLICY, &p);
	denied(PARSE(&p, "issuer=https://idp.example/", "scope=a"), PG_OAUTH_PAM_POLICY_INVALID_POLICY, &p);
	denied(PARSE(&p, "issuer=https://idp.example/", "audience=a"), PG_OAUTH_PAM_POLICY_INVALID_POLICY, &p);
	denied(pg_oauth_pam_policy_parse(0, NULL, &p), PG_OAUTH_PAM_POLICY_INVALID_POLICY, &p);
	denied(PARSE(&p, "issuer=", "audience=a", "scope=a"), PG_OAUTH_PAM_POLICY_INVALID_POLICY, &p);

	/* Unknown, duplicate, role_claim (unsupported) and wrong-case names. */
	denied(PARSE(&p, REQUIRED, "bogus=1"), PG_OAUTH_PAM_POLICY_UNKNOWN_ARGUMENT, &p);
	denied(PARSE(&p, REQUIRED, "role_claims=roles"), PG_OAUTH_PAM_POLICY_UNKNOWN_ARGUMENT, &p);
	denied(PARSE(&p, REQUIRED, "roleclaim=roles"), PG_OAUTH_PAM_POLICY_UNKNOWN_ARGUMENT, &p);
	denied(PARSE(&p, REQUIRED, "Issuer=https://x/"), PG_OAUTH_PAM_POLICY_UNKNOWN_ARGUMENT, &p);
	denied(PARSE(&p, REQUIRED, "issue=https://x/"), PG_OAUTH_PAM_POLICY_UNKNOWN_ARGUMENT, &p);
	denied(PARSE(&p, REQUIRED, "issuer=https://other/"), PG_OAUTH_PAM_POLICY_DUPLICATE_ARGUMENT, &p);
	denied(PARSE(&p, REQUIRED, "scope=other"), PG_OAUTH_PAM_POLICY_DUPLICATE_ARGUMENT, &p);

	/* Malformed arguments. */
	denied(PARSE(&p, REQUIRED, "novalue"), PG_OAUTH_PAM_POLICY_MALFORMED_ARGUMENT, &p);
	denied(PARSE(&p, REQUIRED, "=value"), PG_OAUTH_PAM_POLICY_MALFORMED_ARGUMENT, &p);
	denied(PARSE(&p, REQUIRED, ""), PG_OAUTH_PAM_POLICY_MALFORMED_ARGUMENT, &p);
	denied(PARSE(&p, REQUIRED, "ca_file=/a\tb"), PG_OAUTH_PAM_POLICY_MALFORMED_ARGUMENT, &p);
	denied(PARSE(&p, REQUIRED, "ca_file=/a\nb"), PG_OAUTH_PAM_POLICY_MALFORMED_ARGUMENT, &p);
	denied(PARSE(&p, "issuer=https://idp.example/", "audience=a\x01", "scope=a"),
		   PG_OAUTH_PAM_POLICY_MALFORMED_ARGUMENT, &p);
	{
		const char *null_argument[] = {"issuer=https://idp.example/", NULL};

		denied(parse(2, null_argument, &p), PG_OAUTH_PAM_POLICY_INVALID_ARGUMENT, &p);
	}

	/* Numbers: canonical decimal only. */
	denied(PARSE(&p, REQUIRED, "clock_skew_ms=-1"), PG_OAUTH_PAM_POLICY_INVALID_NUMBER, &p);
	denied(PARSE(&p, REQUIRED, "clock_skew_ms=+1"), PG_OAUTH_PAM_POLICY_INVALID_NUMBER, &p);
	denied(PARSE(&p, REQUIRED, "clock_skew_ms= 1"), PG_OAUTH_PAM_POLICY_INVALID_NUMBER, &p);
	denied(PARSE(&p, REQUIRED, "clock_skew_ms=1 "), PG_OAUTH_PAM_POLICY_INVALID_NUMBER, &p);
	denied(PARSE(&p, REQUIRED, "clock_skew_ms=01"), PG_OAUTH_PAM_POLICY_INVALID_NUMBER, &p);
	denied(PARSE(&p, REQUIRED, "clock_skew_ms="), PG_OAUTH_PAM_POLICY_INVALID_NUMBER, &p);
	denied(PARSE(&p, REQUIRED, "clock_skew_ms=1e3"), PG_OAUTH_PAM_POLICY_INVALID_NUMBER, &p);
	denied(PARSE(&p, REQUIRED, "clock_skew_ms=0x10"), PG_OAUTH_PAM_POLICY_INVALID_NUMBER, &p);
	denied(PARSE(&p, REQUIRED, "clock_skew_ms=99999999999"), PG_OAUTH_PAM_POLICY_INVALID_NUMBER, &p);
	require(PARSE(&p, REQUIRED, "clock_skew_ms=0") == PG_OAUTH_PAM_POLICY_OK && p.validation.clock_skew_ms == 0);
	require(PARSE(&p, REQUIRED, "clock_skew_ms=300000") == PG_OAUTH_PAM_POLICY_OK);
	denied(PARSE(&p, REQUIRED, "clock_skew_ms=300001"), PG_OAUTH_PAM_POLICY_INVALID_POLICY, &p);

	/* Booleans: exactly on or off. */
	denied(PARSE(&p, REQUIRED, "allow_insecure_http=true"), PG_OAUTH_PAM_POLICY_INVALID_BOOLEAN, &p);
	denied(PARSE(&p, REQUIRED, "allow_insecure_http=ON"), PG_OAUTH_PAM_POLICY_INVALID_BOOLEAN, &p);
	denied(PARSE(&p, REQUIRED, "allow_insecure_http="), PG_OAUTH_PAM_POLICY_INVALID_BOOLEAN, &p);
	require(PARSE(&p, REQUIRED, "allow_insecure_http=on") == PG_OAUTH_PAM_POLICY_OK && p.validation.allow_insecure_http);

	/* Semantic rules come from the shared policy builder. */
	denied(PARSE(&p, REQUIRED, "algorithms=none"), PG_OAUTH_PAM_POLICY_INVALID_POLICY, &p);
	denied(PARSE(&p, REQUIRED, "algorithms=RS256,RS256"), PG_OAUTH_PAM_POLICY_INVALID_POLICY, &p);
	denied(PARSE(&p, REQUIRED, "algorithms=HS256"), PG_OAUTH_PAM_POLICY_INVALID_POLICY, &p);
	denied(PARSE(&p, REQUIRED, "token_types=JWT"), PG_OAUTH_PAM_POLICY_INVALID_POLICY, &p);
	denied(PARSE(&p, REQUIRED, "identity_claim="), PG_OAUTH_PAM_POLICY_INVALID_POLICY, &p);

	/* Length and count bounds. */
	memset(long_value, 'a', sizeof(long_value));
	memcpy(long_value, "ca_file=", 8);
	long_value[8 + PG_OAUTH_PAM_MAX_VALUE_LENGTH] = '\0';
	{
		const char *args[] = {"issuer=https://idp.example/", "audience=a", "scope=a", long_value};

		/*
		 * Exactly the limit passes the parser; the shared builder bounds
		 * ca_file itself.
		 */
		denied(parse(4, args, &p), PG_OAUTH_PAM_POLICY_INVALID_POLICY, &p);
		long_value[8 + PG_OAUTH_PAM_MAX_VALUE_LENGTH] = 'a';
		long_value[8 + PG_OAUTH_PAM_MAX_VALUE_LENGTH + 1] = '\0';
		denied(parse(4, args, &p), PG_OAUTH_PAM_POLICY_VALUE_TOO_LONG, &p);
	}
	for (size_t i = 0; i < PG_OAUTH_PAM_MAX_ARGUMENTS + 1; i++)
		many[i] = "issuer=https://idp.example/";
	denied(parse(PG_OAUTH_PAM_MAX_ARGUMENTS + 1, many, &p), PG_OAUTH_PAM_POLICY_TOO_MANY_ARGUMENTS, &p);
	denied(pg_oauth_pam_policy_parse(-1, many, &p), PG_OAUTH_PAM_POLICY_INVALID_ARGUMENT, &p);
	require(pg_oauth_pam_policy_parse(1, NULL, &p) == PG_OAUTH_PAM_POLICY_INVALID_ARGUMENT);
	require(pg_oauth_pam_policy_parse(0, NULL, NULL) == PG_OAUTH_PAM_POLICY_INVALID_ARGUMENT);

	/*
	 * The digest binds effective policy: order-insensitive for arguments,
	 * exact for values.
	 */
	{
		PgOAuthPamPolicy a_policy;
		PgOAuthPamPolicy b_policy;
		uint8_t		first[32];
		uint8_t		second[32];

		require(PARSE(&a_policy, REQUIRED, "clock_skew_ms=1000") == PG_OAUTH_PAM_POLICY_OK);
		require(pg_oauth_pam_policy_digest(&a_policy, first));
		require(PARSE(&b_policy, "clock_skew_ms=1000", "scope=connect:postgres",
					  "audience=postgres://primary", "issuer=https://idp.example/") == PG_OAUTH_PAM_POLICY_OK);
		require(pg_oauth_pam_policy_digest(&b_policy, second));
		require(memcmp(first, second, sizeof(first)) == 0);
		require(PARSE(&b_policy, REQUIRED, "clock_skew_ms=1001") == PG_OAUTH_PAM_POLICY_OK);
		require(pg_oauth_pam_policy_digest(&b_policy, second));
		require(memcmp(first, second, sizeof(first)) != 0);
		require(PARSE(&b_policy, "issuer=https://idp.example/", "audience=postgres://primary",
					  "scope=connect:postgres", "clock_skew_ms=1000", "algorithms=ES256") == PG_OAUTH_PAM_POLICY_OK);
		require(pg_oauth_pam_policy_digest(&b_policy, second));
		require(memcmp(first, second, sizeof(first)) != 0);

		/*
		 * Field boundaries are length-delimited, so concatenations cannot
		 * collide.
		 */
		require(PARSE(&a_policy, "issuer=https://idp.example/", "audience=ab", "scope=c") == PG_OAUTH_PAM_POLICY_OK);
		require(PARSE(&b_policy, "issuer=https://idp.example/", "audience=a", "scope=bc") == PG_OAUTH_PAM_POLICY_OK);
		require(pg_oauth_pam_policy_digest(&a_policy, first) && pg_oauth_pam_policy_digest(&b_policy, second));
		require(memcmp(first, second, sizeof(first)) != 0);

		/*
		 * The role claim is part of the digest, so the two stack lines must
		 * agree on it.
		 */
		require(PARSE(&a_policy, REQUIRED) == PG_OAUTH_PAM_POLICY_OK);
		require(PARSE(&b_policy, REQUIRED, "role_claim=pg_roles") == PG_OAUTH_PAM_POLICY_OK);
		require(pg_oauth_pam_policy_digest(&a_policy, first) && pg_oauth_pam_policy_digest(&b_policy, second));
		require(memcmp(first, second, sizeof(first)) != 0);
		require(!pg_oauth_pam_policy_digest(NULL, first));
		require(!pg_oauth_pam_policy_digest(&a_policy, NULL));
	}

	/* Diagnostic codes are stable and carry no argument text. */
	require(strcmp(pg_oauth_pam_policy_error_code(PG_OAUTH_PAM_POLICY_UNKNOWN_ARGUMENT), "policy_unknown_argument") == 0);
	require(strcmp(pg_oauth_pam_policy_error_code((PgOAuthPamPolicyError) 99), "policy_internal_error") == 0);
	return EXIT_SUCCESS;
}
