#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "claims.h"

static void
fail(const char *message)
{
	fprintf(stderr, "claims_test: %s\n", message);
	exit(EXIT_FAILURE);
}

static PgOAuthClaimsPolicy
valid_policy(void)
{
	PgOAuthClaimsPolicy policy = {
		.issuer = "https://issuer.example/",
		.audiences = "postgres://primary, postgres://secondary",
		.required_scopes = "connect:postgres read:metadata",
		.identity_claim = "sub",
		.role_claim = "",
		.current_time = 1000,
		.clock_skew_seconds = 60,
		.max_identity_size = 1024,
		.max_subject_size = 1024,
		.max_audiences = 16,
		.max_scopes = 64,
	};

	return policy;
}

static json_t *
parse_payload(const char *document)
{
	json_error_t error;
	json_t	   *payload = json_loads(document, JSON_REJECT_DUPLICATES, &error);

	if (payload == NULL)
		fail("test fixture JSON was invalid");
	return payload;
}

static void
expect_error(const char *document, PgOAuthClaimsPolicy *policy,
			 PgOAuthClaimsError expected, const char *message)
{
	json_t	   *payload = parse_payload(document);
	PgOAuthValidatedClaims claims;

	if (pg_oauth_claims_validate(payload, policy, &claims) != expected)
		fail(message);
	if (claims.identity != NULL || claims.identity_length != 0)
		fail("rejected claims retained identity data");
	json_decref(payload);
}

int
main(void)
{
	static const char valid[] =
		"{\"iss\":\"https://issuer.example/\","
		"\"aud\":\"postgres://primary\",\"exp\":1100,\"nbf\":900,"
		"\"iat\":900,\"sub\":\"principal-123\","
		"\"scope\":\"connect:postgres read:metadata extra\"}";
	PgOAuthClaimsPolicy policy = valid_policy();
	PgOAuthValidatedClaims claims;
	json_t	   *payload = parse_payload(valid);

	if (pg_oauth_claims_validate(payload, &policy, &claims) !=
		PG_OAUTH_CLAIMS_OK)
		fail("valid claims were rejected");
	if (claims.identity_length != strlen("principal-123") ||
		memcmp(claims.identity, "principal-123", claims.identity_length) != 0 ||
		claims.expires_at != 1100)
		fail("validated claims result was incorrect");
	json_decref(payload);

	payload = parse_payload(
							"{\"iss\":\"https://issuer.example/\","
							"\"aud\":[\"unrelated\",\"postgres://secondary\"],\"exp\":1100,"
							"\"sub\":\"p\",\"scope\":[\"read:metadata\",\"connect:postgres\"]}");
	if (pg_oauth_claims_validate(payload, &policy, &claims) !=
		PG_OAUTH_CLAIMS_OK)
		fail("valid audience and scope arrays were rejected");
	json_decref(payload);

	expect_error(
				 "{\"aud\":\"postgres://primary\",\"exp\":1100,"
				 "\"sub\":\"p\",\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_ISSUER,
				 "missing issuer was accepted");
	expect_error(
				 "{\"iss\":1,\"aud\":\"postgres://primary\",\"exp\":1100,"
				 "\"sub\":\"p\",\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_ISSUER,
				 "non-string issuer was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\",\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_ISSUER,
				 "issuer URL normalization was applied");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary/extra\","
				 "\"exp\":1100,\"sub\":\"p\",\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_AUDIENCE,
				 "audience substring was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"exp\":1100,"
				 "\"sub\":\"p\",\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_AUDIENCE,
				 "missing audience was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":[],\"exp\":1100,"
				 "\"sub\":\"p\",\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_AUDIENCE,
				 "empty audience array was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\","
				 "\"aud\":[\"postgres://primary\",\"postgres://primary\"],\"exp\":1100,"
				 "\"sub\":\"p\",\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_AUDIENCE,
				 "duplicate audience was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":1,\"exp\":1100,"
				 "\"sub\":\"p\",\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_AUDIENCE,
				 "non-string audience was accepted");

	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"sub\":\"p\",\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_MISSING_EXPIRY, "missing expiry was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100.0,\"sub\":\"p\",\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_EXPIRY,
				 "floating-point expiry was accepted");

	policy = valid_policy();
	policy.current_time = 1060;
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1000,\"sub\":\"p\",\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_EXPIRED,
				 "token at expiry-skew boundary was accepted");
	policy.current_time = 1059;
	payload = parse_payload(
							"{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
							"\"exp\":1000,\"sub\":\"p\",\"scope\":\"connect:postgres read:metadata\"}");
	if (pg_oauth_claims_validate(payload, &policy, &claims) != PG_OAUTH_CLAIMS_OK)
		fail("token inside expiry skew was rejected");
	json_decref(payload);

	policy = valid_policy();
	payload = parse_payload(
							"{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
							"\"exp\":1100,\"nbf\":1060,\"iat\":1060,\"sub\":\"p\","
							"\"scope\":\"connect:postgres read:metadata\"}");
	if (pg_oauth_claims_validate(payload, &policy, &claims) != PG_OAUTH_CLAIMS_OK)
		fail("temporal claims at the future-skew boundary were rejected");
	json_decref(payload);
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"nbf\":\"1060\",\"sub\":\"p\","
				 "\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_NOT_BEFORE,
				 "non-integer not-before was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"iat\":false,\"sub\":\"p\","
				 "\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_ISSUED_AT,
				 "non-integer issued-at was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"nbf\":1061,\"sub\":\"p\","
				 "\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_NOT_YET_VALID,
				 "not-before beyond skew was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"iat\":1061,\"sub\":\"p\","
				 "\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_ISSUED_IN_FUTURE,
				 "issued-at beyond skew was accepted");

	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_SUBJECT,
				 "missing configured identity was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":1,\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_SUBJECT,
				 "non-string identity was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"line\\nfeed\","
				 "\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_SUBJECT,
				 "control character in identity was accepted");
	/* Invisible and reordering characters are as unsafe in logs as controls. */
	{
		static const char *const hostile[] = {
			"a\\u00adb", "a\\u061cb", "a\\u200bb", "a\\u200db", "a\\u200eb",
			"a\\u2028b", "a\\u202eb", "a\\u2060b", "a\\u2066b", "a\\u2069b",
			"a\\ufeffb", "a\\ufff9b",
		};

		for (size_t i = 0; i < sizeof(hostile) / sizeof(hostile[0]); i++)
		{
			char		document[256];

			snprintf(document, sizeof(document),
					 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
					 "\"exp\":1100,\"sub\":\"%s\","
					 "\"scope\":\"connect:postgres read:metadata\"}", hostile[i]);
			expect_error(document, &policy, PG_OAUTH_CLAIMS_INVALID_SUBJECT,
						 "invisible or reordering character in identity was accepted");
		}
	}

	policy = valid_policy();
	policy.identity_claim = "uid";
	policy.max_identity_size = 1;
	policy.max_subject_size = 1;
	payload = parse_payload(
							"{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
							"\"exp\":1100,\"sub\":\"u\",\"uid\":\"u\","
							"\"scope\":\"connect:postgres read:metadata\"}");
	if (pg_oauth_claims_validate(payload, &policy, &claims) != PG_OAUTH_CLAIMS_OK)
		fail("configured identity at the size boundary was rejected");
	json_decref(payload);
	policy.max_subject_size = 1024;
	payload = parse_payload(
							"{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
							"\"exp\":1100,\"sub\":\"long-stable-subject\",\"uid\":\"u\","
							"\"scope\":\"connect:postgres read:metadata\"}");
	if (pg_oauth_claims_validate(payload, &policy, &claims) != PG_OAUTH_CLAIMS_OK)
		fail("valid sub longer than selected identity was rejected");
	json_decref(payload);
	policy.max_subject_size = 1;
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"uid\":\"u\","
				 "\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_SUBJECT,
				 "missing sub with custom identity was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":7,\"uid\":\"u\","
				 "\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_SUBJECT,
				 "wrong-type sub with custom identity was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"xx\",\"uid\":\"u\","
				 "\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_SUBJECT,
				 "oversized sub with custom identity was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"\",\"uid\":\"u\","
				 "\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_SUBJECT,
				 "empty sub with custom identity was accepted");
	policy.max_subject_size = 1024;
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"\\u0085\",\"uid\":\"u\","
				 "\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_SUBJECT,
				 "Unicode control in sub with custom identity was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\\u202e\",\"uid\":\"u\","
				 "\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_SUBJECT,
				 "bidi override in sub with custom identity was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\",\"uid\":\"u\\u200b\","
				 "\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_IDENTITY,
				 "zero width space in a custom identity claim was accepted");
	policy.max_subject_size = 1;
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"u\","
				 "\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_IDENTITY,
				 "missing custom identity claim was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"u\",\"uid\":[\"u\"],"
				 "\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_IDENTITY,
				 "wrong-type custom identity claim was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"u\",\"uid\":\"uu\","
				 "\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_IDENTITY,
				 "identity beyond the size boundary was accepted");
	policy = valid_policy();

	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_SCOPE, "missing scope was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\",\"scope\":\"connect:postgres\"}",
				 &policy, PG_OAUTH_CLAIMS_INSUFFICIENT_SCOPE,
				 "missing required scope was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\","
				 "\"scope\":\"connect:postgres  read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_SCOPE,
				 "empty scope token was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\","
				 "\"scope\":\"connect:postgres read:metadata connect:postgres\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_SCOPE,
				 "duplicate scope token was accepted");
	/* "scp" is accepted in place of "scope" (some providers emit only it). */
	payload = parse_payload(
							"{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
							"\"exp\":1100,\"sub\":\"p\",\"scp\":\"connect:postgres read:metadata\"}");
	if (pg_oauth_claims_validate(payload, &policy, &claims) != PG_OAUTH_CLAIMS_OK)
		fail("scp string was rejected");
	json_decref(payload);
	payload = parse_payload(
							"{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
							"\"exp\":1100,\"sub\":\"p\",\"scp\":[\"connect:postgres\",\"read:metadata\"]}");
	if (pg_oauth_claims_validate(payload, &policy, &claims) != PG_OAUTH_CLAIMS_OK)
		fail("scp array was rejected");
	json_decref(payload);
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\",\"scp\":\"connect:postgres\"}",
				 &policy, PG_OAUTH_CLAIMS_INSUFFICIENT_SCOPE,
				 "scp missing a required scope was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\",\"scp\":\"connect:postgres read:metadata connect:postgres\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_SCOPE,
				 "duplicate scp token was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\",\"scp\":[\"connect:postgres\",7]}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_SCOPE,
				 "non-string scp array entry was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\",\"scp\":42}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_SCOPE,
				 "wrong-type scp was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\",\"scp\":[]}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_SCOPE,
				 "empty scp array was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\",\"scp\":\"connect:postgres read:metadata\",\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_SCOPE,
				 "both scope and scp were accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\",\"scope\":\"connect:postgres\",\"scp\":\"read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_SCOPE,
				 "scp topped up an insufficient scope");

	if (strstr(pg_oauth_claims_error_code(PG_OAUTH_CLAIMS_INVALID_IDENTITY),
			   "principal") != NULL)
		fail("claims error code exposed claim material");

	policy = valid_policy();
	policy.role_claim = "roles";
	policy.requested_role = "reporting";
	policy.max_roles = 4;
	policy.max_role_size = 63;
	payload = parse_payload(
							"{\"iss\":\"https://issuer.example/\","
							"\"aud\":\"postgres://primary\",\"exp\":1100,"
							"\"sub\":\"p\",\"scope\":\"connect:postgres read:metadata\","
							"\"roles\":[\"app_reader\",\"reporting\"]}");
	if (pg_oauth_claims_validate(payload, &policy, &claims) != PG_OAUTH_CLAIMS_OK)
		fail("authorized requested role was rejected");
	json_decref(payload);
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\","
				 "\"scope\":\"connect:postgres read:metadata\","
				 "\"roles\":[\"app_reader\"]}",
				 &policy, PG_OAUTH_CLAIMS_UNAUTHORIZED_ROLE,
				 "role absent from delegated claim was accepted");
	payload = parse_payload(
							"{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
							"\"exp\":1100,\"sub\":\"p\","
							"\"scope\":\"connect:postgres read:metadata\",\"roles\":\"reporting\"}");
	if (pg_oauth_claims_validate(payload, &policy, &claims) != PG_OAUTH_CLAIMS_OK)
		fail("scalar delegated role was rejected");
	json_decref(payload);
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\","
				 "\"scope\":\"connect:postgres read:metadata\",\"roles\":\"\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_ROLES,
				 "empty scalar role was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\","
				 "\"scope\":\"connect:postgres read:metadata\",\"roles\":7}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_ROLES,
				 "wrong-type scalar role was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\","
				 "\"scope\":\"connect:postgres read:metadata\",\"roles\":\"Reporting\"}",
				 &policy, PG_OAUTH_CLAIMS_UNAUTHORIZED_ROLE,
				 "scalar role comparison was not case-sensitive");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\","
				 "\"scope\":\"connect:postgres read:metadata\","
				 "\"roles\":[\"reporting\",\"reporting\"]}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_ROLES,
				 "duplicate delegated role was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\","
				 "\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_ROLES,
				 "missing delegated roles claim was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\","
				 "\"scope\":\"connect:postgres read:metadata\",\"roles\":[]}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_ROLES,
				 "empty delegated roles array was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\","
				 "\"scope\":\"connect:postgres read:metadata\",\"roles\":[\"\"]}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_ROLES,
				 "empty delegated role was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\","
				 "\"scope\":\"connect:postgres read:metadata\","
				 "\"roles\":[\"reporting\",7]}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_ROLES,
				 "non-string delegated role was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\","
				 "\"scope\":\"connect:postgres read:metadata\","
				 "\"roles\":[\"reporting\\nadmin\"]}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_ROLES,
				 "control character in delegated role was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\","
				 "\"scope\":\"connect:postgres read:metadata\","
				 "\"roles\":[\"reporting\\u200b\"]}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_ROLES,
				 "zero width space in a delegated role was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\","
				 "\"scope\":\"connect:postgres read:metadata\","
				 "\"roles\":\"report\\u202eing\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_ROLES,
				 "bidi override in a scalar delegated role was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\","
				 "\"scope\":\"connect:postgres read:metadata\","
				 "\"roles\":[\"one\",\"two\",\"three\",\"four\",\"reporting\"]}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_ROLES,
				 "oversized delegated roles array was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\","
				 "\"scope\":\"connect:postgres read:metadata\","
				 "\"roles\":[\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_ROLES,
				 "oversized delegated role was accepted");
	expect_error(
				 "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\","
				 "\"scope\":\"connect:postgres read:metadata\","
				 "\"roles\":[\"Reporting\"]}",
				 &policy, PG_OAUTH_CLAIMS_UNAUTHORIZED_ROLE,
				 "delegated role comparison was not case-sensitive");

	policy.role_claim = "https://company.example/postgres_roles";
	payload = parse_payload(
							"{\"iss\":\"https://issuer.example/\","
							"\"aud\":\"postgres://primary\",\"exp\":1100,"
							"\"sub\":\"p\",\"scope\":\"connect:postgres read:metadata\","
							"\"https://company.example/postgres_roles\":[\"reporting\"]}");
	if (pg_oauth_claims_validate(payload, &policy, &claims) != PG_OAUTH_CLAIMS_OK)
		fail("custom delegated roles claim was rejected");
	json_decref(payload);

	/* A fresh policy: earlier cases above changed role settings on it. */
	policy = valid_policy();

	/* Temporal claims: wrong types, signs and the exact skew boundaries. */
#define CLAIMS(extra) \
	"{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\"," \
	"\"sub\":\"p\",\"scope\":\"connect:postgres read:metadata\"," extra "}"
	expect_error(CLAIMS("\"exp\":\"1100\""), &policy,
				 PG_OAUTH_CLAIMS_INVALID_EXPIRY, "string expiry was accepted");

	/*
	 * RFC 7519 allows non-integer NumericDate values; this validator does
	 * not.
	 */
	expect_error(CLAIMS("\"exp\":1.1e3"), &policy,
				 PG_OAUTH_CLAIMS_INVALID_EXPIRY, "exponent-form expiry was accepted");
	expect_error(CLAIMS("\"exp\":1100,\"nbf\":900.5"), &policy,
				 PG_OAUTH_CLAIMS_INVALID_NOT_BEFORE, "fractional not-before was accepted");
	expect_error(CLAIMS("\"exp\":1100,\"iat\":900.5"), &policy,
				 PG_OAUTH_CLAIMS_INVALID_ISSUED_AT, "fractional issued-at was accepted");
	expect_error(CLAIMS("\"exp\":0"), &policy,
				 PG_OAUTH_CLAIMS_INVALID_EXPIRY, "zero expiry was accepted");
	expect_error(CLAIMS("\"exp\":-5"), &policy,
				 PG_OAUTH_CLAIMS_INVALID_EXPIRY, "negative expiry was accepted");
	expect_error(CLAIMS("\"exp\":true"), &policy,
				 PG_OAUTH_CLAIMS_INVALID_EXPIRY, "boolean expiry was accepted");
	expect_error(CLAIMS("\"exp\":null"), &policy,
				 PG_OAUTH_CLAIMS_INVALID_EXPIRY, "null expiry was accepted");
	expect_error(CLAIMS("\"exp\":1100,\"nbf\":\"900\""), &policy,
				 PG_OAUTH_CLAIMS_INVALID_NOT_BEFORE, "string not-before was accepted");
	expect_error(CLAIMS("\"exp\":1100,\"nbf\":-1"), &policy,
				 PG_OAUTH_CLAIMS_INVALID_NOT_BEFORE, "negative not-before was accepted");
	expect_error(CLAIMS("\"exp\":1100,\"nbf\":true"), &policy,
				 PG_OAUTH_CLAIMS_INVALID_NOT_BEFORE, "boolean not-before was accepted");
	expect_error(CLAIMS("\"exp\":1100,\"nbf\":1061"), &policy,
				 PG_OAUTH_CLAIMS_NOT_YET_VALID, "not-before one second past skew was accepted");
	expect_error(CLAIMS("\"exp\":1100,\"iat\":\"900\""), &policy,
				 PG_OAUTH_CLAIMS_INVALID_ISSUED_AT, "string issued-at was accepted");
	expect_error(CLAIMS("\"exp\":1100,\"iat\":-1"), &policy,
				 PG_OAUTH_CLAIMS_INVALID_ISSUED_AT, "negative issued-at was accepted");
	expect_error(CLAIMS("\"exp\":1100,\"iat\":1061"), &policy,
				 PG_OAUTH_CLAIMS_ISSUED_IN_FUTURE, "issued-at one second past skew was accepted");
	expect_error(CLAIMS("\"exp\":940"), &policy,
				 PG_OAUTH_CLAIMS_EXPIRED, "expiry exactly at the skew boundary was accepted");
	{
		static const char *const accepted[] = {
			CLAIMS("\"exp\":941"),	/* one second inside the skew */
			CLAIMS("\"exp\":9223372036854775807"),	/* largest NumericDate */
			CLAIMS("\"exp\":1100,\"nbf\":1060"),	/* exactly the skew ahead */
			CLAIMS("\"exp\":1100,\"iat\":1060"),
		};

		for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); i++)
		{
			json_t	   *document = parse_payload(accepted[i]);

			if (pg_oauth_claims_validate(document, &policy, &claims) !=
				PG_OAUTH_CLAIMS_OK)
				fail("a claim on the accepted side of a boundary was rejected");
			json_decref(document);
		}
	}

	/* Audience and issuer shapes. */
#define WITH_AUD(aud) \
	"{\"iss\":\"https://issuer.example/\",\"aud\":" aud ",\"exp\":1100," \
	"\"sub\":\"p\",\"scope\":\"connect:postgres read:metadata\"}"
	expect_error(WITH_AUD("\"\""), &policy, PG_OAUTH_CLAIMS_INVALID_AUDIENCE,
				 "empty audience string was accepted");
	expect_error(WITH_AUD("null"), &policy, PG_OAUTH_CLAIMS_INVALID_AUDIENCE,
				 "null audience was accepted");
	expect_error(WITH_AUD("[1]"), &policy, PG_OAUTH_CLAIMS_INVALID_AUDIENCE,
				 "numeric audience element was accepted");
	expect_error(WITH_AUD("[\"postgres://primary\",1]"), &policy,
				 PG_OAUTH_CLAIMS_INVALID_AUDIENCE,
				 "valid audience beside a non-string element was accepted");
	expect_error(WITH_AUD("[\"postgres://primary\",\"\"]"), &policy,
				 PG_OAUTH_CLAIMS_INVALID_AUDIENCE,
				 "valid audience beside an empty element was accepted");
	expect_error("{\"iss\":\"\",\"aud\":\"postgres://primary\",\"exp\":1100,"
				 "\"sub\":\"p\",\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_ISSUER,
				 "empty issuer was accepted");
	expect_error("{\"iss\":\"HTTPS://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\",\"scope\":\"connect:postgres read:metadata\"}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_ISSUER,
				 "case-folded issuer was accepted");
	expect_error("{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
				 "\"exp\":1100,\"sub\":\"p\",\"scope\":[\"connect:postgres\",1]}",
				 &policy, PG_OAUTH_CLAIMS_INVALID_SCOPE,
				 "numeric scope array element was accepted");
#undef WITH_AUD
#undef CLAIMS

	return EXIT_SUCCESS;
}
