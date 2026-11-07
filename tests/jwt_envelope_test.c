#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_envelope.h"

static const char base64url_alphabet[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static void
fail(const char *message)
{
	fprintf(stderr, "jwt_envelope_test: %s\n", message);
	exit(EXIT_FAILURE);
}

static char *
encode_base64url(const char *input)
{
	size_t		length = strlen(input);
	size_t		encoded_length = (length / 3) * 4 +
		(length % 3 == 0 ? 0 : length % 3 + 1);
	char	   *encoded = malloc(encoded_length + 1);
	size_t		in = 0;
	size_t		out = 0;

	if (encoded == NULL)
		fail("allocation failed");
	while (in + 3 <= length)
	{
		unsigned int bits = ((unsigned char) input[in] << 16) |
			((unsigned char) input[in + 1] << 8) |
			(unsigned char) input[in + 2];

		encoded[out++] = base64url_alphabet[(bits >> 18) & 63];
		encoded[out++] = base64url_alphabet[(bits >> 12) & 63];
		encoded[out++] = base64url_alphabet[(bits >> 6) & 63];
		encoded[out++] = base64url_alphabet[bits & 63];
		in += 3;
	}
	if (length - in == 1)
	{
		unsigned int bits = (unsigned char) input[in] << 4;

		encoded[out++] = base64url_alphabet[(bits >> 6) & 63];
		encoded[out++] = base64url_alphabet[bits & 63];
	}
	else if (length - in == 2)
	{
		unsigned int bits = ((unsigned char) input[in] << 10) |
			((unsigned char) input[in + 1] << 2);

		encoded[out++] = base64url_alphabet[(bits >> 12) & 63];
		encoded[out++] = base64url_alphabet[(bits >> 6) & 63];
		encoded[out++] = base64url_alphabet[bits & 63];
	}
	encoded[out] = '\0';
	return encoded;
}

static char *
make_token(const char *header, const char *payload)
{
	char	   *encoded_header = encode_base64url(header);
	char	   *encoded_payload = encode_base64url(payload);
	size_t		length = strlen(encoded_header) + strlen(encoded_payload) + 5;
	char	   *token = malloc(length);

	if (token == NULL)
		fail("allocation failed");
	snprintf(token, length, "%s.%s.AA", encoded_header, encoded_payload);
	free(encoded_header);
	free(encoded_payload);
	return token;
}

static PgOAuthJwtEnvelopePolicy
valid_policy(void)
{
	PgOAuthJwtEnvelopePolicy policy = {
		.max_token_size = 16384,
		.max_header_size = 4096,
		.max_payload_size = 12288,
		.allowed_algorithms = PG_OAUTH_ALGORITHM_RS256 |
		PG_OAUTH_ALGORITHM_ES256,
		.allowed_token_types = PG_OAUTH_TOKEN_TYPE_AT_JWT,
	};

	return policy;
}

static void
expect_json_error(const char *header, const char *payload,
				  PgOAuthJwtEnvelopeError expected, const char *message)
{
	PgOAuthJwtEnvelopePolicy policy = valid_policy();
	PgOAuthJwtEnvelope envelope;
	char	   *token = make_token(header, payload);
	PgOAuthJwtEnvelopeError actual = pg_oauth_jwt_envelope_parse(
																 token, strlen(token), &policy, &envelope);

	free(token);
	if (actual != expected)
		fail(message);
	if (envelope.untrusted_header != NULL ||
		envelope.untrusted_payload != NULL || envelope.key_id != NULL)
		fail("rejected envelope retained untrusted data");
}

static void
expect_raw_error(const char *token, size_t token_length,
				 PgOAuthJwtEnvelopeError expected, const char *message)
{
	PgOAuthJwtEnvelopePolicy policy = valid_policy();
	PgOAuthJwtEnvelope envelope;

	if (pg_oauth_jwt_envelope_parse(token, token_length, &policy, &envelope) !=
		expected)
		fail(message);
}

int
main(void)
{
	static const char *const valid_header =
		"{\"alg\":\"RS256\",\"typ\":\"at+jwt\",\"kid\":\"key-1\"}";
	PgOAuthJwtEnvelopePolicy policy = valid_policy();
	PgOAuthJwtEnvelope envelope;
	char	   *token = make_token(valid_header, "{\"sub\":\"principal\"}");

	if (pg_oauth_jwt_envelope_parse(token, strlen(token), &policy, &envelope) !=
		PG_OAUTH_JWT_ENVELOPE_OK)
		fail("valid strict envelope was rejected");
	if (envelope.algorithm != PG_OAUTH_ALGORITHM_RS256 ||
		strcmp(envelope.key_id, "key-1") != 0)
		fail("valid envelope fields were not retained");
	pg_oauth_jwt_envelope_clear(&envelope);
	free(token);

	policy = valid_policy();
	policy.allowed_token_types = PG_OAUTH_TOKEN_TYPES_ALL;
	token = make_token("{\"alg\":\"RS256\",\"typ\":\"application/at+jwt\",\"kid\":\"k\"}", "{}");
	if (pg_oauth_jwt_envelope_parse(token, strlen(token), &policy, &envelope) !=
		PG_OAUTH_JWT_ENVELOPE_OK)
		fail("full RFC 9068 type was rejected");
	pg_oauth_jwt_envelope_clear(&envelope);
	free(token);

	policy.allow_missing_token_type = true;
	token = make_token("{\"alg\":\"RS256\",\"kid\":\"k\"}", "{}");
	if (pg_oauth_jwt_envelope_parse(token, strlen(token), &policy, &envelope) !=
		PG_OAUTH_JWT_ENVELOPE_OK)
		fail("explicitly allowed missing type was rejected");
	pg_oauth_jwt_envelope_clear(&envelope);
	free(token);
	token = make_token("{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"k\"}", "{}");
	if (pg_oauth_jwt_envelope_parse(token, strlen(token), &policy, &envelope) !=
		PG_OAUTH_JWT_ENVELOPE_INVALID_TOKEN_TYPE)
		fail("wrong present type was accepted in missing-type mode");
	free(token);
	token = make_token("{\"alg\":\"RS256\",\"typ\":null,\"kid\":\"k\"}", "{}");
	if (pg_oauth_jwt_envelope_parse(token, strlen(token), &policy, &envelope) !=
		PG_OAUTH_JWT_ENVELOPE_INVALID_TOKEN_TYPE)
		fail("null type was accepted in missing-type mode");
	free(token);

	token = make_token("{\"alg\":\"EdDSA\",\"typ\":\"at+jwt\",\"kid\":\"key-1\"}",
					   "{\"sub\":\"principal\"}");
	policy = valid_policy();
	if (pg_oauth_jwt_envelope_parse(token, strlen(token), &policy, &envelope) !=
		PG_OAUTH_JWT_ENVELOPE_INVALID_ALGORITHM)
		fail("EdDSA was accepted without administrator allowance");
	policy.allowed_algorithms |= PG_OAUTH_ALGORITHM_EDDSA;
	if (pg_oauth_jwt_envelope_parse(token, strlen(token), &policy, &envelope) !=
		PG_OAUTH_JWT_ENVELOPE_OK ||
		envelope.algorithm != PG_OAUTH_ALGORITHM_EDDSA)
		fail("allowed EdDSA envelope was rejected");
	pg_oauth_jwt_envelope_clear(&envelope);
	free(token);

	{
		static const char *const rejected[] = {
			"eddsa", "EDDSA", "Ed25519", "Ed448", "EdDSA ", "EdDSA\\u0000x"
		};

		for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++)
		{
			char		header[128];
			PgOAuthJwtEnvelopePolicy eddsa_policy = valid_policy();
			char	   *candidate;
			PgOAuthJwtEnvelopeError result;

			eddsa_policy.allowed_algorithms |= PG_OAUTH_ALGORITHM_EDDSA;
			snprintf(header, sizeof(header),
					 "{\"alg\":\"%s\",\"typ\":\"at+jwt\",\"kid\":\"k\"}", rejected[i]);
			candidate = make_token(header, "{}");
			result = pg_oauth_jwt_envelope_parse(candidate, strlen(candidate),
												 &eddsa_policy, &envelope);
			free(candidate);
			if (result == PG_OAUTH_JWT_ENVELOPE_OK)
				fail("non-canonical EdDSA algorithm name was accepted");
		}
	}

	token = make_token(valid_header, "{}");
	policy = valid_policy();
	policy.max_header_size = 1;
	if (pg_oauth_jwt_envelope_parse(token, strlen(token), &policy, &envelope) !=
		PG_OAUTH_JWT_ENVELOPE_HEADER_TOO_LARGE)
		fail("decoded header size limit was not enforced");
	policy = valid_policy();
	policy.max_payload_size = 1;
	if (pg_oauth_jwt_envelope_parse(token, strlen(token), &policy, &envelope) !=
		PG_OAUTH_JWT_ENVELOPE_PAYLOAD_TOO_LARGE)
		fail("decoded payload size limit was not enforced");
	policy = valid_policy();
	policy.allowed_algorithms = PG_OAUTH_ALGORITHM_ES256;
	if (pg_oauth_jwt_envelope_parse(token, strlen(token), &policy, &envelope) !=
		PG_OAUTH_JWT_ENVELOPE_INVALID_ALGORITHM)
		fail("algorithm outside administrator allowlist was accepted");
	free(token);

	expect_json_error(
					  "{\"alg\":\"RS256\",\"alg\":\"ES256\",\"typ\":\"at+jwt\",\"kid\":\"k\"}",
					  "{}", PG_OAUTH_JWT_ENVELOPE_INVALID_HEADER_JSON,
					  "duplicate algorithm was accepted");
	expect_json_error(valid_header, "{\"iss\":\"a\",\"iss\":\"b\"}",
					  PG_OAUTH_JWT_ENVELOPE_INVALID_PAYLOAD_JSON,
					  "duplicate claim was accepted");
	expect_json_error(valid_header, "{\"outer\":{\"x\":1,\"x\":2}}",
					  PG_OAUTH_JWT_ENVELOPE_INVALID_PAYLOAD_JSON,
					  "nested duplicate member was accepted");
	expect_json_error("[]", "{}", PG_OAUTH_JWT_ENVELOPE_INVALID_HEADER_JSON,
					  "non-object header was accepted");
	expect_json_error(valid_header, "[]",
					  PG_OAUTH_JWT_ENVELOPE_INVALID_PAYLOAD_JSON,
					  "non-object payload was accepted");
	expect_json_error("{\"alg\":\"none\",\"typ\":\"at+jwt\",\"kid\":\"k\"}",
					  "{}", PG_OAUTH_JWT_ENVELOPE_INVALID_ALGORITHM, "none was accepted");
	expect_json_error("{\"alg\":\"HS256\",\"typ\":\"at+jwt\",\"kid\":\"k\"}",
					  "{}", PG_OAUTH_JWT_ENVELOPE_INVALID_ALGORITHM, "HMAC was accepted");
	expect_json_error("{\"alg\":\"RS256\\u0000ignored\",\"typ\":\"at+jwt\",\"kid\":\"k\"}",
					  "{}", PG_OAUTH_JWT_ENVELOPE_INVALID_HEADER_JSON,
					  "algorithm with embedded NUL was accepted");
	expect_json_error("{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"k\"}",
					  "{}", PG_OAUTH_JWT_ENVELOPE_INVALID_TOKEN_TYPE,
					  "ID-token-compatible type was accepted");
	expect_json_error("{\"alg\":\"RS256\",\"kid\":\"k\"}", "{}",
					  PG_OAUTH_JWT_ENVELOPE_INVALID_TOKEN_TYPE, "missing type was accepted");
	expect_json_error("{\"alg\":\"RS256\",\"typ\":\"at+jwt\\u0000JWT\",\"kid\":\"k\"}",
					  "{}", PG_OAUTH_JWT_ENVELOPE_INVALID_HEADER_JSON,
					  "token type with embedded NUL was accepted");
	expect_json_error("{\"alg\":\"RS256\",\"typ\":\"at+jwt\"}", "{}",
					  PG_OAUTH_JWT_ENVELOPE_INVALID_KEY_ID, "missing key id was accepted");
	expect_json_error("{\"alg\":\"RS256\",\"typ\":\"at+jwt\",\"kid\":1}",
					  "{}", PG_OAUTH_JWT_ENVELOPE_INVALID_KEY_ID,
					  "non-string key id was accepted");
	expect_json_error("{\"alg\":\"RS256\",\"typ\":\"at+jwt\",\"kid\":\"key\\nlog\"}",
					  "{}", PG_OAUTH_JWT_ENVELOPE_INVALID_KEY_ID,
					  "control character in key id was accepted");
	expect_json_error("{\"alg\":\"RS256\",\"typ\":\"at+jwt\",\"kid\":\"k\",\"jku\":\"https://attacker/\"}",
					  "{}", PG_OAUTH_JWT_ENVELOPE_UNSUPPORTED_HEADER,
					  "token-provided key URL was accepted");
	expect_json_error("{\"alg\":\"RS256\",\"typ\":\"at+jwt\",\"kid\":\"k\",\"crit\":[]}",
					  "{}", PG_OAUTH_JWT_ENVELOPE_UNSUPPORTED_HEADER,
					  "critical extension was accepted");
	/* Every way for a token to name, embed or pin its own key is refused. */
	expect_json_error("{\"alg\":\"RS256\",\"typ\":\"at+jwt\",\"kid\":\"k\",\"jwk\":{\"kty\":\"RSA\"}}",
					  "{}", PG_OAUTH_JWT_ENVELOPE_UNSUPPORTED_HEADER,
					  "token-embedded key was accepted");
	expect_json_error("{\"alg\":\"RS256\",\"typ\":\"at+jwt\",\"kid\":\"k\",\"x5u\":\"https://attacker/c.pem\"}",
					  "{}", PG_OAUTH_JWT_ENVELOPE_UNSUPPORTED_HEADER,
					  "token-provided certificate URL was accepted");
	expect_json_error("{\"alg\":\"RS256\",\"typ\":\"at+jwt\",\"kid\":\"k\",\"x5c\":[\"MIIB\"]}",
					  "{}", PG_OAUTH_JWT_ENVELOPE_UNSUPPORTED_HEADER,
					  "token-embedded certificate chain was accepted");
	expect_json_error("{\"alg\":\"RS256\",\"typ\":\"at+jwt\",\"kid\":\"k\",\"x5t\":\"abc\"}",
					  "{}", PG_OAUTH_JWT_ENVELOPE_UNSUPPORTED_HEADER,
					  "certificate SHA-1 thumbprint was accepted");
	expect_json_error("{\"alg\":\"RS256\",\"typ\":\"at+jwt\",\"kid\":\"k\",\"x5t#S256\":\"abc\"}",
					  "{}", PG_OAUTH_JWT_ENVELOPE_UNSUPPORTED_HEADER,
					  "certificate SHA-256 thumbprint was accepted");
	expect_json_error("{\"alg\":\"RS256\",\"typ\":\"at+jwt\",\"kid\":\"k\",\"crit\":[\"exp\"]}",
					  "{}", PG_OAUTH_JWT_ENVELOPE_UNSUPPORTED_HEADER,
					  "non-empty critical extension list was accepted");
	expect_json_error("{\"alg\":\"RS256\",\"typ\":\"at+jwt\",\"kid\":\"k\",\"zip\":\"DEF\"}",
					  "{}", PG_OAUTH_JWT_ENVELOPE_UNSUPPORTED_HEADER,
					  "compression was accepted");
	expect_json_error("{\"alg\":\"RS256\",\"typ\":\"at+jwt\",\"kid\":\"k\",\"b64\":false}",
					  "{}", PG_OAUTH_JWT_ENVELOPE_UNSUPPORTED_HEADER,
					  "unencoded payload was accepted");
	expect_json_error("{\"alg\":\"RS256\",\"typ\":\"at+jwt\",\"kid\":\"k\",\"cty\":\"JWT\"}",
					  "{}", PG_OAUTH_JWT_ENVELOPE_UNSUPPORTED_HEADER,
					  "nested token was accepted");

	expect_raw_error("", 0, PG_OAUTH_JWT_ENVELOPE_EMPTY,
					 "empty token was accepted");
	expect_raw_error("a.b", 3, PG_OAUTH_JWT_ENVELOPE_INVALID_COMPACT_JWS,
					 "two-part token was accepted");
	expect_raw_error("a.b.c.d", 7, PG_OAUTH_JWT_ENVELOPE_INVALID_COMPACT_JWS,
					 "four-part token was accepted");
	expect_raw_error(".e30.AA", 7, PG_OAUTH_JWT_ENVELOPE_INVALID_COMPACT_JWS,
					 "empty header was accepted");
	expect_raw_error("e30.e30.", 8, PG_OAUTH_JWT_ENVELOPE_INVALID_COMPACT_JWS,
					 "empty signature was accepted");
	expect_raw_error("e30=.e30.AA", strlen("e30=.e30.AA"),
					 PG_OAUTH_JWT_ENVELOPE_INVALID_BASE64URL,
					 "padded Base64URL was accepted");
	expect_raw_error("e31.e30.AA", 10, PG_OAUTH_JWT_ENVELOPE_INVALID_BASE64URL,
					 "non-canonical trailing bits were accepted");
	expect_raw_error("e30.e3!.AA", 10, PG_OAUTH_JWT_ENVELOPE_INVALID_BASE64URL,
					 "invalid Base64URL alphabet was accepted");

	policy = valid_policy();
	policy.max_token_size = 4;
	if (pg_oauth_jwt_envelope_parse("e30.e30.AA", 10, &policy, &envelope) !=
		PG_OAUTH_JWT_ENVELOPE_TOO_LARGE)
		fail("oversized token was accepted");

	if (strstr(pg_oauth_jwt_envelope_error_code(
												PG_OAUTH_JWT_ENVELOPE_INVALID_ALGORITHM), "RS256") != NULL)
		fail("stable error code exposed token material");
	return EXIT_SUCCESS;
}
