#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwks.h"

static const char alphabet[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static void
fail(const char *message)
{
	fprintf(stderr, "jwks_test: %s\n", message);
	exit(EXIT_FAILURE);
}

static char *
encode_bytes(const unsigned char *input, size_t length)
{
	size_t		encoded_length = (length / 3) * 4 +
		(length % 3 == 0 ? 0 : length % 3 + 1);
	char	   *encoded = malloc(encoded_length + 1);
	size_t		in = 0;
	size_t		out = 0;

	if (encoded == NULL)
		fail("allocation failed");
	while (in + 3 <= length)
	{
		unsigned int bits = ((unsigned int) input[in] << 16) |
			((unsigned int) input[in + 1] << 8) | input[in + 2];

		encoded[out++] = alphabet[(bits >> 18) & 63];
		encoded[out++] = alphabet[(bits >> 12) & 63];
		encoded[out++] = alphabet[(bits >> 6) & 63];
		encoded[out++] = alphabet[bits & 63];
		in += 3;
	}
	if (length - in == 1)
	{
		unsigned int bits = (unsigned int) input[in] << 4;

		encoded[out++] = alphabet[(bits >> 6) & 63];
		encoded[out++] = alphabet[bits & 63];
	}
	else if (length - in == 2)
	{
		unsigned int bits = ((unsigned int) input[in] << 10) |
			((unsigned int) input[in + 1] << 2);

		encoded[out++] = alphabet[(bits >> 12) & 63];
		encoded[out++] = alphabet[(bits >> 6) & 63];
		encoded[out++] = alphabet[bits & 63];
	}
	encoded[out] = '\0';
	return encoded;
}

static PgOAuthJwksPolicy
valid_policy(void)
{
	PgOAuthJwksPolicy policy = {
		.max_jwks_size = 65536,
		.max_keys = 16,
		.max_key_id_size = 1024,
		.allowed_algorithms = PG_OAUTH_ALGORITHM_RS256 |
		PG_OAUTH_ALGORITHM_ES256,
		.minimum_rsa_bits = 2048,
		.maximum_rsa_bits = 8192,
	};

	return policy;
}

static char *
make_rsa_jwks(const char *members, size_t modulus_bytes, unsigned char first)
{
	unsigned char *modulus = malloc(modulus_bytes);
	char	   *encoded;
	char	   *document;
	size_t		capacity;

	if (modulus == NULL)
		fail("allocation failed");
	memset(modulus, 0xa5, modulus_bytes);
	modulus[0] = first;
	encoded = encode_bytes(modulus, modulus_bytes);
	free(modulus);
	capacity = strlen(encoded) + strlen(members) + 128;
	document = malloc(capacity);
	if (document == NULL)
		fail("allocation failed");
	snprintf(document, capacity,
			 "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"%s\",\"e\":\"AQAB\",%s}]}",
			 encoded, members);
	free(encoded);
	return document;
}

static char *
make_ec_jwks(bool valid_point)
{
	static const unsigned char generator_x[32] = {
		0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
		0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
		0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
		0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96
	};
	static const unsigned char generator_y[32] = {
		0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
		0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
		0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
		0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5
	};
	unsigned char y[32];
	char	   *x_encoded = encode_bytes(generator_x, sizeof(generator_x));
	char	   *y_encoded;
	char	   *document;
	size_t		capacity;

	memcpy(y, generator_y, sizeof(y));
	if (!valid_point)
		y[31] ^= 1;
	y_encoded = encode_bytes(y, sizeof(y));
	capacity = strlen(x_encoded) + strlen(y_encoded) + 192;
	document = malloc(capacity);
	if (document == NULL)
		fail("allocation failed");
	snprintf(document, capacity,
			 "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"%s\","
			 "\"y\":\"%s\",\"kid\":\"ec-1\",\"alg\":\"ES256\",\"use\":\"sig\"}]}",
			 x_encoded, y_encoded);
	free(x_encoded);
	free(y_encoded);
	return document;
}

/* RFC 8037 Appendix A.2 public key; a valid Ed25519 point. */
static const char rfc8037_x[] = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

static char *
make_okp_jwks(const char *key_type, const char *curve, const char *x,
			  const char *members)
{
	size_t		capacity = strlen(key_type) + strlen(curve) + strlen(x) +
		strlen(members) + 64;
	char	   *document = malloc(capacity);

	if (document == NULL)
		fail("allocation failed");
	snprintf(document, capacity,
			 "{\"keys\":[{\"kty\":\"%s\",\"crv\":\"%s\",\"x\":\"%s\",%s}]}",
			 key_type, curve, x, members);
	return document;
}

static char *
make_okp_x(size_t length)
{
	unsigned char *bytes = malloc(length);
	char	   *encoded;

	if (bytes == NULL)
		fail("allocation failed");
	memset(bytes, 0x01, length);
	encoded = encode_bytes(bytes, length);
	free(bytes);
	return encoded;
}

static void
expect_error(const char *document, const char *key_id, uint32_t algorithm,
			 PgOAuthJwksError expected, const char *message)
{
	PgOAuthJwksPolicy policy = valid_policy();
	PgOAuthSelectedJwk selected;

	if (pg_oauth_jwks_select(document, strlen(document), key_id, algorithm,
							 &policy, &selected) != expected)
		fail(message);
	if (selected.jwks != NULL || selected.jwk != NULL)
		fail("rejected JWKS retained untrusted data");
}

int
main(void)
{
	PgOAuthJwksPolicy policy = valid_policy();
	PgOAuthSelectedJwk selected;
	char	   *document = make_rsa_jwks(
										 "\"kid\":\"rsa-1\",\"alg\":\"RS256\",\"use\":\"sig\"", 256, 0x80);

	if (pg_oauth_jwks_select(document, strlen(document), "rsa-1",
							 PG_OAUTH_ALGORITHM_RS256, &policy, &selected) != PG_OAUTH_JWKS_OK)
		fail("valid RSA signing key was rejected");
	if (selected.algorithm != PG_OAUTH_ALGORITHM_RS256 || selected.jwk == NULL)
		fail("valid key was selected incorrectly");
	pg_oauth_selected_jwk_clear(&selected);
	free(document);

	document = make_ec_jwks(true);
	if (pg_oauth_jwks_select(document, strlen(document), "ec-1",
							 PG_OAUTH_ALGORITHM_ES256, &policy, &selected) != PG_OAUTH_JWKS_OK)
		fail("valid P-256 signing key was rejected");
	pg_oauth_selected_jwk_clear(&selected);
	free(document);

	document = make_ec_jwks(false);
	expect_error(document, "ec-1", PG_OAUTH_ALGORITHM_ES256,
				 PG_OAUTH_JWKS_INVALID_KEY, "off-curve EC point was accepted");
	free(document);

	document = make_rsa_jwks(
							 "\"kid\":\"rsa-1\",\"alg\":\"RS256\",\"key_ops\":[\"verify\"]",
							 256, 0x80);
	if (pg_oauth_jwks_select(document, strlen(document), "rsa-1",
							 PG_OAUTH_ALGORITHM_RS256, &policy, &selected) != PG_OAUTH_JWKS_OK)
		fail("verify key operation was rejected");
	pg_oauth_selected_jwk_clear(&selected);
	free(document);

	document = make_rsa_jwks(
							 "\"kid\":\"rsa-1\",\"alg\":\"RS256\",\"use\":\"sig\"", 128, 0x80);
	expect_error(document, "rsa-1", PG_OAUTH_ALGORITHM_RS256,
				 PG_OAUTH_JWKS_INVALID_KEY, "undersized RSA modulus was accepted");
	free(document);

	document = make_rsa_jwks(
							 "\"kid\":\"rsa-1\",\"alg\":\"RS256\",\"use\":\"enc\"", 256, 0x80);
	expect_error(document, "rsa-1", PG_OAUTH_ALGORITHM_RS256,
				 PG_OAUTH_JWKS_KEY_NOT_FOR_SIGNATURE, "encryption key was accepted");
	free(document);

	document = make_rsa_jwks(
							 "\"kid\":\"rsa-1\",\"alg\":\"RS256\",\"key_ops\":[\"verify\",\"sign\"]",
							 256, 0x80);
	expect_error(document, "rsa-1", PG_OAUTH_ALGORITHM_RS256,
				 PG_OAUTH_JWKS_KEY_NOT_FOR_SIGNATURE,
				 "mixed public-key operations were accepted");
	free(document);

	document = make_rsa_jwks(
							 "\"kid\":\"rsa-1\",\"alg\":\"RS256\"", 256, 0x80);
	expect_error(document, "rsa-1", PG_OAUTH_ALGORITHM_RS256,
				 PG_OAUTH_JWKS_KEY_NOT_FOR_SIGNATURE,
				 "key without signature intent was accepted");
	free(document);

	document = make_rsa_jwks(
							 "\"kid\":\"rsa-1\",\"alg\":\"ES256\",\"use\":\"sig\"", 256, 0x80);
	expect_error(document, "rsa-1", PG_OAUTH_ALGORITHM_RS256,
				 PG_OAUTH_JWKS_ALGORITHM_MISMATCH, "key algorithm mismatch was accepted");
	free(document);

	document = make_rsa_jwks(
							 "\"kid\":\"rsa-1\",\"alg\":\"RS256\",\"use\":\"sig\",\"d\":\"AQ\"",
							 256, 0x80);
	expect_error(document, "rsa-1", PG_OAUTH_ALGORITHM_RS256,
				 PG_OAUTH_JWKS_INVALID_KEY, "private key material was accepted");
	free(document);

	expect_error("{\"keys\":[]}", "missing", PG_OAUTH_ALGORITHM_RS256,
				 PG_OAUTH_JWKS_INVALID_KEYS, "empty key set was accepted");
	expect_error("{\"keys\":[1]}", "missing", PG_OAUTH_ALGORITHM_RS256,
				 PG_OAUTH_JWKS_KEY_NOT_FOUND, "non-object key was matched");
	expect_error("{\"keys\":[],\"keys\":[]}", "missing",
				 PG_OAUTH_ALGORITHM_RS256, PG_OAUTH_JWKS_INVALID_JSON,
				 "duplicate JWKS member was accepted");
	expect_error("{\"keys\":[{\"kid\":\"k\",\"kid\":\"k\"}]}", "k",
				 PG_OAUTH_ALGORITHM_RS256, PG_OAUTH_JWKS_INVALID_JSON,
				 "duplicate JWK member was accepted");
	expect_error("{\"keys\":[{\"kid\":\"same\"},{\"kid\":\"same\"}]}", "same",
				 PG_OAUTH_ALGORITHM_RS256, PG_OAUTH_JWKS_DUPLICATE_KEY_ID,
				 "duplicate key identifier was accepted");
	expect_error("{\"keys\":[{\"kid\":\"other\"}]}", "missing",
				 PG_OAUTH_ALGORITHM_RS256, PG_OAUTH_JWKS_KEY_NOT_FOUND,
				 "unknown key identifier was accepted");
	expect_error("{\"keys\":[{\"kid\":\"line\\nfeed\"}]}", "missing",
				 PG_OAUTH_ALGORITHM_RS256, PG_OAUTH_JWKS_KEY_NOT_FOUND,
				 "control character in key identifier was matched");
	expect_error("{\"keys\":[{\"kid\":\"line\\nfeed\"}]}", "line",
				 PG_OAUTH_ALGORITHM_RS256, PG_OAUTH_JWKS_KEY_NOT_FOUND,
				 "partial match on an unusable key identifier was accepted");
	expect_error("{\"keys\":[{\"kid\":7},{\"kid\":null},{}]}", "7",
				 PG_OAUTH_ALGORITHM_RS256, PG_OAUTH_JWKS_KEY_NOT_FOUND,
				 "non-string key identifier was matched");

	/*
	 * RFC 7517 section 5: unusable members are ignored, so one of them cannot
	 * take a whole issuer's keys offline. The usable key still verifies.
	 */
	document = make_rsa_jwks("\"kid\":\"rsa-1\",\"alg\":\"RS256\",\"use\":\"sig\"", 256, 0x80);
	{
		static const char junk[] =
			"{\"keys\":[1,\"x\",null,[],{},{\"kid\":5},{\"kid\":\"a\\nb\"},"
			"{\"kty\":\"oct\",\"kid\":\"sym\",\"k\":\"AA\"},";
		const char *rest = strchr(document, '[') + 1;
		size_t		capacity = sizeof(junk) + strlen(rest);
		char	   *mixed = malloc(capacity);

		if (mixed == NULL)
			fail("allocation failed");
		snprintf(mixed, capacity, "%s%s", junk, rest);
		if (pg_oauth_jwks_select(mixed, strlen(mixed), "rsa-1",
								 PG_OAUTH_ALGORITHM_RS256, &policy, &selected) != PG_OAUTH_JWKS_OK)
			fail("unusable sibling entries made a valid key unusable");
		pg_oauth_selected_jwk_clear(&selected);
		expect_error(mixed, "sym", PG_OAUTH_ALGORITHM_RS256,
					 PG_OAUTH_JWKS_ALGORITHM_MISMATCH,
					 "symmetric key was usable for a signature");
		free(mixed);
	}
	free(document);

	/* EdDSA is selected only when the administrator allows it. */
	policy.allowed_algorithms |= PG_OAUTH_ALGORITHM_EDDSA;
	document = make_okp_jwks("OKP", "Ed25519", rfc8037_x,
							 "\"kid\":\"okp-1\",\"alg\":\"EdDSA\",\"use\":\"sig\"");
	if (pg_oauth_jwks_select(document, strlen(document), "okp-1",
							 PG_OAUTH_ALGORITHM_EDDSA, &policy, &selected) != PG_OAUTH_JWKS_OK)
		fail("valid Ed25519 signing key was rejected");
	if (selected.algorithm != PG_OAUTH_ALGORITHM_EDDSA || selected.jwk == NULL)
		fail("valid Ed25519 key was selected incorrectly");
	pg_oauth_selected_jwk_clear(&selected);
	expect_error(document, "okp-1", PG_OAUTH_ALGORITHM_EDDSA,
				 PG_OAUTH_JWKS_INVALID_ARGUMENT,
				 "EdDSA key was selected without administrator allowance");
	free(document);

	document = make_okp_jwks("OKP", "Ed25519", rfc8037_x,
							 "\"kid\":\"okp-1\",\"alg\":\"EdDSA\",\"key_ops\":[\"verify\"]");
	if (pg_oauth_jwks_select(document, strlen(document), "okp-1",
							 PG_OAUTH_ALGORITHM_EDDSA, &policy, &selected) != PG_OAUTH_JWKS_OK)
		fail("Ed25519 verify key operation was rejected");
	pg_oauth_selected_jwk_clear(&selected);
	free(document);

	{
		static const struct
		{
			const char *key_type;
			const char *curve;
			size_t		x_bytes;
			const char *members;
			PgOAuthJwksError expected;
			const char *message;
		}			cases[] = {
			{"OKP", "Ed448", 57, "\"kid\":\"k\",\"alg\":\"EdDSA\",\"use\":\"sig\"",
			PG_OAUTH_JWKS_INVALID_KEY, "Ed448 key was accepted for EdDSA"},
			{"OKP", "X25519", 32, "\"kid\":\"k\",\"alg\":\"EdDSA\",\"use\":\"sig\"",
			PG_OAUTH_JWKS_INVALID_KEY, "X25519 key was accepted for EdDSA"},
			{"OKP", "ed25519", 32, "\"kid\":\"k\",\"alg\":\"EdDSA\",\"use\":\"sig\"",
			PG_OAUTH_JWKS_INVALID_KEY, "case-variant curve name was accepted"},
			{"OKP", "Ed25519", 31, "\"kid\":\"k\",\"alg\":\"EdDSA\",\"use\":\"sig\"",
			PG_OAUTH_JWKS_INVALID_KEY, "short Ed25519 key was accepted"},
			{"OKP", "Ed25519", 33, "\"kid\":\"k\",\"alg\":\"EdDSA\",\"use\":\"sig\"",
			PG_OAUTH_JWKS_INVALID_KEY, "long Ed25519 key was accepted"},
			{"EC", "Ed25519", 32, "\"kid\":\"k\",\"alg\":\"EdDSA\",\"use\":\"sig\"",
			PG_OAUTH_JWKS_INVALID_KEY, "wrong key type was accepted for EdDSA"},
			{"OKP", "Ed25519", 32, "\"kid\":\"k\",\"alg\":\"EdDSA\",\"use\":\"sig\",\"d\":\"AQ\"",
			PG_OAUTH_JWKS_INVALID_KEY, "Ed25519 private key material was accepted"},
			{"OKP", "Ed25519", 32, "\"kid\":\"k\",\"alg\":\"EdDSA\",\"use\":\"enc\"",
			PG_OAUTH_JWKS_KEY_NOT_FOR_SIGNATURE, "Ed25519 encryption key was accepted"},
			{"OKP", "Ed25519", 32, "\"kid\":\"k\",\"alg\":\"EdDSA\"",
			PG_OAUTH_JWKS_KEY_NOT_FOR_SIGNATURE, "Ed25519 key without signature intent was accepted"},
			{"OKP", "Ed25519", 32, "\"kid\":\"k\",\"alg\":\"RS256\",\"use\":\"sig\"",
			PG_OAUTH_JWKS_ALGORITHM_MISMATCH, "Ed25519 key labelled RS256 was accepted for EdDSA"},
			{"OKP", "Ed25519", 32, "\"kid\":\"k\",\"alg\":\"Ed25519\",\"use\":\"sig\"",
			PG_OAUTH_JWKS_ALGORITHM_MISMATCH, "unreviewed fully-specified algorithm name was accepted"},
			{"OKP", "Ed25519", 32, "\"kid\":\"k\",\"use\":\"sig\"",
			PG_OAUTH_JWKS_ALGORITHM_MISMATCH, "Ed25519 key without alg was accepted"},
		};

		for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
		{
			char	   *x = make_okp_x(cases[i].x_bytes);

			document = make_okp_jwks(cases[i].key_type, cases[i].curve, x,
									 cases[i].members);
			if (pg_oauth_jwks_select(document, strlen(document), "k",
									 PG_OAUTH_ALGORITHM_EDDSA, &policy, &selected) !=
				cases[i].expected)
				fail(cases[i].message);
			if (selected.jwks != NULL || selected.jwk != NULL)
				fail("rejected EdDSA JWKS retained untrusted data");
			free(document);
			free(x);
		}
	}

	/* An EdDSA-labelled token must not select an RSA or EC key. */
	document = make_rsa_jwks(
							 "\"kid\":\"rsa-1\",\"alg\":\"RS256\",\"use\":\"sig\"", 256, 0x80);
	if (pg_oauth_jwks_select(document, strlen(document), "rsa-1",
							 PG_OAUTH_ALGORITHM_EDDSA, &policy, &selected) !=
		PG_OAUTH_JWKS_ALGORITHM_MISMATCH)
		fail("EdDSA token selected an RSA key");
	free(document);

	if (strstr(pg_oauth_jwks_error_code(PG_OAUTH_JWKS_INVALID_KEY), "rsa-1") !=
		NULL)
		fail("stable JWKS error exposed key data");

	/* Document-level shapes that must never yield a key. */
	expect_error("[]", "k", PG_OAUTH_ALGORITHM_RS256, PG_OAUTH_JWKS_INVALID_JSON,
				 "top-level array was accepted");
	expect_error("{\"keys\":{}}", "k", PG_OAUTH_ALGORITHM_RS256,
				 PG_OAUTH_JWKS_INVALID_KEYS, "non-array keys member was accepted");
	expect_error("{\"keys\":[],\"keys\":[]}", "k", PG_OAUTH_ALGORITHM_RS256,
				 PG_OAUTH_JWKS_INVALID_JSON, "duplicate keys member was accepted");
	expect_error("{\"keys\":[{\"kid\":\"\",\"kty\":\"RSA\"},{\"kid\":\"k\"}]}", "k",
				 PG_OAUTH_ALGORITHM_RS256, PG_OAUTH_JWKS_INVALID_KEY_ID,
				 "empty key identifier on another key was accepted");
	expect_error("{\"keys\":[{\"kid\":5},{\"kid\":\"k\",\"kty\":\"RSA\"}]}", "k",
				 PG_OAUTH_ALGORITHM_RS256, PG_OAUTH_JWKS_INVALID_KEY_ID,
				 "numeric key identifier on another key was accepted");
	{
		/* One key more than the policy allows, with the wanted key first. */
		char		many[2048] = "{\"keys\":[";

		for (int n = 0; n < 17; n++)
			snprintf(many + strlen(many), sizeof(many) - strlen(many),
					 "%s{\"kid\":\"k%d\",\"kty\":\"RSA\"}", n == 0 ? "" : ",", n);
		strncat(many, "]}", sizeof(many) - strlen(many) - 1);
		expect_error(many, "k0", PG_OAUTH_ALGORITHM_RS256,
					 PG_OAUTH_JWKS_TOO_MANY_KEYS, "more keys than the limit were accepted");
	}

	/* The selected key itself must be complete and usable for verification. */
	expect_error("{\"keys\":[{\"kid\":\"k\",\"alg\":\"RS256\",\"use\":\"sig\"}]}", "k",
				 PG_OAUTH_ALGORITHM_RS256, PG_OAUTH_JWKS_INVALID_KEY,
				 "key without a key type was accepted");
	expect_error("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"k\",\"alg\":\"RS256\","
				 "\"use\":\"sig\",\"n\":\"AQAB\"}]}", "k", PG_OAUTH_ALGORITHM_RS256,
				 PG_OAUTH_JWKS_INVALID_KEY, "RSA key without an exponent was accepted");
	expect_error("{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"k\","
				 "\"alg\":\"ES256\",\"use\":\"sig\","
				 "\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\"}]}", "k",
				 PG_OAUTH_ALGORITHM_ES256, PG_OAUTH_JWKS_INVALID_KEY,
				 "EC key without a y coordinate was accepted");
	expect_error("{\"keys\":[{\"kty\":\"oct\",\"kid\":\"k\",\"alg\":\"RS256\","
				 "\"use\":\"sig\",\"k\":\"c2VjcmV0\"}]}", "k", PG_OAUTH_ALGORITHM_RS256,
				 PG_OAUTH_JWKS_INVALID_KEY, "symmetric key was accepted as an RSA key");

	return EXIT_SUCCESS;
}
