#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "claims.h"
#include "identity.h"
#include "jwt_envelope.h"
#include "jwks.h"
#include "signature.h"

static void
fail(const char *message)
{
	fprintf(stderr, "signature_test: %s\n", message);
	exit(EXIT_FAILURE);
}

#include "signing_support.h"

static char *
signed_token(EVP_PKEY *key, const char *algorithm, const char *key_id)
{
	SigningVariant plain = {NULL, false};

	return signed_token_variant(key, algorithm, key_id, plain);
}

/*
 * libjwt 3.3.3 does not require the token header's algorithm to equal the
 * algorithm configured for the checker when the key itself names one, and
 * verifies under the header's algorithm. A token that is genuinely signed by
 * the trusted RSA key but declares another RSA algorithm must therefore be
 * refused here, whatever earlier stages allow.
 */
static void
check_header_algorithm_binding(void)
{
	PgOAuthJwksPolicy jwks_policy = {
		.max_jwks_size = 65536,
		.max_keys = 16,
		.max_key_id_size = 1024,
		.allowed_algorithms = PG_OAUTH_ALGORITHM_RS256,
		.minimum_rsa_bits = 2048,
		.maximum_rsa_bits = 8192,
	};
	static const struct
	{
		const char *header_algorithm;
		const EVP_MD *(*digest) (void);
		bool		pss;
	}			variants[] = {
		{"RS384", EVP_sha384, false},
		{"RS512", EVP_sha512, false},
		{"PS256", EVP_sha256, true},
		{"PS384", EVP_sha384, true},
	};
	EVP_PKEY   *key = generate_key("RS256");
	char	   *jwks = public_jwks(key, "RS256", "binding-test");
	PgOAuthSelectedJwk selected;
	char	   *token = signed_token(key, "RS256", "binding-test");

	if (pg_oauth_jwks_select(jwks, strlen(jwks), "binding-test",
							 PG_OAUTH_ALGORITHM_RS256, &jwks_policy, &selected) != PG_OAUTH_JWKS_OK)
		fail("binding-test key failed strict selection");
	if (pg_oauth_signature_verify(token, strlen(token), &selected) !=
		PG_OAUTH_SIGNATURE_OK)
		fail("matching header algorithm was rejected");
	free(token);
	for (size_t i = 0; i < sizeof(variants) / sizeof(variants[0]); i++)
	{
		SigningVariant variant = {variants[i].digest(), variants[i].pss};

		token = signed_token_variant(key, variants[i].header_algorithm,
									 "binding-test", variant);
		if (pg_oauth_signature_verify(token, strlen(token), &selected) !=
			PG_OAUTH_SIGNATURE_ALGORITHM_MISMATCH)
		{
			fprintf(stderr, "signature_test: header algorithm %s was not refused\n",
					variants[i].header_algorithm);
			exit(EXIT_FAILURE);
		}
		free(token);
	}
	pg_oauth_selected_jwk_clear(&selected);
	free(jwks);
	EVP_PKEY_free(key);
}

/*
 * libjwt keeps a key it cannot import in the set and flags the item, so a
 * successful set creation proves nothing. The stage must report the import
 * failure itself instead of letting verification fail later as a bad signature.
 */
static void
check_unusable_key_import(void)
{
	static const char *const unusable[] = {
		"{\"kty\":\"RSA\",\"n\":\"!!not-base64url!!\",\"e\":\"AQAB\","
		"\"alg\":\"RS256\",\"use\":\"sig\",\"kid\":\"import-test\"}",
		"{\"kty\":\"RSA\",\"e\":\"AQAB\",\"alg\":\"RS256\","
		"\"use\":\"sig\",\"kid\":\"import-test\"}",
		"{\"kty\":\"RSA\",\"n\":\"\",\"e\":\"\",\"alg\":\"RS256\","
		"\"use\":\"sig\",\"kid\":\"import-test\"}",
	};
	EVP_PKEY   *key = generate_key("RS256");
	char	   *token = signed_token(key, "RS256", "import-test");

	for (size_t i = 0; i < sizeof(unusable) / sizeof(unusable[0]); i++)
	{
		PgOAuthSelectedJwk selected = {0};
		PgOAuthSignatureError error;

		selected.jwks = json_loads(unusable[i], 0, NULL);
		if (selected.jwks == NULL)
			fail("test key document did not parse");
		selected.jwk = selected.jwks;
		selected.algorithm = PG_OAUTH_ALGORITHM_RS256;
		error = pg_oauth_signature_verify(token, strlen(token), &selected);
		if (error != PG_OAUTH_SIGNATURE_KEY_IMPORT_FAILED)
		{
			fprintf(stderr, "signature_test: unusable key %zu reported %s\n", i,
					pg_oauth_signature_error_code(error));
			exit(EXIT_FAILURE);
		}
		json_decref(selected.jwks);
	}
	free(token);
	EVP_PKEY_free(key);
}

static void
check_algorithm(const char *algorithm, uint32_t algorithm_flag,
				const char *key_id)
{
	PgOAuthJwtEnvelopePolicy envelope_policy = {
		.max_token_size = 16384,
		.max_header_size = 4096,
		.max_payload_size = 12288,
		.allowed_algorithms = algorithm_flag,
		.allowed_token_types = PG_OAUTH_TOKEN_TYPE_AT_JWT,
	};
	PgOAuthJwksPolicy jwks_policy = {
		.max_jwks_size = 65536,
		.max_keys = 16,
		.max_key_id_size = 1024,
		.allowed_algorithms = algorithm_flag,
		.minimum_rsa_bits = 2048,
		.maximum_rsa_bits = 8192,
	};
	PgOAuthJwtEnvelope envelope;
	PgOAuthSelectedJwk selected;
	PgOAuthSelectedJwk wrong_selected;
	PgOAuthClaimsPolicy claims_policy = {
		.issuer = "https://issuer.example/",
		.audiences = "postgres://primary",
		.required_scopes = "connect:postgres",
		.identity_claim = "sub",
		.role_claim = "",
		.current_time = 1000,
		.clock_skew_seconds = 60,
		.max_identity_size = 1024,
		.max_subject_size = 1024,
		.max_audiences = 16,
		.max_scopes = 64,
	};
	PgOAuthValidatedClaims claims;
	PgOAuthIdentityPolicy identity_policy = {
		.max_subject_size = 1024,
		.max_authn_id_size = 1024,
	};
	PgOAuthIdentity identity;
	EVP_PKEY   *key = generate_key(algorithm);
	EVP_PKEY   *wrong_key;
	char	   *jwks = public_jwks(key, algorithm, key_id);
	char	   *wrong_jwks;
	char	   *token = signed_token(key, algorithm, key_id);
	char	   *tampered;
	char	   *payload;
	char	   *signature_segment;

	if (pg_oauth_jwt_envelope_parse(token, strlen(token), &envelope_policy,
									&envelope) != PG_OAUTH_JWT_ENVELOPE_OK)
		fail("generated token failed strict envelope validation");
	if (pg_oauth_jwks_select(jwks, strlen(jwks), envelope.key_id,
							 envelope.algorithm, &jwks_policy, &selected) != PG_OAUTH_JWKS_OK)
		fail("generated public key failed strict selection");
	if (pg_oauth_signature_verify(token, strlen(token), &selected) !=
		PG_OAUTH_SIGNATURE_OK)
		fail("valid generated signature was rejected");
	if (pg_oauth_claims_validate(envelope.untrusted_payload, &claims_policy,
								 &claims) != PG_OAUTH_CLAIMS_OK ||
		claims.identity_length != strlen("principal") ||
		memcmp(claims.identity, "principal", claims.identity_length) != 0)
		fail("verified token claims were rejected");
	if (pg_oauth_identity_build(claims.identity, claims.identity_length,
								&identity_policy, &identity) != PG_OAUTH_IDENTITY_OK ||
		strcmp(identity.value, "principal") != 0)
		fail("validated claims identity could not be copied");
	pg_oauth_identity_clear(&identity);
	wrong_key = generate_key(algorithm);
	wrong_jwks = public_jwks(wrong_key, algorithm, key_id);
	if (pg_oauth_jwks_select(wrong_jwks, strlen(wrong_jwks), envelope.key_id,
							 envelope.algorithm, &jwks_policy, &wrong_selected) != PG_OAUTH_JWKS_OK)
		fail("second generated public key failed strict selection");
	if (pg_oauth_signature_verify(token, strlen(token), &wrong_selected) !=
		PG_OAUTH_SIGNATURE_INVALID)
		fail("signature from a different trusted key was accepted");
	pg_oauth_selected_jwk_clear(&wrong_selected);
	free(wrong_jwks);
	EVP_PKEY_free(wrong_key);

	tampered = duplicate_string(token);
	signature_segment = strrchr(tampered, '.');
	if (signature_segment == NULL || signature_segment[1] == '\0')
		fail("generated compact token was malformed");
	signature_segment[1] = signature_segment[1] == 'A' ?
		'B' : 'A';
	if (pg_oauth_signature_verify(tampered, strlen(tampered), &selected) !=
		PG_OAUTH_SIGNATURE_INVALID)
		fail("tampered signature was accepted");
	free(tampered);

	payload = strchr(token, '.');
	if (payload == NULL || payload[1] == '\0')
		fail("generated compact token was malformed");
	tampered = duplicate_string(token);
	payload = strchr(tampered, '.');
	payload[1] = payload[1] == 'A' ? 'B' : 'A';
	if (pg_oauth_signature_verify(tampered, strlen(tampered), &selected) !=
		PG_OAUTH_SIGNATURE_INVALID)
		fail("tampered payload was accepted");

	free(tampered);
	pg_oauth_selected_jwk_clear(&selected);
	pg_oauth_jwt_envelope_clear(&envelope);
	free(jwks);
	free(token);
	EVP_PKEY_free(key);
}

int
main(void)
{
	check_algorithm("RS256", PG_OAUTH_ALGORITHM_RS256, "rsa-signature-test");
	check_algorithm("ES256", PG_OAUTH_ALGORITHM_ES256, "ec-signature-test");
	check_algorithm("EdDSA", PG_OAUTH_ALGORITHM_EDDSA, "okp-signature-test");
	check_header_algorithm_binding();
	check_unusable_key_import();
	if (strstr(pg_oauth_signature_error_code(PG_OAUTH_SIGNATURE_INVALID),
			   "principal") != NULL)
		fail("signature error code exposed token material");
	return EXIT_SUCCESS;
}
