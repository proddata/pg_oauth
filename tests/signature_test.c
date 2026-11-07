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

static const char alphabet[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static void
fail(const char *message)
{
	fprintf(stderr, "signature_test: %s\n", message);
	exit(EXIT_FAILURE);
}

static char *
duplicate_string(const char *input)
{
	size_t		length = strlen(input) + 1;
	char	   *copy = malloc(length);

	if (copy == NULL)
		fail("allocation failed");
	memcpy(copy, input, length);
	return copy;
}

static char *
encode_bytes(const unsigned char *input, size_t length)
{
	size_t		capacity = (length / 3) * 4 +
		(length % 3 == 0 ? 0 : length % 3 + 1);
	char	   *output = malloc(capacity + 1);
	size_t		in = 0;
	size_t		out = 0;

	if (output == NULL)
		fail("allocation failed");
	while (in + 3 <= length)
	{
		unsigned int bits = ((unsigned int) input[in] << 16) |
			((unsigned int) input[in + 1] << 8) | input[in + 2];

		output[out++] = alphabet[(bits >> 18) & 63];
		output[out++] = alphabet[(bits >> 12) & 63];
		output[out++] = alphabet[(bits >> 6) & 63];
		output[out++] = alphabet[bits & 63];
		in += 3;
	}
	if (length - in == 1)
	{
		unsigned int bits = (unsigned int) input[in] << 4;

		output[out++] = alphabet[(bits >> 6) & 63];
		output[out++] = alphabet[bits & 63];
	}
	else if (length - in == 2)
	{
		unsigned int bits = ((unsigned int) input[in] << 10) |
			((unsigned int) input[in + 1] << 2);

		output[out++] = alphabet[(bits >> 12) & 63];
		output[out++] = alphabet[(bits >> 6) & 63];
		output[out++] = alphabet[bits & 63];
	}
	output[out] = '\0';
	return output;
}

static char *
encode_bn(const BIGNUM *number, size_t fixed_size)
{
	size_t		length = fixed_size != 0 ? fixed_size : (size_t) BN_num_bytes(number);
	unsigned char *bytes = malloc(length);
	char	   *encoded;

	if (bytes == NULL || BN_bn2binpad(number, bytes, (int) length) != (int) length)
		fail("BIGNUM encoding failed");
	encoded = encode_bytes(bytes, length);
	free(bytes);
	return encoded;
}

static EVP_PKEY *
generate_key(const char *algorithm)
{
	EVP_PKEY   *key;

	if (strcmp(algorithm, "RS256") == 0)
		key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 2048);
	else if (strcmp(algorithm, "EdDSA") == 0)
		key = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
	else
		key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
	if (key == NULL)
		fail("key generation failed");
	return key;
}

static char *
public_jwks(EVP_PKEY *key, const char *algorithm, const char *key_id)
{
	BIGNUM	   *first = NULL;
	BIGNUM	   *second = NULL;
	char	   *first_encoded;
	char	   *second_encoded;
	char	   *document;
	size_t		capacity;

	if (strcmp(algorithm, "RS256") == 0)
	{
		if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &first) != 1 ||
			EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &second) != 1)
			fail("RSA parameter export failed");
		first_encoded = encode_bn(first, 0);
		second_encoded = encode_bn(second, 0);
		capacity = strlen(first_encoded) + strlen(second_encoded) +
			strlen(key_id) + 160;
		document = malloc(capacity);
		if (document == NULL)
			fail("allocation failed");
		snprintf(document, capacity,
				 "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"%s\",\"e\":\"%s\","
				 "\"kid\":\"%s\",\"alg\":\"RS256\",\"use\":\"sig\"}]}",
				 first_encoded, second_encoded, key_id);
	}
	else if (strcmp(algorithm, "EdDSA") == 0)
	{
		unsigned char raw[32];
		size_t		raw_length = sizeof(raw);

		if (EVP_PKEY_get_raw_public_key(key, raw, &raw_length) != 1 ||
			raw_length != sizeof(raw))
			fail("Ed25519 public key export failed");
		first_encoded = encode_bytes(raw, raw_length);
		second_encoded = duplicate_string("");
		capacity = strlen(first_encoded) + strlen(key_id) + 160;
		document = malloc(capacity);
		if (document == NULL)
			fail("allocation failed");
		snprintf(document, capacity,
				 "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"%s\","
				 "\"kid\":\"%s\",\"alg\":\"EdDSA\",\"use\":\"sig\"}]}",
				 first_encoded, key_id);
	}
	else
	{
		if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_X, &first) != 1 ||
			EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_Y, &second) != 1)
			fail("EC parameter export failed");
		first_encoded = encode_bn(first, 32);
		second_encoded = encode_bn(second, 32);
		capacity = strlen(first_encoded) + strlen(second_encoded) +
			strlen(key_id) + 192;
		document = malloc(capacity);
		if (document == NULL)
			fail("allocation failed");
		snprintf(document, capacity,
				 "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"%s\","
				 "\"y\":\"%s\",\"kid\":\"%s\",\"alg\":\"ES256\","
				 "\"use\":\"sig\"}]}", first_encoded, second_encoded, key_id);
	}
	BN_free(first);
	BN_free(second);
	free(first_encoded);
	free(second_encoded);
	return document;
}

typedef struct SigningVariant
{
	const EVP_MD *digest;		/* NULL means the key type's default */
	bool		pss;			/* RSASSA-PSS instead of PKCS#1 v1.5 */
} SigningVariant;

static unsigned char *
sign_input_variant(EVP_PKEY *key, const char *input, size_t *signature_length,
				   SigningVariant variant)
{
	EVP_MD_CTX *context = EVP_MD_CTX_new();
	EVP_PKEY_CTX *key_context = NULL;
	unsigned char *signature;

	/* Ed25519 signs the message directly; it takes no separate digest. */
	const EVP_MD *digest = EVP_PKEY_id(key) == EVP_PKEY_ED25519 ?
		NULL : (variant.digest != NULL ? variant.digest : EVP_sha256());

	if (context == NULL ||
		EVP_DigestSignInit(context, &key_context, digest, NULL, key) != 1)
		fail("signature initialization failed");
	if (variant.pss &&
		(EVP_PKEY_CTX_set_rsa_padding(key_context, RSA_PKCS1_PSS_PADDING) <= 0 ||
		 EVP_PKEY_CTX_set_rsa_pss_saltlen(key_context, RSA_PSS_SALTLEN_DIGEST) <= 0))
		fail("PSS configuration failed");
	if (EVP_DigestSign(context, NULL, signature_length,
					   (const unsigned char *) input, strlen(input)) != 1)
		fail("signature initialization failed");
	signature = malloc(*signature_length);
	if (signature == NULL ||
		EVP_DigestSign(context, signature, signature_length,
					   (const unsigned char *) input, strlen(input)) != 1)
		fail("signature generation failed");
	EVP_MD_CTX_free(context);
	return signature;
}

static char *
ecdsa_jws_signature(const unsigned char *der, size_t der_length)
{
	const unsigned char *cursor = der;
	ECDSA_SIG  *signature = d2i_ECDSA_SIG(NULL, &cursor, (long) der_length);
	const BIGNUM *r;
	const BIGNUM *s;
	unsigned char raw[64];

	if (signature == NULL || cursor != der + der_length)
		fail("ECDSA signature decoding failed");
	ECDSA_SIG_get0(signature, &r, &s);
	if (BN_bn2binpad(r, raw, 32) != 32 ||
		BN_bn2binpad(s, raw + 32, 32) != 32)
		fail("ECDSA signature conversion failed");
	ECDSA_SIG_free(signature);
	return encode_bytes(raw, sizeof(raw));
}

static char *
signed_token_variant(EVP_PKEY *key, const char *algorithm, const char *key_id,
					 SigningVariant variant)
{
	char		header[160];
	char	   *encoded_header;
	char	   *encoded_payload;
	char	   *signing_input;
	unsigned char *signature;
	size_t		signature_length;
	char	   *encoded_signature;
	char	   *token;
	size_t		capacity;

	snprintf(header, sizeof(header),
			 "{\"alg\":\"%s\",\"typ\":\"at+jwt\",\"kid\":\"%s\"}",
			 algorithm, key_id);
	encoded_header = encode_bytes((const unsigned char *) header, strlen(header));
	encoded_payload = encode_bytes((const unsigned char *)
								   "{\"iss\":\"https://issuer.example/\",\"aud\":\"postgres://primary\","
								   "\"exp\":1100,\"sub\":\"principal\",\"scope\":\"connect:postgres\"}",
								   strlen("{\"iss\":\"https://issuer.example/\","
										  "\"aud\":\"postgres://primary\",\"exp\":1100,"
										  "\"sub\":\"principal\",\"scope\":\"connect:postgres\"}"));
	capacity = strlen(encoded_header) + strlen(encoded_payload) + 2;
	signing_input = malloc(capacity);
	if (signing_input == NULL)
		fail("allocation failed");
	snprintf(signing_input, capacity, "%s.%s", encoded_header, encoded_payload);
	signature = sign_input_variant(key, signing_input, &signature_length,
								   variant);
	encoded_signature = strcmp(algorithm, "ES256") == 0 ?
		ecdsa_jws_signature(signature, signature_length) :
		encode_bytes(signature, signature_length);
	capacity = strlen(signing_input) + strlen(encoded_signature) + 2;
	token = malloc(capacity);
	if (token == NULL)
		fail("allocation failed");
	snprintf(token, capacity, "%s.%s", signing_input, encoded_signature);
	free(encoded_header);
	free(encoded_payload);
	free(signing_input);
	free(signature);
	free(encoded_signature);
	return token;
}

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
	} variants[] = {
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
