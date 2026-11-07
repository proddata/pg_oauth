#ifndef PG_OAUTH_VALIDATOR_TESTS_SIGNING_SUPPORT_H
#define PG_OAUTH_VALIDATOR_TESTS_SIGNING_SUPPORT_H

/*
 * Real keys, public JWKS documents and genuinely signed tokens for tests and
 * fuzz harnesses. The includer must define `static void fail(const char *)`
 * (it must not return) before including this file, and include the OpenSSL
 * headers used below.
 */

static const char alphabet[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

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
}			SigningVariant;

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

#endif
