/*
 * Fuzz signature verification with real keys. The key set holds a genuine
 * RS256, ES256 and Ed25519 public key, each paired with a token signed by the
 * matching private key. The input is a small mutation program applied to one of
 * those tokens (bit flips, truncation, insertion, deletion, replacement, and
 * splicing in another algorithm's signature), so verification runs deep inside
 * libjwt and OpenSSL instead of stopping at the first malformed byte.
 *
 * Memory safety is checked by the sanitizers. The security contract is checked
 * here: a signature that verifies must have been computed over exactly the
 * original signing input (everything before the last '.'). The signature
 * segment itself may differ, since non-canonical base64url tail bits decode to
 * the same bytes, but the header, the payload, and which key was used may not.
 * That also covers algorithm confusion: a token that names a different
 * algorithm than its key changes the header and so must not verify.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "jwks.h"
#include "signature.h"

#define REQUIRE(condition) \
	do { \
		if (!(condition)) \
			abort(); \
	} while (0)

static void
fail(const char *message)
{
	fprintf(stderr, "signature_fuzz: %s\n", message);
	abort();
}

#include "../signing_support.h"

#define KEY_COUNT 3
#define TOKEN_MAX 4096

static const char *const algorithm_names[KEY_COUNT] = {"RS256", "ES256", "EdDSA"};
static const uint32_t algorithm_flags[KEY_COUNT] = {
	PG_OAUTH_ALGORITHM_RS256, PG_OAUTH_ALGORITHM_ES256, PG_OAUTH_ALGORITHM_EDDSA
};

static PgOAuthSelectedJwk selected[KEY_COUNT];
static char *tokens[KEY_COUNT];

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	PgOAuthJwksPolicy policy = {
		.max_jwks_size = 65536,
		.max_keys = 16,
		.max_key_id_size = 1024,
		.allowed_algorithms = PG_OAUTH_ALGORITHM_RS256 |
		PG_OAUTH_ALGORITHM_ES256 | PG_OAUTH_ALGORITHM_EDDSA,
		.minimum_rsa_bits = 2048,
		.maximum_rsa_bits = 8192,
	};
	SigningVariant plain = {NULL, false};

	(void) argc;
	(void) argv;
	for (int i = 0; i < KEY_COUNT; i++)
	{
		EVP_PKEY   *key = generate_key(algorithm_names[i]);
		char	   *jwks = public_jwks(key, algorithm_names[i], "fuzz-key");

		REQUIRE(pg_oauth_jwks_select(jwks, strlen(jwks), "fuzz-key",
									 algorithm_flags[i], &policy, &selected[i]) ==
				PG_OAUTH_JWKS_OK);
		tokens[i] = signed_token_variant(key, algorithm_names[i], "fuzz-key", plain);
		REQUIRE(strlen(tokens[i]) < TOKEN_MAX);
		/* The unmodified token must verify, or the oracle below proves nothing. */
		REQUIRE(pg_oauth_signature_verify(tokens[i], strlen(tokens[i]),
										  &selected[i]) == PG_OAUTH_SIGNATURE_OK);
		free(jwks);
		EVP_PKEY_free(key);
	}
	return 0;
}

/* Position of the last '.', which ends the signing input. */
static size_t
signing_input_length(const char *token, size_t length)
{
	while (length > 0 && token[length - 1] != '.')
		length--;
	return length == 0 ? 0 : length - 1;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char		token[TOKEN_MAX];
	size_t		length;
	size_t		key;
	size_t		original_signing_length;

	if (size < 1 || size > 256)
		return 0;
	key = data[0] % KEY_COUNT;
	length = strlen(tokens[key]);
	memcpy(token, tokens[key], length);
	token[length] = '\0';
	original_signing_length = signing_input_length(tokens[key], length);

	for (size_t i = 1; i + 2 < size; i += 3)
	{
		uint8_t		op = data[i] % 6;
		size_t		position = length == 0 ? 0 :
			(((size_t) data[i + 1] << 8) | data[i + 2]) % length;

		switch (op)
		{
			case 0:				/* flip one bit */
				if (length > 0)
					token[position] = (char) (token[position] ^ (1 << ((data[i] >> 3) & 7)));
				break;
			case 1:				/* truncate */
				length = position;
				token[length] = '\0';
				break;
			case 2:				/* insert a byte */
				if (length + 1 < TOKEN_MAX)
				{
					memmove(token + position + 1, token + position, length - position);
					token[position] = (char) data[i + 1];
					length++;
					token[length] = '\0';
				}
				break;
			case 3:				/* delete a byte */
				if (length > 0)
				{
					memmove(token + position, token + position + 1, length - position - 1);
					length--;
					token[length] = '\0';
				}
				break;
			case 4:				/* replace a byte */
				if (length > 0)
					token[position] = (char) data[i + 1];
				break;
			case 5:				/* splice another algorithm's signature */
				{
					const char *other = tokens[data[i + 1] % KEY_COUNT];
					size_t		other_length = strlen(other);
					size_t		other_start = signing_input_length(other, other_length) + 1;
					size_t		own_start = signing_input_length(token, length) + 1;

					if (own_start + (other_length - other_start) + 1 < TOKEN_MAX)
					{
						memcpy(token + own_start, other + other_start,
							   other_length - other_start);
						length = own_start + (other_length - other_start);
						token[length] = '\0';
					}
				}
				break;
		}
	}

	if (pg_oauth_signature_verify(token, length, &selected[key]) ==
		PG_OAUTH_SIGNATURE_OK)
	{
		/* Only the original signing input can carry a valid signature. */
		REQUIRE(signing_input_length(token, length) == original_signing_length);
		REQUIRE(memcmp(token, tokens[key], original_signing_length) == 0);
	}
	return 0;
}
