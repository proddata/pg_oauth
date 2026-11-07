/*
 * Select exactly one trusted verification key from an already-fetched JWKS.
 *
 * Performs no I/O. The JWKS document comes from the issuer's configured
 * location but is still untrusted input: it is size- and count-bounded,
 * parsed with duplicate-member rejection, and the chosen key must pass every
 * check below before it is handed to signature verification.
 *
 * The key is picked by an exact kid match only; two keys with the same kid is
 * an error rather than a tie-break. The key's own "alg" must equal the
 * token's algorithm and be on the administrator's allowlist, so a token cannot
 * pick the algorithm that verifies it (RSA/EC/Ed25519 confusion), and key type
 * and parameters are checked against local policy per algorithm.
 */
#include "jwks.h"
#include "ascii.h"

#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#include "base64url.h"

#define PG_OAUTH_JWK_MAX_EXPONENT_BYTES 8

static bool
json_string_equals(const json_t *value, const char *expected)
{
	size_t		length;

	if (!json_is_string(value))
		return false;
	length = strlen(expected);
	return json_string_length(value) == length &&
		memcmp(json_string_value(value), expected, length) == 0;
}

static bool
valid_key_id(const json_t *value, size_t maximum)
{
	const char *key_id;
	size_t		length;

	if (!json_is_string(value))
		return false;
	key_id = json_string_value(value);
	length = json_string_length(value);
	if (length == 0 || length > maximum)
		return false;
	for (size_t i = 0; i < length; i++)
	{
		if (pg_oauth_ascii_iscntrl((unsigned char) key_id[i]))
			return false;
	}
	return true;
}

static bool
key_allows_verification(const json_t *key)
{
	json_t	   *use = json_object_get(key, "use");
	json_t	   *operations = json_object_get(key, "key_ops");
	bool		has_marker = false;
	bool		verify = false;

	if (use != NULL)
	{
		has_marker = true;
		if (!json_string_equals(use, "sig"))
			return false;
	}
	if (operations != NULL)
	{
		has_marker = true;
		if (!json_is_array(operations) || json_array_size(operations) != 1)
			return false;
		verify = json_string_equals(json_array_get(operations, 0), "verify");
		if (!verify)
			return false;
	}
	return has_marker;
}

/*
 * A published verification key must be public. Private members in a JWKS mean
 * a misconfigured or compromised issuer, so the key is rejected, not stripped.
 */
static bool
contains_private_key_material(const json_t *key)
{
	static const char *const private_members[] = {
		"d", "p", "q", "dp", "dq", "qi", "oth", "k"
	};

	for (size_t i = 0;
		 i < sizeof(private_members) / sizeof(private_members[0]); i++)
	{
		if (json_object_get(key, private_members[i]) != NULL)
			return true;
	}
	return false;
}

static uint32_t
key_algorithm(const json_t *key)
{
	json_t	   *algorithm = json_object_get(key, "alg");

	if (json_string_equals(algorithm, "RS256"))
		return PG_OAUTH_ALGORITHM_RS256;
	if (json_string_equals(algorithm, "ES256"))
		return PG_OAUTH_ALGORITHM_ES256;
	if (json_string_equals(algorithm, "EdDSA"))
		return PG_OAUTH_ALGORITHM_EDDSA;
	return 0;
}

static bool
decode_parameter(const json_t *value, size_t maximum, uint8_t **decoded,
				 size_t *decoded_length)
{
	const char *encoded;
	size_t		encoded_length;
	uint8_t    *output;

	if (!json_is_string(value))
		return false;
	encoded = json_string_value(value);
	encoded_length = json_string_length(value);
	if (!pg_oauth_base64url_valid(encoded, encoded_length) ||
		!pg_oauth_base64url_decoded_size(encoded_length, maximum,
										 decoded_length))
		return false;
	output = malloc(*decoded_length);
	if (output == NULL)
		return false;
	if (!pg_oauth_base64url_decode(encoded, encoded_length, output,
								   *decoded_length))
	{
		free(output);
		return false;
	}
	*decoded = output;
	return true;
}

static unsigned int
unsigned_bit_length(const uint8_t *value, size_t length)
{
	unsigned int leading = 0;
	uint8_t		first;

	while (length > 0 && *value == 0)
	{
		value++;
		length--;
	}
	if (length == 0 || length > UINT_MAX / 8)
		return 0;
	first = *value;
	while ((first & 0x80) == 0)
	{
		first <<= 1;
		leading++;
	}
	return (unsigned int) (length * 8) - leading;
}

static bool
valid_rsa_key(const json_t *key, const PgOAuthJwksPolicy *policy)
{
	uint8_t    *modulus = NULL;
	uint8_t    *exponent = NULL;
	size_t		modulus_length;
	size_t		exponent_length;
	unsigned int bits;
	uint64_t	exponent_value = 0;
	bool		valid = false;

	if (!json_string_equals(json_object_get(key, "kty"), "RSA") ||
		!decode_parameter(json_object_get(key, "n"),
						  policy->maximum_rsa_bits / 8 + 1, &modulus,
						  &modulus_length) ||
		!decode_parameter(json_object_get(key, "e"),
						  PG_OAUTH_JWK_MAX_EXPONENT_BYTES, &exponent,
						  &exponent_length))
		goto done;
	if (modulus[0] == 0 || exponent[0] == 0 ||
		(modulus[modulus_length - 1] & 1) == 0)
		goto done;
	bits = unsigned_bit_length(modulus, modulus_length);
	if (bits < policy->minimum_rsa_bits || bits > policy->maximum_rsa_bits)
		goto done;
	for (size_t i = 0; i < exponent_length; i++)
		exponent_value = (exponent_value << 8) | exponent[i];
	if (exponent_value < 3 || (exponent_value & 1) == 0)
		goto done;
	valid = true;

done:
	free(modulus);
	free(exponent);
	return valid;
}

static bool
valid_ec_key(const json_t *key)
{
	uint8_t    *x = NULL;
	uint8_t    *y = NULL;
	size_t		x_length;
	size_t		y_length;
	EC_GROUP   *group = NULL;
	EC_POINT   *point = NULL;
	BIGNUM	   *x_coordinate = NULL;
	BIGNUM	   *y_coordinate = NULL;
	bool		valid = false;

	if (!json_string_equals(json_object_get(key, "kty"), "EC") ||
		!json_string_equals(json_object_get(key, "crv"), "P-256") ||
		!decode_parameter(json_object_get(key, "x"), 32, &x, &x_length) ||
		!decode_parameter(json_object_get(key, "y"), 32, &y, &y_length))
		goto done;
	if (x_length != 32 || y_length != 32)
		goto done;
	group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	point = group != NULL ? EC_POINT_new(group) : NULL;
	x_coordinate = BN_bin2bn(x, (int) x_length, NULL);
	y_coordinate = BN_bin2bn(y, (int) y_length, NULL);
	if (group == NULL || point == NULL || x_coordinate == NULL ||
		y_coordinate == NULL ||
		EC_POINT_set_affine_coordinates(group, point, x_coordinate,
										y_coordinate, NULL) != 1 ||
		EC_POINT_is_at_infinity(group, point) == 1 ||
		EC_POINT_is_on_curve(group, point, NULL) != 1)
		goto done;
	valid = true;

done:
	BN_free(x_coordinate);
	BN_free(y_coordinate);
	EC_POINT_free(point);
	EC_GROUP_free(group);
	free(x);
	free(y);
	return valid;
}

/*
 * RFC 8037 OKP/Ed25519 only. The curve is pinned here, as for P-256, rather
 * than inherited from the verifier library: Ed448 and X25519 keys, and any
 * wrong-length coordinate, are rejected before import. OpenSSL decodes the
 * point when verifying; an undecodable point can only yield an invalid
 * signature.
 */
static bool
valid_ed25519_key(const json_t *key)
{
	uint8_t    *x = NULL;
	size_t		x_length;
	EVP_PKEY   *public_key = NULL;
	bool		valid = false;

	if (!json_string_equals(json_object_get(key, "kty"), "OKP") ||
		!json_string_equals(json_object_get(key, "crv"), "Ed25519") ||
		!decode_parameter(json_object_get(key, "x"), 32, &x, &x_length) ||
		x_length != 32)
		goto done;
	public_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, x,
											 x_length);
	valid = public_key != NULL;

done:
	EVP_PKEY_free(public_key);
	free(x);
	return valid;
}

void
pg_oauth_selected_jwk_clear(PgOAuthSelectedJwk *selected)
{
	if (selected == NULL)
		return;
	json_decref(selected->jwks);
	memset(selected, 0, sizeof(*selected));
}

PgOAuthJwksError
pg_oauth_jwks_select(const char *document, size_t document_length,
					 const char *key_id, uint32_t token_algorithm,
					 const PgOAuthJwksPolicy *policy,
					 PgOAuthSelectedJwk *selected)
{
	json_error_t json_error;
	json_t	   *keys;
	json_t	   *candidate = NULL;
	size_t		key_id_length;
	uint32_t	algorithm;

	if (selected == NULL)
		return PG_OAUTH_JWKS_INVALID_ARGUMENT;
	memset(selected, 0, sizeof(*selected));
	if (document == NULL || key_id == NULL || policy == NULL ||
		policy->max_jwks_size == 0 || policy->max_keys == 0 ||
		policy->max_key_id_size == 0 || policy->allowed_algorithms == 0 ||
		policy->minimum_rsa_bits < 2048 ||
		policy->maximum_rsa_bits < policy->minimum_rsa_bits ||
		policy->maximum_rsa_bits > 16384 || token_algorithm == 0 ||
		(token_algorithm & (token_algorithm - 1)) != 0 ||
		(token_algorithm & policy->allowed_algorithms) == 0)
		return PG_OAUTH_JWKS_INVALID_ARGUMENT;
	key_id_length = strlen(key_id);
	if (key_id_length == 0 || key_id_length > policy->max_key_id_size)
		return PG_OAUTH_JWKS_INVALID_ARGUMENT;
	for (size_t i = 0; i < key_id_length; i++)
	{
		if (pg_oauth_ascii_iscntrl((unsigned char) key_id[i]))
			return PG_OAUTH_JWKS_INVALID_ARGUMENT;
	}
	if (document_length == 0)
		return PG_OAUTH_JWKS_EMPTY;
	if (document_length > policy->max_jwks_size)
		return PG_OAUTH_JWKS_TOO_LARGE;
	if (memchr(document, '\0', document_length) != NULL)
		return PG_OAUTH_JWKS_INVALID_JSON;

	selected->jwks = json_loadb(document, document_length,
								JSON_REJECT_DUPLICATES, &json_error);
	if (selected->jwks == NULL || !json_is_object(selected->jwks))
	{
		pg_oauth_selected_jwk_clear(selected);
		return PG_OAUTH_JWKS_INVALID_JSON;
	}
	keys = json_object_get(selected->jwks, "keys");
	if (!json_is_array(keys) || json_array_size(keys) == 0)
	{
		pg_oauth_selected_jwk_clear(selected);
		return PG_OAUTH_JWKS_INVALID_KEYS;
	}
	if (json_array_size(keys) > policy->max_keys)
	{
		pg_oauth_selected_jwk_clear(selected);
		return PG_OAUTH_JWKS_TOO_MANY_KEYS;
	}

	for (size_t i = 0; i < json_array_size(keys); i++)
	{
		json_t	   *key = json_array_get(keys, i);
		json_t	   *candidate_id;

		/*
		 * RFC 7517 section 5: ignore array members that cannot be used. An
		 * entry that is not an object, or whose "kid" is not a usable key ID,
		 * can never be selected for a token (whose own "kid" was validated),
		 * so skipping it cannot admit a key. Duplicate usable key IDs remain
		 * an error because they make the selection ambiguous.
		 */
		if (!json_is_object(key))
			continue;
		candidate_id = json_object_get(key, "kid");
		if (candidate_id == NULL ||
			!valid_key_id(candidate_id, policy->max_key_id_size))
			continue;
		if (json_string_length(candidate_id) == key_id_length &&
			memcmp(json_string_value(candidate_id), key_id, key_id_length) == 0)
		{
			if (candidate != NULL)
			{
				pg_oauth_selected_jwk_clear(selected);
				return PG_OAUTH_JWKS_DUPLICATE_KEY_ID;
			}
			candidate = key;
		}
	}
	if (candidate == NULL)
	{
		pg_oauth_selected_jwk_clear(selected);
		return PG_OAUTH_JWKS_KEY_NOT_FOUND;
	}
	algorithm = key_algorithm(candidate);
	if (algorithm == 0 || algorithm != token_algorithm ||
		(algorithm & policy->allowed_algorithms) == 0)
	{
		pg_oauth_selected_jwk_clear(selected);
		return PG_OAUTH_JWKS_ALGORITHM_MISMATCH;
	}
	if (!key_allows_verification(candidate))
	{
		pg_oauth_selected_jwk_clear(selected);
		return PG_OAUTH_JWKS_KEY_NOT_FOR_SIGNATURE;
	}
	if (contains_private_key_material(candidate))
	{
		pg_oauth_selected_jwk_clear(selected);
		return PG_OAUTH_JWKS_INVALID_KEY;
	}
	if ((algorithm == PG_OAUTH_ALGORITHM_RS256 &&
		 !valid_rsa_key(candidate, policy)) ||
		(algorithm == PG_OAUTH_ALGORITHM_ES256 && !valid_ec_key(candidate)) ||
		(algorithm == PG_OAUTH_ALGORITHM_EDDSA &&
		 !valid_ed25519_key(candidate)))
	{
		pg_oauth_selected_jwk_clear(selected);
		return PG_OAUTH_JWKS_INVALID_KEY;
	}

	selected->jwk = candidate;
	selected->algorithm = algorithm;
	return PG_OAUTH_JWKS_OK;
}

const char *
pg_oauth_jwks_error_code(PgOAuthJwksError error)
{
	static const char *const codes[] = {
		"ok", "invalid_argument", "empty", "too_large", "invalid_json",
		"invalid_keys", "too_many_keys", "invalid_key_id", "duplicate_key_id",
		"key_not_found", "algorithm_mismatch", "key_not_for_signature",
		"invalid_key"
	};

	if ((size_t) error >= sizeof(codes) / sizeof(codes[0]))
		return "unknown";
	return codes[error];
}
