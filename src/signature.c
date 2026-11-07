/*
 * Signature verification: the only place that calls into libjwt to verify.
 *
 * It receives one JWK already vetted by jwks.c and fixes the checker to the
 * single approved algorithm for that key. It makes no claim, time, issuer, URL,
 * or caching decision and uses none of libjwt's remote-JWKS or claim helpers;
 * those policies belong to this project's own stages (ADR 0001).
 */
#include "signature.h"

#include <stdlib.h>
#include <string.h>

#include <jansson.h>
#include <jwt.h>

#include "base64url.h"

/* Defensive bound; the envelope stage enforces the configured header limit. */
#define PG_OAUTH_SIGNATURE_MAX_HEADER 8192

static jwt_alg_t
libjwt_algorithm(uint32_t algorithm)
{
	if (algorithm == PG_OAUTH_ALGORITHM_RS256)
		return JWT_ALG_RS256;
	if (algorithm == PG_OAUTH_ALGORITHM_ES256)
		return JWT_ALG_ES256;
	if (algorithm == PG_OAUTH_ALGORITHM_EDDSA)
		return JWT_ALG_EDDSA;
	return JWT_ALG_INVAL;
}

static const char *
header_algorithm_name(uint32_t algorithm)
{
	if (algorithm == PG_OAUTH_ALGORITHM_RS256)
		return "RS256";
	if (algorithm == PG_OAUTH_ALGORITHM_ES256)
		return "ES256";
	if (algorithm == PG_OAUTH_ALGORITHM_EDDSA)
		return "EdDSA";
	return NULL;
}

/*
 * libjwt 3.3.3 does not require the token header's algorithm to equal the
 * checker's when the key itself names one, and verifies under the header's
 * algorithm (jwt-verify.c, __verify_config_post). Earlier stages already bind
 * the header to the key (jwt_envelope.c allowlist, jwks.c algorithm match), but
 * this stage is the one that grants trust, so it enforces the same binding
 * itself instead of relying on them or on libjwt.
 */
static bool
header_algorithm_matches(const char *token, size_t token_length,
						 uint32_t algorithm)
{
	const char *expected = header_algorithm_name(algorithm);
	const char *dot = memchr(token, '.', token_length);
	size_t		encoded_length;
	size_t		decoded_length;
	uint8_t    *decoded;
	json_t	   *header;
	json_t	   *name;
	bool		matches;

	if (expected == NULL || dot == NULL)
		return false;
	encoded_length = (size_t) (dot - token);
	if (encoded_length == 0 || encoded_length > PG_OAUTH_SIGNATURE_MAX_HEADER ||
		!pg_oauth_base64url_decoded_size(encoded_length,
										 PG_OAUTH_SIGNATURE_MAX_HEADER,
										 &decoded_length))
		return false;
	decoded = malloc(decoded_length + 1);
	if (decoded == NULL)
		return false;
	if (!pg_oauth_base64url_decode(token, encoded_length, decoded,
								   decoded_length))
	{
		free(decoded);
		return false;
	}
	header = json_loadb((const char *) decoded, decoded_length,
						JSON_REJECT_DUPLICATES, NULL);
	free(decoded);
	if (header == NULL)
		return false;
	name = json_object_get(header, "alg");
	matches = json_is_string(name) &&
		strcmp(json_string_value(name), expected) == 0 &&
		json_string_length(name) == strlen(expected);
	json_decref(header);
	return matches;
}

PgOAuthSignatureError
pg_oauth_signature_verify(const char *token, size_t token_length,
						  const PgOAuthSelectedJwk *selected_key)
{
	char	   *jwk_json = NULL;
	char	   *token_copy = NULL;
	jwk_set_t  *key_set = NULL;
	const jwk_item_t *key;
	jwt_checker_t *checker = NULL;
	jwt_alg_t	algorithm;
	PgOAuthSignatureError result = PG_OAUTH_SIGNATURE_VERIFIER_FAILED;

	if (token == NULL || token_length == 0 || selected_key == NULL ||
		selected_key->jwks == NULL || selected_key->jwk == NULL)
		return PG_OAUTH_SIGNATURE_INVALID_ARGUMENT;
	algorithm = libjwt_algorithm(selected_key->algorithm);
	if (algorithm == JWT_ALG_INVAL)
		return PG_OAUTH_SIGNATURE_INVALID_ARGUMENT;
	if (memchr(token, '\0', token_length) != NULL || token_length == SIZE_MAX)
		return PG_OAUTH_SIGNATURE_INVALID_ARGUMENT;
	if (!header_algorithm_matches(token, token_length, selected_key->algorithm))
		return PG_OAUTH_SIGNATURE_ALGORITHM_MISMATCH;

	/* Serialize only the key already selected by the strict JWKS boundary. */
	jwk_json = json_dumps(selected_key->jwk, JSON_COMPACT | JSON_SORT_KEYS);
	if (jwk_json == NULL)
		return PG_OAUTH_SIGNATURE_KEY_SERIALIZATION_FAILED;
	key_set = jwks_create_strn(jwk_json, strlen(jwk_json));
	if (key_set == NULL || jwks_error(key_set) != 0 ||
		jwks_item_count(key_set) != 1)
	{
		result = PG_OAUTH_SIGNATURE_KEY_IMPORT_FAILED;
		goto done;
	}
	key = jwks_item_get(key_set, 0);
	if (key == NULL || jwks_item_error(key) != 0)
	{
		/* libjwt keeps unusable keys in the set and flags them per item. */
		result = PG_OAUTH_SIGNATURE_KEY_IMPORT_FAILED;
		goto done;
	}
	checker = jwt_checker_new();

	/*
	 * The two jwt_checker_time_leeway() calls below disable libjwt's own
	 * exp/nbf decisions. It would evaluate them against the process wall
	 * clock before the signature; time is judged once, by the
	 * injectable-clock claims stage, after verification (ADR 0001).
	 */
	if (key == NULL || checker == NULL ||
		jwt_checker_setkey(checker, algorithm, key) != 0 ||
		jwt_checker_time_leeway(checker, JWT_CLAIM_EXP, -1) != 0 ||
		jwt_checker_time_leeway(checker, JWT_CLAIM_NBF, -1) != 0)
	{
		result = PG_OAUTH_SIGNATURE_VERIFIER_FAILED;
		goto done;
	}

	token_copy = malloc(token_length + 1);
	if (token_copy == NULL)
		goto done;
	memcpy(token_copy, token, token_length);
	token_copy[token_length] = '\0';
	result = jwt_checker_verify(checker, token_copy) == 0 ?
		PG_OAUTH_SIGNATURE_OK : PG_OAUTH_SIGNATURE_INVALID;

done:
	free(token_copy);
	if (checker != NULL)
		jwt_checker_free(checker);
	if (key_set != NULL)
		jwks_free(key_set);
	free(jwk_json);
	return result;
}

const char *
pg_oauth_signature_error_code(PgOAuthSignatureError error)
{
	static const char *const codes[] = {
		"ok", "invalid_argument", "key_serialization_failed",
		"key_import_failed", "verifier_failed", "invalid_signature",
		"algorithm_mismatch"
	};

	if ((size_t) error >= sizeof(codes) / sizeof(codes[0]))
		return "unknown";
	return codes[error];
}
