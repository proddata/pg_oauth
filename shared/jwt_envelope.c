/*
 * Strict structural parse of an untrusted compact JWS access token.
 *
 * This stage decides nothing about trust. It bounds sizes, requires canonical
 * unpadded Base64URL and unique JSON members, and extracts only the values the
 * later stages need: the algorithm and key id from the protected header. The
 * decoded payload is kept as untrusted_payload and must not influence any
 * decision until the signature has been verified (see validator.c).
 *
 * The algorithm is matched case-sensitively against the administrator's
 * allowlist, never against what the token or the JWKS would like to use, and
 * headers that could redirect key selection or change verification (such as
 * token-supplied key locations and critical-header extensions) are rejected
 * outright rather than ignored.
 */
#include "jwt_envelope.h"
#include "ascii.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "base64url.h"

#define PG_OAUTH_JWT_MAX_KEY_ID_SIZE 1024

typedef struct CompactSegment
{
	const char *data;
	size_t		length;
} CompactSegment;

static bool
split_compact_jws(const char *token, size_t token_length,
				  CompactSegment segments[3])
{
	size_t		start = 0;
	size_t		segment_index = 0;

	for (size_t i = 0; i <= token_length; i++)
	{
		if (i != token_length && token[i] != '.')
			continue;
		if (segment_index >= 3 || i == start)
			return false;
		segments[segment_index].data = token + start;
		segments[segment_index].length = i - start;
		segment_index++;
		start = i + 1;
	}

	return segment_index == 3;
}

static unsigned char *
decode_base64url(const CompactSegment *segment, size_t maximum,
				 size_t *decoded_length)
{
	size_t		length;
	unsigned char *decoded;

	if (!pg_oauth_base64url_decoded_size(segment->length, maximum, &length))
		return NULL;

	decoded = malloc(length + 1);
	if (decoded == NULL)
		return NULL;

	if (!pg_oauth_base64url_decode(segment->data, segment->length, decoded,
								   length))
	{
		free(decoded);
		return NULL;
	}
	decoded[length] = '\0';
	*decoded_length = length;
	return decoded;
}

static json_t *
decode_json_object(const CompactSegment *segment, size_t maximum,
				   PgOAuthJwtEnvelopeError *error,
				   PgOAuthJwtEnvelopeError size_error,
				   PgOAuthJwtEnvelopeError json_error)
{
	unsigned char *decoded;
	size_t		decoded_length;
	json_error_t parse_error;
	json_t	   *object;

	decoded = decode_base64url(segment, maximum, &decoded_length);
	if (decoded == NULL)
	{
		*error = size_error;
		return NULL;
	}

	object = json_loadb((const char *) decoded, decoded_length,
						JSON_REJECT_DUPLICATES, &parse_error);
	free(decoded);
	if (object == NULL || !json_is_object(object))
	{
		json_decref(object);
		*error = json_error;
		return NULL;
	}
	return object;
}

static bool
has_unsupported_header(const json_t *header)
{
	static const char *const forbidden[] = {
		"jku", "jwk", "x5u", "x5c", "x5t", "x5t#S256", "crit", "zip",
		"b64", "cty"
	};

	for (size_t i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); i++)
	{
		if (json_object_get(header, forbidden[i]) != NULL)
			return true;
	}
	return false;
}

static uint32_t
parse_algorithm(const json_t *header)
{
	json_t	   *value = json_object_get(header, "alg");
	const char *algorithm;
	size_t		length;

	if (!json_is_string(value))
		return 0;
	algorithm = json_string_value(value);
	length = json_string_length(value);
	if (length == 5 && memcmp(algorithm, "RS256", length) == 0)
		return PG_OAUTH_ALGORITHM_RS256;
	if (length == 5 && memcmp(algorithm, "ES256", length) == 0)
		return PG_OAUTH_ALGORITHM_ES256;
	if (length == 5 && memcmp(algorithm, "EdDSA", length) == 0)
		return PG_OAUTH_ALGORITHM_EDDSA;
	return 0;
}

/*
 * RFC 7515 section 4.1.9: media type names are case-insensitive, and RFC 9068
 * section 2.1's own example spells the type "at+JWT". The allowlist still
 * selects which spelling (with or without "application/") is accepted. Fold
 * only ASCII so the result does not depend on the database locale.
 */
static bool
equals_ignoring_ascii_case(const char *value, size_t length, const char *expected)
{
	if (length != strlen(expected))
		return false;
	for (size_t i = 0; i < length; i++)
	{
		unsigned char c = (unsigned char) value[i];

		if (c >= 'A' && c <= 'Z')
			c = (unsigned char) (c - 'A' + 'a');
		if (c != (unsigned char) expected[i])
			return false;
	}
	return true;
}

static bool
token_type_allowed(const char *value, size_t length,
				   const PgOAuthJwtEnvelopePolicy *policy)
{
	return ((policy->allowed_token_types & PG_OAUTH_TOKEN_TYPE_AT_JWT) != 0 &&
			equals_ignoring_ascii_case(value, length, "at+jwt")) ||
		((policy->allowed_token_types & PG_OAUTH_TOKEN_TYPE_APPLICATION_AT_JWT) != 0 &&
		 equals_ignoring_ascii_case(value, length, "application/at+jwt"));
}

void
pg_oauth_jwt_envelope_clear(PgOAuthJwtEnvelope *envelope)
{
	if (envelope == NULL)
		return;
	json_decref(envelope->untrusted_header);
	json_decref(envelope->untrusted_payload);
	memset(envelope, 0, sizeof(*envelope));
}

PgOAuthJwtEnvelopeError
pg_oauth_jwt_envelope_parse(const char *token, size_t token_length,
							const PgOAuthJwtEnvelopePolicy *policy,
							PgOAuthJwtEnvelope *envelope)
{
	CompactSegment segments[3];
	PgOAuthJwtEnvelopeError error = PG_OAUTH_JWT_ENVELOPE_OK;
	json_t	   *value;
	uint32_t	algorithm;
	const char *key_id;

	if (envelope == NULL)
		return PG_OAUTH_JWT_ENVELOPE_INVALID_ARGUMENT;
	memset(envelope, 0, sizeof(*envelope));
	if (token == NULL || policy == NULL || policy->allowed_token_types == 0 ||
		(policy->allowed_token_types & ~PG_OAUTH_TOKEN_TYPES_ALL) != 0 ||
		policy->max_token_size == 0 || policy->max_header_size == 0 ||
		policy->max_payload_size == 0 || policy->allowed_algorithms == 0)
		return PG_OAUTH_JWT_ENVELOPE_INVALID_ARGUMENT;
	if (token_length == 0)
		return PG_OAUTH_JWT_ENVELOPE_EMPTY;
	if (token_length > policy->max_token_size)
		return PG_OAUTH_JWT_ENVELOPE_TOO_LARGE;
	if (memchr(token, '\0', token_length) != NULL ||
		!split_compact_jws(token, token_length, segments))
		return PG_OAUTH_JWT_ENVELOPE_INVALID_COMPACT_JWS;
	for (size_t i = 0; i < 3; i++)
	{
		if (!pg_oauth_base64url_valid(segments[i].data, segments[i].length))
			return PG_OAUTH_JWT_ENVELOPE_INVALID_BASE64URL;
	}

	envelope->untrusted_header = decode_json_object(&segments[0],
													policy->max_header_size, &error, PG_OAUTH_JWT_ENVELOPE_HEADER_TOO_LARGE,
													PG_OAUTH_JWT_ENVELOPE_INVALID_HEADER_JSON);
	if (envelope->untrusted_header == NULL)
		goto fail;
	envelope->untrusted_payload = decode_json_object(&segments[1],
													 policy->max_payload_size, &error, PG_OAUTH_JWT_ENVELOPE_PAYLOAD_TOO_LARGE,
													 PG_OAUTH_JWT_ENVELOPE_INVALID_PAYLOAD_JSON);
	if (envelope->untrusted_payload == NULL)
		goto fail;

	if (has_unsupported_header(envelope->untrusted_header))
	{
		error = PG_OAUTH_JWT_ENVELOPE_UNSUPPORTED_HEADER;
		goto fail;
	}
	algorithm = parse_algorithm(envelope->untrusted_header);
	if (algorithm == 0 || (algorithm & policy->allowed_algorithms) == 0)
	{
		error = PG_OAUTH_JWT_ENVELOPE_INVALID_ALGORITHM;
		goto fail;
	}
	value = json_object_get(envelope->untrusted_header, "typ");
	if (value == NULL)
	{
		if (!policy->allow_missing_token_type)
		{
			error = PG_OAUTH_JWT_ENVELOPE_INVALID_TOKEN_TYPE;
			goto fail;
		}
	}
	else if (!json_is_string(value) ||
			 !token_type_allowed(json_string_value(value),
								 json_string_length(value), policy))
	{
		error = PG_OAUTH_JWT_ENVELOPE_INVALID_TOKEN_TYPE;
		goto fail;
	}
	value = json_object_get(envelope->untrusted_header, "kid");
	if (!json_is_string(value))
	{
		error = PG_OAUTH_JWT_ENVELOPE_INVALID_KEY_ID;
		goto fail;
	}
	key_id = json_string_value(value);
	if (json_string_length(value) == 0 ||
		json_string_length(value) > PG_OAUTH_JWT_MAX_KEY_ID_SIZE)
	{
		error = PG_OAUTH_JWT_ENVELOPE_INVALID_KEY_ID;
		goto fail;
	}
	for (size_t i = 0; i < json_string_length(value); i++)
	{
		if (pg_oauth_ascii_iscntrl((unsigned char) key_id[i]))
		{
			error = PG_OAUTH_JWT_ENVELOPE_INVALID_KEY_ID;
			goto fail;
		}
	}

	envelope->algorithm = algorithm;
	envelope->key_id = key_id;
	return PG_OAUTH_JWT_ENVELOPE_OK;

fail:
	pg_oauth_jwt_envelope_clear(envelope);
	return error;
}

const char *
pg_oauth_jwt_envelope_error_code(PgOAuthJwtEnvelopeError error)
{
	static const char *const codes[] = {
		"ok", "invalid_argument", "empty", "too_large", "invalid_compact_jws",
		"invalid_base64url", "header_too_large", "payload_too_large",
		"invalid_header_json", "invalid_payload_json", "unsupported_header",
		"invalid_algorithm", "invalid_token_type", "invalid_key_id"
	};

	if ((size_t) error >= sizeof(codes) / sizeof(codes[0]))
		return "unknown";
	return codes[error];
}
