#ifndef PG_OAUTH_VALIDATOR_JWKS_H
#define PG_OAUTH_VALIDATOR_JWKS_H

#include <stddef.h>
#include <stdint.h>

#include <jansson.h>

#include "algorithms.h"

typedef enum PgOAuthJwksError
{
	PG_OAUTH_JWKS_OK = 0,
	PG_OAUTH_JWKS_INVALID_ARGUMENT,
	PG_OAUTH_JWKS_EMPTY,
	PG_OAUTH_JWKS_TOO_LARGE,
	PG_OAUTH_JWKS_INVALID_JSON,
	PG_OAUTH_JWKS_INVALID_KEYS,
	PG_OAUTH_JWKS_TOO_MANY_KEYS,
	PG_OAUTH_JWKS_DUPLICATE_KEY_ID,
	PG_OAUTH_JWKS_KEY_NOT_FOUND,
	PG_OAUTH_JWKS_ALGORITHM_MISMATCH,
	PG_OAUTH_JWKS_KEY_NOT_FOR_SIGNATURE,
	PG_OAUTH_JWKS_INVALID_KEY
} PgOAuthJwksError;

typedef struct PgOAuthJwksPolicy
{
	size_t		max_jwks_size;
	size_t		max_keys;
	size_t		max_key_id_size;
	uint32_t	allowed_algorithms;
	unsigned int minimum_rsa_bits;
	unsigned int maximum_rsa_bits;
} PgOAuthJwksPolicy;

typedef struct PgOAuthSelectedJwk
{
	json_t	   *jwks;
	json_t	   *jwk;
	uint32_t	algorithm;
} PgOAuthSelectedJwk;

extern PgOAuthJwksError pg_oauth_jwks_select(
											 const char *document, size_t document_length, const char *key_id,
											 uint32_t token_algorithm, const PgOAuthJwksPolicy *policy,
											 PgOAuthSelectedJwk *selected);
extern void pg_oauth_selected_jwk_clear(PgOAuthSelectedJwk *selected);
extern const char *pg_oauth_jwks_error_code(PgOAuthJwksError error);

#endif							/* PG_OAUTH_VALIDATOR_JWKS_H */
