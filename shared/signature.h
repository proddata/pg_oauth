#ifndef PG_OAUTH_VALIDATOR_SIGNATURE_H
#define PG_OAUTH_VALIDATOR_SIGNATURE_H

#include <stddef.h>

#include "jwks.h"

typedef enum PgOAuthSignatureError
{
	PG_OAUTH_SIGNATURE_OK = 0,
	PG_OAUTH_SIGNATURE_INVALID_ARGUMENT,
	PG_OAUTH_SIGNATURE_KEY_SERIALIZATION_FAILED,
	PG_OAUTH_SIGNATURE_KEY_IMPORT_FAILED,
	PG_OAUTH_SIGNATURE_VERIFIER_FAILED,
	PG_OAUTH_SIGNATURE_INVALID,
	PG_OAUTH_SIGNATURE_ALGORITHM_MISMATCH
} PgOAuthSignatureError;

extern PgOAuthSignatureError pg_oauth_signature_verify(
													   const char *token, size_t token_length,
													   const PgOAuthSelectedJwk *selected_key);
extern const char *pg_oauth_signature_error_code(PgOAuthSignatureError error);

#endif							/* PG_OAUTH_VALIDATOR_SIGNATURE_H */
