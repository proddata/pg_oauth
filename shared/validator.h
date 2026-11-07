#ifndef PG_OAUTH_VALIDATOR_VALIDATOR_H
#define PG_OAUTH_VALIDATOR_VALIDATOR_H

#include <stddef.h>
#include <stdbool.h>

#include "claims.h"
#include "identity.h"
#include "issuer_key.h"
#include "jwt_envelope.h"
#include "signature.h"

typedef enum PgOAuthValidatorError
{
	PG_OAUTH_VALIDATOR_OK = 0,
	PG_OAUTH_VALIDATOR_INVALID_ARGUMENT,
	PG_OAUTH_VALIDATOR_ENVELOPE,
	PG_OAUTH_VALIDATOR_ISSUER_KEY,
	PG_OAUTH_VALIDATOR_SIGNATURE,
	PG_OAUTH_VALIDATOR_CLAIMS,
	PG_OAUTH_VALIDATOR_IDENTITY
} PgOAuthValidatorError;

typedef struct PgOAuthValidatorPolicy
{
	PgOAuthJwtEnvelopePolicy envelope;
	PgOAuthIssuerKeyPolicy issuer_key;
	PgOAuthClaimsPolicy claims;
	PgOAuthIdentityPolicy identity;
} PgOAuthValidatorPolicy;

typedef struct PgOAuthValidatorResult
{
	PgOAuthIdentity identity;
	int64_t		expires_at;
	PgOAuthJwtEnvelopeError envelope_error;
	PgOAuthIssuerKeyError issuer_key_error;
	PgOAuthHttpError http_error;
	PgOAuthMetadataError metadata_error;
	PgOAuthJwksError jwks_error;
	PgOAuthSignatureError signature_error;
	PgOAuthClaimsError claims_error;
	PgOAuthIdentityError identity_error;
} PgOAuthValidatorResult;

extern PgOAuthValidatorError pg_oauth_validate_access_token(
															const char *token, size_t token_length, const char *metadata_url,
															const PgOAuthValidatorPolicy *policy, PgOAuthValidatorResult *result);
extern PgOAuthValidatorError pg_oauth_validate_access_token_cached(
																   const char *token, size_t token_length, const char *metadata_url,
																   const PgOAuthValidatorPolicy *policy,
																   const PgOAuthIssuerKeyCachePolicy *cache_policy, int64_t now_ms,
																   int64_t response_time_seconds, PgOAuthValidatorResult *result);
extern void pg_oauth_validator_result_clear(PgOAuthValidatorResult *result);
extern const char *pg_oauth_validator_error_code(PgOAuthValidatorError error);

#endif
