#ifndef PG_OAUTH_VALIDATOR_CLAIMS_H
#define PG_OAUTH_VALIDATOR_CLAIMS_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include <jansson.h>

typedef enum PgOAuthClaimsError
{
	PG_OAUTH_CLAIMS_OK = 0,
	PG_OAUTH_CLAIMS_INVALID_ARGUMENT,
	PG_OAUTH_CLAIMS_INVALID_ISSUER,
	PG_OAUTH_CLAIMS_INVALID_AUDIENCE,
	PG_OAUTH_CLAIMS_MISSING_EXPIRY,
	PG_OAUTH_CLAIMS_INVALID_EXPIRY,
	PG_OAUTH_CLAIMS_EXPIRED,
	PG_OAUTH_CLAIMS_INVALID_NOT_BEFORE,
	PG_OAUTH_CLAIMS_NOT_YET_VALID,
	PG_OAUTH_CLAIMS_INVALID_ISSUED_AT,
	PG_OAUTH_CLAIMS_ISSUED_IN_FUTURE,
	PG_OAUTH_CLAIMS_INVALID_SUBJECT,
	PG_OAUTH_CLAIMS_INVALID_IDENTITY,
	PG_OAUTH_CLAIMS_INVALID_SCOPE,
	PG_OAUTH_CLAIMS_INSUFFICIENT_SCOPE,
	PG_OAUTH_CLAIMS_INVALID_ROLES,
	PG_OAUTH_CLAIMS_UNAUTHORIZED_ROLE
} PgOAuthClaimsError;

typedef struct PgOAuthClaimsPolicy
{
	const char *issuer;
	const char *audiences;
	const char *required_scopes;
	const char *identity_claim;
	const char *role_claim;
	const char *requested_role;
	int64_t		current_time;
	uint32_t	clock_skew_seconds;
	size_t		max_identity_size;
	size_t		max_subject_size;
	size_t		max_audiences;
	size_t		max_scopes;
	size_t		max_roles;
	size_t		max_role_size;
} PgOAuthClaimsPolicy;

typedef struct PgOAuthValidatedClaims
{
	/* Owned by the verified payload and valid only while it remains alive. */
	const char *identity;
	size_t		identity_length;
	int64_t		expires_at;
} PgOAuthValidatedClaims;

/* The caller must invoke this only after authenticating the JWS signature. */
extern PgOAuthClaimsError pg_oauth_claims_validate(
												   const json_t *verified_payload, const PgOAuthClaimsPolicy *policy,
												   PgOAuthValidatedClaims *claims);
extern const char *pg_oauth_claims_error_code(PgOAuthClaimsError error);

extern bool pg_oauth_claims_expired(int64_t now, int64_t expires_at,
									uint32_t skew_seconds);

#endif							/* PG_OAUTH_VALIDATOR_CLAIMS_H */
