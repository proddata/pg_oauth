#ifndef PG_OAUTH_VALIDATOR_IDENTITY_H
#define PG_OAUTH_VALIDATOR_IDENTITY_H

#include <stddef.h>

typedef enum PgOAuthIdentityError
{
	PG_OAUTH_IDENTITY_OK = 0,
	PG_OAUTH_IDENTITY_INVALID_ARGUMENT,
	PG_OAUTH_IDENTITY_INVALID_SUBJECT,
	PG_OAUTH_IDENTITY_TOO_LARGE,
	PG_OAUTH_IDENTITY_ALLOCATION_FAILED
} PgOAuthIdentityError;

typedef struct PgOAuthIdentityPolicy
{
	size_t		max_subject_size;
	size_t		max_authn_id_size;
} PgOAuthIdentityPolicy;

typedef struct PgOAuthIdentity
{
	char	   *value;
	size_t		length;
} PgOAuthIdentity;

extern PgOAuthIdentityError pg_oauth_identity_build(
													const char *subject, size_t subject_length,
													const PgOAuthIdentityPolicy *policy,
													PgOAuthIdentity *identity);
extern void pg_oauth_identity_clear(PgOAuthIdentity *identity);
extern const char *pg_oauth_identity_error_code(PgOAuthIdentityError error);

#endif							/* PG_OAUTH_VALIDATOR_IDENTITY_H */
