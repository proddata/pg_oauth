#ifndef PG_OAUTH_PAM_CREDENTIAL_H
#define PG_OAUTH_PAM_CREDENTIAL_H

#include <stddef.h>

#include <security/pam_modules.h>

/*
 * Largest credential PostgreSQL can deliver: its password packet is bounded to
 * 65535 bytes including the four-byte length and the terminating NUL
 * (src/backend/libpq/auth.c, PG_MAX_AUTH_TOKEN_LENGTH).
 */
#define PG_OAUTH_PAM_MAX_CREDENTIAL 65530

typedef enum PgOAuthPamCredentialError
{
	PG_OAUTH_PAM_CREDENTIAL_OK = 0,
	PG_OAUTH_PAM_CREDENTIAL_INVALID_ARGUMENT,
	PG_OAUTH_PAM_CREDENTIAL_NO_CONVERSATION,
	PG_OAUTH_PAM_CREDENTIAL_CONVERSATION_FAILED,
	PG_OAUTH_PAM_CREDENTIAL_NO_RESPONSE,
	PG_OAUTH_PAM_CREDENTIAL_EMPTY,
	PG_OAUTH_PAM_CREDENTIAL_TOO_LARGE
} PgOAuthPamCredentialError;

/* Owns the credential bytes; never copied, logged or kept past a transaction. */
typedef struct PgOAuthPamCredential
{
	char	   *data;
	size_t		length;
} PgOAuthPamCredential;

/*
 * Acquire the credential with one fixed echo-off prompt. Initializes the
 * output to empty before any work. On any error the output stays empty and no
 * response memory remains allocated. The caller must call
 * pg_oauth_pam_credential_clear() after a successful acquisition.
 */
extern PgOAuthPamCredentialError pg_oauth_pam_credential_acquire(
																 pam_handle_t *pamh, size_t max_length, PgOAuthPamCredential *credential);

/* Zeroize (best effort) and free; safe on an already-empty credential. */
extern void pg_oauth_pam_credential_clear(PgOAuthPamCredential *credential);

/* Stable, non-sensitive diagnostic code. */
extern const char *pg_oauth_pam_credential_error_code(PgOAuthPamCredentialError error);

#endif
