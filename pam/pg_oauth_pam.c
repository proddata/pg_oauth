/*
 * Linux-PAM entry points for JWT access-token authentication (ADR 0008).
 *
 * This revision acquires the credential and then denies unconditionally: token
 * validation is not wired in yet, so the module must never authenticate anyone.
 * Account management and credential setup also deny. Session and password
 * operations are intentionally not exported.
 */
#define _GNU_SOURCE
#include <security/pam_modules.h>

#include "pam_credential.h"

#define PG_OAUTH_PAM_DEFAULT_MAX_CREDENTIAL (16 * 1024)

int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	PgOAuthPamCredential credential = {NULL, 0};

	(void) flags;
	(void) argc;
	(void) argv;
	if (pg_oauth_pam_credential_acquire(pamh, PG_OAUTH_PAM_DEFAULT_MAX_CREDENTIAL,
										&credential) == PG_OAUTH_PAM_CREDENTIAL_OK)
		pg_oauth_pam_credential_clear(&credential);
	/* Fail closed until validation is implemented. */
	return PAM_AUTH_ERR;
}

int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	(void) pamh;
	(void) flags;
	(void) argc;
	(void) argv;
	return PAM_PERM_DENIED;
}

int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	(void) pamh;
	(void) argc;
	(void) argv;
	/* No OS credentials exist: deleting them is an idempotent no-op. */
	if (flags & PAM_DELETE_CRED)
		return PAM_SUCCESS;
	return PAM_CRED_ERR;
}
