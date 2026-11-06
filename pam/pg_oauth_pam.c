/*
 * Linux-PAM entry points for JWT access-token authentication (ADR 0008).
 *
 * This revision acquires the credential and then denies unconditionally: token
 * validation is not wired in yet, so the module must never authenticate anyone.
 * Account management and credential setup also deny. Session and password
 * operations are intentionally not exported.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <security/pam_modules.h>

#include "pam_credential.h"
#include "pam_policy.h"

/* PostgreSQL build flags hide symbols by default; PAM must find these. */
#define PG_OAUTH_PAM_EXPORT __attribute__((visibility("default")))

PG_OAUTH_PAM_EXPORT int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	PgOAuthPamCredential credential = {NULL, 0};
	PgOAuthPamPolicy policy;

	(void) flags;
	/* An invalid or incomplete policy denies before any credential is read. */
	if (pg_oauth_pam_policy_parse(argc, argv, &policy) != PG_OAUTH_PAM_POLICY_OK)
		return PAM_AUTH_ERR;
	if (pg_oauth_pam_credential_acquire(pamh, (size_t) policy.validation.max_token_size,
										&credential) == PG_OAUTH_PAM_CREDENTIAL_OK)
		pg_oauth_pam_credential_clear(&credential);
	/* Fail closed until validation is implemented. */
	return PAM_AUTH_ERR;
}

PG_OAUTH_PAM_EXPORT int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	(void) pamh;
	(void) flags;
	(void) argc;
	(void) argv;
	return PAM_PERM_DENIED;
}

PG_OAUTH_PAM_EXPORT int
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
