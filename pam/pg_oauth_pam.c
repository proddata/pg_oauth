/*
 * Linux-PAM entry points for JWT access-token authentication (ADR 0008).
 *
 * pam_sm_authenticate parses the stack-argument policy, reads the credential,
 * validates it with the same pipeline as the OAuth validator, and requires the
 * validated identity to equal the requested database role exactly. It then
 * publishes a bounded transaction record. pam_sm_acct_mgmt succeeds only for a
 * matching, unexpired record. Every other path denies. Session and password
 * operations are intentionally not exported.
 *
 * This revision validates without a cache: each authentication fetches
 * discovery metadata and the JWKS. That is experimental only (ADR 0009).
 */
#include "postgres.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include "http_transport.h"
#include "pam_credential.h"
#include "pam_policy.h"
#include "pam_transaction.h"
#include "validator.h"
#include "validator_policy.h"

/* PostgreSQL build flags hide symbols by default; PAM must find these. */
#define PG_OAUTH_PAM_EXPORT __attribute__((visibility("default")))

static const char transaction_name[] = "pg_oauth_pam_transaction_v1";

static void
clear_transaction(pam_handle_t *pamh, void *data, int status)
{
	(void) pamh;
	(void) status;
	if (data != NULL)
	{
		explicit_bzero(data, sizeof(PgOAuthPamTransaction));
		free(data);
	}
}

static bool
monotonic_ms(int64_t *value)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0 ||
		now.tv_sec > INT64_MAX / 1000)
		return false;
	*value = (int64_t) now.tv_sec * 1000 + now.tv_nsec / 1000000;
	return true;
}

/* Both items are borrowed from PAM and must not be freed or retained. */
static bool
read_items(pam_handle_t *pamh, const char **user, const char **service)
{
	const void *item = NULL;

	if (pam_get_item(pamh, PAM_USER, &item) != PAM_SUCCESS || item == NULL ||
		((const char *) item)[0] == '\0')
		return false;
	*user = item;
	item = NULL;
	if (pam_get_item(pamh, PAM_SERVICE, &item) != PAM_SUCCESS || item == NULL ||
		((const char *) item)[0] == '\0')
		return false;
	*service = item;
	return true;
}

/*
 * Authentication is bounded by the transport timeouts; polling PostgreSQL's
 * interrupt flag from a PAM module is a separate, later change.
 */
static bool
cancel_requested(void *context)
{
	(void) context;
	return false;
}

PG_OAUTH_PAM_EXPORT int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	PgOAuthPamPolicy policy;
	PgOAuthPamCredential credential = {NULL, 0};
	PgOAuthValidatorPolicy validator_policy;
	PgOAuthValidatorResult result;
	PgOAuthPamTransaction *transaction = NULL;
	PgOAuthValidatorError error;
	char		metadata_url[PG_OAUTH_METADATA_URL_BUFFER];
	char	   *metadata_host = NULL;
	const char *user;
	const char *service;
	uint8_t		digest[PG_OAUTH_PAM_DIGEST_SIZE];
	int64_t		completed_ms;
	time_t		wall_time;
	int			outcome = PAM_AUTH_ERR;

	(void) flags;
	memset(&result, 0, sizeof(result));

	/* Old state must never survive into a new authentication. */
	if (pam_set_data(pamh, transaction_name, NULL, clear_transaction) != PAM_SUCCESS)
		return PAM_AUTH_ERR;
	/* An invalid or incomplete policy denies before any credential is read. */
	if (pg_oauth_pam_policy_parse(argc, argv, &policy) != PG_OAUTH_PAM_POLICY_OK ||
		!pg_oauth_pam_policy_digest(&policy, digest) ||
		!read_items(pamh, &user, &service) ||
		!pg_oauth_metadata_url_build(policy.validation.issuer, metadata_url,
									 sizeof(metadata_url)) ||
		pg_oauth_http_url_host(metadata_url, PG_OAUTH_MAX_URL_SIZE,
							   policy.validation.allow_insecure_http,
							   &metadata_host) != PG_OAUTH_HTTP_OK)
		goto done;
	if (pg_oauth_pam_credential_acquire(pamh, (size_t) policy.validation.max_token_size,
										&credential) != PG_OAUTH_PAM_CREDENTIAL_OK)
		goto done;
	wall_time = time(NULL);
	if (wall_time < 0)
		goto done;
	pg_oauth_validator_policy_assemble(&policy.validation, metadata_host, user,
									   (int64_t) wall_time, cancel_requested,
									   &validator_policy);
	error = pg_oauth_validate_access_token(credential.data, credential.length,
										   metadata_url, &validator_policy, &result);
	/* The credential is no longer needed once validation has returned. */
	pg_oauth_pam_credential_clear(&credential);
	if (error != PG_OAUTH_VALIDATOR_OK)
	{
		pam_syslog(pamh, LOG_WARNING, "token rejected: validator=%s",
				   pg_oauth_validator_error_code(error));
		goto done;
	}
	/* Initial PAM authorization: exact equality with the requested role. */
	if (strcmp(result.identity.value, user) != 0)
	{
		pam_syslog(pamh, LOG_WARNING, "token rejected: role_mismatch");
		goto done;
	}
	if (!monotonic_ms(&completed_ms))
		goto done;
	transaction = calloc(1, sizeof(*transaction));
	if (transaction == NULL ||
		!pg_oauth_pam_transaction_bind(transaction, user, service, digest,
									   result.expires_at,
									   (uint32_t) (policy.validation.clock_skew_ms / 1000),
									   completed_ms))
		goto done;
	if (pam_set_data(pamh, transaction_name, transaction, clear_transaction) != PAM_SUCCESS)
		goto done;
	transaction = NULL;			/* owned by PAM now */
	outcome = PAM_SUCCESS;

done:
	if (transaction != NULL)
		clear_transaction(pamh, transaction, 0);
	pg_oauth_pam_credential_clear(&credential);
	pg_oauth_validator_result_clear(&result);
	free(metadata_host);
	explicit_bzero(digest, sizeof(digest));
	return outcome;
}

PG_OAUTH_PAM_EXPORT int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	PgOAuthPamPolicy policy;
	PgOAuthPamAccountResult result;
	const void *data = NULL;
	const char *user;
	const char *service;
	uint8_t		digest[PG_OAUTH_PAM_DIGEST_SIZE];
	int64_t		monotonic_now;
	time_t		wall_time;

	(void) flags;
	/* No authentication state means no account success, whatever else is true. */
	if (pam_get_data(pamh, transaction_name, &data) != PAM_SUCCESS || data == NULL ||
		pg_oauth_pam_policy_parse(argc, argv, &policy) != PG_OAUTH_PAM_POLICY_OK ||
		!pg_oauth_pam_policy_digest(&policy, digest) ||
		!read_items(pamh, &user, &service) ||
		!monotonic_ms(&monotonic_now) || (wall_time = time(NULL)) < 0)
		return PAM_PERM_DENIED;
	result = pg_oauth_pam_transaction_check(data, user, service, digest,
											(int64_t) wall_time, monotonic_now);
	if (result != PG_OAUTH_PAM_ACCOUNT_OK)
	{
		pam_syslog(pamh, LOG_WARNING, "account denied: %s",
				   pg_oauth_pam_account_error_code(result));
		return PAM_PERM_DENIED;
	}
	return PAM_SUCCESS;
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
