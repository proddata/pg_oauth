#ifndef PG_OAUTH_PAM_TRANSACTION_H
#define PG_OAUTH_PAM_TRANSACTION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * State published only after complete token validation and exact requested-role
 * authorization (ADR 0008). It holds no token, claim set or identity beyond the
 * role that PostgreSQL itself supplied.
 */
#define PG_OAUTH_PAM_ROLE_SIZE 64
#define PG_OAUTH_PAM_SERVICE_SIZE 128
#define PG_OAUTH_PAM_DIGEST_SIZE 32

/* Maximum time between validation completion and the account check. */
#define PG_OAUTH_PAM_MAX_ACCOUNT_DELAY_MS 5000

typedef struct PgOAuthPamTransaction
{
	char		role[PG_OAUTH_PAM_ROLE_SIZE];
	char		service[PG_OAUTH_PAM_SERVICE_SIZE];
	uint8_t		policy_digest[PG_OAUTH_PAM_DIGEST_SIZE];
	int64_t		expires_at;
	uint32_t	skew_seconds;
	int64_t		completed_monotonic_ms;
} PgOAuthPamTransaction;

typedef enum PgOAuthPamAccountResult
{
	PG_OAUTH_PAM_ACCOUNT_OK = 0,
	PG_OAUTH_PAM_ACCOUNT_INVALID_ARGUMENT,
	PG_OAUTH_PAM_ACCOUNT_ROLE_MISMATCH,
	PG_OAUTH_PAM_ACCOUNT_SERVICE_MISMATCH,
	PG_OAUTH_PAM_ACCOUNT_POLICY_MISMATCH,
	PG_OAUTH_PAM_ACCOUNT_CLOCK_INVALID,
	PG_OAUTH_PAM_ACCOUNT_DELAY_EXCEEDED,
	PG_OAUTH_PAM_ACCOUNT_EXPIRED
} PgOAuthPamAccountResult;

/* Returns false (leaving the output zeroed) if role/service do not fit. */
extern bool pg_oauth_pam_transaction_bind(
										  PgOAuthPamTransaction *transaction, const char *role,
										  const char *service, const uint8_t *policy_digest,
										  int64_t expires_at, uint32_t skew_seconds,
										  int64_t completed_monotonic_ms);

/*
 * Recheck at the account stage with a fresh wall and monotonic clock. Repeated
 * calls are allowed and each must satisfy every check; there is no second
 * expiry grace beyond the policy's skew.
 */
extern PgOAuthPamAccountResult pg_oauth_pam_transaction_check(
															  const PgOAuthPamTransaction *transaction, const char *role,
															  const char *service, const uint8_t *policy_digest,
															  int64_t wall_now, int64_t monotonic_now_ms);

extern const char *pg_oauth_pam_account_error_code(PgOAuthPamAccountResult result);

#endif
