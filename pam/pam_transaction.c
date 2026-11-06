#include "postgres.h"

#include <string.h>

#include "claims.h"
#include "pam_transaction.h"

bool
pg_oauth_pam_transaction_bind(PgOAuthPamTransaction *transaction, const char *role,
							  const char *service, const uint8_t *policy_digest,
							  int64_t expires_at, uint32_t skew_seconds,
							  int64_t completed_monotonic_ms)
{
	size_t		role_length;
	size_t		service_length;

	if (transaction == NULL)
		return false;
	memset(transaction, 0, sizeof(*transaction));
	if (role == NULL || service == NULL || policy_digest == NULL ||
		expires_at <= 0 || completed_monotonic_ms < 0)
		return false;
	role_length = strnlen(role, PG_OAUTH_PAM_ROLE_SIZE);
	service_length = strnlen(service, PG_OAUTH_PAM_SERVICE_SIZE);
	if (role_length == 0 || role_length >= PG_OAUTH_PAM_ROLE_SIZE ||
		service_length == 0 || service_length >= PG_OAUTH_PAM_SERVICE_SIZE)
		return false;
	memcpy(transaction->role, role, role_length);
	memcpy(transaction->service, service, service_length);
	memcpy(transaction->policy_digest, policy_digest, PG_OAUTH_PAM_DIGEST_SIZE);
	transaction->expires_at = expires_at;
	transaction->skew_seconds = skew_seconds;
	transaction->completed_monotonic_ms = completed_monotonic_ms;
	return true;
}

PgOAuthPamAccountResult
pg_oauth_pam_transaction_check(const PgOAuthPamTransaction *transaction,
							   const char *role, const char *service,
							   const uint8_t *policy_digest, int64_t wall_now,
							   int64_t monotonic_now_ms)
{
	if (transaction == NULL || role == NULL || service == NULL ||
		policy_digest == NULL || transaction->role[0] == '\0')
		return PG_OAUTH_PAM_ACCOUNT_INVALID_ARGUMENT;
	if (strcmp(transaction->role, role) != 0)
		return PG_OAUTH_PAM_ACCOUNT_ROLE_MISMATCH;
	if (strcmp(transaction->service, service) != 0)
		return PG_OAUTH_PAM_ACCOUNT_SERVICE_MISMATCH;
	if (memcmp(transaction->policy_digest, policy_digest, PG_OAUTH_PAM_DIGEST_SIZE) != 0)
		return PG_OAUTH_PAM_ACCOUNT_POLICY_MISMATCH;
	if (wall_now < 0 || monotonic_now_ms < transaction->completed_monotonic_ms)
		return PG_OAUTH_PAM_ACCOUNT_CLOCK_INVALID;
	if (monotonic_now_ms - transaction->completed_monotonic_ms >
		PG_OAUTH_PAM_MAX_ACCOUNT_DELAY_MS)
		return PG_OAUTH_PAM_ACCOUNT_DELAY_EXCEEDED;
	if (pg_oauth_claims_expired(wall_now, transaction->expires_at,
								transaction->skew_seconds))
		return PG_OAUTH_PAM_ACCOUNT_EXPIRED;
	return PG_OAUTH_PAM_ACCOUNT_OK;
}

const char *
pg_oauth_pam_account_error_code(PgOAuthPamAccountResult result)
{
	switch (result)
	{
		case PG_OAUTH_PAM_ACCOUNT_OK:
			return "ok";
		case PG_OAUTH_PAM_ACCOUNT_INVALID_ARGUMENT:
			return "account_invalid_argument";
		case PG_OAUTH_PAM_ACCOUNT_ROLE_MISMATCH:
			return "account_role_mismatch";
		case PG_OAUTH_PAM_ACCOUNT_SERVICE_MISMATCH:
			return "account_service_mismatch";
		case PG_OAUTH_PAM_ACCOUNT_POLICY_MISMATCH:
			return "account_policy_mismatch";
		case PG_OAUTH_PAM_ACCOUNT_CLOCK_INVALID:
			return "account_clock_invalid";
		case PG_OAUTH_PAM_ACCOUNT_DELAY_EXCEEDED:
			return "account_delay_exceeded";
		case PG_OAUTH_PAM_ACCOUNT_EXPIRED:
			return "account_expired";
	}
	return "account_internal_error";
}
