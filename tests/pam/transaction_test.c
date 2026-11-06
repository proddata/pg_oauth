/* Unit tests for the PAM account-stage transaction record (ADR 0008). */
#include "postgres.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pam_transaction.h"

#define require(condition) \
	do { \
		if (!(condition)) \
		{ \
			/* postgres.h redirects fprintf to a symbol the test does not link. */ \
			fputs(__FILE__ ": requirement failed: " #condition "\n", stderr); \
			exit(EXIT_FAILURE); \
		} \
	} while (0)

#define NOW 1000000
#define EXPIRY 1000100
#define SKEW 60

static void
fill(uint8_t *digest, uint8_t value)
{
	memset(digest, value, PG_OAUTH_PAM_DIGEST_SIZE);
}

int
main(void)
{
	PgOAuthPamTransaction tx;
	uint8_t		digest[PG_OAUTH_PAM_DIGEST_SIZE];
	uint8_t		other[PG_OAUTH_PAM_DIGEST_SIZE];
	char		long_role[PG_OAUTH_PAM_ROLE_SIZE + 1];
	char		long_service[PG_OAUTH_PAM_SERVICE_SIZE + 1];

	fill(digest, 1);
	fill(other, 2);
	require(pg_oauth_pam_transaction_bind(&tx, "appuser", "svc", digest, EXPIRY, SKEW, 5000));

	/* Accepted, and repeatable: every call must satisfy every check. */
	require(pg_oauth_pam_transaction_check(&tx, "appuser", "svc", digest, NOW, 5000) == PG_OAUTH_PAM_ACCOUNT_OK);
	require(pg_oauth_pam_transaction_check(&tx, "appuser", "svc", digest, NOW, 5001) == PG_OAUTH_PAM_ACCOUNT_OK);

	/* Binding mismatches. */
	require(pg_oauth_pam_transaction_check(&tx, "other", "svc", digest, NOW, 5000) == PG_OAUTH_PAM_ACCOUNT_ROLE_MISMATCH);
	require(pg_oauth_pam_transaction_check(&tx, "appuse", "svc", digest, NOW, 5000) == PG_OAUTH_PAM_ACCOUNT_ROLE_MISMATCH);
	require(pg_oauth_pam_transaction_check(&tx, "appuser", "svc2", digest, NOW, 5000) == PG_OAUTH_PAM_ACCOUNT_SERVICE_MISMATCH);
	require(pg_oauth_pam_transaction_check(&tx, "appuser", "svc", other, NOW, 5000) == PG_OAUTH_PAM_ACCOUNT_POLICY_MISMATCH);

	/* Delay bound: exactly 5000 ms passes, one more fails. */
	require(pg_oauth_pam_transaction_check(&tx, "appuser", "svc", digest, NOW, 10000) == PG_OAUTH_PAM_ACCOUNT_OK);
	require(pg_oauth_pam_transaction_check(&tx, "appuser", "svc", digest, NOW, 10001) == PG_OAUTH_PAM_ACCOUNT_DELAY_EXCEEDED);
	/* A monotonic clock that moved backwards is untrustworthy. */
	require(pg_oauth_pam_transaction_check(&tx, "appuser", "svc", digest, NOW, 4999) == PG_OAUTH_PAM_ACCOUNT_CLOCK_INVALID);
	require(pg_oauth_pam_transaction_check(&tx, "appuser", "svc", digest, -1, 5000) == PG_OAUTH_PAM_ACCOUNT_CLOCK_INVALID);

	/* Expiry uses the shared predicate: expired once now >= exp and elapsed >= skew. */
	require(pg_oauth_pam_transaction_check(&tx, "appuser", "svc", digest, EXPIRY, 5000) == PG_OAUTH_PAM_ACCOUNT_OK);
	require(pg_oauth_pam_transaction_check(&tx, "appuser", "svc", digest, EXPIRY + SKEW - 1, 5000) == PG_OAUTH_PAM_ACCOUNT_OK);
	require(pg_oauth_pam_transaction_check(&tx, "appuser", "svc", digest, EXPIRY + SKEW, 5000) == PG_OAUTH_PAM_ACCOUNT_EXPIRED);
	require(pg_oauth_pam_transaction_check(&tx, "appuser", "svc", digest, EXPIRY + SKEW + 1, 5000) == PG_OAUTH_PAM_ACCOUNT_EXPIRED);
	/* Zero skew: expiry is immediate at exp. */
	require(pg_oauth_pam_transaction_bind(&tx, "appuser", "svc", digest, EXPIRY, 0, 5000));
	require(pg_oauth_pam_transaction_check(&tx, "appuser", "svc", digest, EXPIRY - 1, 5000) == PG_OAUTH_PAM_ACCOUNT_OK);
	require(pg_oauth_pam_transaction_check(&tx, "appuser", "svc", digest, EXPIRY, 5000) == PG_OAUTH_PAM_ACCOUNT_EXPIRED);

	/* Invalid bind inputs leave a zeroed record that can never pass. */
	memset(long_role, 'r', sizeof(long_role));
	long_role[PG_OAUTH_PAM_ROLE_SIZE] = '\0';
	memset(long_service, 's', sizeof(long_service));
	long_service[PG_OAUTH_PAM_SERVICE_SIZE] = '\0';
	require(!pg_oauth_pam_transaction_bind(&tx, long_role, "svc", digest, EXPIRY, SKEW, 0));
	require(pg_oauth_pam_transaction_check(&tx, long_role, "svc", digest, NOW, 0) == PG_OAUTH_PAM_ACCOUNT_INVALID_ARGUMENT);
	require(!pg_oauth_pam_transaction_bind(&tx, "appuser", long_service, digest, EXPIRY, SKEW, 0));
	require(!pg_oauth_pam_transaction_bind(&tx, "", "svc", digest, EXPIRY, SKEW, 0));
	require(!pg_oauth_pam_transaction_bind(&tx, "appuser", "", digest, EXPIRY, SKEW, 0));
	require(!pg_oauth_pam_transaction_bind(&tx, "appuser", "svc", digest, 0, SKEW, 0));
	require(!pg_oauth_pam_transaction_bind(&tx, "appuser", "svc", digest, EXPIRY, SKEW, -1));
	require(!pg_oauth_pam_transaction_bind(&tx, NULL, "svc", digest, EXPIRY, SKEW, 0));
	require(!pg_oauth_pam_transaction_bind(NULL, "appuser", "svc", digest, EXPIRY, SKEW, 0));
	require(pg_oauth_pam_transaction_check(NULL, "appuser", "svc", digest, NOW, 0) == PG_OAUTH_PAM_ACCOUNT_INVALID_ARGUMENT);
	require(pg_oauth_pam_transaction_check(&tx, NULL, "svc", digest, NOW, 0) == PG_OAUTH_PAM_ACCOUNT_INVALID_ARGUMENT);

	/* Maximum-length role and service fit; the record keeps no other data. */
	long_role[PG_OAUTH_PAM_ROLE_SIZE - 1] = '\0';
	long_service[PG_OAUTH_PAM_SERVICE_SIZE - 1] = '\0';
	require(pg_oauth_pam_transaction_bind(&tx, long_role, long_service, digest, EXPIRY, SKEW, 0));
	require(pg_oauth_pam_transaction_check(&tx, long_role, long_service, digest, NOW, 0) == PG_OAUTH_PAM_ACCOUNT_OK);

	require(strcmp(pg_oauth_pam_account_error_code(PG_OAUTH_PAM_ACCOUNT_EXPIRED), "account_expired") == 0);
	require(strcmp(pg_oauth_pam_account_error_code((PgOAuthPamAccountResult) 99), "account_internal_error") == 0);
	return EXIT_SUCCESS;
}
