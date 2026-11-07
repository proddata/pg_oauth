/*
 * Fuzz the PAM stack-argument parser (ADR 0008). The input is split on newlines
 * into at most 40 arguments (above the 32-argument limit so that boundary is
 * reachable). Besides memory safety, the documented contract is checked: any
 * error leaves no usable policy, and any accepted policy is bounded, complete
 * and has a stable digest.
 */
#include "postgres.h"

#include <stdlib.h>
#include <string.h>

#include "pam_credential.h"
#include "pam_policy.h"

#define FUZZ_MAX_INPUT 16384
#define FUZZ_MAX_ARGS 40

#define REQUIRE(condition) \
	do { \
		if (!(condition)) \
			abort(); \
	} while (0)

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const PgOAuthValidationPolicy zero;
	char		buffer[FUZZ_MAX_INPUT + 1];
	const char *argv[FUZZ_MAX_ARGS];
	PgOAuthPamPolicy policy;
	PgOAuthPamPolicy again;
	uint8_t		first[32];
	uint8_t		second[32];
	int			argc = 0;
	char	   *cursor;

	if (size == 0 || size > FUZZ_MAX_INPUT)
		return 0;
	memcpy(buffer, data, size);
	buffer[size] = '\0';

	for (cursor = buffer; argc < FUZZ_MAX_ARGS;)
	{
		argv[argc++] = cursor;
		cursor = strchr(cursor, '\n');
		if (cursor == NULL)
			break;
		*cursor++ = '\0';
	}

	memset(&policy, 0x5a, sizeof(policy));
	if (pg_oauth_pam_policy_parse(argc, argv, &policy) != PG_OAUTH_PAM_POLICY_OK)
	{
		REQUIRE(memcmp(&policy.validation, &zero, sizeof(zero)) == 0);
		return 0;
	}

	REQUIRE(policy.validation.issuer != NULL && policy.validation.issuer[0] != '\0');
	REQUIRE(policy.validation.audiences != NULL && policy.validation.audiences[0] != '\0');
	REQUIRE(policy.validation.required_scopes != NULL
			&& policy.validation.required_scopes[0] != '\0');
	REQUIRE(policy.validation.max_token_size >= 1
			&& policy.validation.max_token_size <= PG_OAUTH_PAM_MAX_CREDENTIAL);
	REQUIRE(policy.validation.clock_skew_ms >= 0 && policy.validation.clock_skew_ms <= 300000);
	REQUIRE(policy.hba.delegate_ident_mapping
			== (policy.validation.role_claim != NULL && policy.validation.role_claim[0] != '\0'));

	REQUIRE(pg_oauth_pam_policy_digest(&policy, first));
	memset(&again, 0x5a, sizeof(again));
	REQUIRE(pg_oauth_pam_policy_parse(argc, argv, &again) == PG_OAUTH_PAM_POLICY_OK);
	REQUIRE(pg_oauth_pam_policy_digest(&again, second));
	REQUIRE(memcmp(first, second, sizeof(first)) == 0);
	return 0;
}
