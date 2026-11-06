#ifndef PG_OAUTH_PAM_POLICY_H
#define PG_OAUTH_PAM_POLICY_H

#include "postgres.h"

#include "policy.h"

/*
 * Policy for one PAM stack line, read only from module arguments (ADR 0008).
 * Parsing borrows pointers into argv, which libpam keeps stable for the call,
 * so the policy must not outlive the entry point that parsed it.
 */
#define PG_OAUTH_PAM_MAX_ARGUMENTS 32
#define PG_OAUTH_PAM_MAX_VALUE_LENGTH 4096

typedef enum PgOAuthPamPolicyError
{
	PG_OAUTH_PAM_POLICY_OK = 0,
	PG_OAUTH_PAM_POLICY_INVALID_ARGUMENT,
	PG_OAUTH_PAM_POLICY_TOO_MANY_ARGUMENTS,
	PG_OAUTH_PAM_POLICY_MALFORMED_ARGUMENT,
	PG_OAUTH_PAM_POLICY_UNKNOWN_ARGUMENT,
	PG_OAUTH_PAM_POLICY_DUPLICATE_ARGUMENT,
	PG_OAUTH_PAM_POLICY_VALUE_TOO_LONG,
	PG_OAUTH_PAM_POLICY_INVALID_NUMBER,
	PG_OAUTH_PAM_POLICY_INVALID_BOOLEAN,
	PG_OAUTH_PAM_POLICY_INVALID_POLICY,
	PG_OAUTH_PAM_POLICY_TOKEN_SIZE_TOO_LARGE
} PgOAuthPamPolicyError;

typedef struct PgOAuthPamPolicy
{
	PgOAuthPolicyConfig config;
	PgOAuthHbaPolicy hba;
	PgOAuthValidationPolicy validation;
	PgOAuthPolicyError build_error;
} PgOAuthPamPolicy;

/*
 * Parse and validate every argument. On any error the output holds no usable
 * policy (validation is zeroed) and the caller must deny. Unknown, duplicate,
 * malformed, overlong or out-of-range arguments are errors; nothing is
 * defaulted silently except the documented optional settings.
 */
extern PgOAuthPamPolicyError pg_oauth_pam_policy_parse(
													   int argc, const char **argv, PgOAuthPamPolicy *policy);

/* Stable, non-sensitive diagnostic code. */
extern const char *pg_oauth_pam_policy_error_code(PgOAuthPamPolicyError error);

#endif
