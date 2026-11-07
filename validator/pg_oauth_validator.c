/*-------------------------------------------------------------------------
 *
 * pg_oauth_validator.c
 *    OAuth access-token validator for PostgreSQL 18 and 19.
 *
 * The callback begins denied and authorizes only after the complete
 * configured validation pipeline succeeds.
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include <stdlib.h>
#include <time.h>

#include "fmgr.h"
#include "libpq/oauth.h"
#include "miscadmin.h"

#include "config.h"
#include "hba_policy.h"
#include "policy.h"
#include "shared_cache.h"
#include "validator.h"
#include "validator_policy.h"

PG_MODULE_MAGIC;

#if PG_VERSION_NUM < 180000 || PG_VERSION_NUM >= 200000
#error "pg_oauth_validator currently supports PostgreSQL 18 and 19 only"
#endif

static bool pg_oauth_monotonic_ms(int64 *value);
static void pg_oauth_log_configuration_failure(const char *code);
static bool pg_oauth_cancel_requested(void *context);

static bool pg_oauth_validator_validate(const ValidatorModuleState *state,
										const char *token, const char *role,
										ValidatorModuleResult *result);
#if PG_VERSION_NUM >= 190000
static void pg_oauth_validator_startup(ValidatorModuleState *state);
#endif

static const OAuthValidatorCallbacks validator_callbacks = {
	.magic = PG_OAUTH_VALIDATOR_MAGIC,
#if PG_VERSION_NUM >= 190000
	.startup_cb = pg_oauth_validator_startup,
#else
	.startup_cb = NULL,
#endif
	.shutdown_cb = NULL,
	.validate_cb = pg_oauth_validator_validate,
};

#if PG_VERSION_NUM >= 190000
static void
pg_oauth_validator_startup(ValidatorModuleState *state)
{
	pg_oauth_hba_policy_register_options(state);
}
#endif

/*
 * Returning true tells PostgreSQL that the module made an authorization
 * decision; result->authorized distinguishes validation rejection from
 * success. Returning false reports an internal validator error. See
 * PostgreSQL 18/19, "OAuth Validator Callbacks", section 50.3.2.
 */
static bool
pg_oauth_validator_validate(const ValidatorModuleState *state,
							const char *token, const char *role,
							ValidatorModuleResult *result)
{
	PgOAuthPolicyConfig config;
	PgOAuthHbaPolicy hba_policy;
	PgOAuthValidationPolicy policy;
	PgOAuthPolicyError policy_error;
	PgOAuthValidatorPolicy validator_policy;
	PgOAuthIssuerKeyCachePolicy cache_policy;
	PgOAuthValidatorResult validation;
	PgOAuthCacheIo cache_io;
	char		metadata_url[PG_OAUTH_METADATA_URL_BUFFER];
	char	   *metadata_host = NULL;
	size_t		token_length;
	int64		monotonic_ms;
	time_t		wall_time;
	PgOAuthValidatorError validation_error;

	/* Initialize every output explicitly before any validation work. */
	result->authorized = false;
	result->authn_id = NULL;
#if PG_VERSION_NUM >= 190000
	result->error_detail = NULL;
#endif

	/*
	 * Acquire policy only from the matched, administrator-controlled HBA
	 * rule. Trust inputs come only from the matched HBA rule and
	 * administrator GUCs.
	 */
	if (!pg_oauth_hba_policy_read(state, &hba_policy))
	{
		pg_oauth_log_configuration_failure("hba_rule_unreadable");
		return false;
	}
	pg_oauth_config_snapshot(&config);
	policy_error = pg_oauth_policy_build(&config, &hba_policy, &policy);
	if (policy_error != PG_OAUTH_POLICY_OK)
	{
		pg_oauth_log_configuration_failure(pg_oauth_policy_error_code(policy_error));
		return false;
	}
	if (!pg_oauth_shared_cache_configure_capacity(
												  pg_oauth_config_cache_max_entries()) ||
		!pg_oauth_shared_cache_io(&cache_io))
	{
		pg_oauth_log_configuration_failure("shared_cache_unavailable");
		return false;
	}
	if (!pg_oauth_monotonic_ms(&monotonic_ms))
	{
		pg_oauth_log_configuration_failure("clock_unavailable");
		return false;
	}
	if (!pg_oauth_metadata_url_build(policy.issuer, metadata_url,
									 sizeof(metadata_url)) ||
		pg_oauth_http_url_host(metadata_url, PG_OAUTH_MAX_URL_SIZE,
							   policy.allow_insecure_http, &metadata_host) != PG_OAUTH_HTTP_OK)
	{
		pg_oauth_log_configuration_failure("metadata_url_invalid");
		goto internal_failure;
	}

	wall_time = time(NULL);
	if (wall_time < 0)
	{
		pg_oauth_log_configuration_failure("clock_unavailable");
		goto internal_failure;
	}
	pg_oauth_validator_policy_assemble(&policy, metadata_host, role,
									   (int64) wall_time,
									   pg_oauth_cancel_requested,
									   &validator_policy);
	pg_oauth_cache_policy_assemble(&policy, &cache_io, &cache_policy);
	if (token == NULL)
		goto rejected;
	for (token_length = 0;
		 token_length <= (size_t) policy.max_token_size && token[token_length];
		 token_length++)
		;
	if (token_length == 0 || token_length > (size_t) policy.max_token_size)
		goto rejected;
	memset(&validation, 0, sizeof(validation));
	validation_error = pg_oauth_validate_access_token_cached(token,
															 token_length, metadata_url, &validator_policy, &cache_policy,
															 monotonic_ms, (int64) wall_time, &validation);
	if (InterruptPending)
	{
		/* Leave no transport, cache refresh, or identity allocation behind. */
		pg_oauth_validator_result_clear(&validation);
		free(metadata_host);
		CHECK_FOR_INTERRUPTS();
		return false;
	}
	if (validation_error != PG_OAUTH_VALIDATOR_OK)
	{
		ereport(DEBUG1,
				(errmsg_internal("OAuth access token rejected"),
				 errdetail_internal("validator=%s envelope=%s issuer_key=%s http=%s metadata=%s jwks=%s signature=%s claims=%s identity=%s",
									pg_oauth_validator_error_code(validation_error),
									pg_oauth_jwt_envelope_error_code(validation.envelope_error),
									pg_oauth_issuer_key_error_code(validation.issuer_key_error),
									pg_oauth_http_error_code(validation.http_error),
									pg_oauth_metadata_error_code(validation.metadata_error),
									pg_oauth_jwks_error_code(validation.jwks_error),
									pg_oauth_signature_error_code(validation.signature_error),
									pg_oauth_claims_error_code(validation.claims_error),
									pg_oauth_identity_error_code(validation.identity_error))));
		pg_oauth_validator_result_clear(&validation);
		goto rejected;
	}
	result->authn_id = pstrdup(validation.identity.value);
	result->authorized = true;
	pg_oauth_validator_result_clear(&validation);
	free(metadata_host);
	return true;

rejected:
#if PG_VERSION_NUM >= 190000
	result->error_detail = pstrdup("OAuth access token validation failed");
#endif
	free(metadata_host);
	return true;

internal_failure:
	free(metadata_host);
	return false;
}

/*
 * Every login through a rejected configuration is denied, so say why. Only a
 * stable code is logged: never a token, a claim, or a configuration value.
 */
static void
pg_oauth_log_configuration_failure(const char *code)
{
	ereport(LOG,
			(errmsg("OAuth validator configuration rejected"),
			 errdetail_internal("code=%s; connections through this rule are denied",
								code)));
}

static bool
pg_oauth_cancel_requested(void *context)
{
	(void) context;
	return InterruptPending;
}

static bool
pg_oauth_monotonic_ms(int64 *value)
{
	struct timespec now;

	if (value == NULL || clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
		now.tv_sec < 0 || now.tv_sec > INT64_MAX / 1000)
		return false;
	*value = (int64) now.tv_sec * 1000 + now.tv_nsec / 1000000;
	return true;
}

PGDLLEXPORT const OAuthValidatorCallbacks *
_PG_oauth_validator_module_init(void)
{
	return &validator_callbacks;
}
