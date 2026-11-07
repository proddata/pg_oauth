/*
 * Verify the behavior of the actual dynamically loaded bootstrap module.
 */

#include "postgres.h"
#include "miscadmin.h"

#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libpq/hba.h"
#include "libpq/libpq-be.h"
#include "libpq/oauth.h"
#include "storage/condition_variable.h"
#include "storage/dsm_registry.h"
#include "storage/lwlock.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include "utils/guc.h"
#pragma GCC diagnostic pop

/* postgres.h redirects fprintf to a backend helper unavailable to this test. */
#undef fprintf

PGDLLEXPORT Port *MyProcPort;
PGDLLEXPORT volatile sig_atomic_t InterruptPending;
static int	registered_gucs;
static bool cache_gucs_have_expected_contract;
static int	cache_gucs_checked;
static bool token_type_allowlist_default_checked;
static bool missing_token_type_default_checked;

PGDLLEXPORT void
ProcessInterrupts(void)
{
	/* This loader test has no PostgreSQL signal handlers. */
}

PGDLLEXPORT const char *
GetConfigOption(const char *name, bool missing_ok, bool restrict_privileged)
{
	(void) name;
	(void) missing_ok;
	(void) restrict_privileged;
	return NULL;
}

PGDLLEXPORT bool
errstart(int elevel, const char *domain)
{
	(void) elevel;
	(void) domain;
	return true;
}

PGDLLEXPORT bool
errstart_cold(int elevel, const char *domain)
{
	return errstart(elevel, domain);
}

PGDLLEXPORT void
errfinish(const char *filename, int lineno, const char *funcname)
{
	(void) filename;
	(void) lineno;
	(void) funcname;
}

PGDLLEXPORT int
errmsg_internal(const char *fmt, ...)
{
	(void) fmt;
	return 0;
}

PGDLLEXPORT int
errmsg(const char *fmt, ...)
{
	(void) fmt;
	return 0;
}

PGDLLEXPORT int
errdetail_internal(const char *fmt, ...)
{
	(void) fmt;
	return 0;
}

PGDLLEXPORT void
pfree(void *pointer)
{
	free(pointer);
}

PGDLLEXPORT char *
pstrdup(const char *value)
{
	size_t		length = strlen(value);
	char	   *copy = malloc(length + 1);

	if (copy != NULL)
		memcpy(copy, value, length + 1);
	return copy;
}

PGDLLEXPORT char *
psprintf(const char *fmt, ...)
{
	va_list		arguments;
	char	   *result = NULL;

	va_start(arguments, fmt);
	if (vasprintf(&result, fmt, arguments) < 0)
		result = NULL;
	va_end(arguments);
	return result;
}

#if PG_VERSION_NUM >= 190000
PGDLLEXPORT int
LWLockNewTrancheId(const char *name)
{
	(void) name;
	return 1;
}
#else
PGDLLEXPORT int
LWLockNewTrancheId(void)
{
	return 1;
}

PGDLLEXPORT void
LWLockRegisterTranche(int tranche_id, const char *tranche_name)
{
	(void) tranche_id;
	(void) tranche_name;
}
#endif

PGDLLEXPORT void
LWLockInitialize(LWLock *lock, int tranche_id)
{
	(void) lock;
	(void) tranche_id;
}

PGDLLEXPORT bool
LWLockAcquire(LWLock *lock, LWLockMode mode)
{
	(void) lock;
	(void) mode;
	return true;
}

PGDLLEXPORT void
LWLockRelease(LWLock *lock)
{
	(void) lock;
}

PGDLLEXPORT void
ConditionVariableInit(ConditionVariable *cv)
{
	(void) cv;
}

PGDLLEXPORT void
ConditionVariablePrepareToSleep(ConditionVariable *cv)
{
	(void) cv;
}

PGDLLEXPORT bool
ConditionVariableTimedSleep(ConditionVariable *cv, long timeout,
							uint32 wait_event_info)
{
	(void) cv;
	(void) timeout;
	(void) wait_event_info;
	return true;
}

PGDLLEXPORT bool
ConditionVariableCancelSleep(void)
{
	return false;
}

PGDLLEXPORT void
ConditionVariableBroadcast(ConditionVariable *cv)
{
	(void) cv;
}

#if PG_VERSION_NUM >= 190000
PGDLLEXPORT void *
GetNamedDSMSegment(const char *name, size_t size,
				   void (*init_callback) (void *, void *), bool *found,
				   void *argument)
{
	(void) name;
	(void) size;
	(void) init_callback;
	(void) argument;
	(void) found;
	return NULL;
}
#else
PGDLLEXPORT void *
GetNamedDSMSegment(const char *name, size_t size,
				   void (*init_callback) (void *), bool *found)
{
	(void) name;
	(void) size;
	(void) init_callback;
	(void) found;
	return NULL;
}
#endif

PGDLLEXPORT void
MarkGUCPrefixReserved(const char *className)
{
	(void) className;
}

PGDLLEXPORT void
DefineCustomStringVariable(const char *name, const char *short_desc,
						   const char *long_desc, char **value_address,
						   const char *boot_value, GucContext context, int flags,
						   GucStringCheckHook check_hook,
						   GucStringAssignHook assign_hook,
						   GucShowHook show_hook)
{
	(void) name;
	(void) short_desc;
	(void) long_desc;
	(void) context;
	(void) flags;
	(void) check_hook;
	(void) assign_hook;
	(void) show_hook;

	*value_address = (char *) boot_value;
	registered_gucs++;
	if (strcmp(name, "pg_oauth_validator.allowed_token_types") == 0 &&
		strcmp(boot_value, "at+jwt,application/at+jwt") == 0 &&
		context == PGC_SIGHUP)
		token_type_allowlist_default_checked = true;
}

PGDLLEXPORT void
DefineCustomIntVariable(const char *name, const char *short_desc,
						const char *long_desc, int *value_address,
						int boot_value, int min_value, int max_value,
						GucContext context, int flags,
						GucIntCheckHook check_hook,
						GucIntAssignHook assign_hook, GucShowHook show_hook)
{
	(void) short_desc;
	(void) long_desc;
	(void) min_value;
	(void) max_value;
	(void) context;
	(void) flags;
	(void) check_hook;
	(void) assign_hook;
	(void) show_hook;

	*value_address = boot_value;
	registered_gucs++;
	if ((strcmp(name, "pg_oauth_validator.metadata_default_ttl") == 0 ||
		 strcmp(name, "pg_oauth_validator.jwks_default_ttl") == 0) &&
		boot_value == 300000 && min_value == 1000 && max_value == 3600000 &&
		context == PGC_SIGHUP && flags == GUC_UNIT_MS)
		cache_gucs_checked++;
	else if (strcmp(name, "pg_oauth_validator.cache_max_ttl") == 0 &&
			 boot_value == 3600000 && min_value == 1000 && max_value == 86400000 &&
			 context == PGC_SIGHUP && flags == GUC_UNIT_MS)
		cache_gucs_checked++;
	else if (strcmp(name, "pg_oauth_validator.cache_min_ttl") == 0 &&
			 boot_value == 30000 && min_value == 0 && max_value == 300000 &&
			 context == PGC_SIGHUP && flags == GUC_UNIT_MS)
		cache_gucs_checked++;
	else if (strcmp(name, "pg_oauth_validator.jwks_stale_grace") == 0 &&
			 boot_value == 0 && min_value == 0 && max_value == 3600000 &&
			 context == PGC_SIGHUP && flags == GUC_UNIT_MS)
		cache_gucs_checked++;
	else if (strcmp(name,
					"pg_oauth_validator.unknown_kid_refresh_cooldown") == 0 &&
			 boot_value == 30000 && min_value == 1000 && max_value == 300000 &&
			 context == PGC_SIGHUP && flags == GUC_UNIT_MS)
		cache_gucs_checked++;
	else if (strcmp(name, "pg_oauth_validator.refresh_wait_timeout") == 0 &&
			 boot_value == 5000 && min_value == 0 && max_value == 5000 &&
			 context == PGC_SIGHUP && flags == GUC_UNIT_MS)
		cache_gucs_checked++;
	else if (strcmp(name, "pg_oauth_validator.cache_max_entries") == 0 &&
			 boot_value == 32 && min_value == 8 && max_value == 256 &&
			 context == PGC_SIGHUP && flags == 0)
		cache_gucs_checked++;
	cache_gucs_have_expected_contract = cache_gucs_checked == 8;
}

PGDLLEXPORT void
DefineCustomBoolVariable(const char *name, const char *short_desc,
						 const char *long_desc, bool *value_address,
						 bool boot_value, GucContext context, int flags,
						 GucBoolCheckHook check_hook,
						 GucBoolAssignHook assign_hook, GucShowHook show_hook)
{
	(void) name;
	(void) short_desc;
	(void) long_desc;
	(void) context;
	(void) flags;
	(void) check_hook;
	(void) assign_hook;
	(void) show_hook;
	*value_address = boot_value;
	registered_gucs++;
	if (strcmp(name, "pg_oauth_validator.allow_missing_token_type") == 0 &&
		!boot_value && context == PGC_SIGHUP)
		missing_token_type_default_checked = true;
}

#if PG_VERSION_NUM >= 190000
static bool policy_option_registered;
static bool policy_option_read;

PGDLLEXPORT void
RegisterOAuthHBAOptions(ValidatorModuleState *state, int num,
						const char *options[])
{
	(void) state;

	if (num == 1 && options != NULL && options[0] != NULL &&
		strcmp(options[0], "policy") == 0)
		policy_option_registered = true;
}

PGDLLEXPORT const char *
GetOAuthHBAOption(const ValidatorModuleState *state, const char *option_name)
{
	(void) state;

	if (option_name != NULL && strcmp(option_name, "policy") == 0)
	{
		policy_option_read = true;
		return "production";
	}

	return NULL;
}
#endif

static void
fail(const char *message)
{
	fprintf(stderr, "fail_closed_test: %s\n", message);
	exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
	typedef void (*ModuleInit) (void);

	const OAuthValidatorCallbacks *callbacks;
	OAuthValidatorModuleInit init;
	ModuleInit	module_init;
	ValidatorModuleState state = {0};
	ValidatorModuleResult result = {
		.authorized = true,
		.authn_id = (char *) "unsafe-sentinel",
#if PG_VERSION_NUM >= 190000
		.error_detail = (char *) "unsafe-detail-sentinel",
#endif
	};
	void	   *handle;
	void	   *symbol;
	bool		processed;
	HbaLine		hba = {0};
	Port		port = {0};

	if (argc != 2)
		fail("expected the validator shared-library path");

	handle = dlopen(argv[1], RTLD_LAZY | RTLD_LOCAL);
	if (handle == NULL)
		fail(dlerror());

	dlerror();
	symbol = dlsym(handle, "_PG_oauth_validator_module_init");

	if (dlerror() != NULL || symbol == NULL)
		fail("validator initialization symbol is unavailable");

	/* POSIX specifies dlsym conversion; memcpy avoids an ISO C function cast. */
	memcpy(&init, &symbol, sizeof(init));
	callbacks = init();

	dlerror();
	symbol = dlsym(handle, "_PG_init");

	if (dlerror() != NULL || symbol == NULL)
		fail("PostgreSQL module initialization symbol is unavailable");
	memcpy(&module_init, &symbol, sizeof(module_init));
	module_init();
	if (registered_gucs != 19 || !token_type_allowlist_default_checked ||
		!missing_token_type_default_checked)
		fail("module did not register all configuration variables");
	if (!cache_gucs_have_expected_contract)
		fail("cache GUC defaults, bounds, or reload contexts changed");

	if (callbacks == NULL)
		fail("module initialization returned NULL");
	if (callbacks->magic != PG_OAUTH_VALIDATOR_MAGIC)
		fail("module returned the wrong validator ABI magic");
	if (callbacks->validate_cb == NULL)
		fail("module did not register a validation callback");

#if PG_VERSION_NUM >= 190000
	if (callbacks->startup_cb == NULL)
		fail("PostgreSQL 19 module did not register a startup callback");
	callbacks->startup_cb(&state);
	if (!policy_option_registered)
		fail("PostgreSQL 19 module did not register validator.policy");
#else
	if (callbacks->startup_cb != NULL)
		fail("PostgreSQL 18 module registered an unexpected startup callback");
#endif

	processed = callbacks->validate_cb(&state, "secret-test-token", "postgres",
									   &result);
	if (processed)
		fail("callback processed a token without matched HBA state");
	if (result.authorized || result.authn_id != NULL)
		fail("missing HBA state did not fail closed");
#if PG_VERSION_NUM >= 190000
	if (result.error_detail != NULL)
		fail("missing HBA state returned an unsafe error detail");
#endif

	hba.oauth_issuer = (char *) "https://issuer.example/";
	hba.oauth_scope = (char *) "connect:postgres";
	port.hba = &hba;
	MyProcPort = &port;

	processed = callbacks->validate_cb(&state, "secret-test-token", "postgres",
									   &result);
	if (processed)
		fail("callback processed a token without required audience configuration");
	if (result.authorized)
		fail("callback authorized a token without valid configuration");
	if (result.authn_id != NULL)
		fail("callback returned an identity without valid configuration");
#if PG_VERSION_NUM >= 190000
	if (result.error_detail != NULL)
		fail("configuration failure returned an error detail");
	if (!policy_option_read)
		fail("PostgreSQL 19 module did not read validator.policy");
#endif

	if (dlclose(handle) != 0)
		fail("could not close validator shared library");

	return EXIT_SUCCESS;
}
