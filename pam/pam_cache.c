#include "postgres.h"

/* PostgreSQL's own inline helpers trip -Wextra; keep the warning for our code. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include "fmgr.h"
#include "miscadmin.h"
#include "utils/guc.h"
#pragma GCC diagnostic pop

#include "pam_cache.h"
#include "shared_cache.h"

#define PG_OAUTH_PAM_GUC_PREFIX "pg_oauth_pam"

/*
 * The PostgreSQL major this module was compiled for. A test build may define it
 * differently to prove that a mismatch is refused.
 */
#ifndef PG_OAUTH_PAM_EXPECTED_MAJOR
#define PG_OAUTH_PAM_EXPECTED_MAJOR (PG_VERSION_NUM / 10000)
#endif

static int	cache_max_entries = 32;

#if PG_VERSION_NUM >= 170000

static bool guc_defined;

/*
 * A PAM module is loaded by libpam, not by PostgreSQL's module loader, so
 * _PG_init never runs; define the setting on first use. Idempotent per backend.
 */
static void
define_settings(void)
{
	if (guc_defined)
		return;
	DefineCustomIntVariable(PG_OAUTH_PAM_GUC_PREFIX ".cache_max_entries",
							"Maximum number of shared PAM metadata and JWKS cache entries.",
							"Changing this shared-memory bound requires a server restart.",
							&cache_max_entries, 32, 8, 256,
							PGC_SIGHUP, 0, NULL, NULL, NULL);
	MarkGUCPrefixReserved(PG_OAUTH_PAM_GUC_PREFIX);
	guc_defined = true;
}

#else							/* PostgreSQL 15 and 16 */

PG_MODULE_MAGIC;

PGDLLEXPORT void _PG_init(void);

/*
 * Only the postmaster can create shared memory before PostgreSQL 17, so the
 * module must be listed in shared_preload_libraries (ADR 0009). That is the one
 * time PostgreSQL calls _PG_init for it; libpam's later load calls nothing.
 */
void
_PG_init(void)
{
	if (!process_shared_preload_libraries_in_progress)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("pg_oauth_pam must be loaded via shared_preload_libraries")));
	DefineCustomIntVariable(PG_OAUTH_PAM_GUC_PREFIX ".cache_max_entries",
							"Maximum number of shared PAM metadata and JWKS cache entries.",
							"Changing this shared-memory bound requires a server restart.",
							&cache_max_entries, 32, 8, 256,
							PGC_POSTMASTER, 0, NULL, NULL, NULL);
	MarkGUCPrefixReserved(PG_OAUTH_PAM_GUC_PREFIX);
	pg_oauth_shared_cache_preload(cache_max_entries);
}

#endif

/*
 * Before PostgreSQL 17 the server's own loader checks the module's magic block.
 * From 17 libpam loads the module and PostgreSQL never sees it, so nothing else
 * stops a binary built for one major from running in another, whose shared
 * memory and locking calls differ (GetNamedDSMSegment gained an argument in 19).
 * Compare the running server's version once per process and refuse on mismatch.
 */
bool
pg_oauth_pam_server_matches(void)
{
	static int	verdict = -1;

	if (verdict < 0)
	{
		const char *value = GetConfigOption("server_version_num", false, false);
		char	   *end = NULL;
		long		number = value != NULL ? strtol(value, &end, 10) : 0;

		verdict = value != NULL && end != value && *end == '\0' &&
			number / 10000 == PG_OAUTH_PAM_EXPECTED_MAJOR ? 1 : 0;
	}
	return verdict == 1;
}

bool
pg_oauth_pam_cache_io(PgOAuthCacheIo *io)
{
#if PG_VERSION_NUM >= 170000
	define_settings();
#endif
	/* Before PostgreSQL 17 an unpreloaded module has no storage and denies. */
	return pg_oauth_shared_cache_configure_capacity(cache_max_entries) &&
		pg_oauth_shared_cache_io(io);
}
