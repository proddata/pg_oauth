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
