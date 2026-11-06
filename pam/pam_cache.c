#include "postgres.h"

/* PostgreSQL's own inline helpers trip -Wextra; keep the warning for our code. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include "utils/guc.h"
#pragma GCC diagnostic pop

#include "pam_cache.h"
#include "shared_cache.h"

#define PG_OAUTH_PAM_GUC_PREFIX "pg_oauth_pam"

static int	cache_max_entries = 32;
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

bool
pg_oauth_pam_cache_io(PgOAuthCacheIo *io)
{
	define_settings();
	return pg_oauth_shared_cache_configure_capacity(cache_max_entries) &&
		pg_oauth_shared_cache_io(io);
}
