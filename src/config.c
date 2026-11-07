#include "postgres.h"

#include "fmgr.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include "utils/guc.h"
#pragma GCC diagnostic pop

#include "config.h"

static char *oauth_audiences;
static char *oauth_allowed_algorithms;
static char *oauth_allowed_token_types;
static char *oauth_identity_claim;
static char *oauth_role_claim;
static char *oauth_allowed_jwks_hosts;
static char *oauth_ca_file;
static int	oauth_clock_skew_ms;
static int	oauth_max_token_size;
static int	oauth_metadata_default_ttl_ms;
static int	oauth_jwks_default_ttl_ms;
static int	oauth_cache_max_ttl_ms;
static int	oauth_cache_min_ttl_ms;
static int	oauth_jwks_stale_grace_ms;
static int	oauth_unknown_kid_refresh_cooldown_ms;
static int	oauth_refresh_wait_timeout_ms;
static int	oauth_cache_max_entries;
static bool oauth_allow_insecure_http;
static bool oauth_allow_missing_token_type;

PGDLLEXPORT void _PG_init(void);

void
_PG_init(void)
{
	/* Old placeholders must not silently survive a configuration upgrade. */
	static const char *const removed_settings[] = {
		"pg_oauth_validator.identity_format",
		"pg_oauth_validator.authorization_mode",
		"pg_oauth_validator.roles_claim",
		"pg_oauth_validator.required_token_type"
	};

	for (size_t i = 0; i < lengthof(removed_settings); i++)
	{
		if (GetConfigOption(removed_settings[i], true, false) != NULL)
			ereport(ERROR,
					(errmsg("removed OAuth validator setting is configured: %s",
							removed_settings[i])));
	}
	DefineCustomStringVariable("pg_oauth_validator.audiences",
							   "PostgreSQL resource audiences accepted in access tokens.",
							   "Required comma-separated list; no audience is inferred.",
							   &oauth_audiences, "", PGC_SIGHUP, 0,
							   NULL, NULL, NULL);
	DefineCustomStringVariable("pg_oauth_validator.allowed_algorithms",
							   "Asymmetric JWT signing algorithms accepted by the validator.",
							   NULL, &oauth_allowed_algorithms, "RS256,ES256",
							   PGC_SIGHUP, 0, NULL, NULL, NULL);
	DefineCustomStringVariable("pg_oauth_validator.allowed_token_types",
							   "Allowed JWT access-token typ header values.",
							   "Comma-separated RFC 9068 type names.",
							   &oauth_allowed_token_types,
							   "at+jwt,application/at+jwt", PGC_SIGHUP, 0,
							   NULL, NULL, NULL);
	DefineCustomBoolVariable("pg_oauth_validator.allow_missing_token_type",
							 "Allow JWT access tokens without a typ header.",
							 "Requires issuer-specific access-token and ID-token separation.",
							 &oauth_allow_missing_token_type, false, PGC_SIGHUP, 0,
							 NULL, NULL, NULL);
	DefineCustomStringVariable("pg_oauth_validator.identity_claim",
							   "Stable token claim used for authenticated identity.", NULL,
							   &oauth_identity_claim, "sub", PGC_SIGHUP, 0,
							   NULL, NULL, NULL);
	DefineCustomStringVariable("pg_oauth_validator.role_claim",
							   "Token claim authorizing the requested PostgreSQL role.",
							   "Empty uses PostgreSQL identity matching or a usermap.",
							   &oauth_role_claim, "", PGC_SIGHUP, 0,
							   NULL, NULL, NULL);
	DefineCustomStringVariable("pg_oauth_validator.allowed_jwks_hosts",
							   "Additional exact hostnames permitted for JWKS retrieval.",
							   "The discovery endpoint host is always permitted; leave empty unless discovery advertises another host.",
							   &oauth_allowed_jwks_hosts, "", PGC_SIGHUP, 0,
							   NULL, NULL, NULL);
	DefineCustomStringVariable("pg_oauth_validator.ca_file",
							   "CA bundle used for issuer metadata and JWKS HTTPS.",
							   "Empty uses the system trust store.",
							   &oauth_ca_file, "", PGC_SIGHUP, 0,
							   NULL, NULL, NULL);
	DefineCustomIntVariable("pg_oauth_validator.clock_skew",
							"Maximum clock skew allowed during claim validation.", NULL,
							&oauth_clock_skew_ms, 60000, 0, 300000,
							PGC_SIGHUP, GUC_UNIT_MS, NULL, NULL, NULL);
	DefineCustomIntVariable("pg_oauth_validator.max_token_size",
							"Maximum accepted bearer-token size.", NULL,
							&oauth_max_token_size, 16384, 1024, 65536,
							PGC_SIGHUP, GUC_UNIT_BYTE, NULL, NULL, NULL);
	DefineCustomIntVariable("pg_oauth_validator.metadata_default_ttl",
							"Fallback freshness lifetime for metadata without usable cache headers.", NULL,
							&oauth_metadata_default_ttl_ms, 300000, 1000, 3600000,
							PGC_SIGHUP, GUC_UNIT_MS, NULL, NULL, NULL);
	DefineCustomIntVariable("pg_oauth_validator.jwks_default_ttl",
							"Fallback freshness lifetime for JWKS without usable cache headers.", NULL,
							&oauth_jwks_default_ttl_ms, 300000, 1000, 3600000,
							PGC_SIGHUP, GUC_UNIT_MS, NULL, NULL, NULL);
	DefineCustomIntVariable("pg_oauth_validator.cache_max_ttl",
							"Maximum freshness lifetime accepted from provider cache headers.", NULL,
							&oauth_cache_max_ttl_ms, 3600000, 1000, 86400000,
							PGC_SIGHUP, GUC_UNIT_MS, NULL, NULL, NULL);
	DefineCustomIntVariable("pg_oauth_validator.cache_min_ttl",
							"Minimum retention of metadata and JWKS responses whose cache headers would force a refetch on every authentication.",
							"Applies to no-store, no-cache, max-age=0 and unusable headers; a positive provider lifetime is never raised. Zero disables it.",
							&oauth_cache_min_ttl_ms, 30000, 0, 300000,
							PGC_SIGHUP, GUC_UNIT_MS, NULL, NULL, NULL);
	DefineCustomIntVariable("pg_oauth_validator.jwks_stale_grace",
							"Explicit grace for stale JWKS use during provider failure.",
							"Zero preserves fail-closed behavior after freshness expires.",
							&oauth_jwks_stale_grace_ms, 0, 0, 3600000,
							PGC_SIGHUP, GUC_UNIT_MS, NULL, NULL, NULL);
	DefineCustomIntVariable("pg_oauth_validator.unknown_kid_refresh_cooldown",
							"Minimum interval between JWKS refreshes caused by unknown key identifiers.", NULL,
							&oauth_unknown_kid_refresh_cooldown_ms, 30000, 1000, 300000,
							PGC_SIGHUP, GUC_UNIT_MS, NULL, NULL, NULL);
	DefineCustomIntVariable("pg_oauth_validator.refresh_wait_timeout",
							"Maximum time to wait for another backend refreshing the same cache entry.",
							"Zero disables waiting and fails closed immediately.",
							&oauth_refresh_wait_timeout_ms, 5000, 0, 5000,
							PGC_SIGHUP, GUC_UNIT_MS, NULL, NULL, NULL);
	DefineCustomIntVariable("pg_oauth_validator.cache_max_entries",
							"Maximum number of shared metadata and JWKS cache entries.",
							"Changing this shared-memory bound requires a server restart.",
							&oauth_cache_max_entries, 32, 8, 256,
							PGC_SIGHUP, 0, NULL, NULL, NULL);
	DefineCustomBoolVariable("pg_oauth_validator.allow_insecure_http",
							 "Permit HTTP issuer metadata and JWKS URLs.",
							 "Unsafe development option; production deployments must use HTTPS.",
							 &oauth_allow_insecure_http, false, PGC_SIGHUP, 0,
							 NULL, NULL, NULL);
}

void
pg_oauth_config_snapshot(PgOAuthPolicyConfig *config)
{
	config->audiences = oauth_audiences;
	config->allowed_algorithms = oauth_allowed_algorithms;
	config->allowed_token_types = oauth_allowed_token_types;
	config->allow_missing_token_type = oauth_allow_missing_token_type;
	config->identity_claim = oauth_identity_claim;
	config->role_claim = oauth_role_claim;
	config->allowed_jwks_hosts = oauth_allowed_jwks_hosts;
	config->ca_file = oauth_ca_file;
	config->clock_skew_ms = oauth_clock_skew_ms;
	config->max_token_size = oauth_max_token_size;
	config->metadata_default_ttl_ms = oauth_metadata_default_ttl_ms;
	config->jwks_default_ttl_ms = oauth_jwks_default_ttl_ms;
	config->cache_max_ttl_ms = oauth_cache_max_ttl_ms;
	config->cache_min_ttl_ms = oauth_cache_min_ttl_ms;
	config->jwks_stale_grace_ms = oauth_jwks_stale_grace_ms;
	config->unknown_kid_refresh_cooldown_ms = oauth_unknown_kid_refresh_cooldown_ms;
	config->refresh_wait_timeout_ms = oauth_refresh_wait_timeout_ms;
	config->allow_insecure_http = oauth_allow_insecure_http;
}

int
pg_oauth_config_cache_max_entries(void)
{
	return oauth_cache_max_entries;
}
