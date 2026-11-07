#ifndef PG_OAUTH_PAM_CACHE_H
#define PG_OAUTH_PAM_CACHE_H

#include "postgres.h"

#include "cache_io.h"

/*
 * Cross-backend metadata/JWKS cache for the PAM module (ADR 0009). Storage is
 * the same named-DSM implementation the OAuth validator uses, compiled
 * privately under a separate namespace, so the two modules never share
 * entries, locks or capacity.
 *
 * Capacity is a module-level setting, pg_oauth_pam.cache_max_entries, read
 * from postgresql.conf. Returns false -- and the caller must deny rather than
 * validate without coordination -- if storage cannot be attached or its
 * capacity conflicts with the segment's existing one.
 */
extern bool pg_oauth_pam_cache_io(PgOAuthCacheIo *io);

/*
 * True only when the running server is the PostgreSQL major version this module
 * was built for. The caller must deny otherwise.
 */
extern bool pg_oauth_pam_server_matches(void);

#endif
