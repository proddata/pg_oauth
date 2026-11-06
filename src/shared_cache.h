#ifndef PG_OAUTH_VALIDATOR_SHARED_CACHE_H
#define PG_OAUTH_VALIDATOR_SHARED_CACHE_H

#include "postgres.h"

#include "cache_state.h"
#include "cache_io.h"

typedef struct PgOAuthSharedCacheLookup
{
	PgOAuthCacheLookup freshness;
	PgOAuthCacheCopyResult copy_result;
	size_t		payload_length;
} PgOAuthSharedCacheLookup;

extern bool pg_oauth_shared_cache_attach(void);
#if PG_VERSION_NUM < 170000
/*
 * PostgreSQL 15 and 16: request the shared segment from the postmaster. Call
 * only while shared_preload_libraries is being processed.
 */
extern void pg_oauth_shared_cache_preload(int capacity);
#endif
extern bool pg_oauth_shared_cache_configure_capacity(int capacity);
extern PgOAuthSharedCacheLookup pg_oauth_shared_cache_lookup(
															 const void *key, size_t key_length, int64_t now_ms, bool allow_stale,
															 void *output, size_t output_size);
extern PgOAuthCacheRefreshResult pg_oauth_shared_cache_begin_refresh(
																	 const void *key, size_t key_length, int64_t now_ms, bool unknown_kid,
																	 int64_t unknown_kid_cooldown_ms, PgOAuthCacheRefresh *refresh);
extern bool pg_oauth_shared_cache_wait_refresh(
											   const void *key, size_t key_length, int64_t timeout_ms,
											   int64_t *elapsed_ms);
extern bool pg_oauth_shared_cache_complete_refresh(
												   const PgOAuthCacheRefresh *refresh, int64_t now_ms, bool success,
												   bool cacheable, bool revalidation_required, int64_t ttl_ms,
												   int64_t stale_grace_ms, const void *payload, size_t payload_length);
extern bool pg_oauth_shared_cache_stats(PgOAuthCacheStats *stats);
extern bool pg_oauth_shared_cache_io(PgOAuthCacheIo *io);

#endif
