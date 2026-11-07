#ifndef PG_OAUTH_VALIDATOR_CACHE_STATE_H
#define PG_OAUTH_VALIDATOR_CACHE_STATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PG_OAUTH_CACHE_MAX_KEY_SIZE 4096
#define PG_OAUTH_CACHE_MAX_PAYLOAD_SIZE 65536

typedef enum PgOAuthCacheLookup
{
	PG_OAUTH_CACHE_MISS = 0,
	PG_OAUTH_CACHE_FRESH,
	PG_OAUTH_CACHE_STALE
} PgOAuthCacheLookup;

typedef enum PgOAuthCacheRefreshResult
{
	PG_OAUTH_CACHE_REFRESH_STARTED = 0,
	PG_OAUTH_CACHE_REFRESH_IN_PROGRESS,
	PG_OAUTH_CACHE_REFRESH_SUPPRESSED,
	PG_OAUTH_CACHE_REFRESH_CAPACITY,
	PG_OAUTH_CACHE_REFRESH_INVALID_ARGUMENT
} PgOAuthCacheRefreshResult;

typedef enum PgOAuthCacheCopyResult
{
	PG_OAUTH_CACHE_COPY_OK = 0,
	PG_OAUTH_CACHE_COPY_NOT_FOUND,
	PG_OAUTH_CACHE_COPY_TOO_SMALL,
	PG_OAUTH_CACHE_COPY_INVALID_ARGUMENT
} PgOAuthCacheCopyResult;

typedef struct PgOAuthCacheEntry
{
	unsigned char key[PG_OAUTH_CACHE_MAX_KEY_SIZE];
	unsigned char payload[PG_OAUTH_CACHE_MAX_PAYLOAD_SIZE];
	size_t		key_length;
	size_t		payload_length;
	uint64_t	refresh_serial;
	int64_t		fresh_until_ms;
	int64_t		stale_until_ms;
	int64_t		last_used_ms;
	int64_t		last_unknown_kid_refresh_ms;
	bool		occupied;
	bool		has_value;
	bool		refreshing;
	bool		has_unknown_kid_refresh;
} PgOAuthCacheEntry;

typedef struct PgOAuthCacheStats
{
	uint64_t	fresh_hits;
	uint64_t	stale_hits;
	uint64_t	misses;
	uint64_t	refreshes;
	uint64_t	refresh_suppressions;
	uint64_t	evictions;
	uint64_t	failures;
} PgOAuthCacheStats;

typedef struct PgOAuthCacheControl
{
	uint64_t	next_refresh_serial;
	PgOAuthCacheStats stats;
} PgOAuthCacheControl;

typedef struct PgOAuthCache
{
	PgOAuthCacheEntry *entries;
	size_t		capacity;
	PgOAuthCacheControl *control;
	PgOAuthCacheControl local_control;
} PgOAuthCache;

/*
 * This state machine does not lock internally. A shared-memory adapter must
 * serialize each call, copy any selected payload while locked, and release
 * its PostgreSQL lock before performing network I/O.
 */

typedef struct PgOAuthCacheRefresh
{
	size_t		entry_index;
	uint64_t	serial;
} PgOAuthCacheRefresh;

extern bool pg_oauth_cache_init(PgOAuthCache *cache,
								PgOAuthCacheEntry *entries, size_t capacity);
extern bool pg_oauth_cache_attach(PgOAuthCache *cache,
								  PgOAuthCacheEntry *entries, size_t capacity, PgOAuthCacheControl *control);
extern PgOAuthCacheLookup pg_oauth_cache_lookup(PgOAuthCache *cache,
												const void *key, size_t key_length, int64_t now_ms, bool allow_stale,
												size_t *entry_index);
extern PgOAuthCacheRefreshResult pg_oauth_cache_begin_refresh(
															  PgOAuthCache *cache, const void *key, size_t key_length, int64_t now_ms,
															  bool unknown_kid, int64_t unknown_kid_cooldown_ms,
															  PgOAuthCacheRefresh *refresh);
extern bool pg_oauth_cache_is_refreshing(const PgOAuthCache *cache,
										 const void *key, size_t key_length);
extern bool pg_oauth_cache_complete_refresh(PgOAuthCache *cache,
											const PgOAuthCacheRefresh *refresh, int64_t now_ms, bool success,
											bool cacheable, bool revalidation_required, int64_t ttl_ms,
											int64_t stale_grace_ms, const void *payload, size_t payload_length);
extern PgOAuthCacheCopyResult pg_oauth_cache_copy_payload(
														  const PgOAuthCache *cache, size_t entry_index, void *output,
														  size_t output_size, size_t *payload_length);

#endif
