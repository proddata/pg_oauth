#ifndef PG_OAUTH_VALIDATOR_CACHE_IO_H
#define PG_OAUTH_VALIDATOR_CACHE_IO_H

#include "cache_state.h"

typedef struct PgOAuthCacheIoLookup
{
	PgOAuthCacheLookup freshness;
	PgOAuthCacheCopyResult copy_result;
	size_t		payload_length;
} PgOAuthCacheIoLookup;

typedef struct PgOAuthCacheIo
{
	void	   *context;
	PgOAuthCacheIoLookup (*lookup) (void *context, const void *key,
									size_t key_length, int64_t now_ms, bool allow_stale, void *output,
									size_t output_size);
	PgOAuthCacheRefreshResult (*begin_refresh) (void *context, const void *key,
												size_t key_length, int64_t now_ms, bool unknown_kid,
												int64_t unknown_kid_cooldown_ms, PgOAuthCacheRefresh *refresh);
	bool		(*wait_refresh) (void *context, const void *key,
								 size_t key_length, int64_t timeout_ms,
								 int64_t *elapsed_ms);
	bool		(*complete_refresh) (void *context,
									 const PgOAuthCacheRefresh *refresh, int64_t now_ms, bool success,
									 bool cacheable, bool revalidation_required, int64_t ttl_ms,
									 int64_t stale_grace_ms, const void *payload, size_t payload_length);
} PgOAuthCacheIo;

#endif
