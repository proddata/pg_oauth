#include "cache_state.h"

#include <limits.h>
#include <string.h>

static bool
valid_key(const void *key, size_t key_length)
{
	return key != NULL && key_length > 0 &&
		key_length <= PG_OAUTH_CACHE_MAX_KEY_SIZE;
}

static bool
same_key(const PgOAuthCacheEntry *entry, const void *key, size_t key_length)
{
	return entry->occupied && entry->key_length == key_length &&
		memcmp(entry->key, key, key_length) == 0;
}

static int64_t
bounded_add(int64_t value, int64_t duration)
{
	if (duration > INT64_MAX - value)
		return INT64_MAX;
	return value + duration;
}

static void
increment(uint64_t *counter)
{
	if (*counter != UINT64_MAX)
		(*counter)++;
}

bool
pg_oauth_cache_init(PgOAuthCache *cache, PgOAuthCacheEntry *entries,
					size_t capacity)
{
	if (cache == NULL || entries == NULL || capacity == 0)
		return false;
	memset(cache, 0, sizeof(*cache));
	memset(entries, 0, capacity * sizeof(*entries));
	cache->entries = entries;
	cache->capacity = capacity;
	cache->control = &cache->local_control;
	cache->control->next_refresh_serial = 1;
	return true;
}

bool
pg_oauth_cache_attach(PgOAuthCache *cache, PgOAuthCacheEntry *entries,
					  size_t capacity, PgOAuthCacheControl *control)
{
	if (cache == NULL || entries == NULL || capacity == 0 || control == NULL ||
		control->next_refresh_serial == 0)
		return false;
	memset(cache, 0, sizeof(*cache));
	cache->entries = entries;
	cache->capacity = capacity;
	cache->control = control;
	return true;
}

PgOAuthCacheLookup
pg_oauth_cache_lookup(PgOAuthCache *cache, const void *key, size_t key_length,
					  int64_t now_ms, bool allow_stale, size_t *entry_index)
{
	if (entry_index != NULL)
		*entry_index = SIZE_MAX;
	if (cache == NULL || cache->entries == NULL || !valid_key(key, key_length) ||
		now_ms < 0)
		return PG_OAUTH_CACHE_MISS;

	for (size_t i = 0; i < cache->capacity; i++)
	{
		PgOAuthCacheEntry *entry = &cache->entries[i];

		if (!same_key(entry, key, key_length) || !entry->has_value)
			continue;
		if (now_ms < entry->fresh_until_ms)
		{
			entry->last_used_ms = now_ms;
			if (entry_index != NULL)
				*entry_index = i;
			increment(&cache->control->stats.fresh_hits);
			return PG_OAUTH_CACHE_FRESH;
		}
		if (allow_stale && now_ms < entry->stale_until_ms)
		{
			entry->last_used_ms = now_ms;
			if (entry_index != NULL)
				*entry_index = i;
			increment(&cache->control->stats.stale_hits);
			return PG_OAUTH_CACHE_STALE;
		}
		break;
	}
	increment(&cache->control->stats.misses);
	return PG_OAUTH_CACHE_MISS;
}

static size_t
find_refresh_slot(PgOAuthCache *cache, const void *key, size_t key_length,
				  int64_t now_ms, bool *existing)
{
	size_t		empty = SIZE_MAX;
	size_t		victim = SIZE_MAX;
	int64_t		victim_last_used = INT64_MAX;

	*existing = false;
	for (size_t i = 0; i < cache->capacity; i++)
	{
		PgOAuthCacheEntry *entry = &cache->entries[i];

		if (same_key(entry, key, key_length))
		{
			*existing = true;
			return i;
		}
		if (!entry->occupied && empty == SIZE_MAX)
			empty = i;
		else if (entry->occupied && !entry->refreshing &&
				 now_ms >= entry->stale_until_ms &&
				 (victim == SIZE_MAX || entry->last_used_ms < victim_last_used))
		{
			victim = i;
			victim_last_used = entry->last_used_ms;
		}
	}
	return empty != SIZE_MAX ? empty : victim;
}

PgOAuthCacheRefreshResult
pg_oauth_cache_begin_refresh(PgOAuthCache *cache, const void *key,
							 size_t key_length, int64_t now_ms, bool unknown_kid,
							 int64_t unknown_kid_cooldown_ms,
							 PgOAuthCacheRefresh *refresh)
{
	PgOAuthCacheEntry *entry;
	size_t		index;
	bool		existing;

	if (refresh != NULL)
	{
		refresh->entry_index = SIZE_MAX;
		refresh->serial = 0;
	}
	if (cache == NULL || cache->entries == NULL || refresh == NULL ||
		!valid_key(key, key_length) || now_ms < 0 ||
		unknown_kid_cooldown_ms < 0)
		return PG_OAUTH_CACHE_REFRESH_INVALID_ARGUMENT;

	index = find_refresh_slot(cache, key, key_length, now_ms, &existing);
	if (index == SIZE_MAX)
	{
		increment(&cache->control->stats.failures);
		return PG_OAUTH_CACHE_REFRESH_CAPACITY;
	}
	entry = &cache->entries[index];
	if (existing && entry->refreshing)
	{
		increment(&cache->control->stats.refresh_suppressions);
		return PG_OAUTH_CACHE_REFRESH_IN_PROGRESS;
	}
	if (existing && unknown_kid && entry->has_unknown_kid_refresh &&
		now_ms - entry->last_unknown_kid_refresh_ms < unknown_kid_cooldown_ms)
	{
		increment(&cache->control->stats.refresh_suppressions);
		return PG_OAUTH_CACHE_REFRESH_SUPPRESSED;
	}
	if (!existing)
	{
		if (entry->occupied)
			increment(&cache->control->stats.evictions);
		memset(entry, 0, sizeof(*entry));
		memcpy(entry->key, key, key_length);
		entry->key_length = key_length;
		entry->occupied = true;
		entry->last_used_ms = now_ms;
	}
	if (unknown_kid)
	{
		entry->has_unknown_kid_refresh = true;
		entry->last_unknown_kid_refresh_ms = now_ms;
	}
	entry->refreshing = true;
	entry->refresh_serial = cache->control->next_refresh_serial++;
	if (cache->control->next_refresh_serial == 0)
		cache->control->next_refresh_serial = 1;
	refresh->entry_index = index;
	refresh->serial = entry->refresh_serial;
	increment(&cache->control->stats.refreshes);
	return PG_OAUTH_CACHE_REFRESH_STARTED;
}

bool
pg_oauth_cache_is_refreshing(const PgOAuthCache *cache, const void *key,
							 size_t key_length)
{
	if (cache == NULL || cache->entries == NULL ||
		!valid_key(key, key_length))
		return false;

	for (size_t i = 0; i < cache->capacity; i++)
	{
		const PgOAuthCacheEntry *entry = &cache->entries[i];

		if (entry->occupied && entry->key_length == key_length &&
			memcmp(entry->key, key, key_length) == 0)
			return entry->refreshing;
	}
	return false;
}

bool
pg_oauth_cache_complete_refresh(PgOAuthCache *cache,
								const PgOAuthCacheRefresh *refresh, int64_t now_ms,
								bool success, bool cacheable,
								bool revalidation_required, int64_t ttl_ms,
								int64_t stale_grace_ms, const void *payload,
								size_t payload_length)
{
	PgOAuthCacheEntry *entry;

	if (cache == NULL || cache->entries == NULL || refresh == NULL ||
		refresh->entry_index >= cache->capacity || refresh->serial == 0)
		return false;
	entry = &cache->entries[refresh->entry_index];
	if (!entry->occupied || !entry->refreshing ||
		entry->refresh_serial != refresh->serial)
		return false;

	/*
	 * The caller owns this refresh, so a rejected completion must still
	 * release it. Otherwise the entry would stay in progress for every other
	 * backend until restart.
	 */
	if (now_ms < 0 || ttl_ms < 0 || stale_grace_ms < 0 ||
		(success && cacheable &&
		 (payload == NULL || payload_length == 0 ||
		  payload_length > PG_OAUTH_CACHE_MAX_PAYLOAD_SIZE)))
	{
		entry->refreshing = false;
		increment(&cache->control->stats.failures);
		if (!entry->has_value)
			memset(entry, 0, sizeof(*entry));
		return false;
	}

	entry->refreshing = false;
	if (!success)
	{
		increment(&cache->control->stats.failures);
		if (!entry->has_value)
			memset(entry, 0, sizeof(*entry));
		return true;
	}
	if (!cacheable)
	{
		memset(entry, 0, sizeof(*entry));
		return true;
	}
	entry->has_value = true;
	memcpy(entry->payload, payload, payload_length);
	entry->payload_length = payload_length;
	entry->last_used_ms = now_ms;
	entry->fresh_until_ms = bounded_add(now_ms, ttl_ms);
	entry->stale_until_ms = entry->fresh_until_ms;
	if (!revalidation_required)
		entry->stale_until_ms = bounded_add(entry->fresh_until_ms,
											stale_grace_ms);
	return true;
}

PgOAuthCacheCopyResult
pg_oauth_cache_copy_payload(const PgOAuthCache *cache, size_t entry_index,
							void *output, size_t output_size,
							size_t *payload_length)
{
	const PgOAuthCacheEntry *entry;

	if (payload_length != NULL)
		*payload_length = 0;
	if (cache == NULL || cache->entries == NULL || payload_length == NULL ||
		entry_index >= cache->capacity)
		return PG_OAUTH_CACHE_COPY_INVALID_ARGUMENT;
	entry = &cache->entries[entry_index];
	if (!entry->occupied || !entry->has_value)
		return PG_OAUTH_CACHE_COPY_NOT_FOUND;
	*payload_length = entry->payload_length;
	if (output == NULL || output_size < entry->payload_length)
		return PG_OAUTH_CACHE_COPY_TOO_SMALL;
	memcpy(output, entry->payload, entry->payload_length);
	return PG_OAUTH_CACHE_COPY_OK;
}
