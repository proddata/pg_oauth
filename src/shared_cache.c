#include "postgres.h"

#include <string.h>

#include "storage/condition_variable.h"
#include "storage/dsm_registry.h"
#include "storage/lwlock.h"
#include "utils/wait_event.h"

#include "shared_cache.h"

/*
 * The OAuth validator and the PAM module compile this file privately and must
 * never share segments, locks or capacity (ADR 0009), so the PAM build selects
 * its own namespace.
 */
#ifdef PG_OAUTH_CACHE_NAMESPACE_PAM
#define PG_OAUTH_SHARED_CACHE_NAME "pg_oauth_pam.cache.v1"
#define PG_OAUTH_SHARED_CACHE_TRANCHE "pg_oauth_pam_cache"
#else
#define PG_OAUTH_SHARED_CACHE_NAME "pg_oauth_validator.cache.v3"
#define PG_OAUTH_SHARED_CACHE_TRANCHE "pg_oauth_validator_cache"
#endif
#define PG_OAUTH_SHARED_CACHE_MAGIC UINT32_C(0x50474f43)
#define PG_OAUTH_SHARED_CACHE_VERSION UINT32_C(3)

typedef struct PgOAuthSharedCacheState
{
	uint32		magic;
	uint32		version;
	uint32		capacity;
	int			tranche_id;
	LWLock		lock;
	ConditionVariable refresh_cv;
	PgOAuthCacheControl control;
	PgOAuthCacheEntry entries[FLEXIBLE_ARRAY_MEMBER];
} PgOAuthSharedCacheState;

static PgOAuthSharedCacheState *shared_state;
static PgOAuthCache cache_view;
static int	configured_capacity = 32;

static bool
shared_cache_size(int capacity, Size *size)
{
	Size		header = offsetof(PgOAuthSharedCacheState, entries);

	if (size == NULL || capacity < 8 || capacity > 256 ||
		(Size) capacity > (SIZE_MAX - header) / sizeof(PgOAuthCacheEntry))
		return false;
	*size = header + ((Size) capacity * sizeof(PgOAuthCacheEntry));
	return true;
}

static void
#if PG_VERSION_NUM >= 190000
initialize_shared_cache(void *memory, void *argument)
#else
initialize_shared_cache(void *memory)
#endif
{
	PgOAuthSharedCacheState *state = memory;
	int			capacity = configured_capacity;
	Size		segment_size;

#if PG_VERSION_NUM >= 190000
	(void) argument;
#endif
	if (!shared_cache_size(capacity, &segment_size))
		return;
	memset(state, 0, segment_size);
#if PG_VERSION_NUM >= 190000
	state->tranche_id = LWLockNewTrancheId(PG_OAUTH_SHARED_CACHE_TRANCHE);
#else
	state->tranche_id = LWLockNewTrancheId();
#endif
	LWLockInitialize(&state->lock, state->tranche_id);
	ConditionVariableInit(&state->refresh_cv);
	state->control.next_refresh_serial = 1;
	state->capacity = (uint32) capacity;
	state->version = PG_OAUTH_SHARED_CACHE_VERSION;
	state->magic = PG_OAUTH_SHARED_CACHE_MAGIC;
}

bool
pg_oauth_shared_cache_configure_capacity(int capacity)
{
	Size		ignored;

	if (!shared_cache_size(capacity, &ignored))
		return false;
	configured_capacity = capacity;
	return shared_state == NULL || shared_state->capacity == (uint32) capacity;
}

bool
pg_oauth_shared_cache_attach(void)
{
	bool		found;
	Size		segment_size;

	if (shared_state != NULL)
		return shared_state->capacity == (uint32) configured_capacity;
	if (!shared_cache_size(configured_capacity, &segment_size))
		return false;
#if PG_VERSION_NUM >= 190000
	shared_state = GetNamedDSMSegment(PG_OAUTH_SHARED_CACHE_NAME,
									  segment_size, initialize_shared_cache,
									  &found, NULL);
#else
	shared_state = GetNamedDSMSegment(PG_OAUTH_SHARED_CACHE_NAME,
									  segment_size, initialize_shared_cache,
									  &found);
#endif
	if (shared_state == NULL || shared_state->magic != PG_OAUTH_SHARED_CACHE_MAGIC ||
		shared_state->version != PG_OAUTH_SHARED_CACHE_VERSION ||
		shared_state->capacity != (uint32) configured_capacity)
	{
		shared_state = NULL;
		return false;
	}
#if PG_VERSION_NUM < 190000
	LWLockRegisterTranche(shared_state->tranche_id,
						  PG_OAUTH_SHARED_CACHE_TRANCHE);
#endif
	if (!pg_oauth_cache_attach(&cache_view, shared_state->entries,
							   shared_state->capacity, &shared_state->control))
	{
		shared_state = NULL;
		return false;
	}
	(void) found;
	return true;
}

PgOAuthSharedCacheLookup
pg_oauth_shared_cache_lookup(const void *key, size_t key_length,
							 int64_t now_ms, bool allow_stale, void *output,
							 size_t output_size)
{
	PgOAuthSharedCacheLookup result = {
		.freshness = PG_OAUTH_CACHE_MISS,
		.copy_result = PG_OAUTH_CACHE_COPY_NOT_FOUND,
	};
	size_t		entry_index;

	if (!pg_oauth_shared_cache_attach())
		return result;
	LWLockAcquire(&shared_state->lock, LW_EXCLUSIVE);
	result.freshness = pg_oauth_cache_lookup(&cache_view, key, key_length,
											 now_ms, allow_stale, &entry_index);
	if (result.freshness != PG_OAUTH_CACHE_MISS)
		result.copy_result = pg_oauth_cache_copy_payload(&cache_view, entry_index,
														 output, output_size, &result.payload_length);
	LWLockRelease(&shared_state->lock);
	return result;
}

PgOAuthCacheRefreshResult
pg_oauth_shared_cache_begin_refresh(const void *key, size_t key_length,
									int64_t now_ms, bool unknown_kid,
									int64_t unknown_kid_cooldown_ms,
									PgOAuthCacheRefresh *refresh)
{
	PgOAuthCacheRefreshResult result;

	if (!pg_oauth_shared_cache_attach())
		return PG_OAUTH_CACHE_REFRESH_INVALID_ARGUMENT;
	LWLockAcquire(&shared_state->lock, LW_EXCLUSIVE);
	result = pg_oauth_cache_begin_refresh(&cache_view, key, key_length, now_ms,
										  unknown_kid, unknown_kid_cooldown_ms, refresh);
	LWLockRelease(&shared_state->lock);
	return result;
}

bool
pg_oauth_shared_cache_complete_refresh(const PgOAuthCacheRefresh *refresh,
									   int64_t now_ms, bool success, bool cacheable,
									   bool revalidation_required, int64_t ttl_ms,
									   int64_t stale_grace_ms, const void *payload,
									   size_t payload_length)
{
	bool		result;

	if (!pg_oauth_shared_cache_attach())
		return false;
	LWLockAcquire(&shared_state->lock, LW_EXCLUSIVE);
	result = pg_oauth_cache_complete_refresh(&cache_view, refresh, now_ms,
											 success, cacheable, revalidation_required, ttl_ms, stale_grace_ms,
											 payload, payload_length);
	LWLockRelease(&shared_state->lock);
	if (result)
		ConditionVariableBroadcast(&shared_state->refresh_cv);
	return result;
}

bool
pg_oauth_shared_cache_wait_refresh(const void *key, size_t key_length,
								   int64_t timeout_ms, int64_t *elapsed_ms)
{
	bool		refreshing;

	if (elapsed_ms != NULL)
		*elapsed_ms = 0;
	if (!pg_oauth_shared_cache_attach() || key == NULL || key_length == 0 ||
		key_length > PG_OAUTH_CACHE_MAX_KEY_SIZE || timeout_ms <= 0 ||
		timeout_ms > 5000 || elapsed_ms == NULL)
		return false;

	ConditionVariablePrepareToSleep(&shared_state->refresh_cv);
	LWLockAcquire(&shared_state->lock, LW_SHARED);
	refreshing = pg_oauth_cache_is_refreshing(&cache_view, key, key_length);
	LWLockRelease(&shared_state->lock);
	if (!refreshing)
	{
		ConditionVariableCancelSleep();
		return true;
	}

	/*
	 * Use one bounded wait. PostgreSQL 19's x86 instr_time conversion reaches
	 * backend timing globals that are not exported to validator modules.
	 * Rechecking after wakeup is sufficient: a spurious wakeup fails closed.
	 */
	(void) ConditionVariableTimedSleep(&shared_state->refresh_cv, (long) timeout_ms,
									   PG_WAIT_EXTENSION);
	LWLockAcquire(&shared_state->lock, LW_SHARED);
	refreshing = pg_oauth_cache_is_refreshing(&cache_view, key, key_length);
	LWLockRelease(&shared_state->lock);
	ConditionVariableCancelSleep();
	*elapsed_ms = timeout_ms;
	return !refreshing;
}

bool
pg_oauth_shared_cache_stats(PgOAuthCacheStats *stats)
{
	if (stats == NULL || !pg_oauth_shared_cache_attach())
		return false;
	LWLockAcquire(&shared_state->lock, LW_SHARED);
	*stats = shared_state->control.stats;
	LWLockRelease(&shared_state->lock);
	return true;
}

static PgOAuthCacheIoLookup
shared_io_lookup(void *context, const void *key, size_t key_length,
				 int64_t now_ms, bool allow_stale, void *output, size_t output_size)
{
	PgOAuthSharedCacheLookup value;
	PgOAuthCacheIoLookup result;

	(void) context;
	value = pg_oauth_shared_cache_lookup(key, key_length, now_ms, allow_stale,
										 output, output_size);
	result.freshness = value.freshness;
	result.copy_result = value.copy_result;
	result.payload_length = value.payload_length;
	return result;
}

static PgOAuthCacheRefreshResult
shared_io_begin(void *context, const void *key, size_t key_length,
				int64_t now_ms, bool unknown_kid,
				int64_t unknown_kid_cooldown_ms, PgOAuthCacheRefresh *refresh)
{
	(void) context;
	return pg_oauth_shared_cache_begin_refresh(key, key_length, now_ms,
											   unknown_kid, unknown_kid_cooldown_ms, refresh);
}

static bool
shared_io_complete(void *context, const PgOAuthCacheRefresh *refresh,
				   int64_t now_ms, bool success, bool cacheable,
				   bool revalidation_required, int64_t ttl_ms,
				   int64_t stale_grace_ms, const void *payload,
				   size_t payload_length)
{
	(void) context;
	return pg_oauth_shared_cache_complete_refresh(refresh, now_ms, success,
												  cacheable, revalidation_required, ttl_ms, stale_grace_ms, payload,
												  payload_length);
}

static bool
shared_io_wait(void *context, const void *key, size_t key_length,
			   int64_t timeout_ms, int64_t *elapsed_ms)
{
	(void) context;
	return pg_oauth_shared_cache_wait_refresh(key, key_length, timeout_ms,
											  elapsed_ms);
}

bool
pg_oauth_shared_cache_io(PgOAuthCacheIo *io)
{
	if (io == NULL || !pg_oauth_shared_cache_attach())
		return false;
	io->context = NULL;
	io->lookup = shared_io_lookup;
	io->begin_refresh = shared_io_begin;
	io->wait_refresh = shared_io_wait;
	io->complete_refresh = shared_io_complete;
	return true;
}
