#include "postgres.h"

#include <time.h>

#include <string.h>

#include "storage/condition_variable.h"
#if PG_VERSION_NUM >= 170000
#include "storage/dsm_registry.h"
#else
#include "miscadmin.h"
#include "storage/ipc.h"
#include "storage/shmem.h"
#endif
#include "storage/lwlock.h"
#include "utils/wait_event.h"

#include "shared_cache.h"

/*
 * PostgreSQL 17 introduced the named DSM registry, which lets a module attach
 * shared storage on first use. Before 17 only the postmaster can create shared
 * memory, so the PAM module must be listed in shared_preload_libraries (ADR
 * 0009). The OAuth validator never targets those majors.
 */
#if PG_VERSION_NUM < 170000 && !defined(PG_OAUTH_CACHE_NAMESPACE_PAM)
#error "the OAuth validator's shared cache requires PostgreSQL 17 or later"
#endif

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
initialize_state(PgOAuthSharedCacheState *state, int capacity)
{
	Size		segment_size;

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

#if PG_VERSION_NUM >= 170000
static void
#if PG_VERSION_NUM >= 190000
initialize_shared_cache(void *memory, void *argument)
#else
initialize_shared_cache(void *memory)
#endif
{
#if PG_VERSION_NUM >= 190000
	(void) argument;
#endif
	initialize_state(memory, configured_capacity);
}
#endif

bool
pg_oauth_shared_cache_configure_capacity(int capacity)
{
	Size		ignored;

	if (!shared_cache_size(capacity, &ignored))
		return false;
	configured_capacity = capacity;
	return shared_state == NULL || shared_state->capacity == (uint32) capacity;
}

#if PG_VERSION_NUM >= 170000
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

#else							/* PostgreSQL 15 and 16: preloaded shared
								 * memory */

static shmem_request_hook_type previous_shmem_request_hook;
static shmem_startup_hook_type previous_shmem_startup_hook;
static bool attached;

static void
preload_shmem_request(void)
{
	Size		segment_size;

	if (previous_shmem_request_hook != NULL)
		previous_shmem_request_hook();
	if (shared_cache_size(configured_capacity, &segment_size))
		RequestAddinShmemSpace(segment_size);
}

static void
preload_shmem_startup(void)
{
	bool		found;
	Size		segment_size;

	if (previous_shmem_startup_hook != NULL)
		previous_shmem_startup_hook();
	shared_state = NULL;
	if (!shared_cache_size(configured_capacity, &segment_size))
		return;
	LWLockAcquire(AddinShmemInitLock, LW_EXCLUSIVE);
	shared_state = ShmemInitStruct(PG_OAUTH_SHARED_CACHE_NAME, segment_size, &found);

	/*
	 * Shared memory is recreated after a crash restart and is then not found,
	 * so initialization always happens before any backend can attach.
	 */
	if (shared_state != NULL && !found)
		initialize_state(shared_state, configured_capacity);
	LWLockRelease(AddinShmemInitLock);
}

void
pg_oauth_shared_cache_preload(int capacity)
{
	Size		ignored;

	if (!shared_cache_size(capacity, &ignored))
		return;
	configured_capacity = capacity;
	previous_shmem_request_hook = shmem_request_hook;
	shmem_request_hook = preload_shmem_request;
	previous_shmem_startup_hook = shmem_startup_hook;
	shmem_startup_hook = preload_shmem_startup;
}

/*
 * Without the preload there is no shared storage: report unavailable so the
 * caller denies instead of validating without refresh coordination.
 */
bool
pg_oauth_shared_cache_attach(void)
{
	if (shared_state == NULL)
		return false;
	if (attached)
		return shared_state->capacity == (uint32) configured_capacity;
	if (shared_state->magic != PG_OAUTH_SHARED_CACHE_MAGIC ||
		shared_state->version != PG_OAUTH_SHARED_CACHE_VERSION ||
		shared_state->capacity != (uint32) configured_capacity)
		return false;
	/* Tranche names are per-process before PostgreSQL 19. */
	LWLockRegisterTranche(shared_state->tranche_id, PG_OAUTH_SHARED_CACHE_TRANCHE);
	if (!pg_oauth_cache_attach(&cache_view, shared_state->entries,
							   shared_state->capacity, &shared_state->control))
		return false;
	attached = true;
	return true;
}

#endif

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

/*
 * Monotonic milliseconds for wait accounting. PostgreSQL's instr_time helpers
 * are not usable from a module on every platform (PostgreSQL 19 on x86), and
 * validation already uses CLOCK_MONOTONIC for cache time.
 */
static bool
wait_clock_ms(int64_t *value)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0 ||
		now.tv_sec > INT64_MAX / 1000)
		return false;
	*value = (int64_t) now.tv_sec * 1000 + now.tv_nsec / 1000000;
	return true;
}

bool
pg_oauth_shared_cache_wait_refresh(const void *key, size_t key_length,
								   int64_t timeout_ms, int64_t *elapsed_ms)
{
	bool		refreshing;
	bool		have_clock;
	int64_t		started_ms = 0;
	int64_t		waited_ms = 0;

	if (elapsed_ms != NULL)
		*elapsed_ms = 0;
	if (!pg_oauth_shared_cache_attach() || key == NULL || key_length == 0 ||
		key_length > PG_OAUTH_CACHE_MAX_KEY_SIZE || timeout_ms <= 0 ||
		timeout_ms > 5000 || elapsed_ms == NULL)
		return false;

	have_clock = wait_clock_ms(&started_ms);
	ConditionVariablePrepareToSleep(&shared_state->refresh_cv);
	for (;;)
	{
		LWLockAcquire(&shared_state->lock, LW_SHARED);
		refreshing = pg_oauth_cache_is_refreshing(&cache_view, key, key_length);
		LWLockRelease(&shared_state->lock);
		if (!refreshing)
			break;

		/*
		 * Every completed refresh wakes every waiter, including those for
		 * other entries, so a wakeup proves nothing about this entry: check
		 * it again and keep sleeping until this wait's own deadline. Without
		 * a clock fall back to one full-length wait, which fails closed.
		 */
		if (have_clock)
		{
			int64_t		now_ms;

			if (!wait_clock_ms(&now_ms) || now_ms < started_ms)
				have_clock = false;
			else
				waited_ms = now_ms - started_ms;
		}
		if (have_clock && waited_ms >= timeout_ms)
			break;
		(void) ConditionVariableTimedSleep(&shared_state->refresh_cv,
										   (long) (have_clock ? timeout_ms - waited_ms : timeout_ms),
										   PG_WAIT_EXTENSION);
		if (!have_clock)
		{
			LWLockAcquire(&shared_state->lock, LW_SHARED);
			refreshing = pg_oauth_cache_is_refreshing(&cache_view, key, key_length);
			LWLockRelease(&shared_state->lock);
			break;
		}
	}
	ConditionVariableCancelSleep();

	/*
	 * Callers add this to their cache clock. Measure it once, after the last
	 * sleep; without a trustworthy clock assume the whole timeout passed.
	 */
	if (have_clock)
	{
		int64_t		now_ms;

		if (wait_clock_ms(&now_ms) && now_ms >= started_ms)
			waited_ms = now_ms - started_ms;
		else
			waited_ms = timeout_ms;
	}
	else
		waited_ms = timeout_ms;
	*elapsed_ms = waited_ms > timeout_ms ? timeout_ms : waited_ms;
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
