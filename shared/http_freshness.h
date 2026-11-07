#ifndef PG_OAUTH_VALIDATOR_HTTP_FRESHNESS_H
#define PG_OAUTH_VALIDATOR_HTTP_FRESHNESS_H

#include <stdbool.h>
#include <stdint.h>

typedef enum PgOAuthHttpFreshnessError
{
	PG_OAUTH_HTTP_FRESHNESS_OK = 0,
	PG_OAUTH_HTTP_FRESHNESS_INVALID_ARGUMENT
} PgOAuthHttpFreshnessError;

typedef struct PgOAuthHttpFreshnessPolicy
{
	int64_t		default_ttl_ms;
	int64_t		maximum_ttl_ms;

	/*
	 * Retention for responses that would otherwise be refetched on every
	 * authentication (no-store, no-cache, max-age=0, unusable headers). Zero
	 * keeps strict RFC 9111 behavior. Never raises a positive provider
	 * lifetime.
	 */
	int64_t		minimum_ttl_ms;
} PgOAuthHttpFreshnessPolicy;

typedef struct PgOAuthHttpFreshness
{
	int64_t		ttl_ms;
	bool		cacheable;
	bool		revalidation_required;
	bool		explicit_freshness;
} PgOAuthHttpFreshness;

extern PgOAuthHttpFreshnessError pg_oauth_http_freshness_calculate(
																   const char *cache_control, const char *date, const char *expires,
																   const char *age, int64_t response_time_seconds,
																   const PgOAuthHttpFreshnessPolicy *policy, PgOAuthHttpFreshness *result);
extern const char *pg_oauth_http_freshness_error_code(
													  PgOAuthHttpFreshnessError error);

#endif
