#ifndef PG_OAUTH_VALIDATOR_ISSUER_KEY_H
#define PG_OAUTH_VALIDATOR_ISSUER_KEY_H

#include <stdint.h>

#include "cache_io.h"
#include "cache_key.h"
#include "http_freshness.h"
#include "http_transport.h"
#include "jwks.h"
#include "metadata.h"

typedef enum PgOAuthIssuerKeyError
{
	PG_OAUTH_ISSUER_KEY_OK = 0,
	PG_OAUTH_ISSUER_KEY_INVALID_ARGUMENT,
	PG_OAUTH_ISSUER_KEY_METADATA_HTTP,
	PG_OAUTH_ISSUER_KEY_METADATA_INVALID,
	PG_OAUTH_ISSUER_KEY_JWKS_HTTP,
	PG_OAUTH_ISSUER_KEY_JWKS_INVALID,
	PG_OAUTH_ISSUER_KEY_CACHE
} PgOAuthIssuerKeyError;

typedef struct PgOAuthIssuerKeyPolicy
{
	PgOAuthHttpPolicy metadata_http;
	PgOAuthMetadataPolicy metadata;
	PgOAuthHttpPolicy jwks_http;
	PgOAuthJwksPolicy jwks;
} PgOAuthIssuerKeyPolicy;

typedef struct PgOAuthIssuerKeyResult
{
	PgOAuthSelectedJwk selected;
	PgOAuthHttpError http_error;
	PgOAuthMetadataError metadata_error;
	PgOAuthJwksError jwks_error;
} PgOAuthIssuerKeyResult;

typedef struct PgOAuthIssuerKeyCachePolicy
{
	const PgOAuthCacheIo *io;
	PgOAuthCacheKeyPolicy key_policy;
	PgOAuthHttpFreshnessPolicy metadata_freshness;
	PgOAuthHttpFreshnessPolicy jwks_freshness;
	int64_t		jwks_stale_grace_ms;
	int64_t		unknown_kid_refresh_cooldown_ms;
	int64_t		refresh_wait_timeout_ms;
} PgOAuthIssuerKeyCachePolicy;

extern PgOAuthIssuerKeyError pg_oauth_issuer_key_fetch(
													   const char *metadata_url, const char *expected_issuer, const char *key_id,
													   uint32_t token_algorithm, const PgOAuthIssuerKeyPolicy *policy,
													   PgOAuthIssuerKeyResult *result);
extern PgOAuthIssuerKeyError pg_oauth_issuer_key_fetch_cached(
															  const char *metadata_url, const char *expected_issuer, const char *key_id,
															  uint32_t token_algorithm, const PgOAuthIssuerKeyPolicy *policy,
															  const PgOAuthIssuerKeyCachePolicy *cache_policy, int64_t now_ms,
															  int64_t response_time_seconds, PgOAuthIssuerKeyResult *result);
extern void pg_oauth_issuer_key_result_clear(PgOAuthIssuerKeyResult *result);
extern const char *pg_oauth_issuer_key_error_code(PgOAuthIssuerKeyError error);

#endif
