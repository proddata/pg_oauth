#include "issuer_key.h"

#include <stdlib.h>
#include <string.h>

void
pg_oauth_issuer_key_result_clear(PgOAuthIssuerKeyResult *result)
{
	if (result == NULL)
		return;
	pg_oauth_selected_jwk_clear(&result->selected);
	memset(result, 0, sizeof(*result));
}

PgOAuthIssuerKeyError
pg_oauth_issuer_key_fetch(const char *metadata_url,
						  const char *expected_issuer, const char *key_id,
						  uint32_t token_algorithm,
						  const PgOAuthIssuerKeyPolicy *policy,
						  PgOAuthIssuerKeyResult *result)
{
	return pg_oauth_issuer_key_fetch_cached(metadata_url, expected_issuer,
											key_id, token_algorithm, policy, NULL, 0, 0, result);
}

static bool
cache_policy_valid(const PgOAuthIssuerKeyCachePolicy *policy)
{
	return policy != NULL && policy->io != NULL &&
		policy->io->lookup != NULL && policy->io->begin_refresh != NULL &&
		policy->io->complete_refresh != NULL &&
		(policy->refresh_wait_timeout_ms == 0 ||
		 policy->io->wait_refresh != NULL) &&
		policy->metadata_freshness.default_ttl_ms >= 0 &&
		policy->metadata_freshness.maximum_ttl_ms > 0 &&
		policy->jwks_freshness.default_ttl_ms >= 0 &&
		policy->jwks_freshness.maximum_ttl_ms > 0 &&
		policy->jwks_stale_grace_ms >= 0 &&
		policy->unknown_kid_refresh_cooldown_ms >= 0 &&
		policy->refresh_wait_timeout_ms >= 0;
}

static bool
complete_response(const PgOAuthIssuerKeyCachePolicy *policy,
				  const PgOAuthCacheRefresh *refresh, int64_t now_ms,
				  int64_t response_time_seconds,
				  const PgOAuthHttpFreshnessPolicy *freshness_policy,
				  int64_t stale_grace_ms, const PgOAuthHttpResponse *response)
{
	PgOAuthHttpFreshness freshness;

	if (pg_oauth_http_freshness_calculate(response->cache_control,
										  response->date, response->expires, response->age,
										  response_time_seconds, freshness_policy, &freshness) !=
		PG_OAUTH_HTTP_FRESHNESS_OK)
	{
		(void) policy->io->complete_refresh(policy->io->context, refresh,
											now_ms, false, false, false, 0, 0, NULL, 0);
		return false;
	}
	return policy->io->complete_refresh(policy->io->context, refresh, now_ms,
										true, freshness.cacheable, freshness.revalidation_required,
										freshness.ttl_ms, stale_grace_ms, response->body,
										response->body_length);
}

/*
 * Selection outcomes that say only "this token cannot use this document":
 * the whole document was parsed and bounded successfully (selection validates
 * the document before it looks at any key), and the failure concerns the
 * requested key identifier or its algorithm. Errors about the document itself
 * or about the key's contents are excluded.
 */
static bool
jwks_error_leaves_document_usable(PgOAuthJwksError error)
{
	return error == PG_OAUTH_JWKS_KEY_NOT_FOUND ||
		error == PG_OAUTH_JWKS_ALGORITHM_MISMATCH ||
		error == PG_OAUTH_JWKS_KEY_NOT_FOR_SIGNATURE;
}

PgOAuthIssuerKeyError
pg_oauth_issuer_key_fetch_cached(const char *metadata_url,
								 const char *expected_issuer, const char *key_id,
								 uint32_t token_algorithm,
								 const PgOAuthIssuerKeyPolicy *policy,
								 const PgOAuthIssuerKeyCachePolicy *cache_policy,
								 int64_t now_ms, int64_t response_time_seconds,
								 PgOAuthIssuerKeyResult *result)
{
	PgOAuthHttpResponse metadata_response;
	PgOAuthHttpResponse jwks_response;
	PgOAuthMetadata metadata;
	PgOAuthHttpPolicy jwks_http;
	PgOAuthCacheKeyPolicy key_policy;
	PgOAuthCacheKey metadata_key;
	PgOAuthCacheKey jwks_key;
	PgOAuthCacheIoLookup lookup;
	PgOAuthCacheRefresh refresh;
	PgOAuthCacheRefreshResult refresh_result;
	int64_t		cache_now_ms = now_ms;
	int64_t		elapsed_ms;
	unsigned char *cached = NULL;
	size_t		cached_capacity = 0;
	const char *metadata_body = NULL;
	size_t		metadata_length = 0;
	bool		use_cache = cache_policy_valid(cache_policy);
	bool		selected_from_stale = false;
	char	   *discovery_host = NULL;
	PgOAuthIssuerKeyError error;

	if (result == NULL)
		return PG_OAUTH_ISSUER_KEY_INVALID_ARGUMENT;
	memset(result, 0, sizeof(*result));
	memset(&metadata_response, 0, sizeof(metadata_response));
	memset(&jwks_response, 0, sizeof(jwks_response));
	memset(&metadata, 0, sizeof(metadata));
	if (metadata_url == NULL || expected_issuer == NULL || key_id == NULL ||
		policy == NULL || token_algorithm == 0)
		return PG_OAUTH_ISSUER_KEY_INVALID_ARGUMENT;
	if (cache_policy != NULL && !use_cache)
		return PG_OAUTH_ISSUER_KEY_INVALID_ARGUMENT;
	if (use_cache)
	{
		cached_capacity = policy->metadata_http.max_response_size;
		if (policy->jwks_http.max_response_size > cached_capacity)
			cached_capacity = policy->jwks_http.max_response_size;
		if (cached_capacity == 0 ||
			cached_capacity > PG_OAUTH_CACHE_MAX_PAYLOAD_SIZE ||
			(cached = malloc(cached_capacity)) == NULL)
		{
			error = PG_OAUTH_ISSUER_KEY_CACHE;
			goto done;
		}
		key_policy = cache_policy->key_policy;
		key_policy.resource = PG_OAUTH_CACHE_RESOURCE_METADATA;
		key_policy.issuer = expected_issuer;
		key_policy.metadata_url = metadata_url;
		key_policy.jwks_url = NULL;
		if (pg_oauth_cache_key_build(&key_policy, &metadata_key) !=
			PG_OAUTH_CACHE_KEY_OK)
		{
			error = PG_OAUTH_ISSUER_KEY_CACHE;
			goto done;
		}
		lookup = cache_policy->io->lookup(cache_policy->io->context,
										  metadata_key.data, metadata_key.length, now_ms, false, cached,
										  cached_capacity);
		if (lookup.freshness == PG_OAUTH_CACHE_FRESH &&
			lookup.copy_result == PG_OAUTH_CACHE_COPY_OK)
		{
			metadata_body = (const char *) cached;
			metadata_length = lookup.payload_length;
		}
		else
		{
			refresh_result = cache_policy->io->begin_refresh(
															 cache_policy->io->context, metadata_key.data, metadata_key.length,
															 now_ms, false, 0, &refresh);
			if (refresh_result == PG_OAUTH_CACHE_REFRESH_IN_PROGRESS &&
				cache_policy->refresh_wait_timeout_ms > 0 &&
				cache_policy->io->wait_refresh(cache_policy->io->context,
											   metadata_key.data, metadata_key.length,
											   cache_policy->refresh_wait_timeout_ms, &elapsed_ms))
			{
				if (elapsed_ms > INT64_MAX - cache_now_ms)
				{
					error = PG_OAUTH_ISSUER_KEY_CACHE;
					goto done;
				}
				cache_now_ms += elapsed_ms;
				lookup = cache_policy->io->lookup(cache_policy->io->context,
												  metadata_key.data, metadata_key.length, cache_now_ms, false, cached,
												  cached_capacity);
				if (lookup.freshness == PG_OAUTH_CACHE_FRESH &&
					lookup.copy_result == PG_OAUTH_CACHE_COPY_OK)
				{
					metadata_body = (const char *) cached;
					metadata_length = lookup.payload_length;
				}
				else
				{
					error = PG_OAUTH_ISSUER_KEY_CACHE;
					goto done;
				}
			}
			else if (refresh_result != PG_OAUTH_CACHE_REFRESH_STARTED)
			{
				error = PG_OAUTH_ISSUER_KEY_CACHE;
				goto done;
			}
			if (refresh_result == PG_OAUTH_CACHE_REFRESH_STARTED)
				result->http_error = pg_oauth_http_get_json(metadata_url,
															&policy->metadata_http, &metadata_response);
			if (refresh_result == PG_OAUTH_CACHE_REFRESH_STARTED &&
				result->http_error != PG_OAUTH_HTTP_OK)
			{
				(void) cache_policy->io->complete_refresh(
														  cache_policy->io->context, &refresh, now_ms, false, false,
														  false, 0, 0, NULL, 0);
				error = PG_OAUTH_ISSUER_KEY_METADATA_HTTP;
				goto done;
			}
			if (refresh_result == PG_OAUTH_CACHE_REFRESH_STARTED)
			{
				metadata_body = metadata_response.body;
				metadata_length = metadata_response.body_length;
			}
		}
	}
	else
	{
		result->http_error = pg_oauth_http_get_json(metadata_url,
													&policy->metadata_http, &metadata_response);
		if (result->http_error != PG_OAUTH_HTTP_OK)
		{
			error = PG_OAUTH_ISSUER_KEY_METADATA_HTTP;
			goto done;
		}
		metadata_body = metadata_response.body;
		metadata_length = metadata_response.body_length;
	}
	result->metadata_error = pg_oauth_metadata_parse(
													 metadata_body, metadata_length, expected_issuer,
													 &policy->metadata, &metadata);
	if (result->metadata_error != PG_OAUTH_METADATA_OK)
	{
		if (use_cache && metadata_response.body != NULL)
			(void) cache_policy->io->complete_refresh(cache_policy->io->context,
													  &refresh, now_ms, false, false, false, 0, 0, NULL, 0);
		error = PG_OAUTH_ISSUER_KEY_METADATA_INVALID;
		goto done;
	}
	if (use_cache && metadata_response.body != NULL &&
		!complete_response(cache_policy, &refresh, now_ms,
						   response_time_seconds, &cache_policy->metadata_freshness, 0,
						   &metadata_response))
	{
		error = PG_OAUTH_ISSUER_KEY_CACHE;
		goto done;
	}
	result->http_error = pg_oauth_http_url_host(metadata_url,
												policy->metadata_http.max_url_size,
												policy->metadata_http.allow_insecure_http, &discovery_host);
	if (result->http_error != PG_OAUTH_HTTP_OK)
	{
		error = PG_OAUTH_ISSUER_KEY_METADATA_HTTP;
		goto done;
	}

	jwks_http = policy->jwks_http;
	/* The trusted discovery endpoint's host is always the primary JWKS host. */
	jwks_http.allowed_host = discovery_host;
	if (use_cache)
	{
		key_policy = cache_policy->key_policy;
		key_policy.resource = PG_OAUTH_CACHE_RESOURCE_JWKS;
		key_policy.issuer = expected_issuer;
		key_policy.metadata_url = metadata_url;
		key_policy.jwks_url = metadata.jwks_uri;
		if (pg_oauth_cache_key_build(&key_policy, &jwks_key) !=
			PG_OAUTH_CACHE_KEY_OK)
		{
			error = PG_OAUTH_ISSUER_KEY_CACHE;
			goto done;
		}
		lookup = cache_policy->io->lookup(cache_policy->io->context,
										  jwks_key.data, jwks_key.length, cache_now_ms,
										  cache_policy->jwks_stale_grace_ms > 0, cached, cached_capacity);
		if (lookup.freshness != PG_OAUTH_CACHE_MISS &&
			lookup.copy_result == PG_OAUTH_CACHE_COPY_OK)
		{
			result->jwks_error = pg_oauth_jwks_select((const char *) cached,
													  lookup.payload_length, key_id, token_algorithm, &policy->jwks,
													  &result->selected);
			if (result->jwks_error == PG_OAUTH_JWKS_OK &&
				lookup.freshness == PG_OAUTH_CACHE_FRESH)
			{
				error = PG_OAUTH_ISSUER_KEY_OK;
				goto done;
			}
			if (result->jwks_error != PG_OAUTH_JWKS_OK &&
				result->jwks_error != PG_OAUTH_JWKS_KEY_NOT_FOUND)
			{
				error = PG_OAUTH_ISSUER_KEY_CACHE;
				goto done;
			}
			selected_from_stale = result->jwks_error == PG_OAUTH_JWKS_OK;
		}
		refresh_result = cache_policy->io->begin_refresh(
														 cache_policy->io->context, jwks_key.data, jwks_key.length, cache_now_ms,
														 result->jwks_error == PG_OAUTH_JWKS_KEY_NOT_FOUND,
														 cache_policy->unknown_kid_refresh_cooldown_ms, &refresh);
		if (!selected_from_stale &&
			refresh_result == PG_OAUTH_CACHE_REFRESH_IN_PROGRESS &&
			cache_policy->refresh_wait_timeout_ms > 0 &&
			cache_policy->io->wait_refresh(cache_policy->io->context,
										   jwks_key.data, jwks_key.length,
										   cache_policy->refresh_wait_timeout_ms, &elapsed_ms))
		{
			if (elapsed_ms > INT64_MAX - cache_now_ms)
			{
				error = PG_OAUTH_ISSUER_KEY_CACHE;
				goto done;
			}
			cache_now_ms += elapsed_ms;
			lookup = cache_policy->io->lookup(cache_policy->io->context,
											  jwks_key.data, jwks_key.length, cache_now_ms,
											  cache_policy->jwks_stale_grace_ms > 0, cached, cached_capacity);
			if (lookup.freshness != PG_OAUTH_CACHE_MISS &&
				lookup.copy_result == PG_OAUTH_CACHE_COPY_OK)
			{
				result->jwks_error = pg_oauth_jwks_select((const char *) cached,
														  lookup.payload_length, key_id, token_algorithm, &policy->jwks,
														  &result->selected);
				if (result->jwks_error == PG_OAUTH_JWKS_OK)
				{
					error = PG_OAUTH_ISSUER_KEY_OK;
					goto done;
				}
			}
			error = PG_OAUTH_ISSUER_KEY_CACHE;
			goto done;
		}
		if (refresh_result != PG_OAUTH_CACHE_REFRESH_STARTED)
		{
			if (selected_from_stale)
			{
				error = PG_OAUTH_ISSUER_KEY_OK;
				goto done;
			}
			error = PG_OAUTH_ISSUER_KEY_CACHE;
			goto done;
		}
	}
	result->http_error = pg_oauth_http_get_json(metadata.jwks_uri,
												&jwks_http, &jwks_response);
	if (result->http_error != PG_OAUTH_HTTP_OK)
	{
		if (use_cache)
			(void) cache_policy->io->complete_refresh(cache_policy->io->context,
													  &refresh, cache_now_ms, false, false, false, 0, 0, NULL, 0);
		if (selected_from_stale)
		{
			error = PG_OAUTH_ISSUER_KEY_OK;
			goto done;
		}
		error = PG_OAUTH_ISSUER_KEY_JWKS_HTTP;
		goto done;
	}

	/*
	 * A fresh JWKS document is authoritative from here on: discard any key
	 * selected from the stale copy so a later failure cannot accept it.
	 */
	if (selected_from_stale)
		pg_oauth_selected_jwk_clear(&result->selected);
	result->jwks_error = pg_oauth_jwks_select(
											  jwks_response.body, jwks_response.body_length, key_id, token_algorithm,
											  &policy->jwks, &result->selected);
	if (result->jwks_error != PG_OAUTH_JWKS_OK)
	{
		if (use_cache)
		{
			/*
			 * A document that is well-formed but cannot serve this token's
			 * key is still the provider's current key set. Discarding it
			 * would leave the cache empty, so the unknown-key cooldown could
			 * never apply and every hostile token would cost two provider
			 * requests. Publishing is safe: cached bytes are parsed and
			 * checked again on every lookup, and this token is denied either
			 * way. Anything else (malformed document, private key material)
			 * is never retained.
			 */
			if (jwks_error_leaves_document_usable(result->jwks_error))
				(void) complete_response(cache_policy, &refresh, cache_now_ms,
										 response_time_seconds,
										 &cache_policy->jwks_freshness,
										 cache_policy->jwks_stale_grace_ms,
										 &jwks_response);
			else
				(void) cache_policy->io->complete_refresh(cache_policy->io->context,
														  &refresh, cache_now_ms, false, false, false, 0, 0, NULL, 0);
		}
		error = PG_OAUTH_ISSUER_KEY_JWKS_INVALID;
		goto done;
	}
	if (use_cache && !complete_response(cache_policy, &refresh, cache_now_ms,
										response_time_seconds, &cache_policy->jwks_freshness,
										cache_policy->jwks_stale_grace_ms, &jwks_response))
	{
		error = PG_OAUTH_ISSUER_KEY_CACHE;
		goto done;
	}
	error = PG_OAUTH_ISSUER_KEY_OK;

done:
	pg_oauth_http_response_clear(&metadata_response);
	pg_oauth_http_response_clear(&jwks_response);
	pg_oauth_metadata_clear(&metadata);
	free(discovery_host);
	free(cached);
	return error;
}

const char *
pg_oauth_issuer_key_error_code(PgOAuthIssuerKeyError error)
{
	switch (error)
	{
		case PG_OAUTH_ISSUER_KEY_OK:
			return "issuer_key_ok";
		case PG_OAUTH_ISSUER_KEY_INVALID_ARGUMENT:
			return "issuer_key_invalid_argument";
		case PG_OAUTH_ISSUER_KEY_METADATA_HTTP:
			return "issuer_key_metadata_http";
		case PG_OAUTH_ISSUER_KEY_METADATA_INVALID:
			return "issuer_key_metadata_invalid";
		case PG_OAUTH_ISSUER_KEY_JWKS_HTTP:
			return "issuer_key_jwks_http";
		case PG_OAUTH_ISSUER_KEY_JWKS_INVALID:
			return "issuer_key_jwks_invalid";
		case PG_OAUTH_ISSUER_KEY_CACHE:
			return "issuer_key_cache";
	}
	return "issuer_key_unknown_error";
}
