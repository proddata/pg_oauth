#include "http_freshness.h"

#include <ctype.h>
#include <limits.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include <curl/curl.h>

typedef struct CacheControlValues
{
	int64_t		max_age_seconds;
	bool		has_max_age;
	bool		no_store;
	bool		no_cache;
	bool		must_revalidate;
	bool		malformed;
} CacheControlValues;

/*
 * RFC 9111 section 1.2.2: a delta-seconds value above what a cache can
 * represent is treated as 2^31 seconds, not as an error.
 */
#define DELTA_SECONDS_LIMIT INT64_C(2147483648)

static void
trim(const char **start, const char **end)
{
	while (*start < *end && (**start == ' ' || **start == '\t'))
		(*start)++;
	while (*end > *start && ((*end)[-1] == ' ' || (*end)[-1] == '\t'))
		(*end)--;
}

static bool
decimal		(const char *start, const char *end, int64_t *value)
{
	int64_t		parsed = 0;

	if (start == end)
		return false;
	for (const char *cursor = start; cursor < end; cursor++)
	{
		if (*cursor < '0' || *cursor > '9')
			return false;
		if (parsed < DELTA_SECONDS_LIMIT)
			parsed = parsed * 10 + (*cursor - '0');
		if (parsed > DELTA_SECONDS_LIMIT)
			parsed = DELTA_SECONDS_LIMIT;
	}
	*value = parsed;
	return true;
}

static bool
directive_name(const char *start, const char *end, const char *name)
{
	size_t		length = (size_t) (end - start);

	return strlen(name) == length && strncasecmp(start, name, length) == 0;
}

/*
 * Interpret one list element. Returns false when the element is malformed;
 * the caller keeps scanning so a later no-store or no-cache is still honored.
 */
static bool
parse_directive(const char *entry, const char *item_end,
				CacheControlValues *parsed)
{
	const char *equals;
	const char *name_end;

	for (const char *cursor = entry; cursor < item_end; cursor++)
	{
		unsigned char byte = (unsigned char) *cursor;

		if (byte < 0x20 || byte >= 0x7f)
			return false;
	}
	equals = memchr(entry, '=', (size_t) (item_end - entry));
	name_end = equals != NULL ? equals : item_end;
	while (name_end > entry &&
		   (name_end[-1] == ' ' || name_end[-1] == '\t'))
		name_end--;
	if (name_end == entry)
		return false;

	if (directive_name(entry, name_end, "no-store"))
	{
		/* An argument is invalid, but never lets the response be stored. */
		parsed->no_store = true;
		return equals == NULL;
	}
	if (directive_name(entry, name_end, "no-cache"))
	{
		/*
		 * Field-name arguments are irrelevant to this whole-response cache.
		 */
		parsed->no_cache = true;
		return true;
	}
	if (directive_name(entry, name_end, "must-revalidate"))
	{
		parsed->must_revalidate = true;
		return equals == NULL;
	}
	if (directive_name(entry, name_end, "max-age"))
	{
		const char *number_start;
		const char *number_end;

		/* RFC 9111 section 4.2.1: duplicates make the response stale. */
		if (parsed->has_max_age)
			return false;
		parsed->has_max_age = true;
		if (equals == NULL)
			return false;
		number_start = equals + 1;
		number_end = item_end;
		trim(&number_start, &number_end);
		if (number_end - number_start >= 2 && number_start[0] == '"' &&
			number_end[-1] == '"')
		{
			number_start++;
			number_end--;
		}
		return decimal (number_start, number_end, &parsed->max_age_seconds);
	}
	return true;
}

/*
 * Sets parsed->malformed instead of failing: ADR 0002 treats unusable
 * freshness as immediately stale, never as a reason to deny the login.
 * Empty list elements are ignored (RFC 9110 section 5.6.1.2).
 */
static void
parse_cache_control(const char *value, CacheControlValues *parsed)
{
	const char *entry;

	memset(parsed, 0, sizeof(*parsed));
	if (value == NULL || value[0] == '\0')
		return;
	entry = value;
	while (*entry != '\0')
	{
		const char *end = strchr(entry, ',');
		const char *item_end = end != NULL ? end : entry + strlen(entry);

		trim(&entry, &item_end);
		if (entry != item_end && !parse_directive(entry, item_end, parsed))
			parsed->malformed = true;
		if (end == NULL)
			break;
		entry = end + 1;
	}
}

static bool
parse_age(const char *value, int64_t *seconds)
{
	const char *start;
	const char *end;

	*seconds = 0;
	if (value == NULL || value[0] == '\0')
		return true;
	start = value;
	end = value + strlen(value);
	trim(&start, &end);
	return decimal (start, end, seconds);
}

static int64_t
seconds_to_milliseconds(int64_t seconds)
{
	if (seconds > INT64_MAX / 1000)
		return INT64_MAX;
	return seconds * 1000;
}

static PgOAuthHttpFreshnessError
calculate_provider_freshness(const char *cache_control, const char *date,
							 const char *expires, const char *age,
							 int64_t response_time_seconds,
							 const PgOAuthHttpFreshnessPolicy *policy,
							 PgOAuthHttpFreshness *result)
{
	CacheControlValues control;
	int64_t		age_seconds;
	int64_t		freshness_seconds = 0;
	bool		explicit_freshness = false;

	if (result == NULL)
		return PG_OAUTH_HTTP_FRESHNESS_INVALID_ARGUMENT;
	memset(result, 0, sizeof(*result));
	if (policy == NULL || response_time_seconds < 0 ||
		policy->default_ttl_ms < 0 || policy->maximum_ttl_ms < 0 ||
		policy->default_ttl_ms > policy->maximum_ttl_ms)
		return PG_OAUTH_HTTP_FRESHNESS_INVALID_ARGUMENT;
	parse_cache_control(cache_control, &control);
	if (!parse_age(age, &age_seconds))
		control.malformed = true;

	result->cacheable = !control.no_store;
	result->revalidation_required = control.no_cache || control.must_revalidate;
	if (control.malformed)
	{
		/*
		 * Conflicting or unparsable directives: the response may serve the
		 * request that fetched it but is not reusable without revalidation.
		 */
		result->revalidation_required = true;
		result->explicit_freshness = true;
		return PG_OAUTH_HTTP_FRESHNESS_OK;
	}
	if (control.has_max_age)
	{
		freshness_seconds = control.max_age_seconds;
		explicit_freshness = true;
	}
	else if (expires != NULL && expires[0] != '\0')
	{
		time_t		expires_at = curl_getdate(expires, NULL);
		time_t		date_at = date != NULL && date[0] != '\0' ?
			curl_getdate(date, NULL) : (time_t) -1;

		/*
		 * RFC 9111 section 5.3: an invalid Expires, "0" included, means a
		 * time in the past. An invalid Date is ignored in favor of the time
		 * this validator received the response.
		 */
		if (date_at == (time_t) -1)
			date_at = (time_t) response_time_seconds;
		if (expires_at != (time_t) -1 && expires_at > date_at)
			freshness_seconds = (int64_t) (expires_at - date_at);
		explicit_freshness = true;
	}

	result->explicit_freshness = explicit_freshness;
	if (explicit_freshness)
	{
		int64_t		apparent_age = age_seconds;

		if (date != NULL && date[0] != '\0')
		{
			time_t		date_at = curl_getdate(date, NULL);

			if (date_at != (time_t) -1 &&
				response_time_seconds > (int64_t) date_at &&
				response_time_seconds - (int64_t) date_at > apparent_age)
				apparent_age = response_time_seconds - (int64_t) date_at;
		}
		if (apparent_age >= freshness_seconds)
			result->ttl_ms = 0;
		else
			result->ttl_ms = seconds_to_milliseconds(
													 freshness_seconds - apparent_age);
	}
	else
		result->ttl_ms = policy->default_ttl_ms;

	if (result->ttl_ms > policy->maximum_ttl_ms)
		result->ttl_ms = policy->maximum_ttl_ms;
	if (control.no_cache)
		result->ttl_ms = 0;
	return PG_OAUTH_HTTP_FRESHNESS_OK;
}

/*
 * A provider that forbids caching (or sends unusable headers) would otherwise
 * be fetched on every authentication, and concurrent logins would fail while
 * waiting for a refresh that publishes nothing. The key material is public, so
 * the response is retained for a short, administrator-set minimum instead.
 * The floor only fills a zero lifetime and caps a no-store response; it never
 * lengthens a positive lifetime the provider asked for.
 */
static void
apply_minimum_freshness(const PgOAuthHttpFreshnessPolicy *policy,
						PgOAuthHttpFreshness *result)
{
	if (policy->minimum_ttl_ms == 0)
		return;
	if (!result->cacheable)
	{
		result->cacheable = true;
		if (result->ttl_ms == 0 || result->ttl_ms > policy->minimum_ttl_ms)
			result->ttl_ms = policy->minimum_ttl_ms;
	}
	else if (result->ttl_ms == 0)
		result->ttl_ms = policy->minimum_ttl_ms;
}

PgOAuthHttpFreshnessError
pg_oauth_http_freshness_calculate(const char *cache_control, const char *date,
								  const char *expires, const char *age,
								  int64_t response_time_seconds,
								  const PgOAuthHttpFreshnessPolicy *policy,
								  PgOAuthHttpFreshness *result)
{
	PgOAuthHttpFreshnessError error;

	if (result == NULL)
		return PG_OAUTH_HTTP_FRESHNESS_INVALID_ARGUMENT;
	memset(result, 0, sizeof(*result));
	if (policy == NULL || policy->minimum_ttl_ms < 0 ||
		policy->minimum_ttl_ms > policy->maximum_ttl_ms)
		return PG_OAUTH_HTTP_FRESHNESS_INVALID_ARGUMENT;
	error = calculate_provider_freshness(cache_control, date, expires, age,
										 response_time_seconds, policy, result);
	if (error == PG_OAUTH_HTTP_FRESHNESS_OK)
		apply_minimum_freshness(policy, result);
	return error;
}

const char *
pg_oauth_http_freshness_error_code(PgOAuthHttpFreshnessError error)
{
	switch (error)
	{
		case PG_OAUTH_HTTP_FRESHNESS_OK:
			return "http_freshness_ok";
		case PG_OAUTH_HTTP_FRESHNESS_INVALID_ARGUMENT:
			return "http_freshness_invalid_argument";
	}
	return "http_freshness_unknown_error";
}
