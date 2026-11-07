/*
 * Fuzz HTTP freshness calculation (RFC 9111): the Cache-Control, Date,
 * Expires and Age header values decide how long fetched provider keys are
 * trusted, so a mistake here lengthens or shortens key trust.
 *
 * Input layout: one byte says which of the four headers are absent (NULL
 * rather than empty), three bytes pick the default, maximum and minimum
 * lifetimes from a table, four bytes are the response time in seconds, and the
 * rest is split on newlines into Cache-Control, Date, Expires and Age.
 *
 * Besides memory safety, each result is checked against properties that do not
 * restate the parser. Comparing the minimum-lifetime policy with a strict run
 * (minimum zero) of the same headers, the minimum may only fill a zero lifetime
 * or cap a no-store one and never changes a revalidation requirement or touches
 * a positive, cacheable provider lifetime. In strict mode, an added Age header
 * or a later response time can never lengthen freshness. The lifetime is always
 * within the configured maximum.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "http_freshness.h"

#define FUZZ_MAX_INPUT 4096
#define FIXED_BYTES 8
#define FIELDS 4

#define REQUIRE(condition) \
	do { \
		if (!(condition)) \
			abort(); \
	} while (0)

static const int64_t lifetimes[] = {
	0, 1, 1000, 30000, 300000, 3600000, 86400000, INT64_MAX / 2, INT64_MAX
};

#define LIFETIME_COUNT (sizeof(lifetimes) / sizeof(lifetimes[0]))

static bool
same(const PgOAuthHttpFreshness *a, const PgOAuthHttpFreshness *b)
{
	return a->ttl_ms == b->ttl_ms && a->cacheable == b->cacheable &&
		a->revalidation_required == b->revalidation_required &&
		a->explicit_freshness == b->explicit_freshness;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char		buffer[FUZZ_MAX_INPUT + 1];
	const char *fields[FIELDS];
	size_t		count = 0;
	char	   *cursor;
	PgOAuthHttpFreshnessPolicy policy;
	PgOAuthHttpFreshnessPolicy strict;
	PgOAuthHttpFreshness floored;
	PgOAuthHttpFreshness plain;
	PgOAuthHttpFreshness again;
	PgOAuthHttpFreshness without_age;
	PgOAuthHttpFreshness later;
	PgOAuthHttpFreshnessError floored_error;
	PgOAuthHttpFreshnessError strict_error;
	int64_t		response_time;

	if (size < FIXED_BYTES || size > FUZZ_MAX_INPUT)
		return 0;
	memcpy(buffer, data + FIXED_BYTES, size - FIXED_BYTES);
	buffer[size - FIXED_BYTES] = '\0';

	for (cursor = buffer; count < FIELDS;)
	{
		fields[count++] = cursor;
		cursor = strchr(cursor, '\n');
		if (cursor == NULL)
			break;
		*cursor++ = '\0';
	}
	for (size_t i = count; i < FIELDS; i++)
		fields[i] = "";
	for (size_t i = 0; i < FIELDS; i++)
	{
		if ((data[0] >> i) & 1)
			fields[i] = NULL;
	}

	policy.default_ttl_ms = lifetimes[data[1] % LIFETIME_COUNT];
	policy.maximum_ttl_ms = lifetimes[data[2] % LIFETIME_COUNT];
	policy.minimum_ttl_ms = lifetimes[data[3] % LIFETIME_COUNT];
	response_time = (int64_t) (((uint32_t) data[4] << 24) | ((uint32_t) data[5] << 16) |
							   ((uint32_t) data[6] << 8) | data[7]);
	if (data[0] & 0x80)
		response_time = -1 - (response_time & 1) * (INT64_MAX - 1);
	else if (data[0] & 0x40)
		response_time = INT64_MAX / 2 + response_time;
	strict = policy;
	strict.minimum_ttl_ms = 0;

	floored_error = pg_oauth_http_freshness_calculate(fields[0], fields[1], fields[2],
													  fields[3], response_time, &policy, &floored);
	strict_error = pg_oauth_http_freshness_calculate(fields[0], fields[1], fields[2],
													 fields[3], response_time, &strict, &plain);
	if (floored_error != PG_OAUTH_HTTP_FRESHNESS_OK)
	{
		/* An invalid argument leaves a zeroed result: nothing usable. */
		REQUIRE(floored.ttl_ms == 0 && !floored.cacheable &&
				!floored.revalidation_required && !floored.explicit_freshness);
		return 0;
	}
	/* Only the minimum differs, so the strict run cannot reject what passed. */
	REQUIRE(strict_error == PG_OAUTH_HTTP_FRESHNESS_OK);

	/* Deterministic. */
	REQUIRE(pg_oauth_http_freshness_calculate(fields[0], fields[1], fields[2],
											  fields[3], response_time, &policy, &again) ==
			PG_OAUTH_HTTP_FRESHNESS_OK);
	REQUIRE(same(&floored, &again));

	/* Lifetimes stay within the configured maximum, and are never negative. */
	REQUIRE(plain.ttl_ms >= 0 && plain.ttl_ms <= policy.maximum_ttl_ms);
	REQUIRE(floored.ttl_ms >= 0 && floored.ttl_ms <= policy.maximum_ttl_ms);

	/* The minimum never changes whether the response must be revalidated. */
	REQUIRE(floored.revalidation_required == plain.revalidation_required);
	REQUIRE(floored.explicit_freshness == plain.explicit_freshness);

	/* Zero minimum is exactly strict RFC 9111 behaviour. */
	if (policy.minimum_ttl_ms == 0)
		REQUIRE(same(&floored, &plain));

	/* A positive, cacheable provider lifetime is never altered. */
	if (plain.cacheable && plain.ttl_ms > 0)
		REQUIRE(same(&floored, &plain));

	/* A zero lifetime is filled with the minimum, no more. */
	if (plain.cacheable && plain.ttl_ms == 0 && policy.minimum_ttl_ms > 0)
		REQUIRE(floored.cacheable && floored.ttl_ms == policy.minimum_ttl_ms);

	/* A no-store response is retained for at most the minimum, and no longer. */
	if (!plain.cacheable && policy.minimum_ttl_ms > 0)
		REQUIRE(floored.cacheable && floored.ttl_ms > 0 &&
				floored.ttl_ms <= policy.minimum_ttl_ms);
	if (!plain.cacheable && policy.minimum_ttl_ms == 0)
		REQUIRE(!floored.cacheable);

	/* An Age header only consumes lifetime. */
	REQUIRE(pg_oauth_http_freshness_calculate(fields[0], fields[1], fields[2], NULL,
											  response_time, &strict, &without_age) ==
			PG_OAUTH_HTTP_FRESHNESS_OK);
	REQUIRE(plain.ttl_ms <= without_age.ttl_ms);

	/* A later response time only consumes lifetime. */
	if (response_time < INT64_MAX - 100000)
	{
		REQUIRE(pg_oauth_http_freshness_calculate(fields[0], fields[1], fields[2],
												  fields[3], response_time + 100000, &strict, &later) ==
				PG_OAUTH_HTTP_FRESHNESS_OK);
		REQUIRE(later.ttl_ms <= plain.ttl_ms);
	}
	return 0;
}
