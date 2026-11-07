#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "http_freshness.h"

static const int64_t RESPONSE_TIME = 784111787;

static void
fail(const char *message)
{
	fprintf(stderr, "http_freshness_test: %s\n", message);
	exit(EXIT_FAILURE);
}

static PgOAuthHttpFreshness
calculate(const char *cache_control, const char *date, const char *expires,
		  const char *age)
{
	PgOAuthHttpFreshnessPolicy policy = {300000, 3600000, 0};
	PgOAuthHttpFreshness result;

	if (pg_oauth_http_freshness_calculate(cache_control, date, expires, age,
										  RESPONSE_TIME, &policy, &result) != PG_OAUTH_HTTP_FRESHNESS_OK)
		fail("valid freshness headers were rejected");
	return result;
}

/*
 * ADR 0002: unusable freshness is "immediately stale", never an error. The
 * response may serve the request that fetched it but is not reusable without
 * revalidation.
 */
static PgOAuthHttpFreshness
expect_stale(const char *cache_control, const char *date, const char *expires,
			 const char *age, const char *message)
{
	PgOAuthHttpFreshness result = calculate(cache_control, date, expires, age);

	if (result.ttl_ms != 0 || !result.explicit_freshness ||
		!result.revalidation_required)
		fail(message);
	return result;
}

int
main(void)
{
	PgOAuthHttpFreshness result;
	PgOAuthHttpFreshnessPolicy bad_policy = {2000, 1000, 0};

	result = calculate(NULL, NULL, NULL, NULL);
	if (result.ttl_ms != 300000 || result.explicit_freshness ||
		!result.cacheable || result.revalidation_required)
		fail("default freshness was calculated incorrectly");

	result = calculate("public, max-age=120", NULL, NULL, "20");
	if (result.ttl_ms != 100000 || !result.explicit_freshness)
		fail("max-age and Age were not combined");
	result = calculate("MAX-AGE=\"7200\"", NULL, NULL, NULL);
	if (result.ttl_ms != 3600000)
		fail("quoted or capped max-age was handled incorrectly");
	result = calculate("max-age=20", NULL, NULL, "20");
	if (result.ttl_ms != 0)
		fail("age equality extended freshness");

	result = calculate("no-store, max-age=60", NULL, NULL, NULL);
	if (result.cacheable)
		fail("no-store response was cacheable");
	result = calculate("no-cache, max-age=60", NULL, NULL, NULL);
	if (result.ttl_ms != 0 || !result.revalidation_required)
		fail("no-cache did not require immediate revalidation");
	result = calculate("must-revalidate, max-age=60", NULL, NULL, NULL);
	if (result.ttl_ms != 60000 || !result.revalidation_required)
		fail("must-revalidate incorrectly removed fresh use");

	result = calculate(NULL, "Sun, 06 Nov 1994 08:49:37 GMT",
					   "Sun, 06 Nov 1994 08:51:37 GMT", "20");
	if (result.ttl_ms != 100000 || !result.explicit_freshness)
		fail("Expires freshness was calculated incorrectly");
	result = calculate("max-age=60", "Sun, 06 Nov 1994 08:48:37 GMT",
					   NULL, "10");
	if (result.ttl_ms != 0)
		fail("apparent response age was ignored");

	/* Malformed or conflicting directives (RFC 9111 section 4.2.1). */
	expect_stale("max-age=1,max-age=2", NULL, NULL, NULL,
				 "duplicate max-age was trusted");
	expect_stale("max-age=60, max-age=60", NULL, NULL, NULL,
				 "identical duplicate max-age was trusted");
	expect_stale("max-age=invalid", NULL, NULL, NULL,
				 "malformed max-age was trusted");
	expect_stale("max-age=", NULL, NULL, NULL, "empty max-age was trusted");
	expect_stale("max-age", NULL, NULL, NULL, "valueless max-age was trusted");
	expect_stale("max-age=-5", NULL, NULL, NULL,
				 "negative max-age was trusted");
	expect_stale("max-age=60", NULL, NULL, "1,2",
				 "ambiguous Age was trusted");
	expect_stale("max-age=60", NULL, NULL, "abc", "malformed Age was trusted");
	result = expect_stale("no-store=value", NULL, NULL, NULL,
						  "valued no-store was trusted");
	if (result.cacheable)
		fail("valued no-store was cacheable");
	result = expect_stale("max-age=bad, no-store", NULL, NULL, NULL,
						  "no-store after a malformed directive was ignored");
	if (result.cacheable)
		fail("no-store after a malformed directive was cacheable");
	result = expect_stale("no-store, max-age=bad", NULL, NULL, NULL,
						  "no-store before a malformed directive was ignored");
	if (result.cacheable)
		fail("no-store before a malformed directive was cacheable");
	result = expect_stale("must-revalidate=1", NULL, NULL, NULL,
						  "valued must-revalidate was trusted");
	expect_stale("max-age=60\x01", NULL, NULL, NULL,
				 "control character in Cache-Control was trusted");

	/* RFC 9110 section 5.6.1.2: empty list elements are ignored. */
	result = calculate("max-age=60,", NULL, NULL, NULL);
	if (result.ttl_ms != 60000 || result.revalidation_required)
		fail("trailing comma changed freshness");
	result = calculate(", ,max-age=60,,public", NULL, NULL, NULL);
	if (result.ttl_ms != 60000 || result.revalidation_required)
		fail("empty list elements changed freshness");

	/* RFC 9111 section 1.2.2: overflowing delta-seconds saturate. */
	result = calculate("max-age=99999999999999999999999999", NULL, NULL, NULL);
	if (result.ttl_ms != 3600000 || result.revalidation_required)
		fail("overflowing max-age was not saturated and capped");
	result = calculate("max-age=2147483649", NULL, NULL, NULL);
	if (result.ttl_ms != 3600000)
		fail("max-age above 2^31 was not saturated and capped");
	result = calculate("max-age=60", NULL, NULL, "99999999999999999999999999");
	if (result.ttl_ms != 0 || result.revalidation_required)
		fail("overflowing Age did not make the response stale");

	/* RFC 9111 section 5.3: an invalid Expires is a time in the past. */
	{
		static const char *const past[] = {"0", "-1", "invalid", "Sun, 06 Nov 1994 08:49:37 GMT"};

		for (size_t i = 0; i < sizeof(past) / sizeof(past[0]); i++)
		{
			result = calculate(NULL, "Sun, 06 Nov 1994 08:49:37 GMT", past[i],
							   NULL);
			if (result.ttl_ms != 0 || !result.explicit_freshness ||
				!result.cacheable)
				fail("an expired or invalid Expires was treated as fresh");
			result = calculate(NULL, NULL, past[i], NULL);
			if (result.ttl_ms != 0 || !result.explicit_freshness)
				fail("an invalid Expires without Date was treated as fresh");
		}
	}
	/* max-age wins over Expires, so a bad Expires beside it is irrelevant. */
	result = calculate("max-age=60", NULL, "0", NULL);
	if (result.ttl_ms != 60000)
		fail("max-age did not take precedence over an invalid Expires");

	/* An invalid Date is ignored; the local receive time stands in for it. */
	result = calculate("max-age=60", "invalid-date", NULL, NULL);
	if (result.ttl_ms != 60000 || result.revalidation_required)
		fail("an invalid Date changed max-age freshness");
	result = calculate(NULL, "invalid-date", "also-invalid", NULL);
	if (result.ttl_ms != 0 || !result.explicit_freshness)
		fail("malformed HTTP dates were treated as fresh");

	/*
	 * Minimum retention: responses that would be refetched on every login are
	 * kept for the floor, but a positive provider lifetime is never raised.
	 */
	{
		PgOAuthHttpFreshnessPolicy floor_policy = {300000, 3600000, 30000};
		PgOAuthHttpFreshness floored;
		PgOAuthHttpFreshnessPolicy invalid_floor = {300000, 3600000, 3600001};
		PgOAuthHttpFreshnessPolicy negative_floor = {300000, 3600000, -1};

#define FLOORED(cc, exp, age) \
	(pg_oauth_http_freshness_calculate(cc, NULL, exp, age, RESPONSE_TIME, \
									   &floor_policy, &floored) == PG_OAUTH_HTTP_FRESHNESS_OK)

		if (!FLOORED("no-store, max-age=60", NULL, NULL) ||
			!floored.cacheable || floored.ttl_ms != 30000)
			fail("no-store was not retained for the minimum only");
		if (!FLOORED("no-store", NULL, NULL) || !floored.cacheable ||
			floored.ttl_ms != 30000)
			fail("no-store without freshness was retained longer than the minimum");
		if (!FLOORED("no-store, max-age=10", NULL, NULL) ||
			!floored.cacheable || floored.ttl_ms != 10000)
			fail("a shorter no-store lifetime was raised to the minimum");
		if (!FLOORED("no-cache", NULL, NULL) || !floored.cacheable ||
			floored.ttl_ms != 30000 || !floored.revalidation_required)
			fail("no-cache was not retained for the minimum with revalidation");
		if (!FLOORED("max-age=0", NULL, NULL) || floored.ttl_ms != 30000)
			fail("max-age=0 was not retained for the minimum");
		if (!FLOORED("max-age=1, max-age=2", NULL, NULL) ||
			floored.ttl_ms != 30000 || !floored.revalidation_required)
			fail("unusable freshness was not retained for the minimum");
		if (!FLOORED(NULL, "0", NULL) || floored.ttl_ms != 30000)
			fail("an invalid Expires was not retained for the minimum");
		if (!FLOORED("max-age=5", NULL, NULL) || floored.ttl_ms != 5000)
			fail("a positive provider lifetime was raised to the minimum");
		if (!FLOORED("max-age=120", NULL, NULL) || floored.ttl_ms != 120000)
			fail("a longer provider lifetime was altered by the minimum");
		if (!FLOORED(NULL, NULL, NULL) || floored.ttl_ms != 300000 ||
			floored.explicit_freshness)
			fail("the default lifetime was altered by the minimum");
		if (!FLOORED("max-age=60", NULL, "60") || floored.ttl_ms != 30000)
			fail("an Age-exhausted lifetime was not retained for the minimum");
		if (pg_oauth_http_freshness_calculate(NULL, NULL, NULL, NULL,
											  RESPONSE_TIME, &invalid_floor, &floored) !=
			PG_OAUTH_HTTP_FRESHNESS_INVALID_ARGUMENT ||
			pg_oauth_http_freshness_calculate(NULL, NULL, NULL, NULL,
											  RESPONSE_TIME, &negative_floor, &floored) !=
			PG_OAUTH_HTTP_FRESHNESS_INVALID_ARGUMENT)
			fail("an out-of-range minimum was accepted");
#undef FLOORED
	}

	if (pg_oauth_http_freshness_calculate(NULL, NULL, NULL, NULL,
										  RESPONSE_TIME, &bad_policy, &result) !=
		PG_OAUTH_HTTP_FRESHNESS_INVALID_ARGUMENT)
		fail("inconsistent local freshness bounds were accepted");
	if (strcmp(pg_oauth_http_freshness_error_code(
												  PG_OAUTH_HTTP_FRESHNESS_INVALID_ARGUMENT),
			   "http_freshness_invalid_argument") != 0)
		fail("stable freshness error code changed");
	return EXIT_SUCCESS;
}
