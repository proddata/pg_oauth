/*
 * Fuzz the canonical cache key. The cache separates provider metadata and key
 * sets by this key, so two different validation policies must never share an
 * entry (one policy would then trust keys fetched under another), and one
 * policy must always map to the same entry.
 *
 * The harness builds a policy A from the input and a policy B derived from it
 * by one mutation: nothing, one byte moved across the boundary between two
 * adjacent string fields (the concatenation is unchanged, which is the classic
 * framing attack), a changed byte or appended byte in one string, two strings
 * swapped, or one numeric or boolean field changed. The only property checked
 * is: the keys are equal exactly when the policies are equal field by field.
 * Equality is decided here, not by the code under test. A key that cannot be
 * built must leave no bytes behind, and a built key stays within its bound.
 *
 * Input layout: four bytes choose the mutation, the resource and the position,
 * seventeen bytes choose the numeric settings from tables of boundary values,
 * and the rest is split on newlines into the ten string settings. Missing
 * strings take valid defaults.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cache_key.h"

#define FUZZ_MAX_INPUT 9000
#define STRING_FIELDS 10
#define NUMBER_FIELDS 19
#define NUMBER_BYTES 17
#define HEADER_BYTES 4
#define STRING_BUFFER 4200

#define REQUIRE(condition) \
	do { \
		if (!(condition)) \
			abort(); \
	} while (0)

/* The order in which the builder encodes the string fields. */
static const char **
string_field(PgOAuthCacheKeyPolicy *policy, size_t index)
{
	switch (index)
	{
		case 0:
			return &policy->issuer;
		case 1:
			return &policy->metadata_url;
		case 2:
			return &policy->jwks_url;
		case 3:
			return &policy->policy_name;
		case 4:
			return &policy->required_scopes;
		case 5:
			return &policy->audiences;
		case 6:
			return &policy->identity_claim;
		case 7:
			return &policy->role_claim;
		case 8:
			return &policy->allowed_jwks_hosts;
		default:
			return &policy->ca_file;
	}
}

static const uint32_t numbers32[] = {
	1, 2, 255, 256, 65535, 65536, 0x7fffffff, 0xffffffff
};
static const uint64_t numbers64[] = {
	0, 1, 255, 256, 0xffffffffULL, 0x100000000ULL, UINT64_MAX
};

#define N32(i) numbers32[(i) % (sizeof(numbers32) / sizeof(numbers32[0]))]
#define N64(i) numbers64[(i) % (sizeof(numbers64) / sizeof(numbers64[0]))]

/* Change numeric or boolean field number `index`, of NUMBER_FIELDS in total. */
static void
mutate_number(PgOAuthCacheKeyPolicy *policy, size_t index)
{
	switch (index % NUMBER_FIELDS)
	{
		case 0:
			policy->allowed_token_types = (uint8_t) (policy->allowed_token_types % 3 + 1);
			break;
		case 1:
			policy->allow_missing_token_type = !policy->allow_missing_token_type;
			break;
		case 2:
			policy->allowed_algorithms ^= 2;
			break;
		case 3:
			policy->clock_skew_ms++;
			break;
		case 4:
			policy->max_token_size++;
			break;
		case 5:
			policy->max_metadata_size++;
			break;
		case 6:
			policy->max_jwks_size++;
			break;
		case 7:
			policy->max_jwks_keys++;
			break;
		case 8:
			policy->minimum_rsa_bits++;
			break;
		case 9:
			policy->maximum_rsa_bits++;
			break;
		case 10:
			policy->jwks_stale_grace_ms++;
			break;
		case 11:
			policy->metadata_default_ttl_ms++;
			break;
		case 12:
			policy->jwks_default_ttl_ms++;
			break;
		case 13:
			policy->cache_max_ttl_ms++;
			break;
		case 14:
			policy->cache_min_ttl_ms++;
			break;
		case 15:
			policy->unknown_kid_refresh_cooldown_ms++;
			break;
		case 16:
			policy->allow_insecure_http = !policy->allow_insecure_http;
			break;
		case 17:
			policy->resource = policy->resource == PG_OAUTH_CACHE_RESOURCE_JWKS ?
				PG_OAUTH_CACHE_RESOURCE_METADATA : PG_OAUTH_CACHE_RESOURCE_JWKS;
			break;
		default:
			policy->max_jwks_keys ^= 0x80000000U;
			break;
	}
}

static const char *
string_or_empty(const char *value)
{
	return value != NULL ? value : "";
}

/* Field-by-field equality of everything the key is supposed to separate. */
static bool
policies_equal(const PgOAuthCacheKeyPolicy *a, const PgOAuthCacheKeyPolicy *b)
{
	PgOAuthCacheKeyPolicy x = *a;
	PgOAuthCacheKeyPolicy y = *b;

	for (size_t i = 0; i < STRING_FIELDS; i++)
	{
		if (strcmp(string_or_empty(*string_field(&x, i)), string_or_empty(*string_field(&y, i))) != 0)
			return false;
	}
	return a->resource == b->resource &&
		a->allowed_token_types == b->allowed_token_types &&
		a->allow_missing_token_type == b->allow_missing_token_type &&
		a->allowed_algorithms == b->allowed_algorithms &&
		a->clock_skew_ms == b->clock_skew_ms &&
		a->max_token_size == b->max_token_size &&
		a->max_metadata_size == b->max_metadata_size &&
		a->max_jwks_size == b->max_jwks_size &&
		a->max_jwks_keys == b->max_jwks_keys &&
		a->minimum_rsa_bits == b->minimum_rsa_bits &&
		a->maximum_rsa_bits == b->maximum_rsa_bits &&
		a->jwks_stale_grace_ms == b->jwks_stale_grace_ms &&
		a->metadata_default_ttl_ms == b->metadata_default_ttl_ms &&
		a->jwks_default_ttl_ms == b->jwks_default_ttl_ms &&
		a->cache_max_ttl_ms == b->cache_max_ttl_ms &&
		a->cache_min_ttl_ms == b->cache_min_ttl_ms &&
		a->unknown_kid_refresh_cooldown_ms == b->unknown_kid_refresh_cooldown_ms &&
		a->allow_insecure_http == b->allow_insecure_http;
}

static bool
keys_equal(const PgOAuthCacheKey *a, const PgOAuthCacheKey *b)
{
	return a->length == b->length && memcmp(a->data, b->data, a->length) == 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const char *const defaults[STRING_FIELDS] = {
		"https://idp.example/", "https://idp.example/.well-known/openid-configuration",
		"https://idp.example/jwks", "default", "connect:postgres",
		"postgres://primary", "sub", "", "", ""
	};
	static char owned[STRING_FIELDS][STRING_BUFFER];
	char		buffer[FUZZ_MAX_INPUT + 1];
	const char *fields[STRING_FIELDS];
	PgOAuthCacheKeyPolicy a;
	PgOAuthCacheKeyPolicy b;
	PgOAuthCacheKey key_a;
	PgOAuthCacheKey key_b;
	PgOAuthCacheKey again;
	PgOAuthCacheKeyError error_a;
	PgOAuthCacheKeyError error_b;
	size_t		count = 0;
	char	   *cursor;
	uint8_t		kind;
	uint8_t		position;
	uint8_t		variant;

	if (size < HEADER_BYTES + NUMBER_BYTES || size > FUZZ_MAX_INPUT)
		return 0;
	memcpy(buffer, data + HEADER_BYTES + NUMBER_BYTES, size - HEADER_BYTES - NUMBER_BYTES);
	buffer[size - HEADER_BYTES - NUMBER_BYTES] = '\0';
	for (cursor = buffer; count < STRING_FIELDS;)
	{
		fields[count++] = cursor;
		cursor = strchr(cursor, '\n');
		if (cursor == NULL)
			break;
		*cursor++ = '\0';
	}
	for (size_t i = count; i < STRING_FIELDS; i++)
		fields[i] = defaults[i];

	memset(&a, 0, sizeof(a));
	for (size_t i = 0; i < STRING_FIELDS; i++)
		*string_field(&a, i) = fields[i];
	kind = data[0] % 5;
	position = data[1];
	variant = data[2];
	a.resource = (data[3] & 1) ? PG_OAUTH_CACHE_RESOURCE_METADATA : PG_OAUTH_CACHE_RESOURCE_JWKS;
	{
		const uint8_t *n = data + HEADER_BYTES;

		a.allowed_token_types = (uint8_t) (n[0] % 3 + 1);
		a.allow_missing_token_type = n[1] & 1;
		a.allowed_algorithms = N32(n[2]);
		a.clock_skew_ms = N32(n[3]);
		a.max_token_size = N32(n[4]);
		a.max_metadata_size = N32(n[5]);
		a.max_jwks_size = N32(n[6]);
		a.max_jwks_keys = N32(n[7]);
		a.minimum_rsa_bits = N32(n[8]);
		a.maximum_rsa_bits = a.minimum_rsa_bits + (n[9] % 4) * 1024;
		a.jwks_stale_grace_ms = N64(n[10]);
		a.metadata_default_ttl_ms = N64(n[11]);
		a.jwks_default_ttl_ms = N64(n[12]);
		a.cache_max_ttl_ms = N64(n[13]);
		a.cache_min_ttl_ms = N64(n[14]);
		a.unknown_kid_refresh_cooldown_ms = N64(n[15]);
		a.allow_insecure_http = n[16] & 1;
	}

	b = a;
	switch (kind)
	{
		case 0:					/* identical */
			break;
		case 1:					/* move one byte across a field boundary */
			{
				size_t		left = position % (STRING_FIELDS - 1);
				const char *first = *string_field(&a, left);
				const char *second = *string_field(&a, left + 1);
				size_t		first_length = strlen(first);

				if (second[0] != '\0' && first_length + 2 < STRING_BUFFER)
				{
					memcpy(owned[0], first, first_length);
					owned[0][first_length] = second[0];
					owned[0][first_length + 1] = '\0';
					*string_field(&b, left) = owned[0];
					*string_field(&b, left + 1) = second + 1;
				}
				break;
			}
		case 2:					/* change or append one byte of one string */
			{
				size_t		index = position % STRING_FIELDS;
				const char *value = *string_field(&a, index);
				size_t		length = strlen(value);

				if (length + 2 >= STRING_BUFFER)
					break;
				memcpy(owned[1], value, length + 1);
				if (variant & 1 || length == 0)
				{
					owned[1][length] = (char) (variant | 1);
					owned[1][length + 1] = '\0';
				}
				else
					owned[1][variant % length] ^= (char) (1 + (variant >> 1) % 127);
				*string_field(&b, index) = owned[1];
				break;
			}
		case 3:					/* swap two strings */
			{
				size_t		one = position % STRING_FIELDS;
				size_t		two = variant % STRING_FIELDS;
				const char *held = *string_field(&b, one);

				*string_field(&b, one) = *string_field(&b, two);
				*string_field(&b, two) = held;
				break;
			}
		default:				/* change one numeric or boolean field */
			mutate_number(&b, position);
			break;
	}

	error_a = pg_oauth_cache_key_build(&a, &key_a);
	error_b = pg_oauth_cache_key_build(&b, &key_b);

	/* A key that was not built leaves nothing behind; a built one is bounded. */
	REQUIRE(error_a == PG_OAUTH_CACHE_KEY_OK ? key_a.length > 0 : key_a.length == 0);
	REQUIRE(error_b == PG_OAUTH_CACHE_KEY_OK ? key_b.length > 0 : key_b.length == 0);
	REQUIRE(key_a.length <= PG_OAUTH_CACHE_MAX_KEY_SIZE &&
			key_b.length <= PG_OAUTH_CACHE_MAX_KEY_SIZE);
	if (error_a != PG_OAUTH_CACHE_KEY_OK)
		return 0;

	/* Deterministic. */
	REQUIRE(pg_oauth_cache_key_build(&a, &again) == PG_OAUTH_CACHE_KEY_OK);
	REQUIRE(keys_equal(&key_a, &again));

	/* The keys are equal exactly when the policies are. */
	if (error_b == PG_OAUTH_CACHE_KEY_OK)
		REQUIRE(keys_equal(&key_a, &key_b) == policies_equal(&a, &b));
	return 0;
}
