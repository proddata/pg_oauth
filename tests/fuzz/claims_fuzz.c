/*
 * Fuzz claim validation under three policies, so the delegated-role and the
 * custom-identity paths are reached as well as the default one. Besides memory
 * safety, every accepted result is re-checked independently of the code under
 * test: the identity is a nonempty, bounded string that passes the shared text
 * rule, and with delegation the requested role really is listed in the claim.
 */
#include <stdlib.h>
#include <string.h>

#include <stddef.h>
#include <stdint.h>

#include <jansson.h>

#include "claims.h"
#include "identity_text.h"

#define REQUIRE(condition) \
	do { \
		if (!(condition)) \
			abort(); \
	} while (0)

static bool
role_is_listed(const json_t *payload, const char *claim, const char *role)
{
	const json_t *value = json_object_get(payload, claim);

	if (json_is_string(value))
		return strcmp(json_string_value(value), role) == 0;
	if (json_is_array(value))
	{
		for (size_t i = 0; i < json_array_size(value); i++)
		{
			const json_t *entry = json_array_get(value, i);

			if (json_is_string(entry) && strcmp(json_string_value(entry), role) == 0)
				return true;
		}
	}
	return false;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	PgOAuthClaimsPolicy policies[3] = {
		{
			.issuer = "https://issuer.example/",
			.audiences = "postgres://primary,postgres://secondary",
			.required_scopes = "connect:postgres read:metadata",
			.identity_claim = "sub",
			.role_claim = "",
			.current_time = 1000,
			.clock_skew_seconds = 60,
			.max_identity_size = 1024,
			.max_subject_size = 1024,
			.max_audiences = 16,
			.max_scopes = 64,
		},
		{
			.issuer = "https://issuer.example/",
			.audiences = "postgres://primary,postgres://secondary",
			.required_scopes = "connect:postgres read:metadata",
			.identity_claim = "sub",
			.role_claim = "roles",
			.requested_role = "reporting",
			.current_time = 1000,
			.clock_skew_seconds = 60,
			.max_identity_size = 1024,
			.max_subject_size = 1024,
			.max_audiences = 16,
			.max_scopes = 64,
			.max_roles = 64,
			.max_role_size = 63,
		},
		{
			.issuer = "https://issuer.example/",
			.audiences = "postgres://primary",
			.required_scopes = "connect:postgres",
			.identity_claim = "uid",
			.role_claim = "",
			.current_time = 1000,
			.clock_skew_seconds = 0,
			.max_identity_size = 63,
			.max_subject_size = 1024,
			.max_audiences = 4,
			.max_scopes = 8,
		},
	};
	json_error_t error;
	json_t	   *payload;

	if (size > 16384)
		return 0;
	payload = json_loadb((const char *) data, size, JSON_REJECT_DUPLICATES,
						 &error);
	if (payload == NULL)
		return 0;
	for (size_t i = 0; i < sizeof(policies) / sizeof(policies[0]); i++)
	{
		PgOAuthValidatedClaims claims;

		memset(&claims, 0x5a, sizeof(claims));
		if (pg_oauth_claims_validate(payload, &policies[i], &claims) !=
			PG_OAUTH_CLAIMS_OK)
			continue;
		REQUIRE(claims.identity != NULL);
		REQUIRE(claims.identity_length > 0);
		REQUIRE(claims.identity_length <= policies[i].max_identity_size);
		REQUIRE(strlen(claims.identity) == claims.identity_length);
		REQUIRE(pg_oauth_identity_text_valid(claims.identity, claims.identity_length));
		if (policies[i].role_claim[0] != '\0')
			REQUIRE(role_is_listed(payload, policies[i].role_claim,
								   policies[i].requested_role));
	}
	json_decref(payload);
	return 0;
}
