#include "claims.h"
#include "ascii.h"
#include "identity_text.h"

#include <stdbool.h>
#include <string.h>

static bool
json_string_equals(const json_t *value, const char *expected)
{
	size_t		length;

	if (!json_is_string(value) || expected == NULL)
		return false;
	length = strlen(expected);
	return json_string_length(value) == length &&
		memcmp(json_string_value(value), expected, length) == 0;
}

/* Identities use the shared rule in identity_text.h (controls, invisible and bidi characters). */
static bool
valid_identity_string(const json_t *value, size_t maximum)
{
	const char *text;
	size_t		length;

	if (!json_is_string(value) ||
		(length = json_string_length(value)) == 0 || length > maximum)
		return false;
	text = json_string_value(value);

	return pg_oauth_identity_text_valid(text, length);
}

static bool
valid_policy(const PgOAuthClaimsPolicy *policy)
{
	return policy != NULL && policy->issuer != NULL &&
		policy->issuer[0] != '\0' && policy->audiences != NULL &&
		policy->audiences[0] != '\0' && policy->required_scopes != NULL &&
		policy->required_scopes[0] != '\0' && policy->identity_claim != NULL &&
		policy->identity_claim[0] != '\0' && policy->role_claim != NULL && policy->current_time >= 0 &&
		policy->clock_skew_seconds <= 300 && policy->max_identity_size > 0 &&
		policy->max_subject_size > 0 && policy->max_subject_size <= 1024 &&
		policy->max_audiences > 0 && policy->max_audiences <= 64 &&
		policy->max_scopes > 0 && policy->max_scopes <= 256 &&
		(policy->role_claim[0] == '\0' ||
		 (policy->requested_role != NULL && policy->requested_role[0] != '\0' &&
		  policy->max_roles > 0 && policy->max_roles <= 256 &&
		  policy->max_role_size > 0));
}

/*
 * The single expiry predicate: expired once the clock reaches exp and the
 * elapsed time is at least the skew. Shared with the PAM account stage so the
 * two cannot disagree.
 */
bool
pg_oauth_claims_expired(int64_t now, int64_t expires_at, uint32_t skew_seconds)
{
	return now >= expires_at &&
		(uint64_t) (now - expires_at) >= skew_seconds;
}

static PgOAuthClaimsError
validate_requested_role(const json_t *payload,
						const PgOAuthClaimsPolicy *policy)
{
	json_t	   *roles;
	size_t		requested_length;
	bool		found = false;

	if (policy->role_claim[0] == '\0')
		return PG_OAUTH_CLAIMS_OK;
	roles = json_object_get(payload, policy->role_claim);
	requested_length = strlen(policy->requested_role);
	if (requested_length == 0 || requested_length > policy->max_role_size)
		return PG_OAUTH_CLAIMS_INVALID_ARGUMENT;
	if (json_is_string(roles))
	{
		size_t		length = json_string_length(roles);

		if (length == 0 || length > policy->max_role_size)
			return PG_OAUTH_CLAIMS_INVALID_ROLES;
		if (!pg_oauth_identity_text_valid(json_string_value(roles), length))
			return PG_OAUTH_CLAIMS_INVALID_ROLES;
		return length == requested_length &&
			memcmp(json_string_value(roles), policy->requested_role, length) == 0 ?
			PG_OAUTH_CLAIMS_OK : PG_OAUTH_CLAIMS_UNAUTHORIZED_ROLE;
	}
	if (!json_is_array(roles) || json_array_size(roles) == 0 ||
		json_array_size(roles) > policy->max_roles)
		return PG_OAUTH_CLAIMS_INVALID_ROLES;
	for (size_t i = 0; i < json_array_size(roles); i++)
	{
		json_t	   *entry = json_array_get(roles, i);
		size_t		entry_length;

		if (!json_is_string(entry) ||
			(entry_length = json_string_length(entry)) == 0 ||
			entry_length > policy->max_role_size)
			return PG_OAUTH_CLAIMS_INVALID_ROLES;
		if (!pg_oauth_identity_text_valid(json_string_value(entry), entry_length))
			return PG_OAUTH_CLAIMS_INVALID_ROLES;
		for (size_t j = 0; j < i; j++)
		{
			json_t	   *previous = json_array_get(roles, j);

			if (json_string_length(previous) == entry_length &&
				memcmp(json_string_value(previous), json_string_value(entry),
					   entry_length) == 0)
				return PG_OAUTH_CLAIMS_INVALID_ROLES;
		}
		if (entry_length == requested_length &&
			memcmp(json_string_value(entry), policy->requested_role,
				   requested_length) == 0)
			found = true;
	}
	return found ? PG_OAUTH_CLAIMS_OK : PG_OAUTH_CLAIMS_UNAUTHORIZED_ROLE;
}

static bool
configured_audience_matches(const char *configured, const char *token,
							size_t token_length, size_t maximum)
{
	const char *entry = configured;
	size_t		count = 0;

	while (*entry != '\0')
	{
		const char *end = strchr(entry, ',');
		const char *trimmed_end = end != NULL ? end : entry + strlen(entry);

		while (*entry != '\0' && pg_oauth_ascii_isspace((unsigned char) *entry))
			entry++;
		while (trimmed_end > entry &&
			   pg_oauth_ascii_isspace((unsigned char) trimmed_end[-1]))
			trimmed_end--;
		if (trimmed_end == entry || ++count > maximum)
			return false;
		if ((size_t) (trimmed_end - entry) == token_length &&
			memcmp(entry, token, token_length) == 0)
			return true;
		if (end == NULL)
			break;
		entry = end + 1;
	}
	return false;
}

static bool
audience_matches(const json_t *audience, const PgOAuthClaimsPolicy *policy)
{
	if (json_is_string(audience))
	{
		return json_string_length(audience) > 0 &&
			configured_audience_matches(policy->audiences,
										json_string_value(audience), json_string_length(audience),
										policy->max_audiences);
	}
	if (!json_is_array(audience) || json_array_size(audience) == 0 ||
		json_array_size(audience) > policy->max_audiences)
		return false;
	for (size_t i = 0; i < json_array_size(audience); i++)
	{
		json_t	   *entry = json_array_get(audience, i);

		if (!json_is_string(entry) || json_string_length(entry) == 0)
			return false;
		for (size_t j = 0; j < i; j++)
		{
			json_t	   *previous = json_array_get(audience, j);

			if (json_string_length(previous) == json_string_length(entry) &&
				memcmp(json_string_value(previous), json_string_value(entry),
					   json_string_length(entry)) == 0)
				return false;
		}
	}
	for (size_t i = 0; i < json_array_size(audience); i++)
	{
		json_t	   *entry = json_array_get(audience, i);

		if (configured_audience_matches(policy->audiences,
										json_string_value(entry), json_string_length(entry),
										policy->max_audiences))
			return true;
	}
	return false;
}

static bool
valid_scope_token(const char *scope, size_t length)
{
	if (length == 0)
		return false;
	for (size_t i = 0; i < length; i++)
	{
		unsigned char byte = (unsigned char) scope[i];

		/* RFC 6749 scope-token: %x21 / %x23-5B / %x5D-7E. */
		if (!(byte == 0x21 || (byte >= 0x23 && byte <= 0x5b) ||
			  (byte >= 0x5d && byte <= 0x7e)))
			return false;
	}
	return true;
}

static bool
scope_string_contains(const char *scopes, size_t scopes_length,
					  const char *required, size_t required_length,
					  size_t maximum, bool *valid)
{
	size_t		starts[256];
	size_t		lengths[256];
	size_t		start = 0;
	size_t		count = 0;
	bool		found = false;

	*valid = false;
	if (scopes_length == 0)
		return false;
	for (size_t i = 0; i <= scopes_length; i++)
	{
		if (i != scopes_length && scopes[i] != ' ')
			continue;
		if (i == start || count >= maximum ||
			!valid_scope_token(scopes + start, i - start))
			return false;
		for (size_t j = 0; j < count; j++)
		{
			if (lengths[j] == i - start &&
				memcmp(scopes + starts[j], scopes + start, i - start) == 0)
				return false;
		}
		starts[count] = start;
		lengths[count] = i - start;
		count++;
		if (i - start == required_length &&
			memcmp(scopes + start, required, required_length) == 0)
			found = true;
		start = i + 1;
	}
	*valid = true;
	return found;
}

static bool
scope_array_contains(const json_t *scopes, const char *required,
					 size_t required_length, size_t maximum, bool *valid)
{
	bool		found = false;

	*valid = false;
	if (!json_is_array(scopes) || json_array_size(scopes) == 0 ||
		json_array_size(scopes) > maximum)
		return false;
	for (size_t i = 0; i < json_array_size(scopes); i++)
	{
		json_t	   *entry = json_array_get(scopes, i);

		if (!json_is_string(entry) ||
			!valid_scope_token(json_string_value(entry),
							   json_string_length(entry)))
			return false;
		for (size_t j = 0; j < i; j++)
		{
			json_t	   *previous = json_array_get(scopes, j);

			if (json_string_length(previous) == json_string_length(entry) &&
				memcmp(json_string_value(previous), json_string_value(entry),
					   json_string_length(entry)) == 0)
				return false;
		}
		if (json_string_length(entry) == required_length &&
			memcmp(json_string_value(entry), required, required_length) == 0)
			found = true;
	}
	*valid = true;
	return found;
}

static PgOAuthClaimsError
validate_scopes(const json_t *payload, const PgOAuthClaimsPolicy *policy)
{
	json_t	   *token_scopes = json_object_get(payload, "scope");
	const char *required = policy->required_scopes;
	size_t		start = 0;
	size_t		required_length = strlen(required);
	size_t		count = 0;

	if (!json_is_string(token_scopes) && !json_is_array(token_scopes))
		return PG_OAUTH_CLAIMS_INVALID_SCOPE;
	for (size_t i = 0; i <= required_length; i++)
	{
		bool		valid;
		bool		found;

		if (i != required_length && required[i] != ' ')
			continue;
		if (i == start || ++count > policy->max_scopes ||
			!valid_scope_token(required + start, i - start))
			return PG_OAUTH_CLAIMS_INVALID_ARGUMENT;
		if (json_is_string(token_scopes))
			found = scope_string_contains(json_string_value(token_scopes),
										  json_string_length(token_scopes), required + start, i - start,
										  policy->max_scopes, &valid);
		else
			found = scope_array_contains(token_scopes, required + start,
										 i - start, policy->max_scopes, &valid);
		if (!valid)
			return PG_OAUTH_CLAIMS_INVALID_SCOPE;
		if (!found)
			return PG_OAUTH_CLAIMS_INSUFFICIENT_SCOPE;
		start = i + 1;
	}
	return PG_OAUTH_CLAIMS_OK;
}

PgOAuthClaimsError
pg_oauth_claims_validate(const json_t *verified_payload,
						 const PgOAuthClaimsPolicy *policy,
						 PgOAuthValidatedClaims *claims)
{
	json_t	   *value;
	json_int_t	numeric_date;
	PgOAuthClaimsError scope_error;
	PgOAuthClaimsError role_error;

	if (claims == NULL)
		return PG_OAUTH_CLAIMS_INVALID_ARGUMENT;
	memset(claims, 0, sizeof(*claims));
	if (!json_is_object(verified_payload) || !valid_policy(policy))
		return PG_OAUTH_CLAIMS_INVALID_ARGUMENT;

	value = json_object_get(verified_payload, "iss");
	if (!json_string_equals(value, policy->issuer))
		return PG_OAUTH_CLAIMS_INVALID_ISSUER;
	value = json_object_get(verified_payload, "aud");
	if (!audience_matches(value, policy))
		return PG_OAUTH_CLAIMS_INVALID_AUDIENCE;

	value = json_object_get(verified_payload, "exp");
	if (value == NULL)
		return PG_OAUTH_CLAIMS_MISSING_EXPIRY;
	if (!json_is_integer(value) || (numeric_date = json_integer_value(value)) <= 0)
		return PG_OAUTH_CLAIMS_INVALID_EXPIRY;
	if (pg_oauth_claims_expired(policy->current_time, numeric_date,
								policy->clock_skew_seconds))
		return PG_OAUTH_CLAIMS_EXPIRED;
	claims->expires_at = numeric_date;

	value = json_object_get(verified_payload, "nbf");
	if (value != NULL)
	{
		if (!json_is_integer(value) ||
			(numeric_date = json_integer_value(value)) < 0)
			return PG_OAUTH_CLAIMS_INVALID_NOT_BEFORE;
		if (numeric_date > policy->current_time &&
			(uint64_t) (numeric_date - policy->current_time) >
			policy->clock_skew_seconds)
			return PG_OAUTH_CLAIMS_NOT_YET_VALID;
	}
	value = json_object_get(verified_payload, "iat");
	if (value != NULL)
	{
		if (!json_is_integer(value) ||
			(numeric_date = json_integer_value(value)) < 0)
			return PG_OAUTH_CLAIMS_INVALID_ISSUED_AT;
		if (numeric_date > policy->current_time &&
			(uint64_t) (numeric_date - policy->current_time) >
			policy->clock_skew_seconds)
			return PG_OAUTH_CLAIMS_ISSUED_IN_FUTURE;
	}

	value = json_object_get(verified_payload, "sub");
	if (!valid_identity_string(value, policy->max_subject_size))
		return PG_OAUTH_CLAIMS_INVALID_SUBJECT;

	value = json_object_get(verified_payload, policy->identity_claim);
	if (!valid_identity_string(value, policy->max_identity_size))
		return PG_OAUTH_CLAIMS_INVALID_IDENTITY;

	scope_error = validate_scopes(verified_payload, policy);
	if (scope_error != PG_OAUTH_CLAIMS_OK)
		return scope_error;
	role_error = validate_requested_role(verified_payload, policy);
	if (role_error != PG_OAUTH_CLAIMS_OK)
		return role_error;
	claims->identity = json_string_value(value);
	claims->identity_length = json_string_length(value);
	return PG_OAUTH_CLAIMS_OK;
}

const char *
pg_oauth_claims_error_code(PgOAuthClaimsError error)
{
	static const char *const codes[] = {
		"ok", "invalid_argument", "invalid_issuer", "invalid_audience",
		"missing_expiry", "invalid_expiry", "expired", "invalid_not_before",
		"not_yet_valid", "invalid_issued_at", "issued_in_future",
		"invalid_subject", "invalid_identity", "invalid_scope", "insufficient_scope",
		"invalid_roles", "unauthorized_role"
	};

	if ((size_t) error >= sizeof(codes) / sizeof(codes[0]))
		return "unknown";
	return codes[error];
}
