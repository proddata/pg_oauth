/*
 * Orchestrates the strict access-token validation pipeline.
 *
 * Stages run in a fixed trust order and the first failure ends validation:
 *
 *   1. envelope   - bounded structural parse of the untrusted token
 *   2. issuer key - fetch metadata/JWKS from the configured issuer only and
 *                   select the one key named by the token's kid
 *   3. signature  - verify with that key
 *   4. claims     - issuer, audience, expiry, scopes, identity claim
 *   5. identity   - build the authenticated identity string
 *
 * Claims are read only after the signature verifies; before that, the payload
 * is untrusted data. Each stage keeps its own error code so the caller can log
 * a precise, non-sensitive reason, but every failure is a denial: nothing
 * here converts an error into success. See FEATURES.md, "Required validation
 * pipeline".
 */
#include "validator.h"

#include <string.h>

void
pg_oauth_validator_result_clear(PgOAuthValidatorResult *result)
{
	if (result == NULL)
		return;
	pg_oauth_identity_clear(&result->identity);
	memset(result, 0, sizeof(*result));
}

PgOAuthValidatorError
pg_oauth_validate_access_token(const char *token, size_t token_length,
							   const char *metadata_url,
							   const PgOAuthValidatorPolicy *policy,
							   PgOAuthValidatorResult *result)
{
	return pg_oauth_validate_access_token_cached(token, token_length,
												 metadata_url, policy, NULL, 0, 0, result);
}

PgOAuthValidatorError
pg_oauth_validate_access_token_cached(const char *token, size_t token_length,
									  const char *metadata_url,
									  const PgOAuthValidatorPolicy *policy,
									  const PgOAuthIssuerKeyCachePolicy *cache_policy,
									  int64_t now_ms, int64_t response_time_seconds,
									  PgOAuthValidatorResult *result)
{
	PgOAuthJwtEnvelope envelope;
	PgOAuthIssuerKeyResult key_result;
	PgOAuthValidatedClaims claims;
	PgOAuthValidatorError error;

	if (result == NULL)
		return PG_OAUTH_VALIDATOR_INVALID_ARGUMENT;
	memset(result, 0, sizeof(*result));
	memset(&envelope, 0, sizeof(envelope));
	memset(&key_result, 0, sizeof(key_result));
	memset(&claims, 0, sizeof(claims));
	if (token == NULL || metadata_url == NULL || policy == NULL ||
		policy->claims.issuer == NULL)
		return PG_OAUTH_VALIDATOR_INVALID_ARGUMENT;

	result->envelope_error = pg_oauth_jwt_envelope_parse(
														 token, token_length, &policy->envelope, &envelope);
	if (result->envelope_error != PG_OAUTH_JWT_ENVELOPE_OK)
	{
		error = PG_OAUTH_VALIDATOR_ENVELOPE;
		goto done;
	}
	result->issuer_key_error = pg_oauth_issuer_key_fetch_cached(
																metadata_url, policy->claims.issuer, envelope.key_id,
																envelope.algorithm, &policy->issuer_key, cache_policy, now_ms,
																response_time_seconds, &key_result);
	result->http_error = key_result.http_error;
	result->metadata_error = key_result.metadata_error;
	result->jwks_error = key_result.jwks_error;
	if (result->issuer_key_error != PG_OAUTH_ISSUER_KEY_OK)
	{
		error = PG_OAUTH_VALIDATOR_ISSUER_KEY;
		goto done;
	}
	result->signature_error = pg_oauth_signature_verify(
														token, token_length, &key_result.selected);
	if (result->signature_error != PG_OAUTH_SIGNATURE_OK)
	{
		error = PG_OAUTH_VALIDATOR_SIGNATURE;
		goto done;
	}
	result->claims_error = pg_oauth_claims_validate(
													envelope.untrusted_payload, &policy->claims, &claims);
	if (result->claims_error != PG_OAUTH_CLAIMS_OK)
	{
		error = PG_OAUTH_VALIDATOR_CLAIMS;
		goto done;
	}
	result->identity_error = pg_oauth_identity_build(
													 claims.identity, claims.identity_length,
													 &policy->identity, &result->identity);
	if (result->identity_error != PG_OAUTH_IDENTITY_OK)
	{
		error = PG_OAUTH_VALIDATOR_IDENTITY;
		goto done;
	}
	result->expires_at = claims.expires_at;
	error = PG_OAUTH_VALIDATOR_OK;

done:
	pg_oauth_issuer_key_result_clear(&key_result);
	pg_oauth_jwt_envelope_clear(&envelope);
	return error;
}

const char *
pg_oauth_validator_error_code(PgOAuthValidatorError error)
{
	switch (error)
	{
		case PG_OAUTH_VALIDATOR_OK:
			return "validator_ok";
		case PG_OAUTH_VALIDATOR_INVALID_ARGUMENT:
			return "validator_invalid_argument";
		case PG_OAUTH_VALIDATOR_ENVELOPE:
			return "validator_envelope";
		case PG_OAUTH_VALIDATOR_ISSUER_KEY:
			return "validator_issuer_key";
		case PG_OAUTH_VALIDATOR_SIGNATURE:
			return "validator_signature";
		case PG_OAUTH_VALIDATOR_CLAIMS:
			return "validator_claims";
		case PG_OAUTH_VALIDATOR_IDENTITY:
			return "validator_identity";
	}
	return "validator_unknown_error";
}
