#ifndef PG_OAUTH_VALIDATOR_VALIDATOR_POLICY_H
#define PG_OAUTH_VALIDATOR_VALIDATOR_POLICY_H

#include "postgres.h"

#include "cache_io.h"
#include "policy.h"
#include "validator.h"

/*
 * Expansion of one validated policy into the pipeline's per-stage policies,
 * shared by the OAuth validator and the PAM module so that both enforce the
 * same bounds. Pure and allocation-free: host-supplied state (time, requested
 * role, cancellation) is passed in, never read from PostgreSQL here.
 */
#define PG_OAUTH_MAX_URL_SIZE 2048
#define PG_OAUTH_MAX_DOCUMENT_SIZE 65536
#define PG_OAUTH_MAX_IDENTITY_SIZE 1024
#define PG_OAUTH_HTTP_CONNECT_TIMEOUT_MS 2000
#define PG_OAUTH_HTTP_TOTAL_TIMEOUT_MS 5000

/* Room for the longest issuer plus the discovery suffix and a terminator. */
#define PG_OAUTH_METADATA_URL_BUFFER (PG_OAUTH_MAX_URL_SIZE + 1)

/*
 * Derive the OIDC discovery URL from the issuer. Returns false, writing
 * nothing usable, if the result would exceed the URL bound.
 */
extern bool pg_oauth_metadata_url_build(const char *issuer, char *out, size_t size);

/*
 * metadata_host is the already-validated discovery host (borrowed). The result
 * borrows pointers from policy and metadata_host and must not outlive them.
 */
extern void pg_oauth_validator_policy_assemble(
											   const PgOAuthValidationPolicy *policy, const char *metadata_host,
											   const char *requested_role, int64_t wall_time,
											   bool (*cancel) (void *), PgOAuthValidatorPolicy *out);

/* Cache policy for the shared-cache pipeline entry point. */
extern void pg_oauth_cache_policy_assemble(
										   const PgOAuthValidationPolicy *policy, const PgOAuthCacheIo *io,
										   PgOAuthIssuerKeyCachePolicy *out);

#endif
