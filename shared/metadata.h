#ifndef PG_OAUTH_VALIDATOR_METADATA_H
#define PG_OAUTH_VALIDATOR_METADATA_H

#include <stdbool.h>
#include <stddef.h>

typedef enum PgOAuthMetadataError
{
	PG_OAUTH_METADATA_OK = 0,
	PG_OAUTH_METADATA_INVALID_ARGUMENT,
	PG_OAUTH_METADATA_EMPTY,
	PG_OAUTH_METADATA_TOO_LARGE,
	PG_OAUTH_METADATA_INVALID_JSON,
	PG_OAUTH_METADATA_INVALID_ISSUER,
	PG_OAUTH_METADATA_ISSUER_MISMATCH,
	PG_OAUTH_METADATA_INVALID_JWKS_URI,
	PG_OAUTH_METADATA_INSECURE_URI
} PgOAuthMetadataError;

typedef struct PgOAuthMetadataPolicy
{
	size_t		max_document_size;
	size_t		max_url_size;
	bool		allow_insecure_http;
} PgOAuthMetadataPolicy;

typedef struct PgOAuthMetadata
{
	char	   *jwks_uri;
} PgOAuthMetadata;

extern PgOAuthMetadataError pg_oauth_metadata_parse(
													const char *document, size_t document_length, const char *expected_issuer,
													const PgOAuthMetadataPolicy *policy, PgOAuthMetadata *metadata);
extern void pg_oauth_metadata_clear(PgOAuthMetadata *metadata);
extern const char *pg_oauth_metadata_error_code(PgOAuthMetadataError error);

#endif							/* PG_OAUTH_VALIDATOR_METADATA_H */
