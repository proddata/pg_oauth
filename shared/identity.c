#include "identity.h"
#include "identity_text.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void
pg_oauth_identity_clear(PgOAuthIdentity *identity)
{
	if (identity == NULL)
		return;
	free(identity->value);
	memset(identity, 0, sizeof(*identity));
}

PgOAuthIdentityError
pg_oauth_identity_build(const char *subject, size_t subject_length,
						const PgOAuthIdentityPolicy *policy,
						PgOAuthIdentity *identity)
{
	char	   *output;

	if (identity == NULL)
		return PG_OAUTH_IDENTITY_INVALID_ARGUMENT;
	memset(identity, 0, sizeof(*identity));
	if (subject == NULL || policy == NULL || policy->max_subject_size == 0 ||
		policy->max_authn_id_size == 0)
		return PG_OAUTH_IDENTITY_INVALID_ARGUMENT;
	if (subject_length == 0 || subject_length > policy->max_subject_size ||
		subject_length > policy->max_authn_id_size ||
		memchr(subject, '\0', subject_length) != NULL ||
		!pg_oauth_identity_text_valid(subject, subject_length))
		return PG_OAUTH_IDENTITY_INVALID_SUBJECT;
	if (subject_length == SIZE_MAX)
		return PG_OAUTH_IDENTITY_TOO_LARGE;
	output = malloc(subject_length + 1);
	if (output == NULL)
		return PG_OAUTH_IDENTITY_ALLOCATION_FAILED;
	memcpy(output, subject, subject_length);
	output[subject_length] = '\0';
	identity->value = output;
	identity->length = subject_length;
	return PG_OAUTH_IDENTITY_OK;
}

const char *
pg_oauth_identity_error_code(PgOAuthIdentityError error)
{
	static const char *const codes[] = {
		"ok", "invalid_argument", "invalid_subject",
		"too_large", "allocation_failed"
	};

	if ((size_t) error >= sizeof(codes) / sizeof(codes[0]))
		return "unknown";
	return codes[error];
}
