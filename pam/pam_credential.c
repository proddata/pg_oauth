#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>

#include "pam_credential.h"

static void
discard_response(struct pam_response *response)
{
	if (response == NULL)
		return;
	if (response->resp != NULL)
	{
		/* Bound the wipe: the response is a C string owned by the caller. */
		explicit_bzero(response->resp, strnlen(response->resp, PG_OAUTH_PAM_MAX_CREDENTIAL + 1));
		free(response->resp);
	}
	free(response);
}

PgOAuthPamCredentialError
pg_oauth_pam_credential_acquire(pam_handle_t *pamh, size_t max_length,
								PgOAuthPamCredential *credential)
{
	const void *item = NULL;
	const struct pam_conv *conversation;
	struct pam_message message = {PAM_PROMPT_ECHO_OFF, "Access token: "};
	const struct pam_message *messages[1] = {&message};
	struct pam_response *response = NULL;
	size_t		length;

	if (credential == NULL)
		return PG_OAUTH_PAM_CREDENTIAL_INVALID_ARGUMENT;
	credential->data = NULL;
	credential->length = 0;
	if (pamh == NULL || max_length == 0 || max_length > PG_OAUTH_PAM_MAX_CREDENTIAL)
		return PG_OAUTH_PAM_CREDENTIAL_INVALID_ARGUMENT;
	if (pam_get_item(pamh, PAM_CONV, &item) != PAM_SUCCESS || item == NULL)
		return PG_OAUTH_PAM_CREDENTIAL_NO_CONVERSATION;
	conversation = item;
	if (conversation->conv == NULL)
		return PG_OAUTH_PAM_CREDENTIAL_NO_CONVERSATION;
	if (conversation->conv(1, messages, &response, conversation->appdata_ptr) != PAM_SUCCESS)
	{
		/* A failing conversation may still have allocated a response. */
		discard_response(response);
		return PG_OAUTH_PAM_CREDENTIAL_CONVERSATION_FAILED;
	}
	if (response == NULL || response->resp == NULL || response->resp_retcode != 0)
	{
		discard_response(response);
		return PG_OAUTH_PAM_CREDENTIAL_NO_RESPONSE;
	}
	length = strnlen(response->resp, max_length + 1);
	if (length == 0)
	{
		discard_response(response);
		return PG_OAUTH_PAM_CREDENTIAL_EMPTY;
	}
	if (length > max_length)
	{
		discard_response(response);
		return PG_OAUTH_PAM_CREDENTIAL_TOO_LARGE;
	}
	/* Take ownership of the response string; free only the wrapper. */
	credential->data = response->resp;
	credential->length = length;
	free(response);
	return PG_OAUTH_PAM_CREDENTIAL_OK;
}

void
pg_oauth_pam_credential_clear(PgOAuthPamCredential *credential)
{
	if (credential == NULL)
		return;
	if (credential->data != NULL)
	{
		explicit_bzero(credential->data, credential->length);
		free(credential->data);
	}
	credential->data = NULL;
	credential->length = 0;
}

const char *
pg_oauth_pam_credential_error_code(PgOAuthPamCredentialError error)
{
	switch (error)
	{
		case PG_OAUTH_PAM_CREDENTIAL_OK:
			return "ok";
		case PG_OAUTH_PAM_CREDENTIAL_INVALID_ARGUMENT:
			return "credential_invalid_argument";
		case PG_OAUTH_PAM_CREDENTIAL_NO_CONVERSATION:
			return "credential_no_conversation";
		case PG_OAUTH_PAM_CREDENTIAL_CONVERSATION_FAILED:
			return "credential_conversation_failed";
		case PG_OAUTH_PAM_CREDENTIAL_NO_RESPONSE:
			return "credential_no_response";
		case PG_OAUTH_PAM_CREDENTIAL_EMPTY:
			return "credential_empty";
		case PG_OAUTH_PAM_CREDENTIAL_TOO_LARGE:
			return "credential_too_large";
	}
	return "credential_internal_error";
}
