/*
 * Unit tests for the PAM credential conversation. The test provides its own
 * pam_get_item() so no real PAM stack, PostgreSQL or privileges are needed.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pam_credential.h"

typedef enum Behavior
{
	RESPOND_OK,
	RESPOND_FAIL_WITH_RESPONSE,
	RESPOND_NULL_RESPONSE,
	RESPOND_NULL_STRING,
	RESPOND_NONZERO_RETCODE
} Behavior;

static struct pam_conv conversation;
static const struct pam_conv *conversation_item;
static Behavior behavior;
static const char *reply;
static size_t reply_repeat;
static int	calls;
static int	last_count;
static int	last_style;

#define require(condition) \
	do { \
		if (!(condition)) \
		{ \
			fprintf(stderr, "%s:%d: requirement failed: %s\n", __FILE__, __LINE__, #condition); \
			exit(EXIT_FAILURE); \
		} \
	} while (0)

int
pam_get_item(const pam_handle_t *pamh, int item_type, const void **item)
{
	(void) pamh;
	if (item_type != PAM_CONV)
		return PAM_BAD_ITEM;
	*item = conversation_item;
	return PAM_SUCCESS;
}

static char *
make_reply(void)
{
	size_t		base = strlen(reply);
	size_t		total = base * (reply_repeat == 0 ? 1 : reply_repeat);
	char	   *value = malloc(total + 1);

	require(value != NULL);
	for (size_t offset = 0; base > 0 && offset < total; offset += base)
		memcpy(value + offset, reply, base);
	value[total] = '\0';
	return value;
}

static int
fake_conv(int count, const struct pam_message **messages, struct pam_response **responses, void *data)
{
	struct pam_response *response;

	(void) data;
	calls++;
	last_count = count;
	last_style = count > 0 ? messages[0]->msg_style : -1;
	*responses = NULL;
	if (behavior == RESPOND_NULL_RESPONSE)
		return PAM_SUCCESS;
	response = calloc(1, sizeof(*response));
	require(response != NULL);
	if (behavior != RESPOND_NULL_STRING)
		response->resp = make_reply();
	if (behavior == RESPOND_NONZERO_RETCODE)
		response->resp_retcode = 1;
	*responses = response;
	return behavior == RESPOND_FAIL_WITH_RESPONSE ? PAM_CONV_ERR : PAM_SUCCESS;
}

static PgOAuthPamCredentialError
acquire(Behavior mode, const char *value, size_t repeat, size_t max, PgOAuthPamCredential *out)
{
	behavior = mode;
	reply = value;
	reply_repeat = repeat;
	calls = 0;
	return pg_oauth_pam_credential_acquire((pam_handle_t *) 1, max, out);
}

static void
expect_denied(PgOAuthPamCredentialError actual, PgOAuthPamCredentialError expected,
			  const PgOAuthPamCredential *out)
{
	require(actual == expected);
	require(out->data == NULL && out->length == 0);
}

int
main(void)
{
	PgOAuthPamCredential out = {(char *) 1, 99};

	conversation.conv = fake_conv;
	conversation_item = &conversation;

	/* Accepted: one fixed echo-off prompt, exact bytes, owned result. */
	require(acquire(RESPOND_OK, "a.b.c", 1, 64, &out) == PG_OAUTH_PAM_CREDENTIAL_OK);
	require(calls == 1 && last_count == 1 && last_style == PAM_PROMPT_ECHO_OFF);
	require(out.length == 5 && memcmp(out.data, "a.b.c", 5) == 0);
	pg_oauth_pam_credential_clear(&out);
	require(out.data == NULL && out.length == 0);
	pg_oauth_pam_credential_clear(&out);
	pg_oauth_pam_credential_clear(NULL);

	/* No trimming or Bearer handling: bytes are passed through unchanged. */
	require(acquire(RESPOND_OK, " Bearer a.b.c \n", 1, 64, &out) == PG_OAUTH_PAM_CREDENTIAL_OK);
	require(out.length == strlen(" Bearer a.b.c \n") && memcmp(out.data, " Bearer a.b.c \n", out.length) == 0);
	pg_oauth_pam_credential_clear(&out);

	/* Boundaries: exactly the limit is accepted, one more byte is denied. */
	require(acquire(RESPOND_OK, "x", 16384, 16384, &out) == PG_OAUTH_PAM_CREDENTIAL_OK && out.length == 16384);
	pg_oauth_pam_credential_clear(&out);
	expect_denied(acquire(RESPOND_OK, "x", 16385, 16384, &out), PG_OAUTH_PAM_CREDENTIAL_TOO_LARGE, &out);
	require(acquire(RESPOND_OK, "x", PG_OAUTH_PAM_MAX_CREDENTIAL, PG_OAUTH_PAM_MAX_CREDENTIAL, &out)
			== PG_OAUTH_PAM_CREDENTIAL_OK && out.length == PG_OAUTH_PAM_MAX_CREDENTIAL);
	pg_oauth_pam_credential_clear(&out);
	expect_denied(acquire(RESPOND_OK, "x", PG_OAUTH_PAM_MAX_CREDENTIAL + 1, PG_OAUTH_PAM_MAX_CREDENTIAL, &out),
				  PG_OAUTH_PAM_CREDENTIAL_TOO_LARGE, &out);

	/* The configured maximum itself is bounded and nonzero. */
	expect_denied(acquire(RESPOND_OK, "a", 1, 0, &out), PG_OAUTH_PAM_CREDENTIAL_INVALID_ARGUMENT, &out);
	expect_denied(acquire(RESPOND_OK, "a", 1, PG_OAUTH_PAM_MAX_CREDENTIAL + 1, &out),
				  PG_OAUTH_PAM_CREDENTIAL_INVALID_ARGUMENT, &out);
	require(calls == 0);

	/* Empty, missing and failing conversations deny and leave nothing behind. */
	expect_denied(acquire(RESPOND_OK, "", 1, 64, &out), PG_OAUTH_PAM_CREDENTIAL_EMPTY, &out);
	expect_denied(acquire(RESPOND_NULL_RESPONSE, "a", 1, 64, &out), PG_OAUTH_PAM_CREDENTIAL_NO_RESPONSE, &out);
	expect_denied(acquire(RESPOND_NULL_STRING, "a", 1, 64, &out), PG_OAUTH_PAM_CREDENTIAL_NO_RESPONSE, &out);
	expect_denied(acquire(RESPOND_NONZERO_RETCODE, "a", 1, 64, &out), PG_OAUTH_PAM_CREDENTIAL_NO_RESPONSE, &out);
	expect_denied(acquire(RESPOND_FAIL_WITH_RESPONSE, "a", 1, 64, &out),
				  PG_OAUTH_PAM_CREDENTIAL_CONVERSATION_FAILED, &out);

	/* Missing conversation item or callback. */
	conversation_item = NULL;
	expect_denied(acquire(RESPOND_OK, "a", 1, 64, &out), PG_OAUTH_PAM_CREDENTIAL_NO_CONVERSATION, &out);
	conversation_item = &conversation;
	conversation.conv = NULL;
	expect_denied(acquire(RESPOND_OK, "a", 1, 64, &out), PG_OAUTH_PAM_CREDENTIAL_NO_CONVERSATION, &out);
	conversation.conv = fake_conv;

	/* Invalid arguments. */
	require(pg_oauth_pam_credential_acquire((pam_handle_t *) 1, 64, NULL) == PG_OAUTH_PAM_CREDENTIAL_INVALID_ARGUMENT);
	expect_denied(pg_oauth_pam_credential_acquire(NULL, 64, &out), PG_OAUTH_PAM_CREDENTIAL_INVALID_ARGUMENT, &out);

	/* Diagnostic codes are stable and contain no credential text. */
	require(strcmp(pg_oauth_pam_credential_error_code(PG_OAUTH_PAM_CREDENTIAL_TOO_LARGE), "credential_too_large") == 0);
	require(strcmp(pg_oauth_pam_credential_error_code((PgOAuthPamCredentialError) 99), "credential_internal_error") == 0);
	return EXIT_SUCCESS;
}
