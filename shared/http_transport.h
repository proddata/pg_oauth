#ifndef PG_OAUTH_VALIDATOR_HTTP_TRANSPORT_H
#define PG_OAUTH_VALIDATOR_HTTP_TRANSPORT_H

#include <stdbool.h>
#include <stddef.h>

typedef enum PgOAuthHttpError
{
	PG_OAUTH_HTTP_OK = 0,
	PG_OAUTH_HTTP_INVALID_ARGUMENT,
	PG_OAUTH_HTTP_INVALID_URL,
	PG_OAUTH_HTTP_INSECURE_URL,
	PG_OAUTH_HTTP_HOST_NOT_ALLOWED,
	PG_OAUTH_HTTP_TIMEOUT,
	PG_OAUTH_HTTP_INTERRUPTED,
	PG_OAUTH_HTTP_TLS_FAILURE,
	PG_OAUTH_HTTP_RESPONSE_TOO_LARGE,
	PG_OAUTH_HTTP_STATUS,
	PG_OAUTH_HTTP_CONTENT_TYPE,
	PG_OAUTH_HTTP_NETWORK_FAILURE,
	PG_OAUTH_HTTP_OUT_OF_MEMORY
} PgOAuthHttpError;

typedef struct PgOAuthHttpPolicy
{
	size_t		max_url_size;
	size_t		max_response_size;
	long		connect_timeout_ms;
	long		total_timeout_ms;
	const char *allowed_host;
	const char *additional_allowed_hosts;
	const char *ca_file;
	bool		allow_insecure_http;
	/* Optional host callback; called between bounded nonblocking I/O waits. */
	bool		(*cancel_requested) (void *context);
	void	   *cancel_context;
} PgOAuthHttpPolicy;

typedef struct PgOAuthHttpResponse
{
	char	   *body;
	size_t		body_length;
	long		status;
	char	   *cache_control;
	char	   *date;
	char	   *expires;
	char	   *age;
} PgOAuthHttpResponse;

extern PgOAuthHttpError pg_oauth_http_get_json(
											   const char *url, const PgOAuthHttpPolicy *policy,
											   PgOAuthHttpResponse *response);
extern void pg_oauth_http_response_clear(PgOAuthHttpResponse *response);
extern const char *pg_oauth_http_error_code(PgOAuthHttpError error);
extern PgOAuthHttpError pg_oauth_http_url_host(
											   const char *url, size_t max_url_size, bool allow_insecure_http,
											   char **host);

#endif
