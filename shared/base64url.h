#ifndef PG_OAUTH_VALIDATOR_BASE64URL_H
#define PG_OAUTH_VALIDATOR_BASE64URL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

extern bool pg_oauth_base64url_valid(const char *data, size_t length);
extern bool pg_oauth_base64url_decoded_size(size_t encoded_length,
											size_t maximum, size_t *decoded_length);
extern bool pg_oauth_base64url_decode(const char *data, size_t length,
									  uint8_t *decoded, size_t decoded_size);
extern bool pg_oauth_base64url_encoded_size(size_t input_length,
											size_t maximum, size_t *encoded_length);
extern bool pg_oauth_base64url_encode(const uint8_t *data, size_t length,
									  char *encoded, size_t encoded_size);

#endif							/* PG_OAUTH_VALIDATOR_BASE64URL_H */
