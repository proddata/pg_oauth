#ifndef PG_OAUTH_VALIDATOR_ASCII_H
#define PG_OAUTH_VALIDATOR_ASCII_H

#include <stdbool.h>

/*
 * Locale-independent character classes for untrusted tokens, claims and
 * administrator configuration. The <ctype.h> functions follow the database's
 * LC_CTYPE, so the same bytes could be accepted or rejected depending on how a
 * cluster was initialised (for example 0x80-0x9f are controls in ISO-8859-1
 * but continuation bytes of valid UTF-8). These helpers classify only the
 * ASCII range and treat every byte >= 0x80 as an ordinary, non-class byte, the
 * same result the "C" and UTF-8 locales give.
 */

static inline bool
pg_oauth_ascii_iscntrl(unsigned char c)
{
	return c < 0x20 || c == 0x7f;
}

static inline bool
pg_oauth_ascii_isspace(unsigned char c)
{
	return c == ' ' || (c >= '\t' && c <= '\r');
}

static inline bool
pg_oauth_ascii_isalnum(unsigned char c)
{
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z');
}

#endif							/* PG_OAUTH_VALIDATOR_ASCII_H */
