#ifndef PG_OAUTH_VALIDATOR_IDENTITY_TEXT_H
#define PG_OAUTH_VALIDATOR_IDENTITY_TEXT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * The one text rule for authenticated identities and delegated role names.
 *
 * Both reach PostgreSQL's connection log, usermaps and role matching, where a
 * person reads them. Characters that are invisible, or that reorder or split
 * text, let two different identities look the same or let one log line look
 * like several, so they are rejected rather than normalized. Besides ASCII
 * controls and malformed UTF-8 (overlong forms, surrogates, values above
 * U+10FFFF), these code points are refused:
 *
 *   U+0080-U+009F   C1 controls
 *   U+00AD          soft hyphen
 *   U+061C          Arabic letter mark
 *   U+180E          Mongolian vowel separator
 *   U+200B-U+200F   zero width space/joiners, left/right marks
 *   U+2028-U+202E   line and paragraph separators, bidi embeddings/overrides
 *   U+2060-U+206F   word joiner, invisible operators, bidi isolates, and the
 *                   deprecated format controls
 *   U+FEFF          byte order mark / zero width no-break space
 *   U+FFF9-U+FFFB   interlinear annotation characters
 *
 * Emoji joiner sequences (U+200D) are therefore refused too. The decision and
 * its limits are recorded in docs/configuration.md.
 */
static inline bool
pg_oauth_identity_text_valid(const char *text, size_t length)
{
	size_t		index = 0;

	while (index < length)
	{
		uint8_t		first = (uint8_t) text[index];
		size_t		continuations;
		uint32_t	codepoint;

		if (first <= 0x7f)
		{
			if (first < 0x20 || first == 0x7f)
				return false;
			index++;
			continue;
		}
		if (first >= 0xc2 && first <= 0xdf)
		{
			continuations = 1;
			codepoint = first & 0x1f;
		}
		else if (first >= 0xe0 && first <= 0xef)
		{
			continuations = 2;
			codepoint = first & 0x0f;
		}
		else if (first >= 0xf0 && first <= 0xf4)
		{
			continuations = 3;
			codepoint = first & 0x07;
		}
		else
			return false;
		if (continuations > length - index - 1)
			return false;
		for (size_t i = 1; i <= continuations; i++)
		{
			uint8_t		byte = (uint8_t) text[index + i];

			if ((byte & 0xc0) != 0x80)
				return false;
			codepoint = (codepoint << 6) | (byte & 0x3f);
		}
		if ((continuations == 2 && codepoint < 0x800) ||
			(continuations == 3 && codepoint < 0x10000) ||
			(codepoint >= 0xd800 && codepoint <= 0xdfff) ||
			codepoint > 0x10ffff)
			return false;
		if ((codepoint >= 0x80 && codepoint <= 0x9f) ||
			codepoint == 0x00ad || codepoint == 0x061c || codepoint == 0x180e ||
			(codepoint >= 0x200b && codepoint <= 0x200f) ||
			(codepoint >= 0x2028 && codepoint <= 0x202e) ||
			(codepoint >= 0x2060 && codepoint <= 0x206f) ||
			codepoint == 0xfeff ||
			(codepoint >= 0xfff9 && codepoint <= 0xfffb))
			return false;
		index += continuations + 1;
	}
	return true;
}

#endif
