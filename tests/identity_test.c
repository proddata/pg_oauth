#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "identity.h"

static void
expect_error(const char *value, size_t length, PgOAuthIdentityPolicy *policy,
			 PgOAuthIdentityError expected)
{
	PgOAuthIdentity identity;

	if (pg_oauth_identity_build(value, length, policy, &identity) != expected ||
		identity.value != NULL || identity.length != 0)
	{
		fprintf(stderr, "identity_test: invalid identity was accepted\n");
		exit(EXIT_FAILURE);
	}
}

int
main(void)
{
	PgOAuthIdentityPolicy policy = {63, 63};
	PgOAuthIdentity identity;
	static const char invalid_utf8[] = {(char) 0xc0, (char) 0xaf};
	static const char c1_control[] = {(char) 0xc2, (char) 0x85};

	if (pg_oauth_identity_build("provider|123", strlen("provider|123"),
								&policy, &identity) != PG_OAUTH_IDENTITY_OK ||
		strcmp(identity.value, "provider|123") != 0)
		return EXIT_FAILURE;
	pg_oauth_identity_clear(&identity);
	expect_error("", 0, &policy, PG_OAUTH_IDENTITY_INVALID_SUBJECT);
	expect_error("line\nfeed", strlen("line\nfeed"), &policy,
				 PG_OAUTH_IDENTITY_INVALID_SUBJECT);
	expect_error(invalid_utf8, sizeof(invalid_utf8), &policy,
				 PG_OAUTH_IDENTITY_INVALID_SUBJECT);
	expect_error(c1_control, sizeof(c1_control), &policy,
				 PG_OAUTH_IDENTITY_INVALID_SUBJECT);
	policy.max_authn_id_size = 3;
	expect_error("large", 5, &policy, PG_OAUTH_IDENTITY_INVALID_SUBJECT);
	policy.max_authn_id_size = 63;

	/*
	 * Characters that are invisible or reorder or split text must not reach
	 * PostgreSQL's authenticated identity, its logs or a usermap: a person
	 * reading "alice<RLO>..." cannot tell what was logged. Each range is
	 * tested on both edges, and the legitimate neighbours just outside it
	 * stay valid.
	 */
	{
		static const struct
		{
			const char *bytes;
			bool		allowed;
			const char *what;
		}			cases[] = {
			{"\xc2\xad", false, "U+00AD soft hyphen"},
			{"\xc2\xac", true, "U+00AC not sign"},
			{"\xc2\xae", true, "U+00AE registered sign"},
			{"\xd8\x9c", false, "U+061C arabic letter mark"},
			{"\xd8\x9b", true, "U+061B arabic semicolon"},
			{"\xd8\x9d", true, "U+061D arabic end of text mark"},
			{"\xe1\xa0\x8e", false, "U+180E mongolian vowel separator"},
			{"\xe1\xa0\x8d", true, "U+180D mongolian free variation selector three"},
			{"\xe2\x80\x8a", true, "U+200A hair space"},
			{"\xe2\x80\x8b", false, "U+200B zero width space"},
			{"\xe2\x80\x8c", false, "U+200C zero width non-joiner"},
			{"\xe2\x80\x8d", false, "U+200D zero width joiner"},
			{"\xe2\x80\x8e", false, "U+200E left-to-right mark"},
			{"\xe2\x80\x8f", false, "U+200F right-to-left mark"},
			{"\xe2\x80\x90", true, "U+2010 hyphen"},
			{"\xe2\x80\xa7", true, "U+2027 hyphenation point"},
			{"\xe2\x80\xa8", false, "U+2028 line separator"},
			{"\xe2\x80\xa9", false, "U+2029 paragraph separator"},
			{"\xe2\x80\xaa", false, "U+202A left-to-right embedding"},
			{"\xe2\x80\xab", false, "U+202B right-to-left embedding"},
			{"\xe2\x80\xac", false, "U+202C pop directional formatting"},
			{"\xe2\x80\xad", false, "U+202D left-to-right override"},
			{"\xe2\x80\xae", false, "U+202E right-to-left override"},
			{"\xe2\x80\xaf", true, "U+202F narrow no-break space"},
			{"\xe2\x81\x9f", true, "U+205F medium mathematical space"},
			{"\xe2\x81\xa0", false, "U+2060 word joiner"},
			{"\xe2\x81\xa1", false, "U+2061 function application"},
			{"\xe2\x81\xa4", false, "U+2064 invisible plus"},
			{"\xe2\x81\xa6", false, "U+2066 left-to-right isolate"},
			{"\xe2\x81\xa7", false, "U+2067 right-to-left isolate"},
			{"\xe2\x81\xa8", false, "U+2068 first strong isolate"},
			{"\xe2\x81\xa9", false, "U+2069 pop directional isolate"},
			{"\xe2\x81\xaa", false, "U+206A inhibit symmetric swapping"},
			{"\xe2\x81\xaf", false, "U+206F nominal digit shapes"},
			{"\xe2\x81\xb0", true, "U+2070 superscript zero"},
			{"\xef\xbb\xbe", true, "U+FEFE"},
			{"\xef\xbb\xbf", false, "U+FEFF byte order mark"},
			{"\xef\xbc\x80", true, "U+FF00"},
			{"\xef\xbf\xb8", true, "U+FFF8"},
			{"\xef\xbf\xb9", false, "U+FFF9 interlinear annotation anchor"},
			{"\xef\xbf\xba", false, "U+FFFA interlinear annotation separator"},
			{"\xef\xbf\xbb", false, "U+FFFB interlinear annotation terminator"},
			{"\xef\xbf\xbc", true, "U+FFFC object replacement character"},
			/* Ordinary non-ASCII identities remain valid. */
			{"\xc3\xa9", true, "U+00E9 e with acute"},
			{"\xe6\x97\xa5\xe6\x9c\xac", true, "CJK ideographs"},
			{"\xf0\x9f\x98\x80", true, "U+1F600 emoji"},
		};

		for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
		{
			char		value[32];
			size_t		length;
			PgOAuthIdentityError error;

			/* The character alone, and between two ordinary letters. */
			length = (size_t) snprintf(value, sizeof(value), "ab%scd", cases[i].bytes);
			error = pg_oauth_identity_build(value, length, &policy, &identity);
			if (cases[i].allowed != (error == PG_OAUTH_IDENTITY_OK))
			{
				fprintf(stderr, "identity_test: %s was %s\n", cases[i].what,
						cases[i].allowed ? "rejected" : "accepted");
				return EXIT_FAILURE;
			}
			if (error == PG_OAUTH_IDENTITY_OK)
				pg_oauth_identity_clear(&identity);
			else if (identity.value != NULL || identity.length != 0)
				return EXIT_FAILURE;
			length = strlen(cases[i].bytes);
			error = pg_oauth_identity_build(cases[i].bytes, length, &policy, &identity);
			if (cases[i].allowed != (error == PG_OAUTH_IDENTITY_OK))
			{
				fprintf(stderr, "identity_test: lone %s was %s\n", cases[i].what,
						cases[i].allowed ? "rejected" : "accepted");
				return EXIT_FAILURE;
			}
			if (error == PG_OAUTH_IDENTITY_OK)
				pg_oauth_identity_clear(&identity);
		}
	}
	return EXIT_SUCCESS;
}
