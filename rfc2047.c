/*
 * Copyright (C) 1996-2000 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2000-2002 Edmund Grimley Evans <edmundo@rano.org>
 *
 *     This program is free software; you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation; either version 2 of the License, or
 *     (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with this program; if not, write to the Free Software
 *     Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

const char AssumedCharset[] = "us-ascii";
const char B64Chars[64] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
  'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
  'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
  't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
  '8', '9', '+', '/'
};
const int Index_hex[128] = {
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
     0, 1, 2, 3,  4, 5, 6, 7,  8, 9,-1,-1, -1,-1,-1,-1,
    -1,10,11,12, 13,14,15,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,10,11,12, 13,14,15,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1
};
const int Index_64[128] = {
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,62, -1,-1,-1,63,
    52,53,54,55, 56,57,58,59, 60,61,-1,-1, -1,-1,-1,-1,
    -1, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
    15,16,17,18, 19,20,21,22, 23,24,25,-1, -1,-1,-1,-1,
    -1,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
    41,42,43,44, 45,46,47,48, 49,50,51,-1, -1,-1,-1,-1
};

/* Content-Transfer-Encoding */
enum
{
  ENCOTHER,
  ENC7BIT,
  ENC8BIT,
  ENCQUOTEDPRINTABLE,
  ENCBASE64,
  ENCBINARY,
  ENCUUENCODED
};

#define base64val(c) Index_64[(unsigned int)(c)]
#define hexval(c) Index_hex[(unsigned int)(c)]
#define strfcpy(A,B,C) strncpy (A,B,C), *(A+(C)-1)=0
#define mutt_strlen strlen
#define safe_malloc malloc
#define FREE(x) safe_free(x)
#define ICONV_CONST
/* FIXME: do we need this? */
#define mutt_filter_unprintable

void safe_realloc (void *ptr, size_t siz)
{
	void *r;
	void **p = (void **)ptr;

	if (siz == 0)
	{
		if (*p)
		{
			free (*p);			/* __MEM_CHECKED__ */
			*p = NULL;
		}
		return;
	}

	if (*p)
		r = (void *) realloc (*p, siz);		/* __MEM_CHECKED__ */
	else
	{
		/* realloc(NULL, nbytes) doesn't seem to work under SunOS 4.1.x  --- __MEM_CHECKED__ */
		r = (void *) malloc (siz);		/* __MEM_CHECKED__ */
	}

	*p = r;
}

void mutt_str_adjust (char **p)
{
	if (!p || !*p) return;
	safe_realloc (p, strlen (*p) + 1);
}

void safe_free (void *ptr)				/* __SAFE_FREE_CHECKED__ */
{
	void **p = (void **)ptr;
	if (*p)
	{
		free (*p);				/* __MEM_CHECKED__ */
		*p = 0;
	}
}

char *mutt_substrdup (const char *begin, const char *end)
{
	size_t len;
	char *p;

	if (end)
		len = end - begin;
	else
		len = strlen (begin);

	p = safe_malloc (len + 1);
	memcpy (p, begin, len);
	p[len] = 0;
	return p;
}

static int rfc2047_decode_word (char *d, const char *s, size_t len)
{
	const char *pp, *pp1;
	char *pd, *d0;
	const char *t, *t1;
	int enc = 0, count = 0;
	char *charset = NULL;
	int rv = -1;

	pd = d0 = safe_malloc (strlen (s));

	for (pp = s; (pp1 = strchr (pp, '?')); pp = pp1 + 1)
	{
		count++;

		/* hack for non-compliant MUAs that allow unquoted question marks in encoded-text */
		if (count == 4)
		{
			while (pp1 && *(pp1 + 1) != '=')
				pp1 = strchr(pp1 + 1, '?');
			if (!pp1)
				goto error_out_0;
		}

		switch (count)
		{
			case 2:
				/* ignore language specification a la RFC 2231 */
				t = pp1;
				if ((t1 = memchr (pp, '*', t - pp)))
					t = t1;
				charset = mutt_substrdup (pp, t);
				break;
			case 3:
				if (toupper ((unsigned char) *pp) == 'Q')
					enc = ENCQUOTEDPRINTABLE;
				else if (toupper ((unsigned char) *pp) == 'B')
					enc = ENCBASE64;
				else
					goto error_out_0;
				break;
			case 4:
				if (enc == ENCQUOTEDPRINTABLE)
				{
					for (; pp < pp1; pp++)
					{
						if (*pp == '_')
							*pd++ = ' ';
						else if (*pp == '=' &&
							 (!(pp[1] & ~127) && hexval(pp[1]) != -1) &&
							 (!(pp[2] & ~127) && hexval(pp[2]) != -1))
						{
							*pd++ = (hexval(pp[1]) << 4) | hexval(pp[2]);
							pp += 2;
						}
						else
							*pd++ = *pp;
					}
					*pd = 0;
				}
				else if (enc == ENCBASE64)
				{
					int c, b = 0, k = 0;

					for (; pp < pp1; pp++)
					{
						if (*pp == '=')
							break;
						if ((*pp & ~127) || (c = base64val(*pp)) == -1)
							continue;
						if (k + 6 >= 8)
						{
							k -= 2;
							*pd++ = b | (c >> k);
							b = c << (8 - k);
						}
						else
						{
							b |= c << (k + 2);
							k += 6;
						}
					}
					*pd = 0;
				}
				break;
		}
	}

#if 0
	if (charset)
		mutt_convert_string (&d0, charset, Charset, M_ICONV_HOOK_FROM);
#endif
	mutt_filter_unprintable (&d0);
	strfcpy (d, d0, len);
	rv = 0;
error_out_0:
	FREE (&charset);
	FREE (&d0);
	return rv;
}

/*
 * Find the start and end of the first encoded word in the string.
 * We use the grammar in section 2 of RFC 2047, but the "encoding"
 * must be B or Q. Also, we don't require the encoded word to be
 * separated by linear-white-space (section 5(1)).
 */
static const char *find_encoded_word (const char *s, const char **x)
{
	const char *p, *q;

	q = s;
	while ((p = strstr (q, "=?")))
	{
		for (q = p + 2;
				0x20 < *q && *q < 0x7f && !strchr ("()<>@,;:\"/[]?.=", *q);
				q++)
			;
		if (q[0] != '?' || !strchr ("BbQq", q[1]) || q[2] != '?')
			continue;
		/* non-strict check since many MUAs will not encode spaces and question marks */
		for (q = q + 3; 0x20 <= *q && *q < 0x7f && (*q != '?' || q[1] != '='); q++)
			;
		if (q[0] != '?' || q[1] != '=')
		{
			--q;
			continue;
		}

		*x = q + 2;
		return p;
	}

	return 0;
}

/* try to decode anything that looks like a valid RFC2047 encoded
 * header field, ignoring RFC822 parsing rules
 */
void rfc2047_decode (char **pd)
{
	const char *p, *q;
	size_t m, n;
	int found_encoded = 0;
	char *d0, *d;
	const char *s = *pd;
	size_t dlen;

	if (!s || !*s)
		return;

	dlen = 4 * strlen (s); /* should be enough */
	d = d0 = safe_malloc (dlen + 1);

	while (*s && dlen > 0)
	{
		if (!(p = find_encoded_word (s, &q)))
		{
#if 0
			/* no encoded words */
			if (option (OPTIGNORELWS))
			{
				n = mutt_strlen (s);
				if (found_encoded && (m = lwslen (s, n)) != 0)
				{
					if (m != n)
						*d = ' ', d++, dlen--;
					s += m;
				}
			}
#endif
			if (AssumedCharset && *AssumedCharset)
			{
				char *t;
				size_t tlen;

				n = mutt_strlen (s);
				t = safe_malloc (n + 1);
				strfcpy (t, s, n + 1);
#if 0
				convert_nonmime_string (&t);
#endif
				tlen = mutt_strlen (t);
				strncpy (d, t, tlen);
				d += tlen;
				FREE (&t);
				break;
			}
			strncpy (d, s, dlen);
			d += dlen;
			break;
		}

		if (p != s)
		{
			n = (size_t) (p - s);
			/* ignore spaces between encoded word
			 * and linear-white-space between encoded word and *text */
#if 0
			if (option (OPTIGNORELWS))
			{
				if (found_encoded && (m = lwslen (s, n)) != 0)
				{
					if (m != n)
						*d = ' ', d++, dlen--;
					n -= m, s += m;
				}

				if ((m = n - lwsrlen (s, n)) != 0)
				{
					if (m > dlen)
						m = dlen;
					memcpy (d, s, m);
					d += m;
					dlen -= m;
					if (m != n)
						*d = ' ', d++, dlen--;
				}
			}
#endif
			if (!found_encoded || strspn (s, " \t\r\n") != n)
			{
				if (n > dlen)
					n = dlen;
				memcpy (d, s, n);
				d += n;
				dlen -= n;
			}
		}

		if (rfc2047_decode_word (d, p, dlen) == -1)
		{
			/* could not decode word, fall back to displaying the raw string */
			strfcpy(d, p, dlen);
		}
		found_encoded = 1;
		s = q;
		n = mutt_strlen (d);
		dlen -= n;
		d += n;
	}
	*d = 0;

	FREE (pd);				/* __FREE_CHECKED__ */
	*pd = d0;
	mutt_str_adjust (pd);
}

#define BUFSIZE 64 * 1024
int main(int argc, char *argv[])
{
	char buffy[BUFSIZE];
	char *buf;
	int i,n;

	if(argc > 1) {				/* feed via arguments */
		for(i = 1; i < argc; i++){
			buf = strdup(argv[i]);
			rfc2047_decode(&buf);
			printf("%s ", buf);
			free(buf);
		}
		printf("\n");
	} else {				/* feed via stdin */
		while((n = read(STDIN_FILENO, buffy, BUFSIZE)) > 0) {
			buf = strndup(buffy, BUFSIZE);
			rfc2047_decode(&buf);
			printf("%s ", buf);
			free(buf);
		}
	}

	return 0;
}
