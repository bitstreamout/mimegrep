/*
 * Copyright (c) 1996-1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 * Portions Copyright (c) 1995 by International Business Machines, Inc.
 *
 * International Business Machines, Inc. (hereinafter called IBM) grants
 * permission under its copyrights to use, copy, modify, and distribute this
 * Software with or without fee, provided that the above copyright notice and
 * all paragraphs of this notice appear in all copies, and that the name of IBM
 * not be used in connection with the marketing of any product incorporating
 * the Software or modifications thereof, without specific, written prior
 * permission.
 *
 * To the extent it has a right to do so, IBM grants an immunity from suit
 * under its patents, if any, for the use, sale or manufacture of products to
 * the extent that such products are used for performing Domain Name System
 * dynamic updates in TCP/IP networks by means of the Software.  No immunity is
 * granted for any product per se or for any other function of any product.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", AND IBM DISCLAIMS ALL WARRANTIES,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE.  IN NO EVENT SHALL IBM BE LIABLE FOR ANY SPECIAL,
 * DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE, EVEN
 * IF IBM IS APPRISED OF THE POSSIBILITY OF SUCH DAMAGES.
 */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <ctype.h>
#include <string.h>

/* decode64 is based on code of the libresolv of the glibc hence the copyright above */
#if 0
static const char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
#endif
static const char index64[128] = {
    -1,-1,-1,-1,    -1,-1,-1,-1,    -1,-1,-1,-1,    -1,-1,-1,-1,
    -1,-1,-1,-1,    -1,-1,-1,-1,    -1,-1,-1,-1,    -1,-1,-1,-1,
    -1,-1,-1,-1,    -1,-1,-1,-1,    -1,-1,-1,62,    -1,-1,-1,63,
    52,53,54,55,    56,57,58,59,    60,61,-1,-1,    -1,-1,-1,-1,
    -1, 0, 1, 2,     3, 4, 5, 6,     7, 8, 9,10,    11,12,13,14,
    15,16,17,18,    19,20,21,22,    23,24,25,-1,    -1,-1,-1,-1,
    -1,26,27,28,    29,30,31,32,    33,34,35,36,    37,38,39,40,
    41,42,43,44,    45,46,47,48,    49,50,51,-1,    -1,-1,-1,-1
};
unsigned char*
decode64(char **src)
{
    static char state64;
    static unsigned char dest[5];
    static int i;
    int c;

    if (!src)
	goto reset;

    while ((c = *(*src)++) != '\0') {
	if (isspace(c))
	    continue;

	if (c == '=')
	    break;

	const int p = ((c<0||c>127)?-1:index64[c]);
	if (p < 0 || isspace(c))
	    continue;

	switch (state64) {
	case 0:
	    i = 0;
	    memset(dest, '\0', sizeof(dest));
	    dest[i] = p << 2;
	    state64 = 1;
	    continue;
	case 1:
	    dest[i++] |= p >> 4;
	    dest[i]    = (p & 0x0f) << 4;
	    state64 = 2;
	    continue;
	case 2:
	    dest[i++] |= p >> 2;
	    dest[i]    = (p & 0x03) << 6;
	    state64 = 3;
	    continue;
	case 3:
	    dest[i++] |= p;
	    goto out;
	default:
	    goto reset;
	}
    }

    if (c == '=') {
	c = *(*src)++;
	switch (state64) {
	case 0:
	case 1:
	    goto reset;
	case 2:
	    for ( ; c != '\0'; c = *(*src)++)
		if (!isspace(c))
		    break;
	    if (c != '=')
		goto reset;
	    c = *(*src)++;
	    /* fall through! */
	case 3:
	    for ( ; c != '\0'; c = *(*src)++)
		if (!isspace(c))
		    goto reset;
	    if (dest[i] != 0) 
		goto reset;
	    while(*(*src)++ != '\0')
		; /* drain buffer */
	}
    } else /* if (state64 != 0) */
	goto reset;

out:
    i = state64 = 0;
    return (unsigned char*)dest;
reset:
    i = state64 = 0;
    return (unsigned char*)0;
}

/*
 * Portions Copyright (c) 1991 Bell Communications Research, Inc. (Bellcore)
 *
 * Permission to use, copy, modify, and distribute this material
 * for any purpose and without fee is hereby granted, provided
 * that the above copyright notice and this permission notice
 * appear in all copies, and that the name of Bellcore not be
 * used in advertising or publicity pertaining to this
 * material without the specific, prior written permission
 * of an authorized representative of Bellcore.  BELLCORE
 * MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY
 * OF THIS MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS",
 * WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES.
 */

static const char qphex[] = {
    -1,-1,-1,-1,  -1,-1,-1,-1,  -1,-1,-1,-1,  -1,-1,-1,-1,
    -1,-1,-1,-1,  -1,-1,-1,-1,  -1,-1,-1,-1,  -1,-1,-1,-1,
    -1,-1,-1,-1,  -1,-1,-1,-1,  -1,-1,-1,-1,  -1,-1,-1,-1,
     0, 1, 2, 3,   4, 5, 6, 7,   8, 9,-1,-1,  -1,-1,-1,-1,
    -1,10,11,12,  13,14,15,-1,  -1,-1,-1,-1,  -1,-1,-1,-1,
    -1,-1,-1,-1,  -1,-1,-1,-1,  -1,-1,-1,-1,  -1,-1,-1,-1,
    -1,10,11,12,  13,14,15,-1,  -1,-1,-1,-1,  -1,-1,-1,-1,
    -1,-1,-1,-1,  -1,-1,-1,-1,  -1,-1,-1,-1,  -1,-1,-1,-1
};

/* decodeqp is based on code of the metamail package hence the copyright above */
unsigned char*
decodeqp(char **src)
{
    static unsigned char dest[2];
    int c;

    if (!src)
	goto reset;

    while ((c = *(*src)++) != '\0') {
	if (c > 127)
	    goto reset;
	if (c == '=') {
	    unsigned int x, y;
	    x = *(*src)++;
	    if (x == '\n')
		continue;
	    for ( ; x != '\0'; x = *(*src)++)
		if (!isspace(x))
		    break;
	    x = qphex[x];
	    y = *(*src)++;
	    for ( ; y != '\0'; y = *(*src)++)
		if (!isspace(y))
		    break;
	    y = qphex[y];
	    dest[0] = (x<<4)|y;
	} else
	    dest[0] = c;
	goto out;
    }
    if (c == '\0')
	goto reset;
out:
    return (unsigned char*)dest;
reset:
    return (unsigned char*)0;
}
