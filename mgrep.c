/*
 * m(ime)grep(.c)
 *
 * Copyright 2019 Werner Fink, 2019 SUSE LINUX GmbH, Germany.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <ctype.h>
#include <errno.h>
#include <err.h>
#include <getopt.h>
#include <limits.h>
#include <locale.h>
#include <pipeline.h>
#include <regex.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

typedef enum _boolean {false, true} boolean;

typedef struct container_s {
    regex_t    reg_boundary;
    unsigned long      mask;
    char       charset[128];
    int               found;
    int              free:1;
    struct container_s *next;
} container_t;

static char lines[PIPE_BUF];
static char bound[128] = {'^','-','-'};
static char charset[128];
static regex_t     reg_from;
static container_t container = { .next = (container_t*)0 };
static regex_t     reg_multipart;
static regex_t     reg_type;
static regex_t     reg_transfer;
static regex_t     reg_body;
static regmatch_t  match_type[5];
#define reset_match_type() ({int n; for (n=0; n<(int)(sizeof(match_type)/sizeof(regmatch_t)); n++) match_type[n].rm_so=-1;})

static inline void
regcompiler(regex_t *restrict preg, const char *restrict regex, int cflags)
{
    int ret = regcomp(preg, regex, cflags);
    if (ret) {
	char buf[LINE_MAX];
	regerror(ret, preg, buf, sizeof (buf));
	regfree (preg);
	errx(1, "%s\n", buf);
    }
    return;
}

static inline boolean
regexecutor(regex_t *preg, const char *string,
	    size_t nmatch, regmatch_t pmatch[], int eflags)
{
    int ret = regexec(preg, string, nmatch, pmatch, eflags);
    if (ret > REG_NOMATCH) {
	char buf[LINE_MAX];
	regerror(ret, preg, buf, sizeof (buf));
	regfree (preg);
	warnx("%s\n", buf);
    }
    return (ret ? false : true);
}

static char*
value(const char *assign, const char *str)
{
    char *res = strcasestr(str, assign);
    size_t len;

    if (!res || !(*res))
	return (char*)0;

    res += strlen(assign);;
    if (*res == '"')
	res++;

    len = strcspn(res, " \t\";\n");
    res = strndup(res, len);

    return res;
}

typedef enum {
    UNKNOWN = 0,
    HEADER,
    CONTENT,
    BODY
} mbox_t;

static mbox_t mbox = UNKNOWN;
/*
 * Bits for current logic in mbox
 */
#define BOUND		(1<<0)
#define MULTI		(1<<1)
#define TYPE		(1<<2)
#define TRANSFER	(1<<3)
#define CONTAINER	(1<<4)

/*
 * Bits for current properties of an container or body
 */
#define CHARSET		(1<<15)
#define PLAIN		(1<<16)
#define HTML		(1<<17)
#define BASE64		(1<<18)
#define QUOTEPRT	(1<<19)
#define ASCII		(1<<20)
#define UTF8		(1<<21)
#define LATIN		(1<<22)
#define MBYTECHR	(1<<23)

static int
fill(char *lines, const size_t nmemb, size_t *start, size_t *end, FILE *stream)
{
    size_t ret;

    if (!start || !end)
	errx(1, "BUG: fill()\n");
    if (*start > nmemb || *end > nmemb)
	errx(1, "Boundary to large: fill() %lu %lu %lu\n", *start, *end, nmemb);

    if (*start > 0) {
	off_t off = (*end)-(*start);
	(void)memmove(lines, lines+(*start), off);
	(void)memset(lines+off, '\0', nmemb-off);
	*end = off;
	*start = 0;
    }

    ret = fread(lines+(*end), sizeof(char), nmemb - *end, stream);
    *end = ret + *end;
    return !(*start == *end);
}

/*
 * Set and reset signal handlers as well unblock the signal
 * if a handler for that signal is set.
 */
static volatile sig_atomic_t signaled;
static void sighandle(int sig)
{
    if (sig != SIGPIPE)
	return;
    signaled = (volatile sig_atomic_t)sig;
}

static void
set_signal(int sig, struct sigaction *old, sighandler_t handler)
{
    if (old) {
	do {
	    if (sigaction(sig, NULL, old) == 0)
		break;
	} while (errno == EINTR);
    }

    if (!old || (old->sa_handler != handler)) {
	struct sigaction new;
	sigset_t sigset;

	new.sa_handler = handler;
	sigemptyset(&new.sa_mask);
	new.sa_flags = SA_RESTART;
	do {
	    if (sigaction(sig, &new, NULL) == 0)
		break;
	} while (errno == EINTR);

	sigemptyset(&sigset);
	sigaddset(&sigset, sig);

	sigprocmask(SIG_UNBLOCK, &sigset, NULL);
    }
}

static void
reset_signal(int sig, struct sigaction *old)
{
    struct sigaction cur;

    do {
	if (sigaction(sig, NULL, &cur) == 0)
	    break;
    } while (errno == EINTR);

    if (old && old->sa_handler != cur.sa_handler) {
	do {
	    if (sigaction(sig, old, NULL) == 0)
		break;
	} while (errno == EINTR);
    }
}

extern unsigned char* decode64(char **src);
extern  unsigned char* decodeqp(char **src);

static struct option long_options[] =
{
    {"quoted-printable",	0, (int*)0, 'Q'},
    {"base64",			0, (int*)0, 'X'},
    {"help",			0, (int*)0, 'h'},

    /* Options with arguments used by grep */
    {"after-context",		1, (int*)0, 'A'},
    {"before-context",		1, (int*)0, 'B'},
    {"binary-files",		1, (int*)0, 256},
    {"context",			1, (int*)0, 'C'},
    {"color",			2, (int*)0, 257},
    {"colour",			2, (int*)0, 257},
    {"devices",			1, (int*)0, 'D'},
    {"directories",		1, (int*)0, 'd'},
    {"exclude",			1, (int*)0, 258},
    {"exclude-from",		1, (int*)0, 259},
    {"exclude-dir",		1, (int*)0, 260},
    {"file",			1, (int*)0, 'f'},
    {"group-separator",		1, (int*)0, 270},
    {"include",			1, (int*)0, 271},
    {"label",			1, (int*)0, 271},
    {"max-count",		1, (int*)0, 'm'},
    {"regexp",			1, (int*)0, 'e'},

    { 0,			0, (int*)0,  0 },
};

#define optname(v)      ({struct option *opt = &long_options[0]; for (; opt->val; opt++) if (opt->val == (v)) break; (const char*)opt->name;})

int
main(int argc, char **argv)
{
    struct sigaction saved_sigpipe;
    unsigned long int mask = BASE64;
    size_t start, end;
    volatile int olderror;
    int c, eopt = 0, Hopt = 0;
    pipeline *p;
    pipecmd *grep;
    FILE *gout;

    setlocale(LC_ALL, "POSIX");
    set_signal(SIGPIPE, &saved_sigpipe, sighandle);

    /*
     * Use the original grep command, that is m(ime)grep is used
     * as a wrapper to send the decoded BASE64/QP streams to the
     * the grep command.
     */
    grep = pipecmd_new("/usr/bin/grep");

    /*
     * Unknown options are handled by the final grep call
     */
    opterr = 0;
    while ((c = getopt_long(argc, argv, "QXhA:B:C:D:d:e:f:m:", long_options, (int*)0)) != -1) {
	switch (c) {
	case 'Q':			/* Currently unused option of grep */
	    mask &= ~BASE64;
	    mask |= QUOTEPRT;
	    break;
	case 'X':			/* Ohmm undocumented option of grep: set matcher of grep */
	    mask &= ~QUOTEPRT;
	    mask |= BASE64;
	    break;
	case 'h':
	err:
	    fprintf(stdout,
		    "Usage: mimegrep [OPTION]... PATTERNS [FILE]...\n\n"
		    "  -h, --help               Displays this help and exit.\n"
		    "  -Q, --quoted-printable   Assume \"quoted-printable\" encoding\n"
		    "  -X, --base64             Assume \"base64\" encoding (default)\n"
		    "\n"
		    );
	    pipecmd_arg(grep, "--help");
	    p = pipeline_new();
	    pipeline_command(p, grep);
	    pipeline_start(p);
	    c = pipeline_wait(p);
	    pipeline_free(p);
	    return c;
	case 'A':
	case 'B':
	case 256:
	case 'C':
	case 'D':
	case 'd':
	case 258:
	case 259:
	case 260:
	case 'f':
	case 270:
	case 271:
	case 'm':
	    pipecmd_argf(grep, "--%s=%s", optname(c), optarg);
	    break;
	case 'e':
	    eopt++;
	    pipecmd_argf(grep, "--%s=%s", optname(c), optarg);
	    break;
	case 257:
	    if (optarg && *optarg)
		pipecmd_argf(grep, "--%s=%s", optname(c), optarg);
	    else
		pipecmd_argf(grep, "--%s", optname(c));
	    break;
	case '?':
	    if (optopt == 'H')
		Hopt++;
	    pipecmd_argf(grep, "-%c", optopt);
	    break;
	default:
	    break;
	}
    }
    argv += optind;
    argc -= optind;

    if (!eopt) {
	if (!*argv)
	    goto err;
	pipecmd_arg(grep, *argv);
	argv++;
	argc--;
    }

    regcompiler(&reg_from,
		"^From [_[:alnum:]!#$%&'*+/=?`{|}~^-]+(.[_[:alnum:]!#$%&'*+/=?`{|}~^-]+)*@([[:alnum:]-]+.)+[[:alpha:]]{2,}"
		" +(Fri|Mon|Sat|Sun|Thu|Tue|Wed) +(Apr|Aug|Dec|Feb|Jan|Jul|Jun|Mar|May|Nov|Oct|Sep)"
		" +[[:digit:]]{1,2} +[[:digit:]]{2}:[[:digit:]]{2}:[[:digit:]]{2} +[[:digit:]]{4}[[:blank:]]*$",
		REG_NEWLINE|REG_EXTENDED|REG_ICASE);
    regcompiler(&reg_multipart,
		"^content-type:[[:blank:]]+multipart/(alternative|mixed|signed|encrypted|related|report|digest|parallel);"
		"([[:space:]]+[[:alpha:]]+=([[:graph:]]+))+[[:blank:]]*$",
		REG_NEWLINE|REG_EXTENDED|REG_ICASE);
    regcompiler(&reg_type,
		"^content-type:[[:blank:]]+text/([[:graph:]]+);"
		"([[:space:]]+[[:alpha:]]+=([[:graph:]]+))+[[:blank:]]*$",
		REG_NEWLINE|REG_EXTENDED|REG_ICASE);
    regcompiler(&reg_transfer,
		"^content-transfer-encoding:[[:blank:]]+([[:graph:]]+)[[:blank:]]*$",
		REG_NEWLINE|REG_EXTENDED|REG_ICASE);
    regcompiler(&reg_body,
		"^$",
		REG_NEWLINE|REG_EXTENDED|REG_ICASE);

    p = pipeline_new();
    pipeline_want_in(p, -1);
    pipeline_command(p, grep);
    do {							/* while (*argv) */
	container_t *deep = (container_t*)0;

	if (*argv) {
	    stdin = freopen(*argv, "r", stdin);
	    if (!stdin)
		errx(1, "freopen(): %m\n");
	    if (Hopt)
		pipecmd_args(grep, "--label", *argv, NULL);
	    argv++;
	}

	pipeline_start(p);
	gout = pipeline_get_infile (p);
	if (!gout)
	    errx(1, "pipeline_get_infile: %m\n");

	start = end = 0;
	do {							/* while (end) */
	    FILE *body, *scan;
	    char *line = NULL, *buffer = NULL;
	    size_t len = 0, bytes = 0, loc = 0;
	    ssize_t ret;
	    off_t next;

	    if (!fill(lines, sizeof(lines), &start, &end, stdin))
		break;

	    switch (mbox) {
	    case 0:
		reset_match_type();
		if (regexecutor(&reg_from, lines, 1, match_type, 0)) {
		    regmatch_t *sub = &match_type[0];
		    if (sub->rm_so > 0) {
			/* Within a mbox folder file/stream, skip bytes from previous message */
			start = sub->rm_so;
			continue;
		    }
		    mbox = HEADER;				/* leading line of email header found (mbox) */

		    /* fall through */
		} else
		    break;
	    case HEADER:
		reset_match_type();
		if (!(mask&MULTI) && regexecutor(&reg_multipart, lines, 3, match_type, 0)) {
		    regmatch_t *sub = &match_type[0];
		    if (sub->rm_so >= 0) {
			if (sub->rm_so > 0) {
			    start = sub->rm_so;
			    continue;
			}
			mask |= MULTI;
		    }

		    sub = &match_type[2];
		    if (sub->rm_so >= 0) {
			/* The buffer might be much more than only upto next newline */
			char *ptr = &lines[0];
			int eos = *(ptr+sub->rm_eo);
			*(ptr+sub->rm_eo) = '\0';

			sub = &match_type[0];
			if (sub->rm_so >= 0) {
			    char *boundary = value("boundary=", ptr+sub->rm_so);
			    if (boundary) {
				if (strlen(boundary) > sizeof(bound)-9)
				    errx(1, "Boundary to large: %s\n", ptr);
				strcpy(&bound[3], boundary);
				strcat(bound, "(--)?\n");
				regcompiler(&container.reg_boundary, bound, REG_NEWLINE|REG_EXTENDED);
				container.free = 1;
				mask |= BOUND;
				free(boundary);
			    }
			}

			*(ptr+sub->rm_eo) = eos;
		    }

		    mbox = CONTENT;				/* Content description: here multipart message */

		    goto content;
		}

		/* No multipart message body: fall through */

		next = 0;
		reset_match_type();
		if (!(mask&TYPE) && regexecutor(&reg_type, lines, 4, match_type, 0)) {
		    regmatch_t *sub = &match_type[0];
		    if (sub->rm_so >= 0) {
			if (sub->rm_so > 0) {
			    start = sub->rm_so;
			    continue;
			}
			mask |= TYPE;
		    }
		    sub = &match_type[1];
		    if (sub->rm_so >= 0) {
			char *ptr = &lines[0];
			if (strncasecmp("html", ptr+sub->rm_so, sub->rm_eo-sub->rm_so) == 0)
			    mask |= HTML;
			else
			    mask |= PLAIN;
		    }
		    sub = &match_type[2];
		    if (sub->rm_so >= 0) {
			/* The buffer might be much more than only upto next newline */
			char *ptr = &lines[0];
			int eos = *(ptr+sub->rm_eo);
			*(ptr+sub->rm_eo) = '\0';

			next = sub->rm_eo + 1;

			sub = &match_type[0];
			if (sub->rm_so >= 0) {
			    char *set = value("charset=", ptr+sub->rm_so);
			    if (set) {
				mask |= CHARSET;
				mask &= ~(ASCII|LATIN|UTF8|MBYTECHR);
				if (strcasecmp(set, "us-ascii") == 0)
				    mask |= ASCII;
				else if (strncasecmp(set, "iso-latin", 9) == 0)
				    mask |= LATIN;
				else if (strcasecmp(set, "utf-8") == 0)
				    mask |= UTF8;
				else
				    mask |= MBYTECHR;
				strncpy(charset, set, sizeof(charset)-1);
				free(set);
			    }
			}

			*(ptr+sub->rm_eo) = eos;
		    }

		    mbox = CONTENT;				/* Content description: here single message */
		}

		reset_match_type();
		if (!(mask&TRANSFER) && regexecutor(&reg_transfer, lines+next, 2, match_type, 0)) {
		    regmatch_t *sub = &match_type[0];
		    if (sub->rm_so >= 0)
			mask |= TRANSFER;

		    sub = &match_type[1];
		    if (sub->rm_so >= 0) {
			const char *ptr = &lines[next];

			if (strncasecmp("quoted-printable", ptr+sub->rm_so, sub->rm_eo-sub->rm_so) == 0)
			    mask |= QUOTEPRT;
			else if (strncasecmp("base64", ptr+sub->rm_so, sub->rm_eo-sub->rm_so) == 0)
			    mask |= BASE64;
		    }

		    mbox = CONTENT;				/* Content description: here single message */
		}

	    case CONTENT:
	    content:
		reset_match_type();
		if (regexecutor(&reg_body, lines, 1, match_type, 0)) {
		    regmatch_t *sub = &match_type[0];
		    if (sub->rm_so >= 0) {
			const char *ptr;
			if (sub->rm_so > 0) {
			    start = sub->rm_so;
			    continue;
			}
			ptr = &lines[0];
			start = (size_t)sub->rm_eo;		/* refill AFTER container description has been done */
			while (*(ptr+start) == '\n')
			    start++;
			mbox = BODY;				/* Reached body of the mbox */
			continue;
		    }
		} else {
		    const char *ptr = &lines[0];
		    const char *eol = strchr(ptr, '\n');
		    if (++eol > ptr)
			start = eol - ptr;
		    else
			start++;
		    continue;
		}
		/* fall through */

	    case BODY:
		if (mask&BOUND) {
		    deep = &container;
		    deep->found = 0;
		    deep->mask = 0;
		    if (charset[0] != '\0')
			strcpy(deep->charset, charset);
		    else deep->charset[0] = '\0';
		} else
		    deep = (container_t*)0;
		break;
	    default:
		break;
	    }

	    do {						/* while (deep) */

		if (!fill(lines, sizeof(lines), &start, &end, stdin))   /* NOW refill lines */
		    break;

		reset_match_type();
		if (!(mask&CONTAINER) && deep && regexecutor(&deep->reg_boundary, lines, 2, match_type, 0)) {
		    regoff_t description = 0;
		    char *ptr;
		    int eob = -1;
		    regmatch_t *sub = &match_type[0];

		    if (sub->rm_so >= 0) {
			if (sub->rm_so > 0) {
			    start = sub->rm_so;
			    continue;
			}
			deep->found++;
			start = (size_t)sub->rm_eo;
		    }
		    next = 0;

		    sub = &match_type[1];
		    if (sub->rm_so >= 0) {
			deep->found = 0;
			break;
		    }

		    reset_match_type();
		    if (regexecutor(&reg_body, lines, 2, match_type, 0)) {
			regmatch_t *sub = &match_type[0];
			if (sub->rm_so >= 0) {
			    ptr = &lines[sub->rm_so];
			    eob = *ptr;
			    while (*(ptr+description) == '\n')
				description++;
			    description += sub->rm_so;
			    *ptr = '\0';			/* parse only the description of the current container */
			}
		    }

		    reset_match_type();
		    if (!(deep->mask&MULTI) && regexecutor(&reg_multipart, lines, 3, match_type, 0)) {
			regmatch_t *sub = &match_type[0];
			if (sub->rm_so >= 0)
			    deep->mask |= MULTI;

			sub = &match_type[2];
			if (sub->rm_so >= 0) {
			    char *bptr = &lines[0];

			    sub = &match_type[0];
			    if (sub->rm_so >= 0) {
				char *boundary = value("boundary=", bptr+sub->rm_so);
				if (boundary) {
				    container_t *cont;

				    if (strlen(boundary) > sizeof(bound)-9)
					errx(1, "Boundary to large: %s\n", bptr);
				    strcpy(&bound[3], boundary);
				    strcat(bound, "(--)?\n");

				    deep->next = (container_t*)malloc(sizeof(container_t));
				    if (!deep->next)
					errx(1, "malloc(): %m\n");
				    cont = deep->next;
				    memset(cont, 0, sizeof(container_t));
				    regcompiler(&(cont->reg_boundary), bound, REG_NEWLINE|REG_EXTENDED);
				    cont->free = 1;
				    cont->mask |= BOUND;
				    free(boundary);
				}
			    }
			}
		    }

		    reset_match_type();
		    if (!(deep->mask&TYPE) && regexecutor(&reg_type, lines, 4, match_type, 0)) {
			char *bptr = &lines[0];
			regmatch_t *sub = &match_type[0];
			if (sub->rm_so >= 0)
			    deep->mask |= TYPE;

			sub = &match_type[1];
			if (sub->rm_so >= 0) {
			    if (strncasecmp("html", bptr+sub->rm_so, sub->rm_eo-sub->rm_so) == 0)
				deep->mask |= HTML;
			    else
			    deep->mask |= PLAIN;
			}
			sub = &match_type[2];
			if (sub->rm_so >= 0) {
			    /* The buffer might be much more than only upto next newline */
			    *(bptr+sub->rm_eo) = '\0';

			    next = sub->rm_eo + 1;

			    sub = &match_type[0];
			    if (sub->rm_so >= 0) {
				char *set = value("charset=", bptr+sub->rm_so);
				if (set) {
				    deep->mask |= CHARSET;
				    deep->mask &= ~(ASCII|LATIN|UTF8|MBYTECHR);
				    if (strcasecmp(set, "us-ascii") == 0)
					deep->mask |= ASCII;
				    else if (strncasecmp(set, "iso-latin", 9) == 0)
					deep->mask |= LATIN;
				    else if (strcasecmp(set, "utf-8") == 0)
					deep->mask |= UTF8;
				    else
					deep->mask |= MBYTECHR;
				    strncpy(deep->charset, set, sizeof(charset)-1);
				    free(set);
				}
			    }
			}
		    }

		    reset_match_type();
		    if (!(deep->mask&TRANSFER) && regexecutor(&reg_transfer, lines+next, 2, match_type, 0)) {
			const char *bptr = &lines[next];
			regmatch_t *sub = &match_type[0];
			if (sub->rm_so >= 0)
			    deep->mask |= TRANSFER;

			sub = &match_type[1];
			if (sub->rm_so >= 0) {
			    if (strncasecmp("quoted-printable", bptr+sub->rm_so, sub->rm_eo-sub->rm_so) == 0)
				deep->mask |= QUOTEPRT;
			    else if (strncasecmp("base64", bptr+sub->rm_so, sub->rm_eo-sub->rm_so) == 0)
				deep->mask |= BASE64;
			}
		    }

		    if (eob >= 0) {
			*ptr = eob;
			start = description;
		    }

		    if (!fill(lines, sizeof(lines), &start, &end, stdin))
			break;

		    if (deep->next) {
			deep = deep->next;
			continue;
		    }

		    mask &= ~(BASE64|QUOTEPRT);
		    mask &= ~(ASCII|LATIN|UTF8|MBYTECHR);
		    mask |= deep->mask;

		    mask |= CONTAINER;

		}					    /* if (deep && ...) */

		line = NULL;
		len = bytes = 0;
		body = fmemopen(lines, end-start, "r");
		if (!body)
		    errx(1, "fmemopen(): %m\n");
		buffer = NULL;
		loc = 0;
		scan = open_memstream(&buffer, &loc);
		if (!scan)
		    errx(1, "open_memstream(): %m\n");
		olderror = 0;
		while ((ret = getline(&line, &len, body)) > 0) {

		    if (line[ret-1] != '\n' && !feof(stdin))
			break;				    /* refill lines */

		    if (line[0] == '-' && line[1] == '-' && deep) {
			reset_match_type();
			if (regexecutor(&deep->reg_boundary, line, 2, match_type, 0)) {
			    regmatch_t *sub = &match_type[0];
			    if (sub->rm_so >= 0)
				deep->found--;
			    sub = &match_type[1];
			    if (sub->rm_so >= 0) {
				if (deep == &container) {
				    if (deep->free)
					regfree(&deep->reg_boundary);
				    deep->free = 0;
				    deep = (container_t*)0;
				    mask &= ~BOUND;
				} else {
				    container_t *curr = &container;
				    while (curr) {
					container_t *next = curr->next;
					if (next && next == deep) {
					    if (deep->free)
						regfree(&deep->reg_boundary);
					    deep->free = 0;
					    curr->next = deep->next;
					    free(deep);
					    deep = curr;
					}
					curr = curr->next;
				    }
				}
			    }
			    mask &= ~CONTAINER;
			    break; 			    /* end of container */
			}
		    }

		    bytes += ret;			    /* After boundary to get next match */

		    if (mask&BASE64) {
			unsigned char *out;
			char *pos = line;
			int flen = 0;
			while (flen >= 0 && (out = decode64(&pos)))
			    flen = fputs((char*)out, scan);
		    } else if (mask&QUOTEPRT) {
			unsigned char *out;
			char *pos = line;
			int flen = 0;
			while (flen >= 0 && (out = decodeqp(&pos)))
			    flen = fputs((char*)out, scan);
		    } else
			fputs(line, scan);

		    if (line[ret-1] != '\n')
			fputc('\n', scan);

		    if (fflush(scan) < 0)		    /* EOF might indicate an error here */
			errx(1, "open_memstream(): %m\n");

		    memset(line, '\0', len);
		}
		if (ret < 0 && errno && errno != EPIPE)	    /* EOF might indicate an error here */
		    errx(1, "getline(%d): %m\n", __LINE__);
		if (len)
		    free(line);
		fclose(body);
		fclose(scan);

		if (loc) {
		    scan = fmemopen(buffer, loc, "r");
		    if (!scan)
			errx(1, "fmemopen(): %m\n");
		    line = NULL;
		    len = 0;
		    while ((ret = getline(&line, &len, scan)) > 0) {
			if (fputs(line, gout) < 0)
			    break;
		    }
		    if (ret < 0 && errno && errno != EPIPE)  /* EOF might indicate an error here */
			errx(1, "getline(%d): %m\n", __LINE__);
		    if (line)
			free(line);
		    fclose(scan);
		}
		free(buffer);

		if (feof(stdin) && bytes >= end)
		    break;

		if (errno == EPIPE)
		    break;

		start = bytes;

	    } while (deep);

	    if (feof(stdin)) {
		mask = 0;
		mbox = UNKNOWN;
		break;
	    }

	    if (errno == EPIPE)
		break;

	} while (end);

	olderror = errno;				    /* No child is very likely */
	c = (pipeline_wait(p));
	errno = olderror;

	deep = &container;
	if (deep->free)
	    regfree(&deep->reg_boundary);
	deep->free = 0;

    } while (*argv);

    pipeline_free(p);

    regfree(&reg_from);
    regfree(&reg_multipart);
    regfree(&reg_type);
    regfree(&reg_transfer);
    regfree(&reg_body);

    reset_signal(SIGPIPE, &saved_sigpipe);

    return c;
}

