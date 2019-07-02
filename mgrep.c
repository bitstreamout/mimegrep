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

static char lines[PIPE_BUF];
static char bound[128] = {'^', '-','-'};
static char charset[128];
static regex_t    reg_from;
static regex_t    reg_boundary;
static regex_t    reg_multipart;
static regex_t    reg_type;
static regex_t    reg_transfer;
static regex_t    reg_body;
static regmatch_t match_type[5];
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

#define HEADER		(1<<0)
#define BOUND		(1<<1)
#define CONTAINER	(1<<2)
#define TYPE		(1<<3)
#define MULTI		(1<<4)
#define PLAIN		(1<<5)
#define HTML		(1<<6)
#define BASE64		(1<<7)
#define QUOTEPRT	(1<<8)
#define CHARSET		(1<<9)
#define HASCHRSET	(1<<10)
#define LAST		(1<<11)
#define DESCR		(1<<12)
#define ASCII		(1<<13)
#define UTF8		(1<<14)
#define LATIN		(1<<15)
#define MBYTECHR	(1<<16)

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

#define optname(v)	({struct option *opt = &long_options[0]; for (; opt->val; opt++) if (opt->val == (v)) break; (const char*)opt->name;})

int
main(int argc, char **argv)
{
    struct sigaction saved_sigpipe;
    unsigned long int mask = BASE64;
    size_t start, end;
    volatile int olderror;
    int container = 0;
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
		    "  -h, --help                Displays this help and exit.\n"
		    "  -Q, --quoted-printable    Assume \"quoted-printable\" encoding\n"
		    "  -X, --base64              Assume \"base64\" encoding (default)\n"
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
		" +[[:digit:]]{1,2} +[[:digit:]]{2}:[[:digit:]]{2}:[[:digit:]]{2} +[[:digit:]]{4}\n",
		REG_NEWLINE|REG_EXTENDED|REG_ICASE);
    regcompiler(&reg_multipart,
		"^content-type:[[:blank:]]+multipart/(alternative|mixed|signed|encrypted|related|report|digest|parallel);"
		"([[:space:]]+[[:alpha:]]+=([[:graph:]]+))+\n",
		REG_NEWLINE|REG_EXTENDED|REG_ICASE);
    regcompiler(&reg_type,
		"^content-type:[[:blank:]]+text/([[:graph:]]+);"
		"([[:space:]]+[[:alpha:]]+=([[:graph:]]+))+\n",
		REG_NEWLINE|REG_EXTENDED|REG_ICASE);
    regcompiler(&reg_transfer,
		"^content-transfer-encoding:[[:blank:]]+([[:graph:]]+)\n",
		REG_NEWLINE|REG_EXTENDED|REG_ICASE);
    regcompiler(&reg_body,
		"(^\n)+",
		REG_NEWLINE|REG_EXTENDED|REG_ICASE);

    p = pipeline_new();
    pipeline_want_in(p, -1);
    pipeline_command(p, grep);

    do {							/* while (*argv) */

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

	    if (!fill(lines, sizeof(lines), &start, &end, stdin))
		break;

	    reset_match_type();
	    if (!(mask&HEADER) && regexecutor(&reg_from, lines, 1, match_type, 0)) {
		regmatch_t *sub = &match_type[0];
		if (sub->rm_so > 0) {
		    /* Within a mbox folder file/stream, skip bytes from previous message */
		    start = sub->rm_so;
		    if (!fill(lines, sizeof(lines), &start, &end, stdin))
			break;
		}
		mask = HEADER;					/* leading line of email header found (mbox) */
		reset_match_type();
		if (regexecutor(&reg_body, lines, 2, match_type, 0)) {
		    regmatch_t *sub = &match_type[1];
		    if (sub->rm_so >= 0) {
			lines[sub->rm_so-start] = '\0';	    	/* parse only the description of the current container */
			mask |= DESCR;
			start = (size_t)sub->rm_eo;		/* refill AFTER container description has been done */
		    }
		}
	    }

	    reset_match_type();
	    if ((mask&HEADER) && regexecutor(&reg_multipart, lines, 5, match_type, 0)) {
		regmatch_t *sub = &match_type[1];
		char *ptr = &lines[0];
		if (sub->rm_so >= 0)
		    mask |= MULTI;
	    
		sub = &match_type[2];
		if (sub->rm_so >= 0) {
		    /* The buffer might be much more than only upto next newline */
		    *(ptr+sub->rm_eo) = '\0';

		    sub = &match_type[0];
		    if (sub->rm_so >= 0) {
			char *boundary = strcasestr(ptr+sub->rm_so, "boundary=");
			if (boundary && *boundary) {
			    char *eos = strpbrk(boundary, ";\n");
			    if (eos)
				*eos = '\0';
			    mask |= CONTAINER;

			    boundary += strlen("boundary=");;
			    if (*boundary == '"')
				boundary++;
			    eos = strrchr(boundary, '"');
			    if (eos)
				*eos = '\0';
			    if (strlen(boundary) > sizeof(bound)-9)
				errx(1, "Boundary to large: %s\n", ptr);
			    strcpy(&bound[3], boundary);
			    strcat(bound, "(--)?\n");
			    regcompiler(&reg_boundary, bound, REG_NEWLINE|REG_EXTENDED);
			    mask |= BOUND;
			}
		    }
		}

		if (!start) {					/* extrem large mail header?! */
		    reset_match_type();
		    if (regexecutor(&reg_body, lines, 2, match_type, 0)) {
			regmatch_t *sub = &match_type[1];
			if (sub->rm_so >= 0) {
			    lines[sub->rm_so-start] = '\0';	/* parse only the description of the current container */
			    mask |= DESCR;
			    start = (size_t)sub->rm_eo;		/* refill AFTER container description has been done */
			}
		    }
		}
		if (!fill(lines, sizeof(lines), &start, &end, stdin))
		    break;
	    }

	    if (mask&BOUND) {
		reset_match_type();
		if (regexecutor(&reg_boundary, lines, 2, match_type, 0)) {
		    regmatch_t *sub = &match_type[1];
		    if (sub->rm_so >= 0) {
			mask |= LAST;
			mask &= ~HEADER;
			container = 0;
		    }
		    sub = &match_type[0];
		    if (sub->rm_so >= 0) {
			container++;
			if (!(mask&LAST))
			    start = (size_t)sub->rm_eo;
		    }
		}
		if (!fill(lines, sizeof(lines), &start, &end, stdin))
		    break;
		reset_match_type();
		if (!(mask&LAST) && regexecutor(&reg_body, lines, 2, match_type, 0)) {
		    regmatch_t *sub = &match_type[1];
		    if (sub->rm_so >= 0) {
			lines[sub->rm_so-start] = '\0';		/* parse only the description of the current container */
			mask |= DESCR;
			start = (size_t)sub->rm_eo;		/* refill AFTER container description has been done */
		    }
		}
	    }

	    if (mask&DESCR) {					/* Handle container description */
		off_t next = 0;
		reset_match_type();
		if (regexecutor(&reg_type, lines, 4, match_type, 0)) {
		    char *ptr = &lines[0];
		    regmatch_t *sub = &match_type[1];
		    mask |= TYPE;
		    if (sub->rm_so >= 0) {
			if (strncasecmp("html", ptr+sub->rm_so, sub->rm_eo-sub->rm_so) == 0)
			    mask |= HTML;
			else
			    mask |= PLAIN;
		    }
		    sub = &match_type[2];
		    if (sub->rm_so >= 0) {
			/* The buffer might be much more than only upto next newline */
			*(ptr+sub->rm_eo) = '\0';

			next = sub->rm_eo + 1;

			sub = &match_type[0];
			if (sub->rm_so >= 0) {
			    char *set = strcasestr(ptr+sub->rm_so, "charset=");
			    if (set && *set) {
				char *eos = strpbrk(set, ";\n");
				if (eos)
				    *eos = '\0';
				mask |= HASCHRSET;

				set += strlen("charset=");;
				if (*set == '"')
				    set++;
				eos = strrchr(set, '"');
				if (eos)
				    *eos = '\0';
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
			    }
			}
		    }
		}

		reset_match_type();
		if (regexecutor(&reg_transfer, lines+next, 2, match_type, 0)) {
		    const char *ptr = &lines[next];
		    regmatch_t *sub = &match_type[1];
		    if (sub->rm_so >= 0) {
			if (strncasecmp("quoted-printable", ptr+sub->rm_so, sub->rm_eo-sub->rm_so) == 0)
				mask |= QUOTEPRT;
			else if (strncasecmp("base64", ptr+sub->rm_so, sub->rm_eo-sub->rm_so) == 0)
			    mask |= BASE64;
		    }
		}

		if (!fill(lines, sizeof(lines), &start, &end, stdin))	/* NOW refill lines */
		    break;

		mask &= ~DESCR;
	    }

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
	    while ((ret = getline(&line, &len, body)) > 0) {
		int err = 0;

		if (line[ret-1] != '\n')
		    break;				/* refill lines */

		if (line[0] == '-' && line[1] == '-' && (mask&BOUND)) {
		    reset_match_type();
		    if (regexecutor(&reg_boundary, line, 2, match_type, 0)) {
			regmatch_t *sub = &match_type[0];
			if (sub->rm_so >= 0) {
			    container = 0;
			    mask &= ~(BASE64|QUOTEPRT);
			    mask &= ~(ASCII|LATIN|UTF8|MBYTECHR);
			    break;			/* end of container */
			}
		    }
		}

		if (mask&BASE64) {
		    unsigned char *out;
		    char *pos = line;
		    while (err >= 0 && (out = decode64(&pos)))
			err = fputs((char*)out, scan);
		} else if (mask&QUOTEPRT) {
		    unsigned char *out;
		    char *pos = line;
		    while (err >= 0 && (out = decodeqp(&pos)))
			err = fputs((char*)out, scan);
		} else
		    err = fputs(line, scan);

		if (fflush(scan) < 0)			/* EOF might indicate an error here */
		    errx(1, "open_memstream(): %m\n");

		bytes += ret;
	    }
	    if (ret < 0 && errno)			/* EOF might indicate an error here */
		errx(1, "getline(): %m\n");
	    if (len) free(line);
	    fclose(body);
	    fclose(scan);
	    if (loc) {
		scan = fmemopen(buffer, loc, "r");
		if (!scan)
		    errx(1, "fmemopen(): %m\n");
		line = NULL;
		len = 0;
		while ((ret = getline(&line, &len, scan)) > 0) {
		    olderror = errno;
		    if (fputs(line, gout) < 0 && errno == EPIPE) {
			errno = olderror;
			goto pipe;
		    }
		}
		if (ret < 0 && errno)			/* EOF might indicate an error here */
		    errx(1, "getline(): %m\n");
	    pipe:
		if (line)
		    free(line);
		free(buffer);
		fclose(scan);
	    }

	    if (mask & LAST) {
		mask = 0;				/* maybe more than one mail but a mbox folder */
		if (feof(stdin))
		    break;
	    }

	    if (errno == EPIPE)
		break;

	    start = bytes;

	} while (end);

	olderror = errno;				/* No child is very likely */
	c = (pipeline_wait(p));
	errno = olderror;

    } while (*argv);

    pipeline_free(p);

    regfree(&reg_from);
    if (mask&BOUND)
	regfree(&reg_boundary);
    regfree(&reg_multipart);
    regfree(&reg_type);
    regfree(&reg_transfer);
    regfree(&reg_body);

    reset_signal(SIGPIPE, &saved_sigpipe);

    return c;
}
