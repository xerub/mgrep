/*
 *  mgrep - A multiline grep-like tool (ala grep -Pzo)
 *
 *  Copyright (c) 2018 xerub
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#if 0
/* GNU libiberty
 * basic, can't handle advanced stuff:
 * - shorthand character classes
 * - ANSI escape sequences
 * - non-capturing groups
 */
#include "eregex.h"
#include "regex.c"
#define NEED_CONVERT
#elif 0
/*
 * Henry Spencer's "Tcl library"
 * https://github.com/garyhouston/hsrex
 * https://garyhouston.github.io/regex/
 */
#include "regalone.h"
#include "regex.h"
#define regcomp(r, p, c) re_comp(r, (const void *)(p), j, c)
#define regexec(r, s, n, m, e) re_exec(r, (const void *)(s), buf + sz - (char *)(s), NULL, n, m, e)
#define SPENCER
#undef REG_STARTEND
#undef REG_PEND
#else
/* system
 * Linux regex is dumb: regoff_t == int?
 * Apple's TRE is some pretentious shit:
 * - really slow for big files (1.4GB)
 * - can't handle text > 2GB
 */
#include <regex.h>
#ifndef __APPLE__
#define NEED_CONVERT
#endif
#endif

#ifdef NEED_CONVERT
static int
tohex(char nibble)
{
    if (nibble >= '0' && nibble <= '9') {
        return nibble - '0';
    }
    nibble |= 0x20;
    if (nibble >= 'a' && nibble <= 'f') {
        return nibble - ('a' - 10);
    }
    return -1;
}

static int
isspec(int ch)
{
    switch (ch) {
        case '^':
        case '$':
        case '.':
        case '[':
        case '-':
        case ']':
        case '*':
        case '+':
        case '?':
        case '{':
        case ',':
        case '}':
        case '(':
        case ')':
        case '|':
        case '\\':
            return 1;
    }
    return 0;
}
#endif

static void
report_error(int err, const regex_t *reg)
{
    char errbuf[1024];
    regerror(err, reg, errbuf, sizeof(errbuf));
    fprintf(stderr, "%s\n", errbuf);
}

static void
report_substr(const char *ptr, size_t len)
{
    fwrite(ptr, 1, len, stdout);
}

static void
report_match(const char *buf, size_t sz, const char *ptr, size_t len, int sep, int show_byte_offset, int print_match_only)
{
    static const char *oldptr = NULL;
    static size_t oldlen = -1;

    if (!print_match_only) {
        for (; ptr > buf && ptr[-1] != '\n'; ptr--, len++) {
            continue;
        }
        if (!len || ptr[len - 1] != '\n') {
            const char *end = buf + sz;
            for (; ptr + len < end && ptr[len] != '\n'; len++) {
                continue;
            }
        }
        if (ptr == oldptr && len == oldlen) {
            return;
        }
        oldptr = ptr;
        oldlen = len;
    }
    if (sep) {
        printf("--\n");
    }
    if (show_byte_offset) {
        printf("%zu:", ptr - buf);
    }
    report_substr(ptr, len);
    printf("\n");
}

static int
process_pattern(regex_t *reg, const char *pat, int regex_comp_flags, int debug_submatches)
{
    int rv;
    char *buf;
    size_t len;
    unsigned i, j;
    int eolbol = 0;
    int cflags = regex_comp_flags | REG_NEWLINE | REG_EXTENDED
#ifdef REG_ENHANCED
        | REG_ENHANCED
#endif
#ifdef REG_ADVANCED
        | REG_ADVANCED
#endif
    ;
    if (!strncmp(pat, "(?s)", 4)) {
        cflags &= ~REG_NEWLINE;
        pat += 4;
    }
    len = strlen(pat);
    buf = malloc(len * 4 + 1);
    if (!buf) {
        return -1;
    }
    for (i = 0, j = 0; pat[i]; i++, j++) {
        if (pat[i] == '\\') {
            switch (pat[i + 1]) {
#ifdef NEED_CONVERT
                case 'n':
                    buf[j] = '\n';
                    i++;
                    continue;
                case 's':
                    buf[j++] = '[';
                    buf[j++] = ' ';
                    buf[j++] = '\t';
                    buf[j++] = '\r';
                    buf[j++] = '\n';
                    buf[j++] = '\v';
                    buf[j++] = '\f';
                    buf[j] = ']';
                    i++;
                    continue;
                case 'd':
                    buf[j++] = '[';
                    buf[j++] = '0';
                    buf[j++] = '-';
                    buf[j++] = '9';
                    buf[j] = ']';
                    i++;
                    continue;
                case 'x': {
                    int hi, lo;
                    if ((hi = tohex(pat[i + 2])) >= 0 && (lo = tohex(pat[i + 3])) >= 0) {
                        buf[j] = (hi << 4) | lo;
                        /* XXX
                         * cannot escape digits outside {} because of backrefs
                         * should not convert \x31... to real digits inside {}
                         */
                        if (isspec(buf[j])) {
                            buf[j + 1] = buf[j];
                            buf[j++] = '\\';
                        }
                    }
                    i += 3;
                    continue;
                }
#endif
                case 'N':
                    if (cflags & REG_NEWLINE) {
                        buf[j] = '.';
                    } else {
                        buf[j++] = '[';
                        buf[j++] = '^';
                        buf[j++] = '\n';
                        buf[j] = ']';
                    }
                    i++;
                    continue;
                default:
                    buf[j++] = '\\';
                    buf[j] = pat[i + 1];
                    i++;
                    continue;
            }
        }
        if (pat[i] == '^' || pat[i] == '$') {
            eolbol = 1;
        }
        buf[j] = pat[i];
    }
    buf[j] = '\0';
    if (eolbol && debug_submatches) {
        fprintf(stderr, "Warning: unescaped ^ or $ not recommended. Use \\n to match newlines\n");
    }
    if (debug_submatches) {
        fprintf(stderr, "0x%x: '%s'\n", cflags, buf);
    }
#ifdef REG_PEND
    reg->re_endp = buf + j;
#endif
    rv = regcomp(reg, buf, cflags);
    free(buf);
    if (rv) {
        report_error(rv, reg);
        /* regfree(reg); // XXX */
    }
    return rv;
}

static char *
map_file(int fd, size_t sz, size_t psz, size_t *msz)
{
    char *buf;
    if (sz & (psz - 1)) {
        *msz = sz;
        buf = mmap(NULL, *msz, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
    } else {
        *msz = sz + 1;
        buf = mmap(NULL, *msz, PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);
        if (buf != MAP_FAILED) {
            char *tmp = mmap(buf, sz, PROT_READ, MAP_FILE | MAP_FIXED | MAP_PRIVATE, fd, 0);
            if (tmp != buf) {
                int e = errno;
                munmap(buf, *msz);
                buf = MAP_FAILED;
                errno = e;
            }
        }
    }
    if (buf == MAP_FAILED) {
        perror("mmap");
        return NULL;
    }
#if 0
    /* XXX don't do this (though the code below can handle it just fine)
     * the match loop will eliminate an empty match after the trailing \n
     */
    if (sz && buf[sz - 1] == '\n') {
        sz--;
    }
#endif
    if (psz && buf[sz]) {
        int rv = mprotect((char *)(((uintptr_t)buf + sz) & ~(psz - 1)), psz, PROT_READ | PROT_WRITE);
        if (rv) {
            perror("mprotect");
            munmap(buf, *msz);
            return NULL;
        }
        buf[sz] = '\0';
    }
    return buf;
}

static const char *
parse_longarg(int *argc, char ***argv, const char *q, long *pval)
{
    long val;
    char *bp;
    if (!*q) {
        if (*argc < 2) {
            return NULL;
        }
        (*argc)--;
        (*argv)++;
        q = **argv;
    }
    errno = 0;
    val = strtol(q, &bp, 10);
    if (errno || bp == q || *bp) {
        return NULL;
    }
    *pval = val;
    return bp - 1;
}

static int
usage(const char *myself, int help)
{
    fprintf(stderr, "usage: %s [-{Q|F}] [OPTIONS] REGEX FILE\n", myself);
    if (help & 1) {
        fprintf(stderr,
                "    -b show byte offset\n"
                "    -i case insensitive\n"
                "    -m max # of matches\n"
                "    -o print match only\n"
                "    -g group separators\n"
                "    -k debug submatches\n"
#ifdef REG_UNGREEDY
                "    -N nongreedy regexp\n" /* reluctant */
#endif
                "    -V print ver & quit\n"
                "    -Q => bgrep variant\n"
                "    -F => fgrep variant\n"
        );
    }
    if (help & 2) {
        fprintf(stderr, "notes:\n"
                "    \\n is converted to \\x0A\n"
                "    \\N is converted to [^\\x0A]\n"
                "    \\xXX is converted to literal\n"
                "    \\s matches space, \\d matches digit\n"
                "    if REGEX is prefixed by (?s)\n"
                "        . and [^ are allowed to match newlines\n"
                "        ^ matches only at the beginning of file\n"
                "        $ matches only at the end of file\n");
    }
    return 2;
}

int
main_mgrep(int argc, char **argv)
{
    int rv;
    int fd;
    regex_t reg;
    struct stat st;
    char *buf, *ptr;
    size_t sz, psz, msz;
    int show_byte_offset = 0;
    int regex_comp_flags = 0;
    int print_match_only = 0;
    int group_separators = 0;
    int debug_submatches = 0;
    int have_match_limit = 0;
    long max_match_count = 0;
    const char *myself = argv[0];
    const char *pattern = NULL;
    const char *filename = NULL;
    int eflags = 0;
    int pmatch = 0;
    size_t off = 0;
    int any = 0;

    while (--argc > 0) {
        const char *p = *++argv;
        if (!strcmp(p, "--help")) {
            return usage(myself, 3);
        }
        if (p[0] == '-') {
            const char *q;
            for (q = ++p; *q; q++) {
                switch (*q) {
                    case 'b':
                        show_byte_offset = 1;
                        continue;
                    case 'i':
                        regex_comp_flags |= REG_ICASE;
                        continue;
                    case 'm':
                        q = parse_longarg(&argc, &argv, q + 1, &max_match_count);
                        if (!q) {
                            return usage(myself, 1);
                        }
                        have_match_limit = 1;
                        continue;
                    case 'o':
                        print_match_only = 1;
                        continue;
                    case 'g':
                        group_separators = 1;
                        continue;
                    case 'k':
                        debug_submatches = 1;
                        continue;
#ifdef REG_UNGREEDY
                    case 'N':
                        regex_comp_flags |= REG_UNGREEDY;
                        continue;
#endif
                    case 'V':
                        printf("mgrep v1.0 (c) 2018 xerub\n");
                        return 0;
                }
                break;
            }
            if (*q || q == p) {
                return usage(myself, 1);
            }
            continue;
        }
        if (!pattern) {
            pattern = p;
            continue;
        }
        if (!filename) {
            filename = p;
            continue;
        }
    }
    if (!pattern || !filename) {
        return usage(myself, 0);
    }

    rv = process_pattern(&reg, pattern, regex_comp_flags, debug_submatches);
    if (rv) {
        return rv;
    }

    psz = getpagesize();

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open");
        regfree(&reg);
        return -1;
    }
    rv = fstat(fd, &st);
    if (rv) {
        perror("stat");
        close(fd);
        regfree(&reg);
        return rv;
    }
    sz = st.st_size;
    if (!sz) {
        close(fd);
        regfree(&reg);
        return 1;
    }

    /* pass psz = 0 if trailing \0 is not needed */
#ifdef REG_STARTEND
    if ((regoff_t)sz < 0 || (size_t)(regoff_t)sz < sz) {
        if (debug_submatches) {
            fprintf(stderr, "Warning: REG_STARTEND is broken\n");
        }
        buf = map_file(fd, sz, psz, &msz);
    } else {
        eflags |= REG_STARTEND;
        buf = map_file(fd, sz, 0, &msz);
    }
#elif defined(SPENCER)
    buf = map_file(fd, sz, 0, &msz);
#else
    buf = map_file(fd, sz, psz, &msz);
#endif
    close(fd);
    if (!buf) {
        regfree(&reg);
        return -1;
    }

    for (ptr = buf; (!have_match_limit || max_match_count > 0) && ptr < buf + sz; ) {
        regmatch_t match[32];
        size_t whereami = (ptr - buf) & ~(psz - 1);
        if (off < whereami) {
            madvise(buf + off, whereami - off, MADV_DONTNEED);
            off = whereami;
        }
#ifdef REG_STARTEND
        if (eflags & REG_STARTEND) {
            match[0].rm_so = 0;
            match[0].rm_eo = buf + sz - ptr;
        }
#endif
        rv = regexec(&reg, ptr, sizeof(match) / sizeof(match[0]), match, eflags);
        if (rv) {
            if (!any && debug_submatches) {
                report_error(rv, &reg);
            }
            break;
        }
        if (match[0].rm_so < 0 || match[0].rm_so > match[0].rm_eo || ptr + match[0].rm_eo > buf + sz) {
            fprintf(stderr, "bad match @%zu: so = %lld, eo = %lld\n",
                    ptr - buf,
                    (long long)match[0].rm_so,
                    (long long)match[0].rm_eo);
            break;
        }
        ptr += match[0].rm_so;
        /* avoid the empty match after the last newline (see the comment in map_file)
         * NB: at this point, we know sz > 0, otherwise the loop condition won't hold
         */
        if (match[0].rm_eo == match[0].rm_so && ptr == buf + sz && ptr[-1] == '\n') {
            break;
        }
        eflags |= REG_NOTBOL;
        if (pmatch && match[0].rm_eo == 0) {
            /* empty match ending at the same place where a non-empty match ended */
            pmatch = 0;
            ptr++;
            continue;
        }
        report_match(buf, sz, ptr, match[0].rm_eo - match[0].rm_so, group_separators && any, show_byte_offset, print_match_only);
        ptr -= match[0].rm_so;
        if (debug_submatches) {
            unsigned i;
            for (i = 1; i <= reg.re_nsub; i++) {
                if (match[i].rm_so < match[0].rm_so || match[i].rm_so > match[i].rm_eo || match[i].rm_eo > match[0].rm_eo) {
                    continue;
                }
                printf("-=%d=- (", i);
                report_substr(ptr + match[i].rm_so, match[i].rm_eo - match[i].rm_so);
                printf(")\n");
            }
        }
        ptr += match[0].rm_eo;
        max_match_count--;
        pmatch = 1;
        any = 1;
    }

    munmap(buf, msz);
    regfree(&reg);
    return !any;
}

int main_bgrep(int argc, char **argv);
int main_fgrep(int argc, char **argv);

int
main(int argc, char **argv)
{
    char *myself = strrchr(argv[0], '/');
    if (myself) {
        myself++;
    } else {
        myself = argv[0];
    }
    if (!strcmp(myself, "fgrep") || !strcmp(myself, "grepf")) {
        argv[0] = "fgrep";
        return main_fgrep(argc, argv);
    }
    if (!strcmp(myself, "bgrep")) {
        argv[0] = "bgrep";
        return main_bgrep(argc, argv);
    }
    if (argc > 1) {
        if (!strcmp(argv[1], "-F")) {
            *++argv = "fgrep";
            return main_fgrep(argc - 1, argv);
        }
        if (!strcmp(argv[1], "-Q")) {
            *++argv = "bgrep";
            return main_bgrep(argc - 1, argv);
        }
    }
    return main_mgrep(argc, argv);
}
