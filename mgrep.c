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
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#if 0
#include "eregex.h"
#include "regex.c"
#else
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
#endif

static void
report_error(int err, const regex_t *reg)
{
    char errbuf[1024];
    regerror(err, reg, errbuf, sizeof(errbuf));
    fprintf(stderr, "%s\n", errbuf);
}

static void
report_substr(const char *buf, const char *ptr, size_t len)
{
    if (len > INT_MAX) {
        fprintf(stderr, "string too long @0x%zu\n", ptr - buf);
        len = INT_MAX;
    }
    printf("%.*s", (int)len, ptr);
}

static void
report_match(const char *buf, const char *ptr, const regmatch_t *match, int print_match_only)
{
    size_t len = match[0].rm_eo - match[0].rm_so;
    ptr += match[0].rm_so;
    if (!print_match_only) {
        for (; ptr > buf && ptr[-1] != '\n'; ptr--, len++) {
            continue;
        }
        if (!len || ptr[len - 1] != '\n') {
            for (; ptr[len] && ptr[len] != '\n'; len++) {
                continue;
            }
        }
    }
    report_substr(buf, ptr, len);
}

static int
process_pattern(regex_t *reg, const char *pat, int icase, int debug_submatches)
{
    int rv;
    char *buf;
    size_t len;
    unsigned i, j;
    int cflags = REG_NEWLINE | REG_EXTENDED
#ifdef REG_ENHANCED
        | REG_ENHANCED
#endif
    ;
    if (!strncmp(pat, "(?s)", 4)) {
        cflags &= ~REG_NEWLINE;
        pat += 4;
    }
    len = strlen(pat);
    buf = malloc(len * 3 + 1);
    if (!buf) {
        return -1;
    }
    for (i = 0, j = 0; pat[i]; i++, j++) {
        if (pat[i] == '\\') {
            switch (pat[i + 1]) {
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
#ifdef NEED_CONVERT
                case 'n':
                    buf[j] = '\n';
                    i++;
                    continue;
                case 'd':
                    buf[j++] = '[';
                    buf[j++] = '1';
                    buf[j++] = '-';
                    buf[j++] = '9';
                    buf[j] = ']';
                    i++;
                    continue;
                case 'x': {
                    int hi, lo;
                    if ((hi = tohex(pat[i + 2])) >= 0 && (lo = tohex(pat[i + 3])) >= 0) {
                        buf[j] = (hi << 4) | lo;
                    }
                    i += 3;
                    continue;
                }
#endif
            }
        }
        buf[j] = pat[i];
    }
    buf[j] = '\0';
    if (icase) {
        cflags |= REG_ICASE;
    }
    if (debug_submatches) {
        fprintf(stderr, "0x%x: '%s'\n", cflags, buf);
    }
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
    if (buf[sz]) {
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
    fprintf(stderr, "usage: %s [OPTIONS] REGEX FILE\n", myself);
    if (help & 1) {
        fprintf(stderr,
                "    -b show byte offset\n"
                "    -i case insensitive\n"
                "    -m max # of matches\n"
                "    -o print match only\n"
                "    -k debug submatches\n"
#ifdef REG_UNGREEDY
                "    -t reluctant regexp\n"
#endif
                "    -h show help & exit\n"
                "    -V print ver & quit\n"
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
main(int argc, char **argv)
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
    int debug_submatches = 0;
    int have_match_limit = 0;
    long max_match_count = 0;

    const char *myself = argv[0];
    const char *pattern = NULL;
    const char *filename = NULL;

    while (--argc > 0) {
        const char *p = *++argv;
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
                    case 'k':
                        debug_submatches = 1;
                        continue;
#ifdef REG_UNGREEDY
                    case 't':
                        regex_comp_flags |= REG_UNGREEDY;
                        continue;
#endif
                    case 'V':
                        printf("mgrep v1.0 (c) 2018 xerub\n");
                        return 0;
                    case 'h':
                        return usage(myself, 3);
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
    psz = getpagesize();
    buf = map_file(fd, sz, psz, &msz);
    close(fd);
    if (!buf) {
        regfree(&reg);
        return -1;
    }

    for (ptr = buf; (!have_match_limit || max_match_count-- > 0) && ptr < buf + sz; ptr++) {
        int eflags = 0;
        regmatch_t match[32];
        if (ptr != buf) {
            eflags |= REG_NOTBOL;
            madvise(buf, (ptr - buf) & ~(psz - 1), MADV_DONTNEED);
        }
        rv = regexec(&reg, ptr, sizeof(match) / sizeof(match[0]), match, eflags);
        if (rv) {
            if (ptr == buf) {
                report_error(rv, &reg);
            }
            break;
        }
        if (ptr != buf) {
            printf("--\n");
        }
        if (show_byte_offset) {
            printf("%zu:", ptr + match[0].rm_so - buf);
        }
        report_match(buf, ptr, match, print_match_only);
        printf("\n");
        if (debug_submatches) {
            unsigned i;
            for (i = 1; i <= reg.re_nsub; i++) {
                if (match[i].rm_so < 0) {
                    continue;
                }
                printf("-=%d=- (", i);
                report_substr(buf, ptr + match[i].rm_so, match[i].rm_eo - match[i].rm_so);
                printf(")\n");
            }
        }
        ptr += match[0].rm_eo;
    }

    munmap(buf, msz);
    regfree(&reg);
    return (ptr == buf);
}
