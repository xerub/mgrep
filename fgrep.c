/*
 *  grepf - fgrep with multiple patterns and coallescing adjacent runs
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


/*
 * In all honesty, GNU fgrep will murder this implementation. However,
 * BSD fgrep (and OSX, for that matter) is truly in a sorry state; the
 * speed is horrible, and the output is fucked up. Compare:
 *
 * for i in {a..z}; do echo $i; done | fgrep -B 1 $'b\nd'
 * vs
 * for i in {a..z}; do echo $i; done | grepf -B 1 $'b\nd'
 *
 * and...
 *
 * for i in {a..z}; do echo $i; done | fgrep -B 1 -A 2 $'c\nf'
 * vs
 * for i in {a..z}; do echo $i; done | grepf -B 1 -A 2 $'c\nf'
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * http://web.cs.ucdavis.edu/~gusfield/strmat.html
 */
#include "ac.c"

struct string {
    char *str;
    size_t len;
};

static struct string *
split_string(const char *str, int sep, size_t *na)
{
    char *buf;
    size_t i, j, n;
    struct string *a;
    while (*str == sep) {
        str++;
    }
    buf = strdup(str);
    if (!buf) {
        return NULL;
    }
    for (i = 0; buf[i]; i++) {
        if (buf[i] == sep) {
            buf[i] = '\0';
            while (buf[i + 1] == sep) {
                buf[++i] = '\0';
            }
        }
    }
    for (n = 0, j = 0; j < i; j++) {
        if (buf[j] && (j == 0 || buf[j - 1] == '\0')) {
            n++;
        }
    }
    if (!n) {
        free(buf);
        return NULL;
    }
    a = malloc((n + 1) * sizeof(struct string));
    if (!a) {
        free(buf);
        return NULL;
    }
    for (n = 0, j = 0; j < i; j++) {
        if (buf[j] && (j == 0 || buf[j - 1] == '\0')) {
            a[n].str = buf + j;
            a[n].len = strlen(a[n].str);
            n++;
        }
    }
    a[n].str = NULL;
    a[n].len = 0;
    if (na) {
        *na = n;
    }
    return a;
}

#ifdef _AC_H_
static AC_STRUCT *
ac_init(const struct string *a, size_t na)
{
    int rv;
    size_t i;
    AC_STRUCT *node = ac_alloc();
    if (!node) {
        return NULL;
    }
    for (i = 0; i < na; i++) {
        rv = ac_add_string(node, a[i].str, a[i].len, i + 1);
        if (!rv) {
            ac_free(node);
            return NULL;
        }
    }
    rv = ac_prep(node);
    if (!rv) {
        fprintf(stderr, "!ac_prep\n");
        ac_free(node);
        return NULL;
    }
    return node;
}

static void *
search_ac(void *ctx, const char *buf, size_t len)
{
    AC_STRUCT *ac = ctx;
    ac_search_init(ac, (char *)buf, len);
    return ac_search(ac, NULL, NULL);
}
#endif

static void *
search(void *ctx, const char *buf, size_t len)
{
    const struct string *a = ctx;
    while (a->str) {
        char *p = memmem(buf, len, a->str, a->len);
        if (p) {
            return p;
        }
        a++;
    }
    return NULL;
}

struct line {
    char *str;
    size_t sz;
    ssize_t len;
};

static int
fgrep(const char *filename, size_t before, size_t after, const struct string *a, size_t na, int *any, int fn)
{
    size_t j = 0;
    size_t k = 0;
    size_t top = 0;
    FILE *f = stdin;
    int gsep = before > 1 || after;
    struct line *ring, *buf;
    void *(*fun)(void *aut, const char *buf, size_t len) = search;
    void *ctx = (void *)a;
#ifdef _AC_H_
    AC_STRUCT *ac = NULL;
    if (na > 1) {
        ac = ac_init(a, na);
        if (ac) {
            fun = search_ac;
            ctx = ac;
        }
    }
#endif
    if (filename) {
        f = fopen(filename, "rt");
        if (!f) {
            fprintf(stderr, "cannot open %s\n", filename);
#ifdef _AC_H_
            if (ac) {
                ac_free(ac);
            }
#endif
            return -1;
        }
    }
    ring = calloc(before, sizeof(struct line));
    if (!ring) {
        fprintf(stderr, "out of memory\n");
        if (filename) {
            fclose(f);
        }
#ifdef _AC_H_
        if (ac) {
            ac_free(ac);
        }
#endif
        return -1;
    }
    buf = &ring[top];
    while ((buf->len = getline(&buf->str, &buf->sz, f)) >= 0) {
        j++;
        if (buf->len && fun(ctx, buf->str, buf->len)) {
            size_t i = top;
            if (gsep && j > before && *any) {
                printf("--\n");
            }
            do {
                i++;
                if (i >= before) {
                    i = 0;
                }
                if (j >= before) {
                    if (fn) {
                        printf("%s%c", filename, (i == top) ? ':' : '-');
                    }
                    fwrite(ring[i].str, 1, ring[i].len, stdout);
                    *any = 1;
                }
                j++;
            } while (i != top);
            j = 0;
            k = after;
        } else if (k) {
            k--;
            j--;
            if (fn) {
                printf("%s-", filename);
            }
            fwrite(buf->str, 1, buf->len, stdout);
        }
        top++;
        if (top >= before) {
            top = 0;
        }
        buf = &ring[top];
    }
    while (before--) {
        free(ring[before].str);
    }
    free(ring);
    if (filename) {
        fclose(f);
    }
#ifdef _AC_H_
    if (ac) {
        ac_free(ac);
    }
#endif
    return 0;
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
    fprintf(stderr, "usage: %s [OPTIONS] PATTERN [FILE...]\n", myself);
    if (help & 1) {
        fprintf(stderr,
                "    -A max lines after\n"
                "    -B max lines before\n"
                "    -C max context lines\n"
                "    -H prefix filenames\n"
                "    -h inhibit prefixes\n"
                "    -t char is separator\n"
        );
    }
    if (help & 2) {
        fprintf(stderr, "notes:\n"
                "    processing is line-oriented\n"
                "    if FILE is missing, use stdin\n"
                "    PATTERN is TEXT1<SEP>TEXT2...\n"
                "    default separator is newline\n");
    }
    return 2;
}

int
main_fgrep(int argc, char **argv)
{
    int rv;
    size_t na;
    struct string *a;
    int separator = '\n';
    long max_lines_after = 0;
    long max_lines_before = 0;
    int prefix_filenames = 0;
    const char *myself = argv[0];
    const char *pattern = NULL;
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
                    case 'A':
                        q = parse_longarg(&argc, &argv, q + 1, &max_lines_after);
                        if (!q) {
                            return usage(myself, 1);
                        }
                        continue;
                    case 'B':
                        q = parse_longarg(&argc, &argv, q + 1, &max_lines_before);
                        if (!q) {
                            return usage(myself, 1);
                        }
                        continue;
                    case 'C':
                        q = parse_longarg(&argc, &argv, q + 1, &max_lines_before);
                        if (!q) {
                            return usage(myself, 1);
                        }
                        max_lines_after = max_lines_before;
                        continue;
                    case 'H':
                        prefix_filenames = 1;
                        continue;
                    case 'h':
                        prefix_filenames = -1;
                        continue;
                    case 't':
                        if (q[1]) {
                            q++;
#if 0 /* enable this to allow -tsA1 */
                            separator = *q;
                            continue;
#endif
                        } else {
                            if (argc < 2) {
                                return usage(myself, 1);
                            }
                            argc--;
                            argv++;
                            q = *argv;
                        }
                        separator = *q++;
                        break; /* separator must be single char */
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
        break;
    }
    if (!pattern) {
        return usage(myself, 0);
    }

    if (max_lines_after < 0) {
        fprintf(stderr, "bad number: %ld\n", max_lines_after);
        return -1;
    }
    if (max_lines_before < 0) {
        fprintf(stderr, "bad number: %ld\n", max_lines_before);
        return -1;
    }
    a = split_string(pattern, separator, &na);
    if (!a) {
        fprintf(stderr, "bad pattern: %s\n", pattern);
        return -1;
    }
    if (!argc) {
        rv = fgrep(NULL, max_lines_before + 1, max_lines_after, a, na, &any, 0);
    } else {
        int fn = argc > 1;
        if (prefix_filenames > 0) {
            fn = 1;
        }
        if (prefix_filenames < 0) {
            fn = 0;
        }
        rv = 0;
        while (argc--) {
            int rc = fgrep(*argv++, max_lines_before + 1, max_lines_after, a, na, &any, fn);
            if (rc) {
                rv = rc;
            }
        }
    }
    free(a->str);
    free(a);
    if (rv == 0 && !any) {
        return 1;
    }
    return rv;
}
