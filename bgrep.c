/*
 *  bgrep - fast binary grep with wildcards
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


#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define UCHAR_MAX 255

static unsigned char *
boyermoore_horspool_memmem(const unsigned char* haystack, size_t hlen,
                           const unsigned char* needle,   size_t nlen)
{
    size_t last, scan = 0;
    size_t bad_char_skip[UCHAR_MAX + 1]; /* Officially called:
                                          * bad character shift */

    /* Sanity checks on the parameters */
    if (nlen <= 0 || !haystack || !needle)
        return NULL;

    /* ---- Preprocess ---- */
    /* Initialize the table to default value */
    /* When a character is encountered that does not occur
     * in the needle, we can safely skip ahead for the whole
     * length of the needle.
     */
    for (scan = 0; scan <= UCHAR_MAX; scan = scan + 1)
        bad_char_skip[scan] = nlen;

    /* C arrays have the first byte at [0], therefore:
     * [nlen - 1] is the last byte of the array. */
    last = nlen - 1;

    /* Then populate it with the analysis of the needle */
    for (scan = 0; scan < last; scan = scan + 1)
        bad_char_skip[needle[scan]] = last - scan;

    /* ---- Do the matching ---- */

    /* Search the haystack, while the needle can still be within it. */
    while (hlen >= nlen)
    {
        /* scan from the end of the needle */
        for (scan = last; haystack[scan] == needle[scan]; scan = scan - 1)
            if (scan == 0) /* If the first byte matches, we've found it. */
                return (void *)haystack;

        /* otherwise, we need to skip some bytes and start again.
           Note that here we are getting the skip value based on the last byte
           of needle, no matter where we didn't match. So if needle is: "abcd"
           then we are skipping based on 'd' and that value will be 4, and
           for "abcdd" we again skip on 'd' but the value will be only 1.
           The alternative of pretending that the mismatched character was
           the last character is slower in the normal case (E.g. finding
           "abcd" in "...azcd..." gives 4 by using 'd' but only
           4-2==2 using 'z'. */
        hlen     -= bad_char_skip[haystack[last]];
        haystack += bad_char_skip[haystack[last]];
    }

    return NULL;
}

static size_t
str2hex(size_t buflen, unsigned char *buf, unsigned char *mask, const char *str)
{
    unsigned char *ptr = buf;
    int seq = -1;
    int m = 0;
    while (buflen > 0) {
        int nibble = *str++;
        if (nibble >= '0' && nibble <= '9') {
            nibble -= '0';
            m |= 0xF;
        } else if (nibble == '.') {
            nibble = 0;
        } else if (nibble == ' ' && seq < 0) {
            continue;
        } else {
            nibble |= 0x20;
            if (nibble < 'a' || nibble > 'f') {
                break;
            }
            nibble -= 'a' - 10;
            m |= 0xF;
        }
        if (seq >= 0) {
            *buf++ = (seq << 4) | nibble;
            *mask++ = m;
            buflen--;
            seq = -1;
            m = 0;
        } else {
            seq = nibble;
            m <<= 4;
        }
    }
    return buf - ptr;
}

static size_t
find_sequence(const unsigned char *mask, size_t n, size_t *len)
{
    size_t i;
    size_t seq_len = 0;
    size_t best_len = 0;
    size_t best_pos = 0;
    for (i = 0; i < n; i++, seq_len++) {
        if (mask[i] != 0xFF) {
            if (best_len < seq_len) {
                best_len = seq_len;
                best_pos = i;
            }
            seq_len = -1;
        }
    }
    if (best_len < seq_len) {
        best_len = seq_len;
        best_pos = i;
    }
    *len = best_len;
    return best_pos - best_len;
}

unsigned char *
process_pattern(const char *str, size_t *len, unsigned char **out_mask, size_t *seq_pos, size_t *seq_len)
{
    size_t n = strlen(str) / 2;
    unsigned char *pattern, *mask;

    if (!n) {
        return NULL;
    }
    pattern = malloc(n);
    if (!pattern) {
        return NULL;
    }
    mask = malloc(n);
    if (!mask) {
        free(pattern);
        return NULL;
    }

    n = str2hex(n, pattern, mask, str);
    if (!n) {
        free(mask);
        free(pattern);
        return NULL;
    }

    *len = n;
    *out_mask = mask;
    *seq_pos = find_sequence(mask, n, seq_len);
    return pattern;
}

static const unsigned char *
find_string(const unsigned char* haystack, size_t hlen,
            const unsigned char* needle,   size_t nlen,
            const unsigned char* mask, size_t seq_pos, size_t seq_len)
{
    size_t tail = nlen - (seq_pos + seq_len);
    while (hlen >= tail) {
        size_t i;
        const unsigned char *ptr = haystack;
        if (seq_len) {
            ptr = boyermoore_horspool_memmem(haystack + seq_pos, hlen - tail, needle + seq_pos, seq_len);
            if (!ptr) {
                break;
            }
            ptr -= seq_pos;
        }
        for (i = 0; i < seq_pos; i++) {
            if ((ptr[i] & mask[i]) != needle[i]) {
                break;
            }
        }
        if (i < seq_pos) {
            haystack++;
            hlen--;
            continue;
        }
        for (i += seq_len; i < nlen; i++) {
            if ((ptr[i] & mask[i]) != needle[i]) {
                break;
            }
        }
        if (i < nlen) {
            haystack++;
            hlen--;
            continue;
        }
        return ptr;
    }
    return NULL;
}

static int
bgrep(const char *filename, const unsigned char *pattern, size_t len, const unsigned char *mask, ssize_t seq_pos, size_t seq_len, int *any, int fn)
{
    int rv;
    int fd;
    struct stat st;
    const unsigned char *p, *ptr;

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "cannot open %s\n", filename);
        return -1;
    }

    rv = fstat(fd, &st);
    if (rv != 0) {
        fprintf(stderr, "cannot stat %s\n", filename);
        close(fd);
        return -1;
    }

    p = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (p == MAP_FAILED) {
        fprintf(stderr, "cannot map %s\n", filename);
        return -1;
    }

    ptr = p - 1;
    while (1) {
        size_t left = st.st_size - (++ptr - p);
        ptr = find_string(ptr, left, pattern, len, mask, seq_pos, seq_len);
        if (!ptr) {
            break;
        }
        if (fn) {
            printf("%s: ", filename);
        }
        printf("0x%zx\n", ptr - p);
        *any = 1;
    }

    munmap((void *)p, st.st_size);
    return 0;
}

int
main_bgrep(int argc, char **argv)
{
    int rv;
    int fn;
    const char *str;
    size_t len, seq_len, seq_pos;
    unsigned char *pattern, *mask;
    int any = 0;

    if (argc < 3) {
        fprintf(stderr, "usage: %s PATTERN FILE...\n", argv[0]);
        fprintf(stderr, "notes:\n"
                "    PATTERN consists of a series of hexadecimal bytes: ab cd\n"
                "    Spaces between bytes are ignored.  Hexdigit wildcard is .\n");
        return 2;
    }

    str = argv[1];
    pattern = process_pattern(str, &len, &mask, &seq_pos, &seq_len);
    if (!pattern) {
        fprintf(stderr, "error processing pattern\n");
        return -1;
    }

    rv = 0;
    fn = argc > 3;
    while (argc-- > 2) {
        int rc = bgrep((argv++)[2], pattern, len, mask, seq_pos, seq_len, &any, fn);
        if (rc < 0) {
            rv = rc;
        }
    }

    free(mask);
    free(pattern);

    if (rv == 0 && !any) {
        return 1;
    }
    return rv;
}