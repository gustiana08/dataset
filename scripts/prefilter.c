#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>

/* Operational safety limit, not a dataset schema claim. Excludes LF;
 * CR (if present) counts. Abort before copying/allocating beyond the cap. */
#define MAX_RECORD_BYTES (1024u * 1024u)

/* Usage: prefilter stats_file [auth|proc|flows|dns] (default: dns).
 * Newline-delimited source records; deliberately not a general CSV parser.
 * Stats: logical_records_scanned complete_success early_stop malformed_records.
 * Success stats are written only after EOF and successful stdout flush.
 */
static unsigned long long scanned, malformed;

static int record(const unsigned char *buf, size_t len, unsigned fields) {
    unsigned count = 1;
    size_t i = 0;
    unsigned long long t = 0;
    scanned++;
    if (!len || buf[0] < '0' || buf[0] > '9') goto invalid;
    while (i < len && buf[i] >= '0' && buf[i] <= '9') {
        unsigned digit = buf[i++] - '0';
        if (t > (ULLONG_MAX - digit) / 10) goto invalid;
        t = t * 10 + digit;
    }
    if (i == len || buf[i] != ',') goto invalid;
    for (size_t j = i; j < len; j++) {
        if (buf[j] == '\0') goto invalid;
        if (buf[j] == ',' && ++count > fields) goto invalid;
    }
    if (count != fields) goto invalid;
    if ((t >= 147285 && t <= 154485) ||
        (t >= 574838 && t <= 582038) ||
        (t >= 1062794 && t <= 1069994) ||
        (t >= 1350375 && t <= 1357575) ||
        (t >= 1754626 && t <= 1761826) ||
        (t >= 2292575 && t <= 2299775)) {
        if (fwrite(buf, 1, len, stdout) != len || fputc('\n', stdout) == EOF)
            return -1;
    }
    return 0;
invalid:
    malformed++;
    return 0;
}

int main(int argc, char **argv) {
    unsigned fields = 3;
    if (argc < 2 || argc > 3) return 2;
    if (argc == 3) {
        if (!strcmp(argv[2], "auth") || !strcmp(argv[2], "flows")) fields = 9;
        else if (!strcmp(argv[2], "proc")) fields = 5;
        else if (strcmp(argv[2], "dns")) return 2;
    }
    unsigned char block[65536], *buf = NULL;
    size_t len = 0, capacity = 0, n;
    int failed = 0;
    while ((n = fread(block, 1, sizeof(block), stdin)) != 0) {
        size_t start = 0;
        while (start < n) {
            unsigned char *nl = memchr(block + start, '\n', n - start);
            size_t part = nl ? (size_t)(nl - block) - start : n - start;
            if (part > MAX_RECORD_BYTES - len) {
                fprintf(stderr, "prefilter: oversized_records=1 record_index=%llu max_record_bytes=%u; aborting without emitting oversized record\n", scanned + 1, MAX_RECORD_BYTES);
                goto failure;
            }
            if (part > SIZE_MAX - len) goto failure;
            size_t needed = len + part;
            if (needed > capacity) {
                size_t grown = capacity ? capacity : 4096;
                while (grown < needed) {
                    if (grown > SIZE_MAX / 2) { grown = needed; break; }
                    grown *= 2;
                }
                void *next = realloc(buf, grown);
                if (!next) goto failure;
                buf = next;
                capacity = grown;
            }
            if (part) memcpy(buf + len, block + start, part);
            len += part;
            start += part;
            if (nl) {
                if (record(buf, len, fields)) goto failure;
                len = 0;
                start++;
            }
        }
    }
    if (ferror(stdin)) goto failure;
    if (len && record(buf, len, fields)) goto failure;
    if (fflush(stdout) == EOF) goto failure;
    free(buf);
    FILE *stats = fopen(argv[1], "w");
    if (!stats) return 1;
    if (fprintf(stats, "%llu 1 0 %llu\n", scanned, malformed) < 0) failed = 1;
    if (fflush(stats) == EOF) failed = 1;
    if (fclose(stats) == EOF) failed = 1;
    return failed;
failure:
    free(buf);
    fprintf(stderr, "prefilter: input, allocation, or output failure\n");
    return 1;
}
