#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;
    unsigned long long scanned = 0;
    int early_stop = 0;

    char *stats_file = (argc > 1) ? argv[1] : NULL;

    while ((nread = getline(&line, &len, stdin)) != -1) {
        scanned++;

        /* Fast integer parse of the first column (timestamp) */
        char *p = line;
        long long t = 0;
        while (*p >= '0' && *p <= '9') {
            t = t * 10 + (*p - '0');
            p++;
        }

        /* Early stop if time exceeds max window */
        if (t > 2299775) {
            early_stop = 1;
            break;
        }

        /* Check the 6 non-overlapping candidate intervals */
        if ((t >= 147285 && t <= 154485) ||
            (t >= 574838 && t <= 582038) ||
            (t >= 1062794 && t <= 1069994) ||
            (t >= 1350375 && t <= 1357575) ||
            (t >= 1754626 && t <= 1761826) ||
            (t >= 2292575 && t <= 2299775)) {
            if (fwrite(line, 1, nread, stdout) != (size_t)nread) {
                break; /* Broken pipe from downstream consumer */
            }
        }
    }

    if (stats_file) {
        FILE *sf = fopen(stats_file, "w");
        if (sf) {
            fprintf(sf, "%llu 1 %d\n", scanned, early_stop);
            fclose(sf);
        }
    }

    fprintf(stderr, "raw_lines_scanned=%llu early_stop=%d\n", scanned, early_stop);

    free(line);
    return 0;
}
