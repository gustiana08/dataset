# Input must be timestamp-sorted, unquoted LANL auth CSV.
# Optional -v stats_file=PATH publishes exact final statistics.
BEGIN { FS = "," }
{
    t = $1 + 0
    if (t > 2299775) { early_stop = 1; exit 0 }
    if ((t >= 147285 && t <= 154485) ||
        (t >= 574838 && t <= 582038) ||
        (t >= 1062794 && t <= 1069994) ||
        (t >= 1350375 && t <= 1357575) ||
        (t >= 1754626 && t <= 1761826) ||
        (t >= 2292575 && t <= 2299775)) print
}
END {
    if (stats_file != "") {
        printf "%.0f %d %d\n", NR, 1, early_stop > stats_file
        close(stats_file)
    }
    printf "raw_lines_scanned=%.0f early_stop=%d\n", NR, early_stop > "/dev/stderr"
}
