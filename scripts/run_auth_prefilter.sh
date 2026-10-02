#!/usr/bin/env bash
# Usage: run_auth_prefilter.sh [auth.txt.gz] [processor options...]
set -uo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
INPUT=${1:-/root/dataset/auth.txt.gz}
if (( $# )); then shift; fi
STATS=$(mktemp) || exit 1
trap 'rm -f -- "$STATS"' EXIT
printf '0 0 0\n' > "$STATS"
export LC_ALL=C
# Native C pre-filter: O(1) memory (<2 MB RSS), zero allocation leak
gzip -dc -- "$INPUT" |
    "$ROOT/scripts/prefilter_auth" "$STATS" |
    python3 "$ROOT/scripts/03_process_auth_stream.py" "$@" --raw-stats-file "$STATS"
statuses=("${PIPESTATUS[@]}")
# Early mawk exit deliberately closes gzip's pipe. Only accept SIGPIPE when
# mawk confirms the timestamp cutoff and both downstream stages succeeded.
read -r raw complete early < "$STATS"
if (( statuses[1] != 0 || statuses[2] != 0 )); then
    printf 'Auth pipeline failed: gzip=%s mawk=%s python=%s\n' "${statuses[@]}" >&2
    exit 1
fi
if (( statuses[0] != 0 )); then
    if ! (( statuses[0] == 141 && complete == 1 && early == 1 )); then
        printf 'gzip failed: status=%s\n' "${statuses[0]}" >&2
        exit 1
    fi
fi
