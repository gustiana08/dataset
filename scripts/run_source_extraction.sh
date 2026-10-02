#!/usr/bin/env bash
# Usage: run_source_extraction.sh <auth|proc|flows|dns> [source.txt.gz] [processor options...]
# Input may be unordered; every logical record is scanned.
set -uo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if (( $# == 0 )); then
    printf 'Usage: %s <auth|proc|flows|dns> [source.txt.gz] [processor options...]\n' "$0" >&2
    exit 2
fi
SOURCE=$1
shift
case "$SOURCE" in
    auth|proc|flows|dns) ;;
    *) printf 'Invalid source: %s\n' "$SOURCE" >&2; exit 2 ;;
esac
INPUT="/root/dataset/$SOURCE.txt.gz"
if (( $# )) && [[ $1 != --* ]]; then
    INPUT=$1
    shift
fi
# Consume destination options so Python can only write to staging.
OUTPUT="$ROOT/candidate_cases"
REPORT="$ROOT/logs/${SOURCE}_stats.json"
OPTIONS=()
while (( $# )); do
    case "$1" in
        --output-dir|--stats-json)
            (( $# >= 2 )) || exit 2
            if [[ $1 == --output-dir ]]; then OUTPUT=$2; else REPORT=$2; fi
            shift 2 ;;
        --output-dir=*) OUTPUT=${1#*=}; shift ;;
        --stats-json=*) REPORT=${1#*=}; shift ;;
        *) OPTIONS+=("$1"); shift ;;
    esac
done
PARENT=$(dirname -- "$OUTPUT")
mkdir -p -- "$PARENT" || exit 1
STAGING=$(mktemp -d -- "$PARENT/.extraction.XXXXXXXX") || exit 1
trap 'rm -rf -- "$STAGING"' EXIT
STATS="$STAGING/raw.stats"
export LC_ALL=C
gzip -dc -- "$INPUT" |
    "$ROOT/scripts/prefilter" "$STATS" "$SOURCE" |
    python3 "$ROOT/scripts/03_process_stream.py" "${OPTIONS[@]}" \
        --source "$SOURCE" --raw-stats-file "$STATS" \
        --output-dir "$STAGING/cases" --stats-json "$STAGING/report.json"
statuses=("${PIPESTATUS[@]}")
if (( statuses[0] != 0 )); then
    printf 'gzip failed: status=%s\n' "${statuses[0]}" >&2
fi
if (( statuses[0] != 0 || statuses[1] != 0 || statuses[2] != 0 )); then
    printf 'Pipeline failed: gzip=%s prefilter=%s python=%s\n' "${statuses[@]}" >&2
    exit 1
fi
# Validate again before promotion. Keep backups to roll back ordinary rename
# failures. Each source file is atomically replaced, not its case directory.
python3 - "$ROOT" "$STAGING" "$OUTPUT" "$REPORT" "$SOURCE" <<'PROMOTE'
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

root, stage, output, report = map(Path, sys.argv[1:5])
source = sys.argv[5]
spec = importlib.util.spec_from_file_location('processor', root / 'scripts/03_process_stream.py')
processor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(processor)
processor.read_raw_stats(stage / 'raw.stats')
metadata = json.loads((stage / 'report.json').read_text())
operations = []
promoted = []
report_temp = None
try:
    for cid in metadata['output_files']:
        src = stage / 'cases' / cid / processor.FILENAMES[source]
        dst = output.resolve() / cid / src.name
        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.is_symlink() or (dst.exists() and not dst.is_file()):
            raise ValueError(f'Not a regular destination: {dst}')
        if src.stat().st_dev != dst.parent.stat().st_dev:
            raise ValueError(f'Destination is on a different filesystem: {dst}')
        metadata['output_files'][cid]['path'] = str(dst)
        operations.append((src, dst))
    report.parent.mkdir(parents=True, exist_ok=True)
    if report.is_symlink() or (report.exists() and not report.is_file()):
        raise ValueError(f'Not a regular stats destination: {report}')
    with tempfile.NamedTemporaryFile(mode='w', dir=report.parent, delete=False) as handle:
        report_temp = Path(handle.name)
        json.dump(metadata, handle, indent=2)
        handle.write('\n')
    operations.append((report_temp, report))
    # Prepare every backup before changing any destination.
    prepared = []
    for i, (src, dst) in enumerate(operations):
        backup = stage / f'backup-{i}' if dst.exists() else None
        if backup is not None:
            shutil.copy2(dst, backup)
        prepared.append((src, dst, backup))
    for src, dst, backup in prepared:
        os.replace(src, dst)
        promoted.append((dst, backup))
except Exception:
    for dst, backup in reversed(promoted):
        if backup is None:
            dst.unlink()
        else:
            # Source backups share the output filesystem. The report is last,
            # so no rollback of it is needed after a successful replacement.
            os.replace(backup, dst)
    print('Pipeline failed: promotion (python=1)', file=sys.stderr)
    raise
finally:
    if report_temp is not None:
        report_temp.unlink(missing_ok=True)
PROMOTE
promote_status=$?
if (( promote_status != 0 )); then
    printf 'Pipeline failed: promotion status=%s\n' "$promote_status" >&2
    exit 1
fi
