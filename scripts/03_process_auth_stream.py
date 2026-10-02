#!/usr/bin/env python3
"""Stream prefiltered auth CSV; retain only one input record and per-case counts.

RSS is sampled every --log-interval seconds and at startup/completion. Raw
progress from mawk is a lower bound (published every million rows); it is exact
at completion. Without --raw-stats-file the raw count is unavailable.
"""

import argparse
import csv
import json
import logging
import threading
import time
import sys
from contextlib import ExitStack
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HEADER = 'time,src_user,dst_user,src_comp,dst_comp,auth_type,logon_type,auth_orientation,result'.split(',')
WINDOWS = [(147285, 154485), (574838, 582038), (1062794, 1069994),
           (1350375, 1357575), (1754626, 1761826), (2292575, 2299775)]


def load_cases(path):
    cases = sorted(json.loads(path.read_text()), key=lambda c: c['case_id'])
    if [c['case_id'] for c in cases] != [f'case_{i:03d}' for i in range(1, 7)]:
        raise ValueError('Expected exactly case_001 through case_006')
    for case, (start, end) in zip(cases, WINDOWS):
        window, anchor = case['pilot_time_window'], case['anchor']
        if (window['start'], window['end']) != (start, end):
            raise ValueError('Candidate windows disagree with native prefilter')
        if type(anchor['time']) is not int or not start <= anchor['time'] <= end:
            raise ValueError('Invalid anchor timestamp')
        if any(not isinstance(anchor[k], str) or not anchor[k]
               for k in ('user', 'src_comp', 'dst_comp')):
            raise ValueError('Invalid anchor identifiers')
    return cases


def current_rss_mb():
    with open('/proc/self/status', encoding='ascii') as handle:
        for line in handle:
            if line.startswith('VmRSS:'):
                return int(line.split()[1]) / 1024
    raise RuntimeError('VmRSS unavailable')


def process(args):
    cases = load_cases(args.candidates)
    started = time.monotonic()
    counts = {c['case_id']: 0 for c in cases}
    exact = dict.fromkeys(counts, 0)
    passed = 0
    rss_min = rss_max = current_rss_mb()
    raw = None
    raw_final = False
    lock = threading.Lock()
    stop = threading.Event()
    monitor_errors = []
    with ExitStack() as stack:
        handles, writers = [], []
        for case in cases:
            folder = args.output_dir / case['case_id']
            folder.mkdir(parents=True, exist_ok=True)
            # Existing full-pipeline metadata no longer describes these outputs.
            (folder / 'metadata.json').unlink(missing_ok=True)
            handle = stack.enter_context((folder / 'auth_records.csv').open(
                'w', encoding='utf-8', newline=''))
            writer = csv.writer(handle)
            writer.writerow(HEADER)
            handles.append(handle)
            writers.append(writer)

        def report(state):
            nonlocal rss_min, rss_max, raw, raw_final
            with lock:
                rss = current_rss_mb()
                rss_min, rss_max = min(rss_min, rss), max(rss_max, rss)
                if args.raw_stats_file:
                    try:
                        fields = args.raw_stats_file.read_text().split()
                        if len(fields) == 3:
                            raw, raw_final = int(fields[0]), bool(int(fields[1]))
                    except (OSError, ValueError):
                        pass  # mawk may be in the middle of a progress update
                for handle in handles:
                    handle.flush()
                stats = dict(state=state, raw_lines_scanned=raw,
                             raw_count_final=raw_final, lines_passed_prefilter=passed,
                             matched_records_per_case=dict(counts),
                             exact_anchor_matches_per_case=dict(exact),
                             rss_min_mb=rss_min, rss_max_mb=rss_max,
                             elapsed_seconds=time.monotonic() - started)
                logging.info('%s', json.dumps(stats, sort_keys=True))
                return stats

        def monitor():
            try:
                while not stop.wait(args.log_interval):
                    report('progress')
            except Exception as exc:
                monitor_errors.append(exc)

        report('started')
        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
        try:
            for line in sys.stdin:
                with lock:
                    passed += 1
                    row = next(csv.reader([line], strict=True))
                    if len(row) != len(HEADER):
                        raise ValueError(f'stdin line {passed}: expected 9 fields')
                    timestamp = int(row[0])
                    for case, writer in zip(cases, writers):
                        anchor, window = case['anchor'], case['pilot_time_window']
                        computers = (anchor['src_comp'], anchor['dst_comp'])
                        if (window['start'] <= timestamp <= window['end'] and
                            (anchor['user'] in (row[1], row[2]) or
                             row[3] in computers or row[4] in computers)):
                            writer.writerow(row)
                            counts[case['case_id']] += 1
                            if (timestamp == anchor['time'] and
                                anchor['user'] in (row[1], row[2]) and
                                row[3] == anchor['src_comp'] and
                                row[4] == anchor['dst_comp']):
                                exact[case['case_id']] += 1
                if monitor_errors:
                    raise monitor_errors[0]
        finally:
            stop.set()
            thread.join()
        if monitor_errors:
            raise monitor_errors[0]
        if args.raw_stats_file:
            for _ in range(50):
                try:
                    fields = args.raw_stats_file.read_text().split()
                    if len(fields) == 3 and bool(int(fields[1])):
                        raw, raw_final = int(fields[0]), True
                        break
                except (OSError, ValueError):
                    pass
                time.sleep(0.05)
        stats = report('complete')
        if args.raw_stats_file and not raw_final:
            raise RuntimeError('Missing final mawk scan statistics')
        if args.stats_json:
            args.stats_json.write_text(json.dumps(stats, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidates', type=Path, default=ROOT / 'selected_candidates.json')
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'candidate_cases')
    parser.add_argument('--raw-stats-file', type=Path)
    parser.add_argument('--stats-json', type=Path)
    parser.add_argument('--log-file', type=Path)
    parser.add_argument('--log-interval', type=float, default=10)
    args = parser.parse_args()
    if not 0 < args.log_interval < float('inf'):
        parser.error('--log-interval must be positive and finite')
    handlers = [logging.StreamHandler(sys.stderr)]
    if args.log_file:
        args.log_file.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(args.log_file, encoding='utf-8'))
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s', handlers=handlers)
    process(args)


if __name__ == '__main__':
    main()
