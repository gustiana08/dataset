#!/usr/bin/env python3
"""Stream prefiltered source CSV; retain only one input record and per-case counts.

RSS is sampled every --log-interval seconds and at startup/completion.
Raw counts follow the prefilter stats format: logical_records_scanned complete_success early_stop malformed_records.
Malformed CSV/timestamps and wrong field counts are counted separately and
skipped. Without --raw-stats-file the raw count is unavailable.
Input is one CSV record per physical line, as in the LANL source files.
--output-dir must be a disposable staging directory; the runner owns promotion.
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
HEADERS = {
    'auth': 'time,src_user,dst_user,src_comp,dst_comp,auth_type,logon_type,auth_orientation,result'.split(','),
    'proc': 'time,user,comp,proc_name,start_or_end'.split(','),
    'flows': 'time,duration,src_comp,src_port,dst_comp,dst_port,protocol,packet_count,byte_count'.split(','),
    'dns': 'time,src_comp,comp_resolved'.split(','),
}
FILENAMES = {s: f'{"flow" if s == "flows" else s}_records.csv' for s in HEADERS}


def read_raw_stats(path):
    fields = path.read_text(encoding='ascii').split()
    if (len(fields) != 4 or any(not f.isascii() or not f.isdigit() for f in fields)
            or fields[1:3] != ['1', '0']):
        raise ValueError('Invalid or incomplete prefilter statistics')
    scanned, _, _, malformed = map(int, fields)
    if malformed > scanned:
        raise ValueError('Malformed count exceeds scanned count')
    return scanned, malformed


def related(source, row, anchor):
    computers = (anchor['src_comp'], anchor['dst_comp'])
    if source == 'auth':
        return anchor['user'] in row[1:3] or row[3] in computers or row[4] in computers
    if source == 'proc':
        return row[1] == anchor['user'] or row[2] in computers
    if source == 'flows':
        return row[2] in computers or row[4] in computers
    return row[1] in computers or row[2] in computers


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
    if args.case_id is not None:
        cases = [case for case in cases if case['case_id'] == args.case_id]
    started = time.monotonic()
    counts = {c['case_id']: 0 for c in cases}
    exact = dict.fromkeys(counts, 0)
    passed = parsing_errors = invalid_records = 0
    header = HEADERS[args.source]
    output_files = {}
    rss_min = rss_max = current_rss_mb()
    raw = None
    raw_final = False
    malformed = None
    lock = threading.Lock()
    stop = threading.Event()
    monitor_errors = []
    with ExitStack() as stack:
        handles, writers = [], []
        for case in cases:
            folder = args.output_dir / case['case_id']
            folder.mkdir(parents=True, exist_ok=True)
            output_path = (folder / FILENAMES[args.source]).resolve()
            output_files[case['case_id']] = output_path
            handle = stack.enter_context(output_path.open(
                'w', encoding='utf-8', newline=''))
            writer = csv.writer(handle)
            writer.writerow(header)
            handles.append(handle)
            writers.append(writer)

        def report(state):
            nonlocal rss_min, rss_max, raw, raw_final, malformed
            with lock:
                rss = current_rss_mb()
                rss_min, rss_max = min(rss_min, rss), max(rss_max, rss)
                if args.raw_stats_file:
                    try:
                        raw, malformed = read_raw_stats(args.raw_stats_file)
                        raw_final = True
                    except (OSError, ValueError):
                        if state == 'complete':
                            raise
                for handle in handles:
                    handle.flush()
                stats = dict(source=args.source, state=state, raw_lines_scanned=raw,
                             parsing_errors=parsing_errors, invalid_records=invalid_records,
                             output_files={cid: {"path": str(path), "size_bytes": path.stat().st_size}
                                           for cid, path in output_files.items()},
                             raw_count_final=raw_final, malformed_records=malformed,
                             early_stop=0, lines_passed_prefilter=passed,
                             matched_records_per_case=dict(counts),
                             rss_min_mb=rss_min, rss_max_mb=rss_max,
                             elapsed_seconds=time.monotonic() - started)
                if args.source == 'auth':
                    stats['exact_anchor_matches_per_case'] = dict(exact)
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
                    try:
                        row = next(csv.reader([line], strict=True))
                    except csv.Error:
                        parsing_errors += 1
                        continue
                    if len(row) != len(header):
                        invalid_records += 1
                        continue
                    try:
                        timestamp = int(row[0])
                    except ValueError:
                        parsing_errors += 1
                        continue
                    for case, writer in zip(cases, writers):
                        anchor, window = case['anchor'], case['pilot_time_window']
                        if (window['start'] <= timestamp <= window['end'] and
                            related(args.source, row, anchor)):
                            writer.writerow(row)
                            counts[case['case_id']] += 1
                            if (args.source == 'auth' and timestamp == anchor['time'] and
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
                    raw, malformed = read_raw_stats(args.raw_stats_file)
                    raw_final = True
                    break
                except (OSError, ValueError):
                    pass
                time.sleep(0.05)
        stats = report('complete')
        if args.raw_stats_file and not raw_final:
            raise RuntimeError('Missing final prefilter scan statistics')
        if args.stats_json:
            args.stats_json.parent.mkdir(parents=True, exist_ok=True)
            args.stats_json.write_text(json.dumps(stats, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', choices=HEADERS, required=True)
    parser.add_argument('--candidates', type=Path, default=ROOT / 'selected_candidates.json')
    parser.add_argument('--case-id', choices=[f'case_{i:03d}' for i in range(1, 7)],
                        help='Extract only this case from the validated six-case configuration; default: all six.')
    parser.add_argument('--output-dir', type=Path, required=True)
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
