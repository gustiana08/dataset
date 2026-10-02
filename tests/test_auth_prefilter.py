"""Small fixtures only: never open the production auth archive."""
import csv
import gzip
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES = json.loads((ROOT / 'selected_candidates.json').read_text())


def row(t, su='other', du='other', sc='other', dc='other'):
    return f'{t},{su},{du},{sc},{dc},Negotiate,Network,LogOn,Success\n'


class AuthPrefilterTests(unittest.TestCase):
    def test_numeric_boundaries_and_immediate_stop(self):
        lines, expected = [], []
        for case in CASES:
            w = case['pilot_time_window']
            for t in (w['start'] - 1, w['start'], w['end'], w['end'] + 1):
                lines.append(row(t))
                if w['start'] <= t <= w['end']:
                    expected.append(row(t))
        # This eligible row must never be read after the cutoff.
        lines.append(row(CASES[0]['anchor']['time']))
        result = subprocess.run(['mawk', '-f', str(ROOT / 'scripts/03_prefilter_auth.awk')],
                                input=''.join(lines), text=True, capture_output=True, check=True)
        self.assertEqual(result.stdout, ''.join(expected))
        self.assertIn('raw_lines_scanned=24 early_stop=1', result.stderr)

    def test_runner_matches_and_stats(self):
        lines = []
        for case in CASES:
            a, w = case['anchor'], case['pilot_time_window']
            lines.extend([
                row(w['start'] - 1, su=a['user']),
                row(w['start'], su=a['user']),
                row(a['time'], du=a['user'], sc=a['src_comp'], dc=a['dst_comp']),
                row(a['time'], sc=a['src_comp']),
                row(a['time'], sc=a['dst_comp']),
                row(a['time'], dc=a['src_comp']),
                row(a['time'], dc=a['dst_comp']),
                row(a['time']),
                row(w['end'], du=a['user']),
            ])
        lines.append(row(2299776))
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            archive, stats = base / 'fixture.gz', base / 'stats.json'
            with gzip.open(archive, 'wt') as handle:
                handle.writelines(lines)
                # Ensure gzip is still writing when mawk closes its input.
                for _ in range(20000):
                    handle.write(row(2300000))
            result = subprocess.run([str(ROOT / 'scripts/run_auth_prefilter.sh'),
                                     str(archive), '--output-dir', str(base / 'out'),
                                     '--stats-json', str(stats), '--log-interval', '0.001'],
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(stats.read_text())
            self.assertEqual(report['raw_lines_scanned'], 55)
            self.assertTrue(report['raw_count_final'])
            self.assertEqual(report['lines_passed_prefilter'], 48)
            self.assertGreater(report['rss_min_mb'], 0)
            self.assertGreaterEqual(report['rss_max_mb'], report['rss_min_mb'])
            for case in CASES:
                cid = case['case_id']
                self.assertEqual(report['matched_records_per_case'][cid], 7)
                self.assertEqual(report['exact_anchor_matches_per_case'][cid], 1)
                with (base / 'out' / cid / 'auth_records.csv').open() as handle:
                    rows = list(csv.reader(handle))
                self.assertEqual(len(rows), 8)
                self.assertEqual(rows[0], 'time,src_user,dst_user,src_comp,dst_comp,auth_type,logon_type,auth_orientation,result'.split(','))

    def test_empty_and_corrupt_archives(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            archive = base / 'fixture.gz'
            with gzip.open(archive, 'wt'):
                pass
            cmd = [str(ROOT / 'scripts/run_auth_prefilter.sh'), str(archive),
                   '--output-dir', str(base / 'out')]
            result = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('"raw_lines_scanned": 0', result.stderr)
            archive.write_bytes(b'not gzip')
            result = subprocess.run(cmd, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)

    def test_processor_rejects_bad_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(['python3', str(ROOT / 'scripts/03_process_auth_stream.py'),
                                     '--output-dir', tmp], input='150885,bad\n',
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('expected 9 fields', result.stderr)


if __name__ == '__main__':
    unittest.main()
