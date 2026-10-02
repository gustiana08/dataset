"""Small synthetic fixtures only; never open production archives."""
import csv
import gzip
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('processor', ROOT / 'scripts/03_process_stream.py')
PROCESSOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROCESSOR)
CASES = json.loads((ROOT / 'selected_candidates.json').read_text())


def row(source, t, user='other', src='other', dst='other', dst_user='other'):
    return {
        'auth': f'{t},{user},{dst_user},{src},{dst},Negotiate,Network,LogOn,Success\n',
        'proc': f'{t},{user},{src},P1,Start\n',
        'flows': f'{t},1,{src},123,{dst},456,6,2,100\n',
        'dns': f'{t},{src},{dst}\n',
    }[source]


class AllSourcesTests(unittest.TestCase):
    def run_processor(self, source, base, data, extra=()):
        return subprocess.run([
            sys.executable, str(ROOT / 'scripts/03_process_stream.py'),
            '--source', source, '--output-dir', str(base / 'out'),
            '--stats-json', str(base / 'stats.json'), *extra,
        ], input=data, text=True, capture_output=True, timeout=15)

    def fixture(self, source):
        lines, expected = [], {}
        for case in CASES:
            a, w = case['anchor'], case['pilot_time_window']
            matches = [
                row(source, w['start'], src=a['src_comp']),
                row(source, a['time'], src=a['dst_comp']),
                row(source, w['end'], src=a['src_comp']),
            ]
            if source != 'proc':
                matches += [row(source, a['time'], dst=c)
                            for c in (a['src_comp'], a['dst_comp'])]
            if source in ('auth', 'proc'):
                matches.append(row(source, a['time'], user=a['user']))
            if source == 'auth':
                matches += [row(source, a['time'], dst_user=a['user']),
                            row(source, a['time'], user=a['user'],
                                src=a['src_comp'], dst=a['dst_comp']),
                            row(source, a['time'], dst_user=a['user'],
                                src=a['src_comp'], dst=a['dst_comp'])]
            expected[case['case_id']] = sorted(matches, key=lambda s: int(s.split(',')[0]))
            lines += matches + [row(source, w['start'] - 1, src=a['src_comp']),
                                row(source, w['end'] + 1, src=a['dst_comp']),
                                row(source, a['time']),
                                row(source, a['time'], src=a['src_comp'] + 'suffix')]
        return sorted(lines, key=lambda s: int(s.split(',')[0])), expected

    def check_outputs(self, source, base, expected, exact_count=2):
        stats = json.loads((base / 'stats.json').read_text())
        self.assertEqual(stats['source'], source)
        self.assertGreater(stats['rss_min_mb'], 0)
        self.assertGreaterEqual(stats['rss_max_mb'], stats['rss_min_mb'])
        self.assertGreater(stats['elapsed_seconds'], 0)
        for cid, lines in expected.items():
            path = base / 'out' / cid / PROCESSOR.FILENAMES[source]
            with path.open(newline='') as handle:
                actual = list(csv.reader(handle))
            self.assertEqual(actual, [PROCESSOR.HEADERS[source], *list(csv.reader(lines))])
            self.assertEqual(stats['matched_records_per_case'][cid], len(lines))
            self.assertEqual(stats['output_files'][cid],
                             {'path': str(path), 'size_bytes': path.stat().st_size})
        if source == 'auth':
            self.assertEqual(stats['exact_anchor_matches_per_case'], dict.fromkeys(expected, exact_count))
        else:
            self.assertNotIn('exact_anchor_matches_per_case', stats)
        return stats

    def test_correlations_boundaries_and_malformed_lines(self):
        for source in PROCESSOR.HEADERS:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp)
                lines, expected = self.fixture(source)
                lines += ['150885,"unterminated\n', row(source, 'bad-time'),
                          '150885,bad\n', '\n']
                result = self.run_processor(source, base, ''.join(lines),
                                            ['--log-file', str(base / 'run.log'),
                                             '--log-interval', '0.001'])
                self.assertEqual(result.returncode, 0, result.stderr)
                stats = self.check_outputs(source, base, expected)
                self.assertEqual(stats['parsing_errors'], 2)
                self.assertEqual(stats['invalid_records'], 2)
                self.assertEqual(stats['lines_passed_prefilter'], len(lines))
                self.assertIsNone(stats['raw_lines_scanned'])
                self.assertIn('complete', (base / 'run.log').read_text())

    def test_runner_all_sources_full_scan(self):
        for source in PROCESSOR.HEADERS:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp)
                lines, expected = self.fixture(source)
                archive = base / 'fixture.gz'
                with gzip.open(archive, 'wt') as handle:
                    handle.writelines(lines)
                    handle.write(row(source, 2300000) * 20000)
                    later = expected['case_001'][0]
                    handle.write(later)
                expected['case_001'].append(later)
                result = subprocess.run([
                    str(ROOT / 'scripts/run_source_extraction.sh'), source, str(archive),
                    '--output-dir', str(base / 'out'), '--stats-json', str(base / 'stats.json'),
                ], text=True, capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                stats = self.check_outputs(source, base, expected)
                self.assertEqual(stats['raw_lines_scanned'], len(lines) + 20001)
                self.assertTrue(stats['raw_count_final'])
                self.assertEqual(stats['early_stop'], 0)
                self.assertEqual(stats['lines_passed_prefilter'], len(lines) - 11)
                self.assertEqual(stats['parsing_errors'], 0)
                self.assertEqual(stats['invalid_records'], 0)

    def test_empty_and_corrupt_archives(self):
        for source in PROCESSOR.HEADERS:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp)
                archive = base / 'fixture.gz'
                cmd = [str(ROOT / 'scripts/run_source_extraction.sh'), source, str(archive),
                       '--output-dir', str(base / 'out'), '--stats-json', str(base / 'stats.json')]
                with gzip.open(archive, 'wt'):
                    pass
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                stats = self.check_outputs(
                    source, base, {c['case_id']: [] for c in CASES}, exact_count=0)
                self.assertEqual(stats['raw_lines_scanned'], 0)
                self.assertEqual(stats['lines_passed_prefilter'], 0)
                archive.write_bytes(b'not gzip')
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                self.assertNotEqual(result.returncode, 0)

    def test_bad_source_and_downstream_failure(self):
        result = subprocess.run([str(ROOT / 'scripts/run_source_extraction.sh'), 'invalid'],
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 2)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            archive = base / 'fixture.gz'
            with gzip.open(archive, 'wt') as handle:
                handle.write(row('dns', 150885) * 20000)
            result = subprocess.run([
                str(ROOT / 'scripts/run_source_extraction.sh'), 'dns', str(archive),
                '--candidates', str(base / 'missing.json'),
            ], capture_output=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
