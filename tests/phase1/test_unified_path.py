"""Safe-contract regressions using unchanged production executables and tiny inputs."""
import csv
import gzip
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
WINDOWS = [(147285,154485),(574838,582038),(1062794,1069994),
           (1350375,1357575),(1754626,1761826),(2292575,2299775)]


def record(t=150000, tail='D'):
    return f'{t},C,{tail}\n'


class UnifiedPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sandbox = tempfile.TemporaryDirectory(prefix='phase1-unified-')
        cls.root = Path(cls.sandbox.name)
        scripts = cls.root / 'scripts'
        scripts.mkdir()
        for name in ('run_source_extraction.sh', '03_process_stream.py', 'prefilter.c'):
            shutil.copy2(ROOT / 'scripts' / name, scripts / name)
            assert (scripts / name).read_bytes() == (ROOT / 'scripts' / name).read_bytes()
        subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra',
                        str(scripts / 'prefilter.c'), '-o', str(scripts / 'prefilter')], check=True)
        cls.binary = scripts / 'prefilter'
        cls.candidates = cls.root / 'selected_candidates.json'
        cls.candidates.write_text(json.dumps([
            dict(case_id=f'case_{i:03d}', pilot_time_window=dict(start=a,end=b),
                 anchor=dict(time=a,user='U',src_comp='C',dst_comp='D'))
            for i,(a,b) in enumerate(WINDOWS,1)]))

    @classmethod
    def tearDownClass(cls):
        cls.sandbox.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=self.root)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def native(self, data, stats=None, **kwargs):
        stats = stats or self.base / 'raw.stats'
        result = subprocess.run([str(self.binary), str(stats)], input=data.encode(),
                                capture_output=True, timeout=10, **kwargs)
        return result, stats

    def runner(self, data='', source='dns', extra=(), compressed=None):
        archive = self.base / 'synthetic.gz'
        archive.write_bytes(gzip.compress(data.encode(), mtime=0) if compressed is None else compressed)
        return subprocess.run(['bash', str(self.root / 'scripts/run_source_extraction.sh'),
            source, str(archive), '--candidates', str(self.candidates),
            '--output-dir', str(self.base / 'out'), '--stats-json', str(self.base / 'stats.json'),
            *map(str,extra)], capture_output=True, text=True, timeout=15)

    def rows(self, source='dns'):
        filename = 'flow' if source == 'flows' else source
        with (self.base / 'out/case_001' / f'{filename}_records.csv').open(newline='') as f:
            return list(csv.reader(f))[1:]

    def safe_retention(self, data, expected):
        result = self.runner(data)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.rows(), list(csv.reader(io.StringIO(expected))))

    def test_runner_all_four_sources(self):
        fixtures = {'dns':record(), 'auth':'150000,U,X,C,D,N,N,L,S\n',
                    'proc':'150000,U,C,P,Start\n','flows':'150000,1,C,1,D,2,6,1,2\n'}
        for source,data in fixtures.items():
            with self.subTest(source=source):
                result = self.runner(data, source)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(self.rows(source),list(csv.reader(io.StringIO(data))))
                report=json.loads((self.base/'stats.json').read_text())
                self.assertEqual(report['raw_lines_scanned'],1)
                self.assertTrue(report['raw_count_final'])

    def test_long_record_native_integrity(self):
        data=record(tail='X'*5000)
        result,stats=self.native(data)
        self.assertEqual(result.stdout,data.encode(), 'C must preserve the entire logical record')
        self.assertEqual(stats.read_text(),'1 1 0 0\n')

    def test_long_record_c_to_python_integrity(self):
        self.safe_retention(record(tail='X'*5000),record(tail='X'*5000))

    def test_final_record_without_newline(self):
        data=record().rstrip('\n')
        result,stats=self.native(data)
        # Approved contract: emit the complete EOF residual with a trailing newline.
        self.assertEqual(result.stdout,record().encode())
        self.assertEqual(stats.read_text(),'1 1 0 0\n')
        self.safe_retention(data,data)

    def test_numeric_fragment_not_forwarded(self):
        result,_=self.native('150000fragment\n'+record())
        self.assertEqual(result.stdout,record().encode())

    def test_numeric_fragment_cannot_stop_runner(self):
        self.safe_retention('9999999fragment\n'+record(),record())

    def test_long_numeric_continuation_cannot_stop_runner(self):
        prefix='150000,C,'
        data=prefix+'X'*(4095-len(prefix))+'9999999\n'+record(150001)
        self.safe_retention(data,data)

    def test_nonnumeric_incomplete_rejected_observably(self):
        # No production window includes zero; internal t=0 is not observable here.
        data='garbage\n,C,D\n\n'+record()
        result,stats=self.native(data)
        self.assertEqual(result.stdout,record().encode())
        self.assertEqual(stats.read_text(),'4 1 0 3\n')
        self.safe_retention(data,record())

    def test_complete_field_count_required_before_forwarding(self):
        for malformed in ('150000\n','150000,C\n','150000,C,D,extra\n','150000,"open\n'):
            with self.subTest(malformed=malformed):
                result,_=self.native(malformed+record())
                self.assertEqual(result.stdout,record().encode())

    def test_complete_field_count_required_before_cutoff(self):
        for malformed in ('9999999\n','9999999,C\n','9999999,C,D,extra\n','9999999,"open\n'):
            with self.subTest(malformed=malformed):
                self.safe_retention(malformed+record(),record())

    def test_sorted_valid_early_stop(self):
        data='147284,C,D\n'+record(147285)+record(154485)+record(2299775)+record(2299776)+record(2300000)
        result,stats=self.native(data)
        self.assertEqual(result.stdout,(record(147285)+record(154485)+record(2299775)).encode())
        # Correctness baseline: scan to EOF, early_stop always 0.
        self.assertEqual(stats.read_text(),'6 1 0 0\n')
        result=self.runner(data)
        self.assertEqual(result.returncode,0,result.stderr)
        report=json.loads((self.base/'stats.json').read_text())
        self.assertEqual(report['raw_lines_scanned'],6)
        self.assertEqual(report['early_stop'],0)

    def test_invalid_timestamp_cannot_stop(self):
        self.safe_retention(record('9999999x')+record(),record())

    def test_invalid_timestamp_not_forwarded(self):
        result,_=self.native(record('150000x')+record())
        self.assertEqual(result.stdout,record().encode())

    def test_nonmonotonic_input_must_reject_or_preserve(self):
        # Safe contract: explicit failure OR full retention; silent success/loss is unsafe.
        result=self.runner(record(2300000)+record())
        if result.returncode == 0:
            self.assertEqual(self.rows(),[['150000','C','D']],
                             'Unsorted input must fail explicitly or retain later eligible rows')

    def test_corrupt_gzip_propagates(self):
        result=self.runner(compressed=b'not gzip')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('gzip failed: status=',result.stderr)

    def test_downstream_failure_propagates(self):
        result=self.runner(record(),extra=['--candidates',self.base/'missing.json'])
        self.assertNotEqual(result.returncode,0)
        self.assertIn('Pipeline failed:',result.stderr)
        self.assertIn('python=1',result.stderr)

    def test_processor_stats_failure_propagates(self):
        blocked=self.base/'stats-directory'
        blocked.mkdir()
        result=self.runner(record(),extra=['--stats-json',blocked])
        self.assertNotEqual(result.returncode,0)
        self.assertIn('python=1',result.stderr)

    def test_native_stats_open_failure_must_fail(self):
        result,_=self.native(record(),stats=self.base)
        self.assertNotEqual(result.returncode,0,'Unwritable stats destination must report failure')

    def test_native_flush_failure_must_fail(self):
        with open('/dev/full','wb') as sink:
            result=subprocess.run([str(self.binary),str(self.base/'raw.stats')],
                input=record().encode(),stdout=sink,stderr=subprocess.PIPE,timeout=10)
        self.assertNotEqual(result.returncode,0,'Failed fflush must not report successful completion')

    def test_native_broken_pipe(self):
        read_fd,write_fd=os.pipe()
        os.close(read_fd)  # Deterministic EPIPE: no reader exists before C starts.
        try:
            result=subprocess.run([str(self.binary),str(self.base/'raw.stats')],
                input=record().encode(),stdout=write_fd,stderr=subprocess.PIPE,
                restore_signals=True,timeout=10)
        finally:
            os.close(write_fd)
        self.assertEqual(result.returncode,-signal.SIGPIPE)
        self.assertFalse((self.base/'raw.stats').exists())

    def test_failed_run_preserves_existing_output(self):
        path=self.base/'out/case_001/dns_records.csv'
        path.parent.mkdir(parents=True)
        original=b'PREEXISTING OUTPUT MUST SURVIVE\n'
        path.write_bytes(original)
        result=self.runner(record(),compressed=gzip.compress(record().encode(),mtime=0)[:-8])
        self.assertNotEqual(result.returncode,0,result.stderr)
        self.assertEqual(path.read_bytes(),original,'Failed gzip run overwrote existing output')


if __name__ == '__main__':
    unittest.main(verbosity=2)
