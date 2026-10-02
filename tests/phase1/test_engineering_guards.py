"""Synthetic-only engineering gates; reuses isolated production-runner sandbox."""
import json
import unittest
import test_unified_path as existing

def Harness():
    return existing.UnifiedPathTests()

class EngineeringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        existing.UnifiedPathTests.setUpClass()
    @classmethod
    def tearDownClass(cls):
        existing.UnifiedPathTests.tearDownClass()
    def setUp(self):
        self.h = Harness()
        self.h.setUp()
        self.addCleanup(self.h.doCleanups)
    def test_oversize_rejected_before_emit(self):
        data='574838,C,'+'X'*(1024*1024)
        r,s=self.h.native(data)
        self.assertNotEqual(r.returncode,0)
        self.assertEqual(r.stdout,b'')
        self.assertFalse(s.exists())
        self.assertIn(b'oversized_records=1',r.stderr)

    def test_default_all_six_unchanged(self):
        r=self.h.runner('578438,C,D\n')
        self.assertEqual(r.returncode,0,r.stderr)
        s=json.loads((self.h.base/'stats.json').read_text())
        self.assertEqual(set(s['output_files']),{f'case_{i:03d}' for i in range(1,7)})

    def test_invalid_selector_fails_no_promotion(self):
        r=self.h.runner('578438,C,D\n',extra=['--case-id','case_999'])
        self.assertNotEqual(r.returncode,0)
        self.assertFalse((self.h.base/'stats.json').exists())
        self.assertFalse((self.h.base/'out').exists())

    def test_exact_limit_native_and_eof(self):
        data='574838,C,'+'X'*(1024*1024-len('574838,C,'))
        for suffix in ('','\n'):
            with self.subTest(suffix=repr(suffix)):
                r,s=self.h.native(data+suffix)
                self.assertEqual(r.returncode,0,r.stderr)
                self.assertEqual(r.stdout,(data+'\n').encode())
                self.assertEqual(s.read_text(),'1 1 0 0\n')

    def test_chunk_boundary_through_runner(self):
        data='578438,C,'+'X'*70000+'\n'
        r=self.h.runner(data,extra=['--case-id','case_002'])
        self.assertEqual(r.returncode,0,r.stderr)
        import csv
        with (self.h.base/'out/case_002/dns_records.csv').open(newline='') as f:
            rows=list(csv.reader(f))
        self.assertEqual(rows[1],data.rstrip('\n').split(','))
        self.assertEqual(len(rows),2)

    def test_oversize_preserves_existing_output_and_stats(self):
        out=self.h.base/'out/case_002/dns_records.csv'
        out.parent.mkdir(parents=True)
        out.write_bytes(b'EXISTING')
        stats=self.h.base/'stats.json'
        stats.write_bytes(b'EXISTING-STATS')
        r=self.h.runner('578438,C,D\n578439,C,'+'X'*(1024*1024)+'\n',extra=['--case-id','case_002'])
        self.assertNotEqual(r.returncode,0)
        self.assertIn('prefilter=1',r.stderr)
        self.assertEqual(out.read_bytes(),b'EXISTING')
        self.assertEqual(stats.read_bytes(),b'EXISTING-STATS')

    def test_oversize_no_newline_under_memory_limit(self):
        import subprocess,resource
        data=self.h.base/'oversize.bin'
        with data.open('wb') as f:
            f.write(b'574838,C,')
            for _ in range(128):
                f.write(b'X'*65536)
        def limit():
            resource.setrlimit(resource.RLIMIT_AS,(32*1024*1024,32*1024*1024))
        rss=self.h.base/'rss.txt'
        with data.open('rb') as f:
            r=subprocess.run(['/usr/bin/time','-f','%M','-o',str(rss),str(self.h.binary),str(self.h.base/'raw.stats')],stdin=f,capture_output=True,preexec_fn=limit,timeout=10)
        self.assertEqual(r.returncode,1)
        self.assertIn(b'oversized_records=1',r.stderr)
        self.assertEqual(r.stdout,b'')
        peak=int(rss.read_text().splitlines()[-1])
        print(f'oversize prefilter measured peak RSS={peak} KiB; AS limit=32 MiB')
        self.assertLess(peak,16*1024)

    def test_single_case_real_runner(self):
        r = self.h.runner('150000,U,X,C,D,N,N,L,S\n578438,U,X,C,D,N,N,L,S\n', 'auth', extra=['--case-id','case_002'])
        self.assertEqual(r.returncode,0,r.stderr)
        s=json.loads((self.h.base/'stats.json').read_text())
        self.assertEqual(s['matched_records_per_case'],{'case_002':1})
        self.assertEqual(set(s['output_files']),{'case_002'})
        self.assertEqual([p.name for p in (self.h.base/'out').iterdir()],['case_002'])

if __name__ == '__main__':
    unittest.main()
