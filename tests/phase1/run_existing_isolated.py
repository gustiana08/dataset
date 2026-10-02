"""Run existing tests unchanged, with all default writes confined to a temp mirror."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='phase1-existing-') as tmp:
    base = Path(tmp)
    (base / 'scripts').mkdir()
    (base / 'tests').mkdir()
    (base / 'logs').mkdir()
    for name in ('run_source_extraction.sh', 'prefilter.c', '03_process_stream.py',
                 'run_auth_prefilter.sh', '03_prefilter_auth.c',
                 '03_prefilter_auth.awk', '03_process_auth_stream.py'):
        shutil.copy2(ROOT / 'scripts' / name, base / 'scripts' / name)
    for name in ('test_auth_prefilter.py', 'test_all_sources.py'):
        shutil.copy2(ROOT / 'tests' / name, base / 'tests' / name)
    shutil.copy2(ROOT / 'selected_candidates.json', base / 'selected_candidates.json')
    for source, binary in [('prefilter.c', 'prefilter'), ('03_prefilter_auth.c', 'prefilter_auth')]:
        subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra',
                        str(base / 'scripts' / source), '-o', str(base / 'scripts' / binary)], check=True)
    result = subprocess.run([sys.executable, '-m', 'unittest', 'discover',
                             '-s', str(base / 'tests'), '-p', 'test_*.py', '-v'], cwd=base)
    sys.exit(result.returncode)
