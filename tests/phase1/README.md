# Phase 1 unified-path regression suite

Only synthetic gzip inputs are generated. No production archive is opened or enumerated.
No repository candidate output is accessed, including `candidate_cases/case_001`.
The tests copy the unchanged runner, processor and C source into a temporary repository
mirror, verify byte identity, and compile that source into the mirror's actual
`scripts/prefilter`. The real Bash runner invokes that binary, real gzip and the real
Python processor. There are no mocked pipeline stages or PATH replacements. Repository
production files and any existing binary are left untouched. All new fixtures, candidates,
outputs and statistics live in temporary directories. Individual new inputs are at most
about 5 KB uncompressed. Linux, Python 3, Bash, gzip, cc and mawk (legacy tests) are required.

Commands run from `/root/lanl_pilot_audit`:

```sh
python3 -m unittest discover -s tests/phase1 -p 'test_*.py' -v > tests/phase1/new-test-results.txt 2>&1
python3 tests/phase1/run_existing_isolated.py > tests/phase1/existing-test-results.txt 2>&1
```

Compilation performed by both harnesses:
`cc -std=c11 -O2 -Wall -Wextra <temporary scripts/prefilter.c> -o <temporary scripts/prefilter>`.
The existing-test harness additionally compiles `03_prefilter_auth.c` to `prefilter_auth`
with the same flags. It copies the two existing test files unchanged and invokes
`python3 -m unittest discover -s <temporary tests> -p 'test_*.py' -v`.
This isolation is necessary because existing tests use some default stats/output paths.
The existing fixtures are also synthetic (some repeat 20,000 short records).

## Observed results

New suite: exit 1; **21 test methods, 8 passing, 13 failing**.
Unittest reports `FAILED (failures=19)` because two failing methods each have four
failing subtests. These are ordinary safe-contract assertions, not expectedFailure
annotations: defects remain visible as a red regression suite.
Existing suite: exit 0; **8 test methods pass**. Full output and tracebacks are saved
in `new-test-results.txt` and `existing-test-results.txt`.

All names below have the `test_` prefix in `test_unified_path.py`.

| Test | Result | Observation / assumption exposed |
| --- | --- | --- |
| runner_all_four_sources | PASS | Actual runner produces matching auth, proc, flows and dns records and final raw stats. |
| long_record_native_integrity | FAIL | A 5,010-byte valid DNS record is emitted only through byte 4,095; the alphabetic continuation is discarded. `fgets` chunks are not logical records. |
| long_record_c_to_python_integrity | FAIL | Python accepts the truncated three-field row as valid, silently shortening the field. |
| final_record_without_newline | PASS | Intended behavior: retain a complete valid final CSV record at EOF. C preserves its bytes; Python's CSV writer normalizes the output terminator. |
| numeric_fragment_not_forwarded | FAIL | `150000fragment` is forwarded on the strength of its leading digits. |
| numeric_fragment_cannot_stop_runner | FAIL | `9999999fragment` triggers cutoff and loses the following valid row, with successful runner status. |
| long_numeric_continuation_cannot_stop_runner | FAIL | Digits positioned exactly at the next 4,095-byte chunk trigger a false cutoff inside a valid CSV field; subsequent row is lost. |
| nonnumeric_incomplete_rejected_observably | PASS | Empty/nonnumeric records are absent from output; subsequent valid input survives. This does NOT establish that C avoids an internal zero timestamp (see limits). |
| complete_field_count_required_before_forwarding | FAIL (4 subtests) | Timestamp-only, short, extra-field and unterminated-quote rows are all forwarded by C. |
| complete_field_count_required_before_cutoff | FAIL (4 subtests) | The same invalid structures with high leading digits stop the runner before a valid row. |
| sorted_valid_early_stop | PASS | Valid sorted records retain inclusive window boundaries and stop on the first complete record beyond the final window; scan count is 5. |
| invalid_timestamp_cannot_stop | FAIL | Full three-field CSV with timestamp `9999999x` causes cutoff without complete timestamp validation. |
| invalid_timestamp_not_forwarded | FAIL | Full three-field CSV with timestamp `150000x` is forwarded by C. |
| nonmonotonic_input_must_reject_or_preserve | FAIL | Safe contract allows explicit rejection or full retention. Current runner succeeds but drops an eligible row after a high timestamp. Sortedness is assumed, not verified. |
| corrupt_gzip_propagates | PASS | Invalid gzip returns runner failure with gzip status diagnostic. |
| downstream_failure_propagates | PASS | Missing candidate configuration makes the actual processor fail; runner reports python=1 and fails. |
| processor_stats_failure_propagates | PASS | A directory as JSON stats destination deterministically causes processor failure and runner failure, even as root. |
| native_stats_open_failure_must_fail | FAIL | C cannot open a directory as its stats file yet exits 0. |
| native_flush_failure_must_fail | FAIL | Real `/dev/full` makes the buffered output flush fail; C ignores this and exits 0. |
| native_broken_pipe | PASS | A pipe with its read end closed before execution deterministically terminates C with SIGPIPE; no final stats file is written. |
| failed_run_preserves_existing_output | FAIL | Truncated gzip emits a valid row then fails. Runner returns failure but has already overwritten a sentinel output file. Durability is not implemented. |

## Scope and deterministic limits

* Nonnumeric-to-zero: the C source initializes `t=0` and never requires a digit.
  All six immutable production windows exclude zero. Therefore external output/stats
  cannot distinguish discarding malformed data from interpreting it as zero and
  filtering it out. The observable test passes, but the stronger requested property
  is not proven. Testing internal parsing directly would require instrumentation or
  production changes; neither is made. Malformed lines discarded in C never reach
  Python's invalid/parsing counters.
* CSV field counts differ by source, but C receives no source argument. Native
  structure assertions use DNS's three-field contract. They state a safety requirement
  for the unified path; they do not imply the current C interface can enforce every
  source schema. Python's later validation cannot undo a premature C cutoff.
* Non-monotonic timestamps deliberately violate the runner's documented sorted-input
  precondition. The test explicitly demands rejection or retention; its failure exposes
  dependence on that precondition. Detecting arbitrary regressions after a cutoff
  requires reading the suffix or an independently established ordering guarantee.
* The real runner privately allocates the C stats filename using `mktemp`. Forcing
  that exact file to become unwritable after initialization would require a race,
  privileged filesystem manipulation or stage replacement. No such flaky test is
  used. C stats-open failure is deterministic directly; Python stats-write failure is
  deterministic through the actual runner. C stats `fprintf`/`fclose` failures are
  not independently injected here.
* SIGPIPE status within a running pipeline depends on scheduling, write size and
  buffering. The downstream failure test asserts processor/runner failure, not a
  particular upstream status. The native closed-pipe test removes that race; the
  `/dev/full` test separately exposes ignored flush errors. No claim is made that
  the runner propagates a C status which C never emits. The existing all-sources
  early-exit test exercises large synthetic tails but does not prove gzip always
  receives SIGPIPE. No timing-based assertions or integer-overflow fixtures are used.
* The long native test stops at its first failed assertion, so its later logical
  scan-count assertion is not reached in this run. The independent C-to-Python test
  ensures record corruption is still measured through the full runner.

Created files: `test_unified_path.py`, `run_existing_isolated.py`, `README.md`,
`new-test-results.txt`, `existing-test-results.txt`, all under `tests/phase1/`.
No production implementation or existing test was changed.
