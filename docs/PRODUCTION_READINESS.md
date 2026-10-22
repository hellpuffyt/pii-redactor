# Production readiness — pii-redactor

Audit date: 2026-10-22. Tested code commit: `ca078c9` (branch
`audit/production-readiness`); later commits change
documentation only.

## Scope

A local CLI and library that detects ten categories of PII in text, log,
CSV, JSON and JSONL files with regex + checksum detectors and applies a
per-detector / per-column / per-path policy action (`redact`, `hash`,
`tokenise`, `partial`, `keep`), with a reversible token map in a separate
file. Architecture: `detectors/` (pure functions returning spans) →
`engine.py` (overlap de-duplication, policy application, value-free report)
→ `formats/` (streaming adapters) → `cli.py`.

Out of scope: guaranteed detection, non-US national IDs, non-US address
formats, ML/NER-based name detection, JSON key scanning.

## Platforms and prerequisites

- Python 3.10–3.13. Verified locally on macOS 27 (Apple Silicon) with
  Python 3.12.14 (full suite, lint, types, clean clone) and with Python
  3.10.21 and 3.13 (full suite).
- Linux and Windows are covered by the existing CI matrix but were **not**
  run for this audit (no Windows host available).
- No external services, network access, credentials or hardware needed.

## Clean-clone verification (README followed literally)

```bash
git clone -b audit/production-readiness <repo> pii-redactor && cd pii-redactor
python3.12 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"          # exit 0
.venv/bin/python -m pytest                           # 171 passed, exit 0
.venv/bin/python -m ruff check .                     # All checks passed, exit 0
.venv/bin/python -m mypy                             # no issues in 14 files, exit 0
.venv/bin/pii-redactor redact examples/sample.txt --format text --dry-run          # exit 0
.venv/bin/pii-redactor redact examples/sample.csv --format csv \
  --policy examples/policy.toml --mapping-file ../m.json -o ../out.csv             # exit 0
.venv/bin/pii-redactor resolve --mapping-file ../m.json --detector email --token EMAIL_001  # exit 0
.venv/bin/python -m tests.eval.metrics               # table below
```

Result: all steps passed; the redacted CSV contained `EMAIL_001`,
`[SSN]`, `[PHONE]` in place of the synthetic values.

## Commands and outcomes

| Step | Command | Exit | Result |
|---|---|---:|---|
| Baseline tests (main `21d04c7`) | `python -m pytest -q` | 0 | 121 passed, 0 failed, 0 skipped |
| Baseline lint / types | `ruff check .` / `mypy` | 0 / 0 | clean |
| Final tests | `python -m pytest -q -rs` | 0 | 171 passed, 0 failed, 0 skipped (1 test is `skipif` on Windows only) |
| Final tests, Python 3.10 / 3.13 | `uv run -p 3.10 ... pytest` | 0 / 0 | 171 passed each |
| Lint / types | `ruff check .` / `mypy` (strict) | 0 / 0 | clean |
| Dependency audit | `uvx pip-audit -r <frozen dev env> --disable-pip --no-deps --strict` | 0 | No known vulnerabilities (no runtime deps on 3.11+) |
| Tree secret scan | `uvx detect-secrets scan --all-files` | – | only synthetic fixtures and example salts |
| History secret scan | full-history `git grep` for token/key patterns | – | see Security |

CI: default branch `main`: **success** (run on `21d04c7`). Audit branch:
pending until pushed.

## Measured detection quality

`python -m tests.eval.metrics` on the labelled **synthetic** corpus in
`tests/eval/corpus.py` (110 lines, 79 labelled values, 38 hard negatives).
Strict scoring: exact span and type. `leaked` = labelled values still present
after redacting with every detector set to `redact`.

| entity | support | TP | FP | FN | precision | recall | leaked |
|---|---:|---:|---:|---:|---:|---:|---:|
| email | 9 | 9 | 1 | 0 | 0.90 | 1.00 | 0 |
| phone | 9 | 8 | 5 | 1 | 0.62 | 0.89 | 1 |
| credit_card | 10 | 10 | 0 | 0 | 1.00 | 1.00 | 0 |
| iban | 10 | 10 | 0 | 0 | 1.00 | 1.00 | 0 |
| ip_address | 8 | 8 | 0 | 0 | 1.00 | 1.00 | 0 |
| national_id | 6 | 4 | 0 | 2 | 1.00 | 0.67 | 1 |
| date_of_birth | 5 | 4 | 0 | 1 | 1.00 | 0.80 | 1 |
| person_name | 6 | 5 | 2 | 1 | 0.71 | 0.83 | 1 |
| address | 7 | 7 | 1 | 0 | 0.88 | 1.00 | 0 |
| api_key | 9 | 9 | 1 | 0 | 0.90 | 1.00 | 0 |
| **all** | 79 | 74 | 10 | 5 | 0.88 | 0.94 | 4 |

The same corpus scored against the original code: overall precision 0.83,
recall 0.89, 6 leaked values. These figures are evidence about this corpus
only — the corpus was written alongside the detectors and is small. They do
not estimate recall on real data.

Remaining measured false negatives: bare 10-digit phone number, SSN with
spaces (redacted as a phone, so not leaked) and without separators (leaked),
month-name date of birth, first name outside the dictionary. Remaining false
positives: `logo@2x.png` as email; dotted-quad build id and SSN-shaped
reserved numbers as phone; "Mark Complete" / "George Washington [Bridge]" as
names; "5 Miles Drive" as address; a snake_case identifier as an API key.

## Bugs found and fixed (each with a regression test)

| # | Severity | Defect | Test |
|---|---|---|---|
| 1 | High (data loss) | `-o` equal to input truncated the input | `test_output_equal_to_input_is_refused_and_input_survives` |
| 2 | High (leak) | `--mapping-file` equal to `-o` overwrote the redacted output with all original values | `test_mapping_file_equal_to_output_is_refused` |
| 3 | High (data loss) | `--mapping-file` equal to input overwrote the source | `test_mapping_file_equal_to_input_is_refused` |
| 4 | High (fail-open) | unknown `--detectors` name silently redacted nothing | `test_unknown_detector_name_is_an_error_not_a_silent_no_op` |
| 5 | High (leak) | JSON numbers never scanned, even under an explicit `json_paths` policy | `test_json_numeric_values_are_scanned_and_forced_paths_apply` |
| 6 | Medium (leak) | `keep_private_ips` kept documentation/benchmark/reserved ranges, wider than documented | `test_keep_private_ips_only_skips_internal_networks` |
| 7 | Medium | mapping file (as sensitive as the source) created world-readable | `test_mapping_file_is_owner_only` |
| 8 | Medium | failed run left partial output / clobbered existing output | `test_failed_run_leaves_no_partial_output`, `..._does_not_clobber_existing_output` |
| 9 | Medium (DoS) | O(n²) overlap de-duplication: ~21 s for one 200 kB line | `test_overlap_dedupe_is_not_quadratic` |
| 10 | Medium | `--dry-run` crashed with a `tokenise` policy and no mapping file | `test_dry_run_with_tokenise_policy_and_no_mapping_file` |
| 11 | Low (fail-open) | misspelled detector in policy silently ignored | `test_policy_with_misspelled_detector_is_rejected` |
| 12 | Low | malformed JSON/JSONL, non-UTF-8, missing file → traceback | `test_malformed_input_fails_cleanly_without_echoing_content`, `test_missing_input_file_is_a_clean_error`, `test_corrupt_mapping_file_is_a_clean_error` |
| 13 | Low (leak) | email with `'` in local part left a fragment | `test_email_local_part_with_apostrophe_is_matched_whole` |
| 14 | Low (miss) | unseparated E.164 phone numbers missed | `test_e164_phone_without_separators_is_detected` |
| 15 | Low (miss) | lowercase IBAN; spaced IBAN followed by an uppercase word | `test_lowercase_iban_is_detected`, `test_spaced_iban_followed_by_uppercase_word_is_detected` |
| 16 | Low (FP) | MM-DD-YYYY dates as phones; UUIDs as API keys; address ate trailing `.` | `test_us_and_eu_style_calendar_dates_are_not_phones`, `test_uuid_is_not_flagged_as_api_key`, `test_address_does_not_swallow_sentence_period_after_city` |

Also: a warning when `hash` is used without a `salt` (the default salt is
public); token-shaped fixtures are now built at runtime; README install and
test commands now work on macOS/Linux (they were Windows-only paths);
`permissions: contents: read` added to CI.

## Security review

- **No value in diagnostics:** asserted for every labelled corpus value, for
  all four transforming actions and for text/CSV/JSON/JSONL, on stdout and
  stderr, including dry-run and error paths (`tests/test_cli_safety.py`).
- **Injection / traversal:** the tool reads and writes only paths given on
  the command line; no shell, network, `eval` or deserialisation beyond
  `json`/`tomllib`.
- **Resource exhaustion:** adversarial 50–200 kB single lines tested for all
  detectors; the only super-linear case found (overlap de-dup) was fixed.
  Regexes have bounded repetition; no catastrophic backtracking observed.
- **Secrets in history:** the single pre-existing commit contains the AWS
  documentation placeholder key `AKIA…EXAMPLE` (in `examples/sample.txt` and a
  test) and a GitHub fine-grained-PAT prefix regex literal. These are public documentation
  examples, **not credentials — no rotation needed**. History was not
  rewritten; the current tree no longer contains them.
- **Dependencies:** none at runtime on 3.11+; dev tools audited clean.

## Known limitations and risks

- Detection is pattern/checksum based; it will miss formats it does not know
  and over-redact look-alikes (see the measured table). Review output before
  sharing it.
- JSON keys and the CSV header row are not scanned.
- `hash` output is 48 bits of salted SHA-256; with a weak or public salt it
  is reversible for small input spaces (phone numbers).
- Single JSON documents are loaded whole into memory.
- Windows and Linux were not executed in this audit.

## Acceptance checklist

| Item | Expected behaviour | Command / test | Result | Actual | Reference |
|---|---|---|---|---|---|
| A1 | Installs from a clean clone | `pip install -e ".[dev]"` | pass | exit 0 | clean-clone section |
| A2 | Full suite, lint, strict types green | `pytest`, `ruff`, `mypy` | pass | 171 passed; clean; clean | CI config |
| A3 | Checksum-validated types have no FP/FN on the corpus | `python -m tests.eval.metrics` | pass | card 10/10, IBAN 10/10, 0 FP | `tests/test_detection_eval.py` |
| A4 | Per-entity precision/recall measured and guarded | same | pass | table above; ceilings enforced | `test_error_counts_do_not_regress` |
| A5 | Only documented misses leak under redact-all | test | pass | 4 known leaks | `test_only_documented_misses_leak` |
| A6 | No original value in stdout/stderr/dry-run/errors | tests | pass | 0 occurrences | `tests/test_cli_safety.py` |
| A7 | Originals only in the separate mapping file, mode 0600 | tests | pass | yes | `test_mapping_file_is_owner_only` |
| A8 | Path collisions refused, no partial output | tests | pass | exit 2, files intact | `test_*_refused`, `test_failed_run_*` |
| A9 | Malformed input → exit 2, one-line error | tests | pass | yes | `test_malformed_input_*` |
| A10 | Linear-ish time on long lines | test | pass | 200 kB line 0.12 s | `test_overlap_dedupe_is_not_quadratic` |

## Classification proposal

**Partially Verified** — all documented behaviour is implemented and tested
on macOS with Python 3.10/3.12/3.13, detection quality is measured on a
synthetic corpus, and the clean clone passes. Not verified here: the Linux
and Windows CI legs on the audit branch (pending push), and detection quality
on any real-world data (by design — synthetic data only).
