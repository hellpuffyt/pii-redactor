# pii-redactor

Detect and redact personal data (PII) in text, CSV, JSON/JSONL, and log
files, under a configurable, per-detector policy — with an optional
reversible token map kept in a file separate from the redacted output.

## What

`pii-redactor` scans a file for common categories of personal data (email
addresses, phone numbers, payment card numbers, IBANs, IP addresses,
national ID numbers, dates of birth, person names, postal addresses, and
API keys/tokens) and applies a configurable action to each match: redact
it, hash it, tokenise it (with a reversible mapping), partially mask it, or
explicitly keep it.

It runs entirely locally. Nothing is uploaded anywhere.

## Why

Sharing a production log, a support ticket export, or a CSV of customer
records with a vendor, a model provider, or a public bug tracker routinely
means leaking real customer data along with it. The two common ways people
deal with this are both unsatisfying:

- **Destroy the data** (blanket find/replace, or a cloud DLP tool set to
  maximum aggressiveness) — you can no longer correlate records across the
  redacted export, count distinct users, or reproduce a bug tied to a
  specific account.
- **Use a cloud redaction service** — you've "solved" leaking the data by
  sending it to a third party first.

`pii-redactor` is local-only and policy-driven: you decide, per detector
and per field, whether something gets destroyed (`redact`), pseudonymised
in a way that preserves joins (`hash`, `tokenise`), partially shown
(`partial`), or left alone (`keep`). Tokenisation keeps a reversible
mapping so an analyst with the mapping file (and only that analyst) can
still recover the original values later.

## Features

- Ten built-in detectors, several backed by real checksum validation
  (Luhn for cards, ISO 7064 mod-97 for IBAN) rather than pattern matching
  alone.
- Five policy actions per detector, per CSV column, or per JSON dotted
  path: `redact`, `hash`, `tokenise`, `partial`, `keep`.
- Reversible token map written to a **separate file**, never inline in the
  redacted output.
- Format-aware handling: plain text, line-structured logs, CSV (header +
  per-column policy), and JSON/JSONL (per dotted-path policy).
- Streaming line-by-line / row-by-row processing for text, log, CSV, and
  JSONL, so files far larger than available memory can be redacted.
- `--dry-run` reporting exactly what *would* be redacted — by detector
  type and count — without writing any output or ever printing a detected
  value.

## Detectors reference

| Detector        | Method                                              | Confidence |
|------------------|------------------------------------------------------|------------|
| `email`          | RFC-shaped pattern match                              | high |
| `phone`          | Separator-aware pattern match, digit-count bounded    | medium/high |
| `credit_card`    | Digit-run candidate + **Luhn checksum**               | high |
| `iban`           | Pattern + **ISO 7064 mod-97-10 checksum** + length check per country | high |
| `ip_address`     | IPv4/IPv6 parsed with `ipaddress`; optional `keep_private_ips` to skip RFC 1918 / IPv6 unique-local (`fc00::/7`), loopback and link-local addresses (documentation, CGNAT and reserved ranges are still redacted) | high |
| `national_id`    | US SSN-shaped pattern with area/group/serial exclusions | high |
| `date_of_birth`  | Date pattern, only matched near a birth-context keyword (`DOB`, `born`, `date of birth`), plus a plausibility check (real calendar date, not in the future) | medium |
| `person_name`    | Two-token capitalised span where the first token is in a common-first-name dictionary | low |
| `address`        | Street-number + street-name + suffix pattern (optionally city/state/ZIP) | medium |
| `api_key`        | Known-vendor prefixes (AWS `AKIA`/`ASIA`, OpenAI `sk-`, GitHub classic (`ghp_`) and fine-grained PATs, Slack `xox*`, Google `AIza`, JWTs) plus a generic high-entropy-token heuristic | high/medium |

## Policies

A policy is a TOML or JSON file with three optional sections:

```toml
keep_private_ips = true
salt = "a-project-specific-salt-do-not-share"

[detectors]
email = "tokenise"
phone = "redact"
credit_card = "redact"
iban = "redact"
ip_address = "partial"
national_id = "redact"
date_of_birth = "redact"
person_name = "keep"
address = "redact"
api_key = "redact"

[csv_columns]
customer_email = "tokenise"
notes = "redact"

[json_paths]
"user.ssn" = "redact"
"user.email" = "tokenise"
```

- Detectors without an entry fall back to a sensible built-in default (see
  `pii_redactor.policy.DEFAULT_ACTIONS`).
- `csv_columns` and `json_paths` force an action on the **whole cell /
  whole field value** for that column or dotted path, regardless of
  whether a detector pattern matches — useful for a column you know is
  always sensitive (e.g. `ssn`) even if its stored format varies.
- `salt` is used for the `hash` action. Use a project-specific salt; two
  files redacted with the same salt will hash the same input value to the
  same output, which is what makes joins across redacted files possible —
  and also why the salt itself must be kept as confidential as the data.

### Actions

| Action | Behaviour | Example |
|---|---|---|
| `redact` | Replace with a type marker | `[EMAIL]` |
| `hash` | Stable salted hash (joinable, not reversible without the salt) | `EMAIL_HASH_9f86d081...` |
| `tokenise` | Sequential token, reversible via a **separate** mapping file | `EMAIL_001` |
| `partial` | Partially mask, keeping some structure | `j***@example.com` |
| `keep` | Leave the value untouched | (unchanged) |

## Architecture

```
src/pii_redactor/
  detectors/       regex + checksum detectors, return Match(start, end, value, confidence)
  validators.py     Luhn and IBAN checksum implementations
  policy.py         Policy config model + loader (TOML/JSON)
  mapping.py        TokenMap: reversible token <-> value store, persisted separately
  engine.py         run_detectors + apply_policy -> (redacted_text, RedactionReport)
  formats/          per-format streaming adapters (text, log, csv, json/jsonl)
  cli.py            argparse CLI: `redact` and `resolve` subcommands
```

`RedactionReport` only ever stores detector names, action names, and
integer counts — never the detected values themselves (see Security,
below).

## Installation

Requires Python 3.10+. No runtime dependencies on 3.11+ (`tomli` on 3.10).

```bash
python -m venv .venv
# macOS / Linux
.venv/bin/python -m pip install -e ".[dev]"
# Windows
.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

The rest of this README writes `python` for the virtualenv's interpreter
(`.venv/bin/python` or `.venv\Scripts\python.exe`) and `pii-redactor` for
the console script installed next to it.

## Usage

```bash
# Redact a text file with the default policy, to stdout
pii-redactor redact input.txt --format text

# Redact a CSV with a custom policy, tokenising the email column
pii-redactor redact customers.csv --format csv \
  --policy policy.toml --mapping-file customers.mapping.json \
  -o customers.redacted.csv

# Redact JSONL, one JSON object per line
pii-redactor redact events.jsonl --format jsonl --policy policy.toml -o events.redacted.jsonl

# Dry run: report what would be redacted without writing anything
pii-redactor redact support_export.log --format log --dry-run

# Recover an original value from a token, given the mapping file
pii-redactor resolve --mapping-file customers.mapping.json --detector email --token EMAIL_001
```

### Dry-run output

`--dry-run` writes a report to stderr with detector names, action names,
and counts only — it never prints the values that were found:

```
Would redact 4 item(s):
  credit_card: 1 (redact=1)
  email: 2 (tokenise=2)
  phone: 1 (redact=1)
```

## Examples

`examples/sample.txt`, `examples/sample.csv`, and `examples/sample.jsonl`
contain synthetic (non-real) data — invented names, `example.com`
addresses, RFC 5737/RFC 3849 documentation IP ranges, and the standard
`4111111111111111` Luhn-valid test card number — used by the CI smoke test
and safe to experiment with locally.

## Testing

```bash
python -m pytest
python -m ruff check .
python -m mypy
```

The test suite places particular emphasis on **false-positive guards**:
order numbers must not be flagged as credit cards, version strings must
not be flagged as IP addresses, and a capitalised sentence start must not
be flagged as a person name. Luhn and IBAN checksum validation is tested
in both directions (valid numbers accepted, invalid numbers rejected).

### Measured detection quality (synthetic corpus)

`tests/eval/corpus.py` is a hand-labelled corpus of **synthetic** data (110
lines: 72 containing 79 labelled PII values, plus 38 hard negatives such as
order numbers, dates, UUIDs, git SHAs, version strings and MAC addresses).
`python -m tests.eval.metrics` scores every detector against it; the result
below is copied from that command (all detectors enabled, private IPs not
skipped). A prediction counts as a true positive only with the right type
and the exact gold span; `leaked` is the number of gold values still present
verbatim after redacting with every detector set to `redact`.

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

**These numbers describe this small corpus only. They are not an estimate
of recall on your data and not a guarantee of anything.** The corpus was
written by the same people who wrote the detectors, so it is biased toward
formats the detectors know. The four values that leak are documented misses
(bare 10-digit phone number, SSN without separators, month-name date of
birth, a first name outside the dictionary); `tests/test_detection_eval.py`
fails if any other value leaks or if any error count rises.

## Security

- **This tool never prints or logs a detected value.** Dry-run reports and
  all diagnostic output contain only detector type, action, and count;
  error messages for malformed input give a line number or byte offset,
  never the offending content. `tests/test_cli_safety.py` checks this for
  every labelled value in the evaluation corpus, across all formats.
  A redaction tool that leaks what it found defeats its own purpose.
- The reversible token map is written to a file separate from the
  redacted output. **That mapping file is exactly as sensitive as the
  original, un-redacted data** — anyone with it can recover every
  tokenised value. Store it with the same access controls as the source
  data, never commit it to version control, and delete it once it is no
  longer needed. It is written with owner-only permissions (`0600`) on
  POSIX systems.
- The CLI refuses to run when `-o` is the input file, or when
  `--mapping-file` is the input or the output file (either would destroy
  data or put the original values where the redacted copy was expected).
  Output files are written to a temporary file and renamed into place, so a
  failed run never leaves a partial or overwritten output.
- An unknown name in `--detectors` or in a policy's `[detectors]` table is an
  error rather than being silently ignored.
- The `hash` action's salt is a secret in its own right: knowing the salt
  plus a guessable input space (e.g. all possible phone numbers) lets an
  attacker reconstruct a lookup table. Use a random, project-specific
  salt and keep it out of version control. If a policy uses `hash` without
  a `salt`, a built-in **public** default salt is used and the CLI prints a
  warning. Hashes are truncated to 12 hex characters (48 bits).

## Limitations

Be realistic about what this tool is:

- It is **pattern-and-validation-based detection, not a guarantee**. It
  will miss PII in formats it doesn't recognise (non-US national IDs
  beyond the SSN-style pattern, addresses outside the US street-suffix
  convention, phone numbers with unusual formatting) and it will
  occasionally over- or under-match on inherently ambiguous input.
- `person_name` detection is a low-confidence heuristic (dictionary +
  capitalisation) and is disabled (`keep`) by default because its false
  positive/negative rates are the highest of any detector here — enable
  it deliberately and review its output.
- `date_of_birth` only fires near an explicit context keyword (`DOB`,
  `born`, `date of birth`) by design, to avoid flagging every date in a
  document; this trades recall for precision.
- JSON/JSONL **keys** are never scanned or redacted, only values. Numeric
  values are scanned in their decimal form (and replaced by a string when
  something is redacted); booleans and `null` are left alone.
- The CSV header row is passed through unchanged.
- Known measured misses and false positives are listed under "Measured
  detection quality" above (e.g. bare digit runs, SSNs without separators,
  month-name dates, `logo@2x.png` looking like an email, SSN-shaped
  reserved numbers being redacted as phone numbers).
- A single large JSON document (not JSONL) is loaded into memory as a
  whole, since JSON has no natural line-based streaming boundary. Text,
  log, CSV, and JSONL inputs stream line-by-line / row-by-row and are not
  bounded by available memory.
- This tool reduces risk; it does not eliminate it. Always review a
  sample of redacted output before sharing it externally, and treat this
  as one control among several (access controls, data minimisation,
  contractual terms), not a substitute for them.

## License

MIT © 2026 Prabesh Sharma. See [LICENSE](LICENSE).
