# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `-o` pointing at the input file truncated the input; `--mapping-file`
  equal to the output overwrote the redacted output with every original
  value. Both (and mapping == input) are now refused.
- `--detectors` with an unknown name silently ran nothing; it is now an
  error. Unknown detector names in a policy's `[detectors]` table are errors.
- `--dry-run` crashed when the policy used `tokenise` without
  `--mapping-file`.
- JSON numeric values were never inspected, even under an explicit
  `json_paths` policy (an SSN or card stored as an integer leaked).
- `keep_private_ips` also kept documentation, benchmarking and reserved
  ranges; it now skips only RFC 1918 / IPv6 ULA, loopback and link-local,
  as documented.
- Mapping file is written with owner-only (`0600`) permissions.
- Output is written atomically; a failed run leaves no partial output.
- Malformed JSON/JSONL, non-UTF-8 input and missing files produce a one-line
  error (no traceback, no content echoed) and exit code 2.
- Detectors: email local parts containing `'`; unseparated E.164 phone
  numbers; MM-DD-YYYY / DD.MM.YYYY dates no longer flagged as phones;
  lowercase IBANs and spaced IBANs followed by an uppercase word; address
  no longer swallows a sentence-ending period; UUIDs no longer flagged as
  API keys.
- Overlap de-duplication was O(n²) in the number of candidates on a line
  (~21 s for a 200 kB line); it is now O(n log n).

### Added

- Labelled synthetic evaluation corpus with per-entity precision/recall
  (`python -m tests.eval.metrics`) and regression ceilings.
- Warning when `hash` is used without a `salt`.
- `SECURITY.md`, `.editorconfig`, `docs/PRODUCTION_READINESS.md`.

## [0.1.0] - 2026-08-30

### Added

- Initial release.
- Ten detectors: email, phone, credit card (Luhn-validated), IBAN
  (mod-97 checksum), IP address (v4/v6), national ID (US SSN-style),
  date of birth (context-gated), person name (dictionary heuristic),
  postal address, and API key/token.
- Policy engine with five actions (`redact`, `hash`, `tokenise`,
  `partial`, `keep`), configurable per detector, per CSV column, and per
  JSON dotted path.
- Reversible token mapping persisted to a separate file.
- Streaming format handlers for plain text, line-structured logs, CSV,
  and JSONL; whole-document handling for single JSON files.
- CLI with `redact` and `resolve` subcommands, including `--dry-run`
  reporting that never prints detected values.
