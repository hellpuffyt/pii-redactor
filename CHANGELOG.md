# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
