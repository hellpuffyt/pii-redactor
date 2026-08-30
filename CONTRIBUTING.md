# Contributing

Contributions are welcome. This project is deliberately small in scope —
local, dependency-free PII detection and redaction — so please open an
issue to discuss significant additions (new detectors, new formats) before
sending a large pull request.

## Development setup

```bash
python -m venv .venv
./.venv/Scripts/python.exe -m pip install -e ".[dev]"    # Windows
# source .venv/bin/activate && pip install -e ".[dev]"   # macOS/Linux
```

## Before opening a pull request

```bash
./.venv/Scripts/python.exe -m pytest
./.venv/Scripts/python.exe -m ruff check .
./.venv/Scripts/python.exe -m mypy
```

All three must pass. New detectors or policy actions should come with:

- Tests for the happy path (a valid example is correctly detected).
- **False-positive guard tests** — this is the single most important
  category of test in this project. If you add a detector, add at least
  one test proving it does *not* fire on plausible look-alike input
  (an order number, a version string, a UUID, etc.).
- A checksum test in both directions, if the detector uses one.
- An update to the detectors table in `README.md`.

## Reporting a security issue

If you find a case where this tool fails to redact something it should
have, or where diagnostic output leaks a detected value (see the "never
print a detected value" rule in `README.md`), please open an issue
describing the failure mode without including real personal data in the
report — a synthetic reproduction is preferred.

## Code style

- Format and lint with `ruff`; type-check with `mypy --strict`.
- Keep detectors as pure functions with no I/O.
- Never log, print, or persist a detected value outside of applying the
  configured policy action to it.
