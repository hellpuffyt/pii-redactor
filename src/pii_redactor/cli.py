"""Command-line interface for pii-redactor."""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import TextIO

from pii_redactor.detectors import DETECTORS
from pii_redactor.engine import RedactionReport
from pii_redactor.formats.csv_format import redact_csv_stream
from pii_redactor.formats.json_format import (
    JsonlDecodeError,
    redact_json_document,
    redact_jsonl_stream,
)
from pii_redactor.formats.log import redact_log_stream
from pii_redactor.formats.text import redact_file_stream
from pii_redactor.mapping import TokenMap
from pii_redactor.policy import Policy

_FORMATS = ("text", "csv", "json", "jsonl", "log")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pii-redactor",
        description="Detect and redact personal data in text, CSV, JSON, and log files.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    redact = sub.add_parser("redact", help="Redact a file according to a policy.")
    redact.add_argument("input", type=Path, help="Path to the input file.")
    redact.add_argument(
        "-o", "--output", type=Path, help="Path to write redacted output (default: stdout)."
    )
    redact.add_argument(
        "--format", choices=_FORMATS, required=True, help="Input format."
    )
    redact.add_argument("--policy", type=Path, help="Path to a policy config file (.toml/.json).")
    redact.add_argument(
        "--mapping-file",
        type=Path,
        help="Path to the reversible token map (required if any detector uses the "
        "'tokenise' action). Kept separate from the redacted output on purpose.",
    )
    redact.add_argument(
        "--detectors",
        type=str,
        default=None,
        help="Comma-separated list of detectors to run (default: all).",
    )
    redact.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would be redacted (type and count only) without writing output.",
    )

    resolve = sub.add_parser(
        "resolve", help="Resolve a token back to its original value using a mapping file."
    )
    resolve.add_argument("--mapping-file", type=Path, required=True)
    resolve.add_argument("--detector", type=str, required=True)
    resolve.add_argument("--token", type=str, required=True)

    return parser


def _load_policy(path: Path | None) -> Policy:
    if path is None:
        return Policy.default()
    return Policy.from_file(path)


def _print_report(report: RedactionReport, *, dry_run: bool) -> None:
    label = "Would redact" if dry_run else "Redacted"
    if report.total == 0:
        print(f"{label}: nothing detected.", file=sys.stderr)
        return
    print(f"{label} {report.total} item(s):", file=sys.stderr)
    for detector in sorted(report.counts):
        count = report.counts[detector]
        actions = report.action_counts.get(detector, {})
        action_summary = ", ".join(f"{a}={c}" for a, c in sorted(actions.items()))
        print(f"  {detector}: {count} ({action_summary})", file=sys.stderr)


def _same_file(a: Path, b: Path) -> bool:
    return a.resolve() == b.resolve()


def _check_paths(args: argparse.Namespace) -> str | None:
    """Refuse path combinations that would destroy data or leak it.

    * output == input: the source would be replaced by its redacted copy.
    * mapping == output: the mapping (every original value) would overwrite
      the redacted output, so the "redacted" file would contain the PII.
    * mapping == input: the mapping would overwrite the source data.
    """
    if args.output is not None and _same_file(args.output, args.input):
        return "output path is the same as the input path"
    if args.mapping_file is not None:
        if args.output is not None and _same_file(args.mapping_file, args.output):
            return "--mapping-file must not be the same path as the output"
        if _same_file(args.mapping_file, args.input):
            return "--mapping-file must not be the same path as the input"
    return None


def _parse_detectors(raw: str | None) -> list[str] | None:
    if raw is None:
        return None
    names = [name.strip() for name in raw.split(",") if name.strip()]
    unknown = sorted(set(names) - set(DETECTORS))
    if unknown or not names:
        # Silently skipping an unknown name would redact nothing while the
        # user believes a detector ran.
        raise ValueError(
            f"unknown or empty detector list {unknown}; valid detectors: {sorted(DETECTORS)}"
        )
    return names


def _all_actions(policy: Policy) -> set[str]:
    return (
        set(policy.actions.values())
        | set(policy.csv_columns.values())
        | set(policy.json_paths.values())
    )


def _run_redact(args: argparse.Namespace) -> int:
    try:
        policy = _load_policy(args.policy)
        detector_names = _parse_detectors(args.detectors)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    problem = _check_paths(args)
    if problem is not None:
        print(f"error: {problem}", file=sys.stderr)
        return 2

    if policy.salt is None and "hash" in _all_actions(policy):
        print(
            "warning: policy uses the 'hash' action without a 'salt'; the built-in "
            "default salt is public, so hashes of guessable values (phone numbers, "
            "card numbers) can be reversed by brute force. Set a secret salt.",
            file=sys.stderr,
        )

    token_map: TokenMap | None = None
    if args.mapping_file is not None:
        try:
            token_map = TokenMap.load(args.mapping_file)
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            print(f"error: cannot read mapping file ({type(exc).__name__})", file=sys.stderr)
            return 2
    elif "tokenise" in _all_actions(policy):
        if not args.dry_run:
            print(
                "error: policy uses the 'tokenise' action; pass --mapping-file",
                file=sys.stderr,
            )
            return 2
        # A dry run only counts; this in-memory map is never written anywhere.
        token_map = TokenMap()

    try:
        report = _redact_to_output(args, policy, token_map, detector_names)
    except FileNotFoundError:
        print(f"error: input file not found: {args.input}", file=sys.stderr)
        return 2
    except UnicodeDecodeError as exc:
        print(f"error: input is not valid UTF-8 (byte offset {exc.start})", file=sys.stderr)
        return 2
    except JsonlDecodeError as exc:
        print(f"error: invalid JSON on line {exc.line_number}: {exc.reason}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        # Only the parser's reason and position, never the offending content.
        print(f"error: invalid JSON: {exc.msg} (line {exc.lineno})", file=sys.stderr)
        return 2
    except csv.Error as exc:
        print(f"error: invalid CSV: {exc}", file=sys.stderr)
        return 2

    _print_report(report, dry_run=args.dry_run)

    if token_map is not None and args.mapping_file is not None and not args.dry_run:
        token_map.save(args.mapping_file)

    return 0


def _redact_to_output(
    args: argparse.Namespace,
    policy: Policy,
    token_map: TokenMap | None,
    detector_names: list[str] | None,
) -> RedactionReport:
    """Redact ``args.input``. File output is written to a temporary file in
    the target directory and renamed into place only on success, so a failure
    part-way through never leaves a truncated output file behind."""
    with args.input.open("r", encoding="utf-8", newline="") as f:
        if args.dry_run:
            return _redact_stream(args.format, f, policy, token_map, detector_names, None)
        if args.output is None:
            return _redact_stream(args.format, f, policy, token_map, detector_names, sys.stdout)
        target: Path = args.output
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{target.name}.", suffix=".tmp", dir=target.resolve().parent
        )
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as out:
                report = _redact_stream(args.format, f, policy, token_map, detector_names, out)
            os.replace(tmp, target)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        return report


def _redact_stream(
    fmt: str,
    f: TextIO,
    policy: Policy,
    token_map: TokenMap | None,
    detector_names: list[str] | None,
    out: TextIO | None,
) -> RedactionReport:
    """Run one format handler; ``out=None`` consumes the stream without
    writing (dry run)."""
    report: RedactionReport
    if fmt in ("text", "log"):
        stream = redact_file_stream if fmt == "text" else redact_log_stream
        output_iter, report = stream(f, policy, token_map=token_map, detector_names=detector_names)
        _write_lines(output_iter, out)
    elif fmt == "csv":
        row_iter, report = redact_csv_stream(
            csv.reader(f), policy, token_map=token_map, detector_names=detector_names
        )
        _write_csv_rows(row_iter, out)
    elif fmt == "jsonl":
        output_iter, report = redact_jsonl_stream(
            f, policy, token_map=token_map, detector_names=detector_names
        )
        _write_lines(output_iter, out)
    elif fmt == "json":
        document = json.load(f)
        redacted, report = redact_json_document(
            document, policy, token_map=token_map, detector_names=detector_names
        )
        if out is not None:
            out.write(json.dumps(redacted, indent=2) + "\n")
    else:  # pragma: no cover - guarded by argparse choices
        raise ValueError(f"Unknown format: {fmt}")
    return report


def _write_lines(lines: Iterable[str], out: TextIO | None) -> None:
    for line in lines:
        if out is not None:
            out.write(line if line.endswith("\n") else line + "\n")


def _write_csv_rows(rows: Iterable[list[str]], out: TextIO | None) -> None:
    writer = csv.writer(out, lineterminator="\n") if out is not None else None
    for row in rows:
        if writer is not None:
            writer.writerow(row)


def _run_resolve(args: argparse.Namespace) -> int:
    try:
        token_map = TokenMap.load(args.mapping_file)
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        print(f"error: cannot read mapping file ({type(exc).__name__})", file=sys.stderr)
        return 2
    value = token_map.resolve(args.detector, args.token)
    if value is None:
        print("error: token not found in mapping file", file=sys.stderr)
        return 1
    print(value)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "redact":
        return _run_redact(args)
    if args.command == "resolve":
        return _run_resolve(args)
    parser.print_help()  # pragma: no cover
    return 1  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(main())
