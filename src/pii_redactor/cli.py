"""Command-line interface for pii-redactor."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

from pii_redactor.engine import RedactionReport
from pii_redactor.formats.csv_format import redact_csv_stream
from pii_redactor.formats.json_format import redact_json_document, redact_jsonl_stream
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


def _run_redact(args: argparse.Namespace) -> int:
    policy = _load_policy(args.policy)
    detector_names = args.detectors.split(",") if args.detectors else None

    token_map: TokenMap | None = None
    needs_mapping = "tokenise" in policy.actions.values() or bool(
        set(policy.csv_columns.values()) & {"tokenise"}
    ) or bool(set(policy.json_paths.values()) & {"tokenise"})
    if args.mapping_file is not None:
        token_map = TokenMap.load(args.mapping_file)
    elif needs_mapping and not args.dry_run:
        print(
            "error: policy uses the 'tokenise' action; pass --mapping-file",
            file=sys.stderr,
        )
        return 2

    with args.input.open("r", encoding="utf-8", newline="") as f:
        if args.format == "text":
            output_iter, report = redact_file_stream(
                f, policy, token_map=token_map, detector_names=detector_names
            )
            _write_lines(output_iter, args.output, args.dry_run)
        elif args.format == "log":
            output_iter, report = redact_log_stream(
                f, policy, token_map=token_map, detector_names=detector_names
            )
            _write_lines(output_iter, args.output, args.dry_run)
        elif args.format == "csv":
            reader = csv.reader(f)
            row_iter, report = redact_csv_stream(
                reader, policy, token_map=token_map, detector_names=detector_names
            )
            _write_csv_rows(row_iter, args.output, args.dry_run)
        elif args.format == "jsonl":
            output_iter, report = redact_jsonl_stream(
                f, policy, token_map=token_map, detector_names=detector_names
            )
            _write_lines(output_iter, args.output, args.dry_run)
        elif args.format == "json":
            document = json.load(f)
            redacted, report = redact_json_document(
                document, policy, token_map=token_map, detector_names=detector_names
            )
            if not args.dry_run:
                text = json.dumps(redacted, indent=2)
                if args.output:
                    args.output.write_text(text, encoding="utf-8")
                else:
                    print(text)
        else:  # pragma: no cover - guarded by argparse choices
            raise ValueError(f"Unknown format: {args.format}")

    _print_report(report, dry_run=args.dry_run)

    if token_map is not None and args.mapping_file is not None and not args.dry_run:
        token_map.save(args.mapping_file)

    return 0


def _write_lines(lines: object, output: Path | None, dry_run: bool) -> None:
    if dry_run:
        for _ in lines:  # type: ignore[attr-defined]
            pass
        return
    if output is not None:
        with output.open("w", encoding="utf-8", newline="") as out:
            for line in lines:  # type: ignore[attr-defined]
                out.write(line if line.endswith("\n") else line + "\n")
    else:
        for line in lines:  # type: ignore[attr-defined]
            sys.stdout.write(line if line.endswith("\n") else line + "\n")


def _write_csv_rows(rows: object, output: Path | None, dry_run: bool) -> None:
    if dry_run:
        for _ in rows:  # type: ignore[attr-defined]
            pass
        return
    if output is not None:
        with output.open("w", encoding="utf-8", newline="") as out:
            writer = csv.writer(out)
            for row in rows:  # type: ignore[attr-defined]
                writer.writerow(row)
    else:
        writer = csv.writer(sys.stdout, lineterminator="\n")
        for row in rows:  # type: ignore[attr-defined]
            writer.writerow(row)


def _run_resolve(args: argparse.Namespace) -> int:
    token_map = TokenMap.load(args.mapping_file)
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
