"""JSON and JSONL redaction with per-key dotted-path policies.

JSONL is processed one line (one JSON document) at a time, which keeps
memory bounded for large files. A single large JSON document is loaded
whole since JSON has no natural line-based streaming boundary; very large
single JSON documents are outside this tool's streaming guarantee (see
README "Limitations").
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from typing import Any

from pii_redactor.engine import RedactionReport
from pii_redactor.formats.cell import redact_cell
from pii_redactor.mapping import TokenMap
from pii_redactor.policy import Policy


class JsonlDecodeError(ValueError):
    """A JSONL line failed to parse. Carries the 1-based line number and the
    parser's reason only -- never the line content, which may be PII."""

    def __init__(self, line_number: int, reason: str) -> None:
        super().__init__(f"invalid JSON on line {line_number}: {reason}")
        self.line_number = line_number
        self.reason = reason


def _walk_and_redact(
    node: Any,
    path: str,
    policy: Policy,
    token_map: TokenMap | None,
    detector_names: list[str] | None,
    report: RedactionReport,
) -> Any:
    if isinstance(node, dict):
        return {
            key: _walk_and_redact(
                value,
                f"{path}.{key}" if path else str(key),
                policy,
                token_map,
                detector_names,
                report,
            )
            for key, value in node.items()
        }
    if isinstance(node, list):
        return [
            _walk_and_redact(item, path, policy, token_map, detector_names, report)
            for item in node
        ]
    if isinstance(node, (int, float)) and not isinstance(node, bool):
        # Numbers can carry PII too (a card number or SSN stored as an
        # integer). Scan their decimal form; an explicit path policy applies
        # regardless. A number is only replaced (by a string) when something
        # was actually redacted, so ordinary numeric fields keep their type.
        forced_action = policy.action_for_json_path(path)
        label = path.rsplit(".", 1)[-1] if path else "value"
        as_text = str(node)
        redacted_num, num_report = redact_cell(
            as_text,
            policy,
            forced_action=forced_action,
            forced_label=label,
            token_map=token_map,
            detector_names=detector_names,
        )
        report.merge(num_report)
        return node if redacted_num == as_text else redacted_num
    if isinstance(node, str):
        forced_action = policy.action_for_json_path(path)
        label = path.rsplit(".", 1)[-1] if path else "value"
        redacted, cell_report = redact_cell(
            node,
            policy,
            forced_action=forced_action,
            forced_label=label,
            token_map=token_map,
            detector_names=detector_names,
        )
        report.merge(cell_report)
        return redacted
    return node


def redact_json_document(
    document: Any,
    policy: Policy,
    *,
    token_map: TokenMap | None = None,
    detector_names: list[str] | None = None,
) -> tuple[Any, RedactionReport]:
    report = RedactionReport()
    redacted = _walk_and_redact(document, "", policy, token_map, detector_names, report)
    return redacted, report


def redact_jsonl_stream(
    lines: Iterable[str],
    policy: Policy,
    *,
    token_map: TokenMap | None = None,
    detector_names: list[str] | None = None,
) -> tuple[Iterator[str], RedactionReport]:
    total_report = RedactionReport()

    def _generate() -> Iterator[str]:
        for line_number, line in enumerate(lines, start=1):
            stripped = line.rstrip("\n")
            if not stripped.strip():
                yield line if line.endswith("\n") else line + "\n"
                continue
            try:
                document = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise JsonlDecodeError(line_number, exc.msg) from None
            redacted, report = redact_json_document(
                document, policy, token_map=token_map, detector_names=detector_names
            )
            total_report.merge(report)
            yield json.dumps(redacted) + "\n"

    return _generate(), total_report
