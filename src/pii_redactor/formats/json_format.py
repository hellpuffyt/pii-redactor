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
        for line in lines:
            stripped = line.rstrip("\n")
            if not stripped.strip():
                yield line if line.endswith("\n") else line + "\n"
                continue
            document = json.loads(stripped)
            redacted, report = redact_json_document(
                document, policy, token_map=token_map, detector_names=detector_names
            )
            total_report.merge(report)
            yield json.dumps(redacted) + "\n"

    return _generate(), total_report
