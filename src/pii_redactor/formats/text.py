"""Plain-text and line-structured log redaction, processed one line at a
time so files larger than memory can be handled."""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from pii_redactor.engine import RedactionReport, redact_text
from pii_redactor.mapping import TokenMap
from pii_redactor.policy import Policy


def redact_lines(
    lines: Iterable[str],
    policy: Policy,
    *,
    token_map: TokenMap | None = None,
    detector_names: list[str] | None = None,
) -> Iterator[tuple[str, RedactionReport]]:
    """Yield (redacted_line, report) pairs, one per input line.

    Each line is processed independently, which keeps memory bounded to a
    single line regardless of overall file size.
    """
    for line in lines:
        redacted, report = redact_text(
            line, policy, token_map=token_map, detector_names=detector_names
        )
        yield redacted, report


def redact_file_stream(
    lines: Iterable[str],
    policy: Policy,
    *,
    token_map: TokenMap | None = None,
    detector_names: list[str] | None = None,
) -> tuple[Iterator[str], RedactionReport]:
    """Return a lazily-evaluated iterator of redacted lines plus a report
    object that fills in as the iterator is consumed."""
    total_report = RedactionReport()

    def _generate() -> Iterator[str]:
        for redacted, report in redact_lines(
            lines, policy, token_map=token_map, detector_names=detector_names
        ):
            total_report.merge(report)
            yield redacted

    return _generate(), total_report
