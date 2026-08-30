"""Header-aware, per-column CSV redaction.

Rows are streamed through `csv.reader`/`csv.writer` one at a time, so the
whole file never needs to be resident in memory. A column with an explicit
policy in `policy.csv_columns` has its *entire cell value* replaced under
that action whenever a detector would flag it. Columns without an explicit
policy fall back to normal span-level detection (a single cell such as a
free-text "notes" column might contain several distinct PII spans).
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from pii_redactor.engine import RedactionReport
from pii_redactor.formats.cell import redact_cell
from pii_redactor.mapping import TokenMap
from pii_redactor.policy import Policy


def redact_csv_rows(
    reader: Iterable[list[str]],
    policy: Policy,
    *,
    token_map: TokenMap | None = None,
    detector_names: list[str] | None = None,
) -> Iterator[tuple[list[str], RedactionReport]]:
    header: list[str] | None = None
    for row in reader:
        if header is None:
            header = row
            yield row, RedactionReport()
            continue

        new_row: list[str] = []
        row_report = RedactionReport()
        for index, cell in enumerate(row):
            column_name = header[index] if index < len(header) else f"column_{index}"
            forced_action = policy.action_for_csv_column(column_name)
            redacted_cell, cell_report = redact_cell(
                cell,
                policy,
                forced_action=forced_action,
                forced_label=column_name,
                token_map=token_map,
                detector_names=detector_names,
            )
            new_row.append(redacted_cell)
            row_report.merge(cell_report)
        yield new_row, row_report


def redact_csv_stream(
    reader: Iterable[list[str]],
    policy: Policy,
    *,
    token_map: TokenMap | None = None,
    detector_names: list[str] | None = None,
) -> tuple[Iterator[list[str]], RedactionReport]:
    total_report = RedactionReport()

    def _generate() -> Iterator[list[str]]:
        for row, report in redact_csv_rows(
            reader, policy, token_map=token_map, detector_names=detector_names
        ):
            total_report.merge(report)
            yield row

    return _generate(), total_report
