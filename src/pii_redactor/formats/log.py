"""Line-structured log file redaction.

Logs are treated the same way as plain text: one line at a time, so a
multi-gigabyte log can be streamed through without loading it all into
memory. This module exists as a distinct entry point (rather than reusing
`formats.text` directly everywhere) so future log-specific handling --
e.g. structured-log-aware field extraction -- has a natural home.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from pii_redactor.engine import RedactionReport
from pii_redactor.formats.text import redact_file_stream
from pii_redactor.mapping import TokenMap
from pii_redactor.policy import Policy


def redact_log_stream(
    lines: Iterable[str],
    policy: Policy,
    *,
    token_map: TokenMap | None = None,
    detector_names: list[str] | None = None,
) -> tuple[Iterator[str], RedactionReport]:
    return redact_file_stream(
        lines, policy, token_map=token_map, detector_names=detector_names
    )
