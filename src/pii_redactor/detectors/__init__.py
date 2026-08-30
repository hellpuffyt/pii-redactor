"""PII detectors.

Each detector is a pure function that takes a string and returns a list of
`Match` objects describing where a candidate was found. Detectors never log
or print the matched value themselves -- that responsibility (and the
"never print a detected value" rule) is enforced at the reporting layer.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Match:
    """A single detected span within a piece of text.

    `value` is kept in memory only long enough to apply the configured
    policy action (hash / tokenise / partial / redact); it must never be
    written to a log or a dry-run report.
    """

    detector: str
    start: int
    end: int
    value: str
    confidence: str  # "high" | "medium" | "low"

    def __len__(self) -> int:
        return self.end - self.start


from pii_redactor.detectors.patterns import (  # noqa: E402
    DETECTORS,
    detect_address,
    detect_api_key,
    detect_credit_card,
    detect_date_of_birth,
    detect_email,
    detect_iban,
    detect_ip_address,
    detect_national_id,
    detect_person_name,
    detect_phone,
)

__all__ = [
    "Match",
    "DETECTORS",
    "detect_address",
    "detect_api_key",
    "detect_credit_card",
    "detect_date_of_birth",
    "detect_email",
    "detect_iban",
    "detect_ip_address",
    "detect_national_id",
    "detect_person_name",
    "detect_phone",
]
