"""Shared "whole cell / whole field" redaction logic used by the CSV and
JSON/JSONL format handlers.

When a column (CSV) or dotted path (JSON) has an explicit policy action
configured, that action applies to the *entire* value rather than just the
spans a detector would flag -- this lets a user say "the `ssn` column is
always sensitive" without depending on the SSN regex matching every stored
format. Fields without an explicit policy fall back to ordinary span-level
detection, same as free text.
"""

from __future__ import annotations

from pii_redactor.engine import (
    RedactionReport,
    apply_policy,
    hash_value,
    partial_mask,
    run_detectors,
)
from pii_redactor.mapping import TokenMap
from pii_redactor.policy import Action, Policy


def redact_cell(
    value: str,
    policy: Policy,
    *,
    forced_action: Action | None,
    forced_label: str,
    token_map: TokenMap | None = None,
    detector_names: list[str] | None = None,
) -> tuple[str, RedactionReport]:
    if not value:
        return value, RedactionReport()

    if forced_action is not None:
        report = RedactionReport()
        if forced_action == "keep":
            return value, report
        salt = policy.salt or "pii-redactor-default-salt"
        label = forced_label.upper()
        if forced_action == "redact":
            report.record(forced_label, forced_action)
            return f"[{label}]", report
        if forced_action == "hash":
            report.record(forced_label, forced_action)
            return f"{label}_HASH_{hash_value(value, salt)}", report
        if forced_action == "tokenise":
            if token_map is None:
                raise ValueError("tokenise action requires a token_map")
            report.record(forced_label, forced_action)
            return token_map.tokenise(forced_label.lower(), value), report
        if forced_action == "partial":
            report.record(forced_label, forced_action)
            return partial_mask(forced_label.lower(), value), report
        raise ValueError(f"Unknown action: {forced_action}")  # pragma: no cover

    matches = run_detectors(
        value, detector_names=detector_names, keep_private_ips=policy.keep_private_ips
    )
    if not matches:
        return value, RedactionReport()
    return apply_policy(value, matches, policy, token_map=token_map)
