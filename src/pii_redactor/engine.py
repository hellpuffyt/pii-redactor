"""Core redaction engine: run detectors, apply policy actions, produce a
redacted string plus a report that never contains the detected values."""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass, field

from pii_redactor.detectors import DETECTORS, Match
from pii_redactor.mapping import TokenMap
from pii_redactor.policy import Policy

DEFAULT_SALT = "pii-redactor-default-salt"


@dataclass
class RedactionReport:
    """Aggregate counts by detector type and action. Never holds values."""

    counts: dict[str, int] = field(default_factory=dict)
    action_counts: dict[str, dict[str, int]] = field(default_factory=dict)

    def record(self, detector: str, action: str) -> None:
        self.counts[detector] = self.counts.get(detector, 0) + 1
        by_action = self.action_counts.setdefault(detector, {})
        by_action[action] = by_action.get(action, 0) + 1

    def merge(self, other: RedactionReport) -> None:
        for detector, count in other.counts.items():
            self.counts[detector] = self.counts.get(detector, 0) + count
        for detector, actions in other.action_counts.items():
            mine = self.action_counts.setdefault(detector, {})
            for action, count in actions.items():
                mine[action] = mine.get(action, 0) + count

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def run_detectors(
    text: str,
    *,
    detector_names: list[str] | None = None,
    keep_private_ips: bool = False,
) -> list[Match]:
    names = detector_names or list(DETECTORS)
    matches: list[Match] = []
    for name in names:
        func = DETECTORS.get(name)
        if func is None:
            continue
        if name == "ip_address":
            # Always collect *all* IP matches (public and private) here so
            # that a private-range address still wins the overlap-dedup
            # step against other detectors (e.g. a dotted-quad phone
            # candidate). Private addresses are dropped afterwards, once
            # they've already done their job of blocking other detectors
            # from claiming the same span.
            matches.extend(func(text, keep_private=False))
        else:
            matches.extend(func(text))
    deduped = _dedupe_overlaps(matches)
    if keep_private_ips:
        deduped = [
            m
            for m in deduped
            if not (m.detector == "ip_address" and _is_private_ip(m.value))
        ]
    return deduped


def _is_private_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def _dedupe_overlaps(matches: list[Match]) -> list[Match]:
    confidence_rank = {"high": 2, "medium": 1, "low": 0}
    ordered = sorted(
        matches,
        key=lambda m: (m.start, -confidence_rank.get(m.confidence, 0), -(m.end - m.start)),
    )
    kept: list[Match] = []
    for match in ordered:
        if any(match.start < k.end and match.end > k.start for k in kept):
            continue
        kept.append(match)
    return sorted(kept, key=lambda m: m.start)


def partial_mask(detector: str, value: str) -> str:
    if detector == "email" and "@" in value:
        local, _, domain = value.partition("@")
        visible = local[0] if local else ""
        return f"{visible}{'*' * max(len(local) - 1, 1)}@{domain}"
    if detector in {"credit_card"}:
        digits_only = "".join(ch for ch in value if ch.isdigit())
        return "*" * (len(digits_only) - 4) + digits_only[-4:]
    if detector == "ip_address" and "." in value and ":" not in value:
        octets = value.split(".")
        if len(octets) == 4:
            return ".".join([*octets[:2], "xxx", "xxx"])
    if len(value) <= 4:
        return "*" * len(value)
    return value[0] + "*" * (len(value) - 2) + value[-1]


def hash_value(value: str, salt: str) -> str:
    digest = hashlib.sha256((salt + value).encode("utf-8")).hexdigest()
    return digest[:12]


def apply_policy(
    text: str,
    matches: list[Match],
    policy: Policy,
    *,
    token_map: TokenMap | None = None,
) -> tuple[str, RedactionReport]:
    """Apply the policy's per-detector action to each match and rebuild the
    string. Returns the redacted text and a value-free report."""
    salt = policy.salt or DEFAULT_SALT
    report = RedactionReport()
    pieces: list[str] = []
    cursor = 0
    for match in sorted(matches, key=lambda m: m.start):
        action = policy.action_for(match.detector)
        pieces.append(text[cursor : match.start])
        if action == "keep":
            pieces.append(text[match.start : match.end])
        elif action == "redact":
            pieces.append(f"[{match.detector.upper()}]")
        elif action == "hash":
            pieces.append(f"{match.detector.upper()}_HASH_{hash_value(match.value, salt)}")
        elif action == "tokenise":
            if token_map is None:
                raise ValueError("tokenise action requires a token_map")
            pieces.append(token_map.tokenise(match.detector, match.value))
        elif action == "partial":
            pieces.append(partial_mask(match.detector, match.value))
        else:  # pragma: no cover - guarded by Policy validation
            raise ValueError(f"Unknown action: {action}")
        report.record(match.detector, action)
        cursor = match.end
    pieces.append(text[cursor:])
    return "".join(pieces), report


def redact_text(
    text: str,
    policy: Policy,
    *,
    token_map: TokenMap | None = None,
    detector_names: list[str] | None = None,
) -> tuple[str, RedactionReport]:
    matches = run_detectors(
        text, detector_names=detector_names, keep_private_ips=policy.keep_private_ips
    )
    return apply_policy(text, matches, policy, token_map=token_map)
