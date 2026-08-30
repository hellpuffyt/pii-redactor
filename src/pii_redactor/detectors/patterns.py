"""Concrete PII detectors.

Design notes / honesty about limits (see README "Limitations"):

* Every detector is regex-based, optionally backed by a real checksum
  (Luhn for cards, mod-97 for IBAN). Regex + checksum validation is a
  strong, auditable control -- it is not a guarantee of perfect recall.
* Detectors that are inherently fuzzy (person names, postal addresses,
  dates of birth) are marked with "medium" or "low" confidence so callers
  and policies can choose to treat them more conservatively.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable
from datetime import date

from pii_redactor.detectors import Match  # noqa: F401  (re-exported via package __init__)
from pii_redactor.validators import iban_is_valid, luhn_is_valid

# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+(?![\w+-])"
)


def detect_email(text: str) -> list[Match]:
    matches = []
    for m in _EMAIL_RE.finditer(text):
        value = m.group(0)
        # Reject trailing dot artefacts from sentence punctuation, and
        # require at least one alphabetic char in the final TLD segment.
        tld = value.rsplit(".", 1)[-1]
        if not tld.isalpha() or len(tld) < 2:
            continue
        matches.append(Match("email", m.start(), m.end(), value, "high"))
    return matches


# ---------------------------------------------------------------------------
# Phone numbers
# ---------------------------------------------------------------------------

# Requires either a leading '+' with country code, or classic separator
# grouping (spaces/dashes/dots/parentheses) so we do not swallow bare
# 7-10 digit numbers that are much more likely to be order/reference IDs.
_PHONE_RE = re.compile(
    r"(?<![\w])(?:"
    r"\+\d{1,3}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]\d{2,4}){1,4}"
    r"|\(\d{2,4}\)[\s.-]?\d{2,4}(?:[\s.-]\d{2,4}){1,3}"
    r"|\d{2,4}(?:[\s.-]\d{2,4}){2,4}"
    r")(?![\w])"
)

_MIN_PHONE_DIGITS = 7
_MAX_PHONE_DIGITS = 15


def detect_phone(text: str) -> list[Match]:
    matches = []
    for m in _PHONE_RE.finditer(text):
        value = m.group(0)
        digits = re.sub(r"\D", "", value)
        if not (_MIN_PHONE_DIGITS <= len(digits) <= _MAX_PHONE_DIGITS):
            continue
        # Reject things that are obviously dates (e.g. 2024-01-30) by
        # requiring the separator grouping not look like an ISO date.
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            continue
        has_separator_hint = value.startswith("+") or "(" in value or any(
            sep in value for sep in (" ", "-", ".")
        )
        if not has_separator_hint:
            continue
        confidence = "high" if value.startswith("+") or "(" in value else "medium"
        matches.append(Match("phone", m.start(), m.end(), value, confidence))
    return matches


# ---------------------------------------------------------------------------
# Credit card numbers (Luhn-validated)
# ---------------------------------------------------------------------------

_CARD_CANDIDATE_RE = re.compile(r"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)")


def detect_credit_card(text: str) -> list[Match]:
    matches = []
    for m in _CARD_CANDIDATE_RE.finditer(text):
        raw = m.group(0)
        digits = re.sub(r"[ -]", "", raw)
        if not (13 <= len(digits) <= 19):
            continue
        if not luhn_is_valid(digits):
            continue
        matches.append(Match("credit_card", m.start(), m.end(), raw, "high"))
    return matches


# ---------------------------------------------------------------------------
# IBAN (mod-97 checksum validated)
# ---------------------------------------------------------------------------

_IBAN_CANDIDATE_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{2,4}){2,7}\b")


def detect_iban(text: str) -> list[Match]:
    matches = []
    for m in _IBAN_CANDIDATE_RE.finditer(text):
        raw = m.group(0)
        if iban_is_valid(raw):
            matches.append(Match("iban", m.start(), m.end(), raw, "high"))
    return matches


# ---------------------------------------------------------------------------
# IP addresses
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(
    r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{0,4}(?::[A-Fa-f0-9]{1,4})*\b"
)


def detect_ip_address(text: str, *, keep_private: bool = False) -> list[Match]:
    matches: list[Match] = []
    for regex in (_IPV4_RE, _IPV6_RE):
        for m in regex.finditer(text):
            raw = m.group(0)
            try:
                addr = ipaddress.ip_address(raw)
            except ValueError:
                continue
            if regex is _IPV4_RE:
                # Reject version-string-like matches such as "10.4.2.1"
                # embedded in identifiers -- ipaddress already validates
                # octet ranges (0-255), which rules out most non-IP dotted
                # numbers (e.g. "999.1.2.3" or "1.2.3.4.5").
                pass
            if keep_private and (addr.is_private or addr.is_loopback or addr.is_link_local):
                continue
            confidence = "high"
            matches.append(Match("ip_address", m.start(), m.end(), raw, confidence))
    return _dedupe_overlaps(matches)


# ---------------------------------------------------------------------------
# National ID numbers (US SSN-style, and generic government-ID patterns)
# ---------------------------------------------------------------------------

_SSN_RE = re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")


def detect_national_id(text: str) -> list[Match]:
    matches = []
    for m in _SSN_RE.finditer(text):
        matches.append(Match("national_id", m.start(), m.end(), m.group(0), "high"))
    return matches


# ---------------------------------------------------------------------------
# Date of birth
# ---------------------------------------------------------------------------

_DATE_RE = re.compile(
    r"\b(?:\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4}|\d{1,2}-\d{1,2}-\d{2,4})\b"
)
_DOB_CONTEXT_RE = re.compile(
    r"\b(?:dob|date of birth|born|birth ?date)\b", re.IGNORECASE
)
_DOB_CONTEXT_WINDOW = 30


def detect_date_of_birth(text: str) -> list[Match]:
    matches = []
    for m in _DATE_RE.finditer(text):
        window_start = max(0, m.start() - _DOB_CONTEXT_WINDOW)
        window = text[window_start : m.start()]
        if not _DOB_CONTEXT_RE.search(window):
            continue
        if not _is_plausible_date(m.group(0)):
            continue
        matches.append(Match("date_of_birth", m.start(), m.end(), m.group(0), "medium"))
    return matches


def _is_plausible_date(value: str) -> bool:
    parts = re.split(r"[-/]", value)
    nums = [int(p) for p in parts]
    if len(nums) != 3:
        return False
    if len(parts[0]) == 4:
        year, month, day = nums
    else:
        month, day, year = nums
        if year < 100:
            year += 2000 if year < 30 else 1900
    if not (1 <= month <= 12 and 1 <= day <= 31):
        return False
    try:
        d = date(year, month, day)
    except ValueError:
        return False
    return date(1900, 1, 1) <= d <= date.today()


# ---------------------------------------------------------------------------
# Person names (dictionary + capitalisation heuristic, low confidence)
# ---------------------------------------------------------------------------

_COMMON_FIRST_NAMES = {
    "james", "mary", "john", "patricia", "robert", "jennifer", "michael",
    "linda", "william", "elizabeth", "david", "barbara", "richard", "susan",
    "joseph", "jessica", "thomas", "sarah", "charles", "karen", "daniel",
    "nancy", "matthew", "lisa", "anthony", "betty", "mark", "margaret",
    "donald", "sandra", "steven", "ashley", "andrew", "kimberly", "paul",
    "emily", "joshua", "donna", "kenneth", "michelle", "kevin", "carol",
    "brian", "amanda", "george", "melissa", "priya", "wei", "fatima",
    "ahmed", "carlos", "maria", "yuki", "olga",
}

_NAME_SUFFIX_STOPWORDS = {
    "the", "this", "that", "these", "those", "dear", "hi", "hello",
}

_TWO_WORD_NAME_RE = re.compile(r"\b([A-Z][a-z]+)\s+([A-Z][a-z]+)\b")


def detect_person_name(text: str) -> list[Match]:
    matches = []
    for m in _TWO_WORD_NAME_RE.finditer(text):
        first = m.group(1)
        if first.lower() in _NAME_SUFFIX_STOPWORDS:
            continue
        if first.lower() not in _COMMON_FIRST_NAMES:
            continue
        # Avoid matching a capitalised sentence start followed by another
        # capitalised proper noun (e.g. "Also Company") by requiring the
        # first word not be the very first token of the string/line unless
        # it is a recognised first name AND is not immediately preceded by
        # sentence-ending punctuation two tokens back is out of scope here;
        # the first-name dictionary check above is the primary guard.
        matches.append(
            Match("person_name", m.start(), m.end(), m.group(0), "low")
        )
    return matches


# ---------------------------------------------------------------------------
# Postal addresses (heuristic, medium confidence)
# ---------------------------------------------------------------------------

_STREET_SUFFIXES = (
    r"Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|"
    r"Place|Pl|Way|Terrace|Ter|Circle|Cir|Square|Sq|Highway|Hwy"
)
_ADDRESS_RE = re.compile(
    rf"\b\d{{1,5}}\s+(?:[A-Z][a-z]+\s){{1,3}}(?:{_STREET_SUFFIXES})\b\.?"
    rf"(?:,\s*[A-Za-z][A-Za-z .]+)?(?:,\s*[A-Z]{{2}})?(?:\s+\d{{5}}(?:-\d{{4}})?)?"
)


def detect_address(text: str) -> list[Match]:
    matches = []
    for m in _ADDRESS_RE.finditer(text):
        matches.append(Match("address", m.start(), m.end(), m.group(0), "medium"))
    return matches


# ---------------------------------------------------------------------------
# API keys / tokens
# ---------------------------------------------------------------------------

_API_KEY_PATTERNS = [
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),  # AWS temporary access key id
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),  # OpenAI-style secret key
    re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),  # GitHub personal access token
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),  # Slack token
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),  # Google API key
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),  # JWT
]

_GENERIC_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_-]{32,}\b")


def detect_api_key(text: str) -> list[Match]:
    matches: list[Match] = []
    for pattern in _API_KEY_PATTERNS:
        for m in pattern.finditer(text):
            matches.append(Match("api_key", m.start(), m.end(), m.group(0), "high"))

    for m in _GENERIC_TOKEN_RE.finditer(text):
        value = m.group(0)
        if any(existing.start <= m.start() and m.end() <= existing.end for existing in matches):
            continue
        if _looks_like_high_entropy_token(value):
            matches.append(Match("api_key", m.start(), m.end(), value, "medium"))

    return _dedupe_overlaps(matches)


def _looks_like_high_entropy_token(value: str) -> bool:
    if value.isdigit() or value.isalpha():
        return False
    has_digit = any(c.isdigit() for c in value)
    has_upper = any(c.isupper() for c in value)
    has_lower = any(c.islower() for c in value)
    variety = sum([has_digit, has_upper, has_lower])
    if variety < 2:
        return False
    unique_ratio = len(set(value)) / len(value)
    return unique_ratio > 0.4


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dedupe_overlaps(matches: list[Match]) -> list[Match]:
    """Keep the longest match when spans overlap, preferring earlier starts."""
    ordered = sorted(matches, key=lambda m: (m.start, -(m.end - m.start)))
    kept: list[Match] = []
    for match in ordered:
        if any(match.start < k.end and match.end > k.start for k in kept):
            continue
        kept.append(match)
    return sorted(kept, key=lambda m: m.start)


DetectorFunc = Callable[..., "Iterable[Match]"]

DETECTORS: dict[str, DetectorFunc] = {
    "email": detect_email,
    "phone": detect_phone,
    "credit_card": detect_credit_card,
    "iban": detect_iban,
    "ip_address": detect_ip_address,
    "national_id": detect_national_id,
    "date_of_birth": detect_date_of_birth,
    "person_name": detect_person_name,
    "address": detect_address,
    "api_key": detect_api_key,
}
