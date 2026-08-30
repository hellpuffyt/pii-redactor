"""Checksum validators used to cut down false positives.

Pattern matching alone produces far too many false positives (an order
number looks like a card number, a version string looks like an IP). These
validators apply the real checksum algorithms so a candidate match is only
accepted when it is mathematically plausible.
"""

from __future__ import annotations

import re

_IBAN_COUNTRY_LENGTH = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16,
    "BG": 22, "BH": 22, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28,
    "CZ": 24, "DE": 22, "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24,
    "FI": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18,
    "GR": 27, "GT": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23,
    "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32,
    "LI": 21, "LT": 20, "LU": 20, "LV": 21, "LY": 25, "MC": 27, "MD": 24,
    "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15,
    "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22,
    "SA": 24, "SC": 31, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "ST": 25,
    "SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24,
    "XK": 20,
}


def luhn_is_valid(digits: str) -> bool:
    """Validate a numeric string against the Luhn checksum (mod 10).

    Only digits should be passed in; separators must be stripped by the
    caller. Returns False for anything shorter than 8 digits since that is
    too short to plausibly be a payment card number.
    """
    if not digits.isdigit() or len(digits) < 8:
        return False
    total = 0
    reverse_digits = digits[::-1]
    for index, char in enumerate(reverse_digits):
        n = int(char)
        if index % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def iban_is_valid(candidate: str) -> bool:
    """Validate an IBAN using the ISO 7064 mod-97-10 checksum.

    Also enforces the known per-country IBAN length where the country code
    is recognised, which further cuts false positives from arbitrary
    alphanumeric strings that happen to pass the checksum by chance.
    """
    cleaned = re.sub(r"[\s-]", "", candidate).upper()
    if not re.fullmatch(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}", cleaned):
        return False

    country = cleaned[:2]
    expected_length = _IBAN_COUNTRY_LENGTH.get(country)
    if expected_length is not None and len(cleaned) != expected_length:
        return False

    rearranged = cleaned[4:] + cleaned[:4]
    numeric = "".join(str(int(ch, 36)) for ch in rearranged)
    try:
        return int(numeric) % 97 == 1
    except ValueError:
        return False
