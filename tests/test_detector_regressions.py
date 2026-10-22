"""Regression tests for detector defects found during the production-readiness audit."""

from __future__ import annotations

from pii_redactor.detectors.patterns import (
    detect_address,
    detect_api_key,
    detect_email,
    detect_iban,
    detect_phone,
)


def test_email_local_part_with_apostrophe_is_matched_whole() -> None:
    # Before: only "brien@example.com" matched, leaving "o'" behind.
    matches = detect_email("user=o'brien@example.com logged in")
    assert [m.value for m in matches] == ["o'brien@example.com"]


def test_single_quoted_email_still_matches() -> None:
    matches = detect_email("WHERE email = 'jane@example.com'")
    assert [m.value for m in matches] == ["jane@example.com"]


def test_e164_phone_without_separators_is_detected() -> None:
    # The phone regex's own comment promised "leading '+' with country code"
    # *or* separators; unseparated E.164 was missed.
    matches = detect_phone("Dial +14155550188 now")
    assert [m.value for m in matches] == ["+14155550188"]


def test_us_and_eu_style_calendar_dates_are_not_phones() -> None:
    assert detect_phone("Invoice dated 01-30-2024 was paid.") == []
    assert detect_phone("Invoice dated 30.01.2024 was paid.") == []


def test_non_date_dashed_number_is_still_a_phone() -> None:
    assert [m.value for m in detect_phone("Mobile: 415-555-0177")] == ["415-555-0177"]


def test_lowercase_iban_is_detected() -> None:
    matches = detect_iban("iban de89370400440532013000 lowercase")
    assert [m.value for m in matches] == ["de89370400440532013000"]


def test_spaced_iban_followed_by_uppercase_word_is_detected() -> None:
    # Before: the greedy candidate swallowed "REF" and failed the checksum.
    matches = detect_iban("IBAN DE89 3704 0044 0532 0130 00 REF 12")
    assert [m.value for m in matches] == ["DE89 3704 0044 0532 0130 00"]


def test_iban_with_bad_checksum_still_rejected_after_trimming() -> None:
    assert detect_iban("IBAN DE89 3704 0044 0532 0130 01 REF 12") == []


def test_address_does_not_swallow_sentence_period_after_city() -> None:
    matches = detect_address("Located at 500 Market Ave, Chicago.")
    assert [m.value for m in matches] == ["500 Market Ave, Chicago"]


def test_uuid_is_not_flagged_as_api_key() -> None:
    assert detect_api_key("request_id=123e4567-e89b-12d3-a456-426614174000") == []


def test_keep_private_ips_only_skips_internal_networks() -> None:
    # Before: ipaddress.is_private was used, which also covers documentation
    # (203.0.113.0/24), benchmarking (198.18.0.0/15) and reserved ranges, so
    # those were silently kept despite the README promising RFC 1918 only.
    from pii_redactor.engine import run_detectors

    text = "a 10.1.2.3 b 172.16.0.9 c 192.168.1.1 d 127.0.0.1 e 169.254.1.1 f fd00::1 " \
        "g 203.0.113.42 h 198.18.0.1 i 2001:db8::1 j 8.8.8.8"
    kept_out = {m.value for m in run_detectors(text, keep_private_ips=True)}
    assert kept_out == {"203.0.113.42", "198.18.0.1", "2001:db8::1", "8.8.8.8"}


def test_overlap_dedupe_is_not_quadratic() -> None:
    # Before: ~21 s for this 200 kB single line (O(n^2) overlap scan).
    import time

    from pii_redactor.engine import run_detectors

    started = time.perf_counter()
    run_detectors("1." * 100_000)
    run_detectors(" ".join(f"u{i}@example.com" for i in range(8000)))
    assert time.perf_counter() - started < 5.0
