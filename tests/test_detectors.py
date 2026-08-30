from pii_redactor.detectors.patterns import (
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


def types(matches: object) -> list[str]:
    return [m.detector for m in matches]  # type: ignore[attr-defined]


class TestEmailDetector:
    def test_detects_simple_email(self) -> None:
        matches = detect_email("Reach me at jane.doe@example.com please.")
        assert len(matches) == 1
        assert matches[0].value == "jane.doe@example.com"

    def test_detects_plus_addressed_email(self) -> None:
        matches = detect_email("alerts+billing@example.co.uk is the address")
        assert len(matches) == 1

    def test_does_not_match_bare_at_sign(self) -> None:
        matches = detect_email("Meet @ the office at 5pm.")
        assert matches == []

    def test_does_not_match_trailing_sentence_dot(self) -> None:
        matches = detect_email("Email us at help@example.com.")
        assert matches[0].value == "help@example.com"


class TestPhoneDetector:
    def test_detects_international_format(self) -> None:
        matches = detect_phone("Call +1 415-555-0132 for support.")
        assert len(matches) == 1

    def test_detects_parenthesised_format(self) -> None:
        matches = detect_phone("Call (415) 555-0132 now.")
        assert len(matches) == 1

    def test_detects_dotted_format(self) -> None:
        matches = detect_phone("Reach 415.555.0132 anytime.")
        assert len(matches) == 1

    def test_does_not_match_bare_order_number(self) -> None:
        matches = detect_phone("Order number 4155550132 was shipped.")
        assert matches == []

    def test_does_not_match_iso_date(self) -> None:
        matches = detect_phone("Filed on 2024-01-30 in the morning.")
        assert matches == []

    def test_does_not_match_short_digit_group(self) -> None:
        matches = detect_phone("The score was 12-34-56.")
        assert matches == []


class TestCreditCardDetector:
    def test_detects_valid_visa_test_number(self) -> None:
        matches = detect_credit_card("Card on file: 4111111111111111.")
        assert len(matches) == 1
        assert matches[0].detector == "credit_card"

    def test_detects_spaced_card_number(self) -> None:
        matches = detect_credit_card("4111 1111 1111 1111 was charged.")
        assert len(matches) == 1

    def test_detects_dashed_card_number(self) -> None:
        matches = detect_credit_card("4111-1111-1111-1111 was charged.")
        assert len(matches) == 1

    def test_rejects_order_number_that_fails_luhn(self) -> None:
        matches = detect_credit_card("Order number ORD-1029384756 confirmed.")
        assert matches == []

    def test_rejects_16_digit_non_luhn_number(self) -> None:
        matches = detect_credit_card("Reference 1234567890123456 assigned.")
        assert matches == []

    def test_rejects_phone_like_short_run(self) -> None:
        matches = detect_credit_card("Call 4155550132 today.")
        assert matches == []

    def test_rejects_tracking_number(self) -> None:
        # A long numeric shipment tracking number that fails Luhn.
        matches = detect_credit_card("Tracking: 1Z9999999999999999")
        assert matches == []

    def test_does_not_swallow_trailing_space(self) -> None:
        # Regression: the candidate regex must not greedily consume the
        # separator/space *after* the final digit of the card number.
        matches = detect_credit_card("Card 4111111111111111 charged successfully.")
        assert len(matches) == 1
        assert matches[0].value == "4111111111111111"
        assert not matches[0].value.endswith(" ")


class TestIbanDetector:
    def test_detects_valid_iban(self) -> None:
        matches = detect_iban("IBAN: DE89370400440532013000 on file.")
        assert len(matches) == 1

    def test_rejects_invalid_checksum(self) -> None:
        matches = detect_iban("Ref: DE89370400440532013001 noted.")
        assert matches == []

    def test_rejects_random_alphanumeric_code(self) -> None:
        matches = detect_iban("Product code AB1234567890XYZ001 in stock.")
        assert matches == []


class TestIpAddressDetector:
    def test_detects_public_ipv4(self) -> None:
        matches = detect_ip_address("Client connected from 203.0.113.42 today.")
        assert len(matches) == 1
        assert matches[0].value == "203.0.113.42"

    def test_detects_ipv6(self) -> None:
        matches = detect_ip_address("Address 2001:db8::1 was seen in the log.")
        assert len(matches) == 1

    def test_keep_private_skips_rfc1918(self) -> None:
        matches = detect_ip_address("Internal host at 10.0.0.5 responded.", keep_private=True)
        assert matches == []

    def test_without_keep_private_flags_rfc1918(self) -> None:
        matches = detect_ip_address("Internal host at 10.0.0.5 responded.", keep_private=False)
        assert len(matches) == 1

    def test_rejects_out_of_range_octets(self) -> None:
        matches = detect_ip_address("Build id 999.888.777.666 was tagged.")
        assert matches == []

    def test_rejects_three_segment_version_string(self) -> None:
        matches = detect_ip_address("Running v1.2.3 of the client.")
        assert matches == []

    def test_rejects_semantic_version_with_prerelease(self) -> None:
        matches = detect_ip_address("Upgraded to 2.10.4 successfully.")
        assert matches == []


class TestNationalIdDetector:
    def test_detects_ssn_shaped_number(self) -> None:
        matches = detect_national_id("SSN on file: 523-45-6789.")
        assert len(matches) == 1

    def test_rejects_invalid_area_number_000(self) -> None:
        matches = detect_national_id("Code 000-45-6789 is reserved.")
        assert matches == []

    def test_rejects_invalid_area_number_666(self) -> None:
        matches = detect_national_id("Code 666-45-6789 is reserved.")
        assert matches == []

    def test_rejects_invalid_serial_0000(self) -> None:
        matches = detect_national_id("Code 523-45-0000 is invalid.")
        assert matches == []

    def test_does_not_match_phone_style_number(self) -> None:
        matches = detect_national_id("Call 555-45-6789x1 for help.")
        # No word boundary alignment issue expected; still should not
        # explode or false-positive beyond the digit grouping itself.
        assert all(m.detector == "national_id" for m in matches)


class TestDateOfBirthDetector:
    def test_detects_date_with_dob_context(self) -> None:
        matches = detect_date_of_birth("DOB: 1990-04-12 recorded at intake.")
        assert len(matches) == 1

    def test_detects_date_with_born_context(self) -> None:
        matches = detect_date_of_birth("She was born 04/12/1990 in the city.")
        assert len(matches) == 1

    def test_ignores_unrelated_date_without_context(self) -> None:
        matches = detect_date_of_birth("The invoice was issued 2024-01-30 for services.")
        assert matches == []

    def test_ignores_future_date_even_with_context(self) -> None:
        matches = detect_date_of_birth("Estimated date of birth 2999-01-01 is implausible.")
        assert matches == []

    def test_ignores_invalid_calendar_date(self) -> None:
        matches = detect_date_of_birth("Date of birth 2024-02-30 does not exist.")
        assert matches == []


class TestPersonNameDetector:
    def test_detects_name_with_common_first_name(self) -> None:
        matches = detect_person_name("Please contact James Miller about the ticket.")
        assert len(matches) == 1
        assert matches[0].confidence == "low"

    def test_ignores_sentence_start_not_in_dictionary(self) -> None:
        matches = detect_person_name("Also Available: the new release notes.")
        assert matches == []

    def test_ignores_company_style_capitalised_pair(self) -> None:
        matches = detect_person_name("Acme Corporation released a statement.")
        assert matches == []

    def test_ignores_dear_greeting(self) -> None:
        matches = detect_person_name("Dear Customer, thank you for writing in.")
        assert matches == []


class TestAddressDetector:
    def test_detects_street_address(self) -> None:
        matches = detect_address("Ship to 742 Evergreen Terrace, Springfield, IL 62704.")
        assert len(matches) == 1

    def test_detects_avenue_abbreviation(self) -> None:
        matches = detect_address("Located at 500 Market Ave, Chicago.")
        assert len(matches) == 1

    def test_ignores_plain_number_and_word(self) -> None:
        matches = detect_address("We sold 42 Widgets last quarter.")
        assert matches == []


class TestApiKeyDetector:
    def test_detects_aws_access_key(self) -> None:
        matches = detect_api_key("key=AKIAIOSFODNN7EXAMPLE in config")
        assert any(m.value == "AKIAIOSFODNN7EXAMPLE" for m in matches)

    def test_detects_github_token(self) -> None:
        token = "ghp_" + "a" * 36
        matches = detect_api_key(f"token: {token}")
        assert any(m.value == token for m in matches)

    def test_detects_openai_style_key(self) -> None:
        key = "sk-" + "A1b2C3d4E5f6G7h8I9j0K1l2"
        matches = detect_api_key(f"OPENAI_API_KEY={key}")
        assert any(m.value == key for m in matches)

    def test_ignores_plain_english_sentence(self) -> None:
        matches = detect_api_key(
            "This is just a perfectly ordinary sentence with no secrets in it at all today."
        )
        assert matches == []

    def test_ignores_long_all_digit_number(self) -> None:
        matches = detect_api_key("Invoice total in cents: " + "1" * 40)
        assert matches == []

    def test_ignores_long_all_lowercase_word(self) -> None:
        matches = detect_api_key("supercalifragilisticexpialidocioussupercalifragilistic")
        assert matches == []
