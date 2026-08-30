from pii_redactor.validators import iban_is_valid, luhn_is_valid


class TestLuhn:
    def test_valid_visa_test_card(self) -> None:
        assert luhn_is_valid("4111111111111111") is True

    def test_valid_mastercard_test_card(self) -> None:
        assert luhn_is_valid("5555555555554444") is True

    def test_valid_amex_test_card(self) -> None:
        assert luhn_is_valid("378282246310005") is True

    def test_invalid_off_by_one_digit(self) -> None:
        # Flip the last digit of a known-valid number -> checksum fails.
        assert luhn_is_valid("4111111111111112") is False

    def test_invalid_random_digits(self) -> None:
        assert luhn_is_valid("1234567890123456") is False

    def test_rejects_non_digit_characters(self) -> None:
        assert luhn_is_valid("4111-1111-1111-1111") is False

    def test_rejects_too_short(self) -> None:
        assert luhn_is_valid("1234567") is False

    def test_rejects_empty_string(self) -> None:
        assert luhn_is_valid("") is False


class TestIban:
    def test_valid_german_iban(self) -> None:
        assert iban_is_valid("DE89370400440532013000") is True

    def test_valid_gb_iban(self) -> None:
        assert iban_is_valid("GB29NWBK60161331926819") is True

    def test_valid_fr_iban(self) -> None:
        assert iban_is_valid("FR1420041010050500013M02606") is True

    def test_valid_iban_with_spaces(self) -> None:
        assert iban_is_valid("DE89 3704 0044 0532 0130 00") is True

    def test_invalid_checksum(self) -> None:
        # Same digits as the valid DE example above, transposed -> fails checksum.
        assert iban_is_valid("DE89370400440532013001") is False

    def test_invalid_wrong_length_for_country(self) -> None:
        assert iban_is_valid("DE8937040044053201300") is False

    def test_invalid_format_no_country_code(self) -> None:
        assert iban_is_valid("1234567890123456") is False

    def test_invalid_random_alphanumeric(self) -> None:
        assert iban_is_valid("ZZ00ABCDEFGHIJKLMNOPQR") is False
