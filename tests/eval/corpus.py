"""Labelled synthetic evaluation corpus for the built-in detectors.

Every value here is synthetic: ``example.com``/``example.org``/``example.net``
mail domains, 555-01xx style phone numbers, published payment-card *test*
numbers, published IBAN *examples*, RFC 5737 / RFC 3849 documentation IP
ranges, invented SSN-shaped numbers and invented names/addresses. Token-shaped
API-key fixtures are assembled at import time so no credential-shaped literal
is stored in the source tree.

Each case is ``(text, [(entity_type, value), ...])``. The gold list is the
complete set of PII spans a perfect detector would return for that text;
``[]`` marks a hard negative (text that must not be flagged).
"""

from __future__ import annotations

# Token-shaped fixtures, assembled at runtime (never real credentials).
_AWS = "AK" + "IA" + "Q3EXAMPLE7FAKE01"  # 4 + 16 chars, documentation-style
_AWS_TMP = "AS" + "IA" + "Z9EXAMPLE7FAKE02"
_GH = "gh" + "p_" + "Fake0Token1For2Tests3Only4abcdefghij"
_GH_FG = "github" + "_pat_" + "11FAKEFIXTURE0_abcdefghijklmnopqr"
_SK = "s" + "k-" + "Fake1Key2For3Unit4Tests5Only6"
_SLACK = "xo" + "xb-" + "0000000000-fakefixture"
_GOOG = "AI" + "za" + "SyFakeFixture0123456789abcdefghijk"
_JWT = ".".join(
    ["ey" + "JhbGciOiJIUzI1NiJ9", "eyJzdWIiOiJmYWtlLXVzZXIifQ", "ZmFrZS1zaWduYXR1cmUtdmFsdWU"]
)
_GENERIC = "Zx9" + "Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0LmNbVc"

Case = tuple[str, list[tuple[str, str]]]

CASES: list[Case] = [
    # ------------------------------------------------------------------ email
    ("Reach me at jane.doe@example.com please.", [("email", "jane.doe@example.com")]),
    ("cc: ops+alerts@example.org, billing@example.net", [
        ("email", "ops+alerts@example.org"), ("email", "billing@example.net")]),
    ("Contact <first_last@sub.example.co.uk> for access.", [
        ("email", "first_last@sub.example.co.uk")]),
    ("user=o'brien@example.com logged in", [("email", "o'brien@example.com")]),
    ("EMAIL: UPPER.CASE@EXAMPLE.COM", [("email", "UPPER.CASE@EXAMPLE.COM")]),
    ("mailto:a1@example.io?subject=hi", [("email", "a1@example.io")]),
    ("Write to x@example.com.", [("email", "x@example.com")]),
    ("name (at) example (dot) com is obfuscated", []),
    ("Tag @channel in chat; ping @here too.", []),
    ("Image asset logo@2x.png was missing.", []),
    # ------------------------------------------------------------------ phone
    ("Call +1 415-555-0132 for support.", [("phone", "+1 415-555-0132")]),
    ("Office (415) 555-0199 ext 4", [("phone", "(415) 555-0199")]),
    ("Reach 415.555.0143 anytime.", [("phone", "415.555.0143")]),
    ("UK line +44 20 7946 0958 today", [("phone", "+44 20 7946 0958")]),
    ("Mobile: 415-555-0177", [("phone", "415-555-0177")]),
    ("Call +33 1 99 00 12 34 in Paris", [("phone", "+33 1 99 00 12 34")]),
    ("Dial +14155550188 now", [("phone", "+14155550188")]),
    ("Fax 4155550166 (no separators)", [("phone", "4155550166")]),
    ("Order number 4155550132 was shipped.", []),
    ("Filed on 2024-01-30 in the morning.", []),
    ("Invoice dated 01-30-2024 was paid.", []),
    ("Score was 12-34-56 at halftime.", []),
    ("Price 1 299.00 EUR incl. VAT", []),
    # ------------------------------------------------------------ credit_card
    ("Card on file: 4111111111111111.", [("credit_card", "4111111111111111")]),
    ("MC 5555 5555 5555 4444 expires 12/30", [("credit_card", "5555 5555 5555 4444")]),
    ("Amex 3782-822463-10005 charged", [("credit_card", "3782-822463-10005")]),
    ("Discover 6011111111111117 refunded", [("credit_card", "6011111111111117")]),
    ("Visa 4012 8888 8888 1881 declined", [("credit_card", "4012 8888 8888 1881")]),
    ("JCB 3530111333300000 ok", [("credit_card", "3530111333300000")]),
    ("Diners 30569309025904 ok", [("credit_card", "30569309025904")]),
    ("card=5105105105105100;cvv=***", [("credit_card", "5105105105105100")]),
    ("Card 4111 1111 1111 1111 1234 was keyed with a PIN suffix", [
        ("credit_card", "4111 1111 1111 1111")]),
    ("Reference 1234567890123456 assigned.", []),
    ("Tracking: 1Z9999999999999999", []),
    ("Timestamp 1700000000000 ms", []),
    # ------------------------------------------------------------------- iban
    ("IBAN: DE89370400440532013000 on file.", [("iban", "DE89370400440532013000")]),
    ("Pay to GB82 WEST 1234 5698 7654 32 by Friday", [("iban", "GB82 WEST 1234 5698 7654 32")]),
    ("FR1420041010050500013M02606 is the account", [("iban", "FR1420041010050500013M02606")]),
    ("NL91ABNA0417164300 (Dutch)", [("iban", "NL91ABNA0417164300")]),
    ("ES9121000418450200051332 Spanish", [("iban", "ES9121000418450200051332")]),
    ("CH9300762011623852957 Swiss", [("iban", "CH9300762011623852957")]),
    ("BE68539007547034 Belgian", [("iban", "BE68539007547034")]),
    ("IT60X0542811101000000123456 Italian", [("iban", "IT60X0542811101000000123456")]),
    ("iban de89370400440532013000 lowercase", [("iban", "de89370400440532013000")]),
    ("Ref: DE89370400440532013001 noted.", []),
    ("Product code AB1234567890XYZ001 in stock.", []),
    # ------------------------------------------------------------- ip_address
    ("Client connected from 203.0.113.42 today.", [("ip_address", "203.0.113.42")]),
    ("upstream=198.51.100.7:8443", [("ip_address", "198.51.100.7")]),
    ("src 192.0.2.1 dst 192.0.2.254", [
        ("ip_address", "192.0.2.1"), ("ip_address", "192.0.2.254")]),
    ("IPv6 2001:db8::1 seen", [("ip_address", "2001:db8::1")]),
    ("v6 full 2001:0db8:85a3:0000:0000:8a2e:0370:7334 ok", [
        ("ip_address", "2001:0db8:85a3:0000:0000:8a2e:0370:7334")]),
    ("internal 10.0.0.5 replied", [("ip_address", "10.0.0.5")]),
    ("Running v1.2.3 of the client.", []),
    ("Build id 999.888.777.666 was tagged.", []),
    ("Meeting at 12:30:45 sharp", []),
    ("MAC 00:1a:2b:3c:4d:5e on port 3", []),
    # ------------------------------------------------------------ national_id
    ("SSN on file: 523-45-6789.", [("national_id", "523-45-6789")]),
    ("ssn=401-22-7788", [("national_id", "401-22-7788")]),
    ("Taxpayer 318-90-1234 filed", [("national_id", "318-90-1234")]),
    ("SSN 612 33 4455 (spaces)", [("national_id", "612 33 4455")]),
    ("SSN 612334455 (no separators)", [("national_id", "612334455")]),
    ("Code 000-45-6789 is reserved.", []),
    ("Code 666-45-6789 is reserved.", []),
    ("Part no. 123-45-0000 is a SKU", []),
    # ---------------------------------------------------------- date_of_birth
    ("DOB: 1990-04-12 recorded at intake.", [("date_of_birth", "1990-04-12")]),
    ("She was born 04/12/1985 in the city.", [("date_of_birth", "04/12/1985")]),
    ("Date of birth 7-3-1962, verified", [("date_of_birth", "7-3-1962")]),
    ("birthdate: 1979-11-30", [("date_of_birth", "1979-11-30")]),
    ("born on 12 March 1991", [("date_of_birth", "12 March 1991")]),
    ("The invoice was issued 2024-01-30 for services.", []),
    ("Estimated date of birth 2999-01-01 is implausible.", []),
    ("Date of birth 2024-02-30 does not exist.", []),
    # ------------------------------------------------------------ person_name
    ("Please contact James Miller about the ticket.", [("person_name", "James Miller")]),
    ("Assigned to Priya Raman yesterday", [("person_name", "Priya Raman")]),
    ("Signed, Maria Gonzalez", [("person_name", "Maria Gonzalez")]),
    ("Escalated by Siobhan Okafor", [("person_name", "Siobhan Okafor")]),
    ("cc Wei Zhang", [("person_name", "Wei Zhang")]),
    ("Also Available: the new release notes.", []),
    ("Acme Corporation released a statement.", []),
    ("Dear Customer, thank you for writing in.", []),
    ("Mark Complete when done.", []),
    ("George Washington Bridge traffic is heavy.", []),
    # ---------------------------------------------------------------- address
    ("Ship to 742 Evergreen Terrace, Springfield, IL 62704.", [
        ("address", "742 Evergreen Terrace, Springfield, IL 62704")]),
    ("Located at 500 Market Ave, Chicago.", [("address", "500 Market Ave, Chicago")]),
    ("Office: 1600 Example Blvd", [("address", "1600 Example Blvd")]),
    ("Return to 12 Oak Lane", [("address", "12 Oak Lane")]),
    ("Visit 221 Baker Street in London", [("address", "221 Baker Street")]),
    ("Send to 10 Downing St", [("address", "10 Downing St")]),
    ("Apt 4B, 77 Mass Ave", [("address", "77 Mass Ave")]),
    ("We sold 42 Widgets last quarter.", []),
    ("Ran 5 Miles Drive-thru test", []),
    # ---------------------------------------------------------------- api_key
    (f"key={_AWS} in config", [("api_key", _AWS)]),
    (f"temp creds {_AWS_TMP}", [("api_key", _AWS_TMP)]),
    (f"token: {_GH}", [("api_key", _GH)]),
    (f"fine-grained {_GH_FG}", [("api_key", _GH_FG)]),
    (f"OPENAI_API_KEY={_SK}", [("api_key", _SK)]),
    (f"slack {_SLACK}", [("api_key", _SLACK)]),
    (f"maps key {_GOOG}", [("api_key", _GOOG)]),
    (f"Authorization: Bearer {_JWT}", [("api_key", _JWT)]),
    (f"secret={_GENERIC}", [("api_key", _GENERIC)]),
    ("This is just a perfectly ordinary sentence with no secrets in it.", []),
    ("request_id=123e4567-e89b-12d3-a456-426614174000", []),
    ("commit 9fceb02d0ae598e95dc970b74767f19372d61af8 merged", []),
    ("sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", []),
    ("path /var/lib/app/cache_entries_by_customer_region_v2", []),
    ("CONSTANT_NAME_FOR_MAXIMUM_RETRY_BACKOFF_SECONDS = 30", []),
    # ------------------------------------------------------------ mixed lines
    ("James Miller <james.miller@example.com> +1 415-555-0132 from 203.0.113.9", [
        ("person_name", "James Miller"), ("email", "james.miller@example.com"),
        ("phone", "+1 415-555-0132"), ("ip_address", "203.0.113.9")]),
    ("refund 4111111111111111 to DE89370400440532013000, SSN 523-45-6789", [
        ("credit_card", "4111111111111111"), ("iban", "DE89370400440532013000"),
        ("national_id", "523-45-6789")]),
    ("2026-01-01T10:00:00Z INFO GET /health 200 3ms", []),
    ("Version 3.11.4 released on 2023-06-06", []),
]
