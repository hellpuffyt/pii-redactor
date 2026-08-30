import csv
import io
import json

from pii_redactor.formats.csv_format import redact_csv_stream
from pii_redactor.formats.json_format import redact_json_document, redact_jsonl_stream
from pii_redactor.formats.log import redact_log_stream
from pii_redactor.formats.text import redact_file_stream
from pii_redactor.mapping import TokenMap
from pii_redactor.policy import Policy


class TestTextStreaming:
    def test_redacts_each_line_independently(self) -> None:
        policy = Policy.default()
        policy.actions["email"] = "redact"
        lines = ["a@example.com wrote in.\n", "no pii here.\n", "b@example.com too.\n"]
        output_iter, report = redact_file_stream(lines, policy)
        output = list(output_iter)
        assert output[0].strip() == "[EMAIL] wrote in."
        assert output[1].strip() == "no pii here."
        assert report.counts["email"] == 2

    def test_handles_empty_input(self) -> None:
        policy = Policy.default()
        output_iter, report = redact_file_stream([], policy)
        assert list(output_iter) == []
        assert report.total == 0


class TestLogStreaming:
    def test_redacts_log_lines(self) -> None:
        policy = Policy.default()
        policy.actions["ip_address"] = "redact"
        lines = ["2026-01-01 INFO request from 203.0.113.5\n", "2026-01-01 INFO ok\n"]
        output_iter, report = redact_log_stream(lines, policy)
        output = list(output_iter)
        assert "[IP_ADDRESS]" in output[0]
        assert "203.0.113.5" not in output[0]
        assert report.counts["ip_address"] == 1


class TestCsvFormat:
    def test_header_row_passes_through_unmodified(self) -> None:
        policy = Policy.default()
        rows = [["name", "email"], ["Jane", "jane@example.com"]]
        row_iter, report = redact_csv_stream(rows, policy, token_map=TokenMap())
        output = list(row_iter)
        assert output[0] == ["name", "email"]

    def test_column_policy_forces_whole_cell_action(self) -> None:
        policy = Policy.from_dict({"csv_columns": {"ssn": "redact"}})
        rows = [["name", "ssn"], ["Jane", "not-ssn-shaped-value"]]
        row_iter, report = redact_csv_stream(rows, policy)
        output = list(row_iter)
        assert output[1][1] == "[SSN]"
        assert report.counts["ssn"] == 1

    def test_column_without_policy_falls_back_to_detection(self) -> None:
        policy = Policy.default()
        policy.actions["email"] = "redact"
        rows = [["name", "notes"], ["Jane", "contact jane@example.com for details"]]
        row_iter, _ = redact_csv_stream(rows, policy)
        output = list(row_iter)
        assert "[EMAIL]" in output[1][1]
        assert "jane@example.com" not in output[1][1]

    def test_column_policy_keep_leaves_cell_untouched(self) -> None:
        policy = Policy.from_dict({"csv_columns": {"city": "keep"}})
        rows = [["name", "city"], ["Jane", "Springfield"]]
        row_iter, _ = redact_csv_stream(rows, policy)
        output = list(row_iter)
        assert output[1][1] == "Springfield"

    def test_round_trip_through_real_csv_writer_reader(self) -> None:
        policy = Policy.default()
        policy.actions["email"] = "redact"
        buf = io.StringIO("name,email\r\nJane,jane@example.com\r\n")
        reader = csv.reader(buf)
        row_iter, _ = redact_csv_stream(reader, policy)
        out_buf = io.StringIO()
        writer = csv.writer(out_buf)
        for row in row_iter:
            writer.writerow(row)
        result = out_buf.getvalue()
        assert "jane@example.com" not in result
        assert "[EMAIL]" in result


class TestJsonFormat:
    def test_redacts_nested_string_values(self) -> None:
        policy = Policy.default()
        policy.actions["email"] = "redact"
        document = {"user": {"email": "jane@example.com", "id": 42}}
        redacted, report = redact_json_document(document, policy)
        assert redacted["user"]["email"] == "[EMAIL]"
        assert redacted["user"]["id"] == 42
        assert report.counts["email"] == 1

    def test_json_path_policy_forces_field(self) -> None:
        policy = Policy.from_dict({"json_paths": {"user.ssn": "redact"}})
        document = {"user": {"ssn": "not-detectable-as-ssn"}}
        redacted, report = redact_json_document(document, policy)
        assert redacted["user"]["ssn"] == "[SSN]"

    def test_redacts_values_inside_lists(self) -> None:
        policy = Policy.default()
        policy.actions["email"] = "redact"
        document = {"emails": ["a@example.com", "b@example.com"]}
        redacted, report = redact_json_document(document, policy)
        assert redacted["emails"] == ["[EMAIL]", "[EMAIL]"]
        assert report.counts["email"] == 2

    def test_non_string_leaves_are_untouched(self) -> None:
        policy = Policy.default()
        document = {"count": 5, "active": True, "ratio": 1.5, "tag": None}
        redacted, report = redact_json_document(document, policy)
        assert redacted == document
        assert report.total == 0


class TestJsonlFormat:
    def test_redacts_each_line_as_a_document(self) -> None:
        policy = Policy.default()
        policy.actions["email"] = "redact"
        lines = [
            json.dumps({"email": "a@example.com"}) + "\n",
            json.dumps({"email": "b@example.com"}) + "\n",
        ]
        output_iter, report = redact_jsonl_stream(lines, policy)
        output = [json.loads(line) for line in output_iter]
        assert output[0]["email"] == "[EMAIL]"
        assert output[1]["email"] == "[EMAIL]"
        assert report.counts["email"] == 2

    def test_skips_blank_lines(self) -> None:
        policy = Policy.default()
        lines = [json.dumps({"a": 1}) + "\n", "\n", json.dumps({"b": 2}) + "\n"]
        output_iter, _ = redact_jsonl_stream(lines, policy)
        output = list(output_iter)
        assert len(output) == 3
