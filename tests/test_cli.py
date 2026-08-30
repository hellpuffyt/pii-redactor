import json
from pathlib import Path

from pii_redactor.cli import main


class TestCliRedactText:
    def test_redacts_text_file_to_output(self, tmp_path: Path, capsys: object) -> None:
        input_path = tmp_path / "in.txt"
        input_path.write_text("Contact jane@example.com now.\n", encoding="utf-8")
        output_path = tmp_path / "out.txt"

        exit_code = main(
            ["redact", str(input_path), "--format", "text", "-o", str(output_path)]
        )
        assert exit_code == 0
        result = output_path.read_text(encoding="utf-8")
        assert "jane@example.com" not in result

    def test_dry_run_does_not_write_output_file(self, tmp_path: Path) -> None:
        input_path = tmp_path / "in.txt"
        input_path.write_text("Contact jane@example.com now.\n", encoding="utf-8")
        output_path = tmp_path / "out.txt"

        exit_code = main(
            ["redact", str(input_path), "--format", "text", "-o", str(output_path), "--dry-run"]
        )
        assert exit_code == 0
        assert not output_path.exists()

    def test_missing_mapping_file_for_tokenise_policy_errors(self, tmp_path: Path) -> None:
        input_path = tmp_path / "in.txt"
        input_path.write_text("Contact jane@example.com now.\n", encoding="utf-8")
        policy_path = tmp_path / "policy.json"
        policy_path.write_text(json.dumps({"detectors": {"email": "tokenise"}}), encoding="utf-8")

        exit_code = main(
            ["redact", str(input_path), "--format", "text", "--policy", str(policy_path)]
        )
        assert exit_code == 2


class TestCliRedactCsv:
    def test_redacts_csv_with_column_policy(self, tmp_path: Path) -> None:
        input_path = tmp_path / "in.csv"
        input_path.write_text("name,ssn\nJane,secret-value\n", encoding="utf-8")
        policy_path = tmp_path / "policy.json"
        policy_path.write_text(json.dumps({"csv_columns": {"ssn": "redact"}}), encoding="utf-8")
        output_path = tmp_path / "out.csv"

        exit_code = main(
            [
                "redact", str(input_path), "--format", "csv",
                "--policy", str(policy_path), "-o", str(output_path),
            ]
        )
        assert exit_code == 0
        result = output_path.read_text(encoding="utf-8")
        assert "secret-value" not in result
        assert "[SSN]" in result


class TestCliRedactJson:
    def test_redacts_json_document(self, tmp_path: Path) -> None:
        input_path = tmp_path / "in.json"
        input_path.write_text(json.dumps({"email": "jane@example.com"}), encoding="utf-8")
        output_path = tmp_path / "out.json"

        exit_code = main(
            ["redact", str(input_path), "--format", "json", "-o", str(output_path)]
        )
        assert exit_code == 0
        result = json.loads(output_path.read_text(encoding="utf-8"))
        assert result["email"] != "jane@example.com"


class TestCliResolve:
    def test_resolve_recovers_original_value(self, tmp_path: Path) -> None:
        input_path = tmp_path / "in.txt"
        input_path.write_text("Contact jane@example.com now.\n", encoding="utf-8")
        policy_path = tmp_path / "policy.json"
        policy_path.write_text(json.dumps({"detectors": {"email": "tokenise"}}), encoding="utf-8")
        mapping_path = tmp_path / "map.json"
        output_path = tmp_path / "out.txt"

        exit_code = main(
            [
                "redact", str(input_path), "--format", "text",
                "--policy", str(policy_path), "--mapping-file", str(mapping_path),
                "-o", str(output_path),
            ]
        )
        assert exit_code == 0
        redacted = output_path.read_text(encoding="utf-8")
        token = next(w for w in redacted.replace(".", " ").split() if w.startswith("EMAIL_"))

        exit_code = main(
            [
                "resolve", "--mapping-file", str(mapping_path),
                "--detector", "email", "--token", token,
            ]
        )
        assert exit_code == 0

    def test_resolve_unknown_token_returns_error(self, tmp_path: Path) -> None:
        mapping_path = tmp_path / "map.json"
        mapping_path.write_text(json.dumps({"forward": {}, "counters": {}}), encoding="utf-8")
        exit_code = main(
            [
                "resolve", "--mapping-file", str(mapping_path),
                "--detector", "email", "--token", "EMAIL_001",
            ]
        )
        assert exit_code == 1
