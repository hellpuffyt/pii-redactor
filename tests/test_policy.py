import json
from pathlib import Path

import pytest

from pii_redactor.policy import DEFAULT_ACTIONS, Policy


class TestPolicyDefaults:
    def test_default_policy_covers_all_detectors(self) -> None:
        policy = Policy.default()
        for detector in DEFAULT_ACTIONS:
            assert policy.action_for(detector) in {
                "redact", "hash", "tokenise", "partial", "keep"
            }

    def test_unknown_detector_falls_back_to_redact(self) -> None:
        policy = Policy.default()
        assert policy.action_for("nonexistent_detector") == "redact"


class TestPolicyFromDict:
    def test_overrides_specific_detector(self) -> None:
        policy = Policy.from_dict({"detectors": {"email": "keep"}})
        assert policy.action_for("email") == "keep"
        assert policy.action_for("phone") == DEFAULT_ACTIONS["phone"]

    def test_rejects_invalid_action(self) -> None:
        with pytest.raises(ValueError):
            Policy.from_dict({"detectors": {"email": "delete_forever"}})

    def test_csv_column_override(self) -> None:
        policy = Policy.from_dict({"csv_columns": {"ssn": "redact"}})
        assert policy.action_for_csv_column("ssn") == "redact"
        assert policy.action_for_csv_column("other_column") is None

    def test_json_path_override(self) -> None:
        policy = Policy.from_dict({"json_paths": {"user.email": "tokenise"}})
        assert policy.action_for_json_path("user.email") == "tokenise"

    def test_keep_private_ips_flag(self) -> None:
        policy = Policy.from_dict({"keep_private_ips": True})
        assert policy.keep_private_ips is True

    def test_salt_passthrough(self) -> None:
        policy = Policy.from_dict({"salt": "abc123"})
        assert policy.salt == "abc123"


class TestPolicyFromFile:
    def test_loads_json_policy_file(self, tmp_path: Path) -> None:
        path = tmp_path / "policy.json"
        path.write_text(json.dumps({"detectors": {"email": "keep"}}), encoding="utf-8")
        policy = Policy.from_file(path)
        assert policy.action_for("email") == "keep"

    def test_loads_toml_policy_file(self, tmp_path: Path) -> None:
        path = tmp_path / "policy.toml"
        path.write_text('[detectors]\nemail = "hash"\n', encoding="utf-8")
        policy = Policy.from_file(path)
        assert policy.action_for("email") == "hash"

    def test_unsupported_extension_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "policy.yaml"
        path.write_text("detectors: {}", encoding="utf-8")
        with pytest.raises(ValueError):
            Policy.from_file(path)
