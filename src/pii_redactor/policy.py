"""Policy configuration: per-detector actions, loaded from TOML/YAML/JSON."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

Action = Literal["redact", "hash", "tokenise", "partial", "keep"]

_VALID_ACTIONS = {"redact", "hash", "tokenise", "partial", "keep"}

DEFAULT_ACTIONS: dict[str, Action] = {
    "email": "redact",
    "phone": "redact",
    "credit_card": "redact",
    "iban": "redact",
    "ip_address": "partial",
    "national_id": "redact",
    "date_of_birth": "redact",
    "person_name": "keep",
    "address": "redact",
    "api_key": "redact",
}


@dataclass
class Policy:
    """A redaction policy: one action per detector, plus format-specific
    field overrides for CSV columns and JSON dotted paths."""

    actions: dict[str, Action] = field(default_factory=lambda: dict(DEFAULT_ACTIONS))
    csv_columns: dict[str, Action] = field(default_factory=dict)
    json_paths: dict[str, Action] = field(default_factory=dict)
    keep_private_ips: bool = False
    salt: str | None = None

    def action_for(self, detector: str) -> Action:
        return self.actions.get(detector, "redact")

    def action_for_csv_column(self, column: str) -> Action | None:
        return self.csv_columns.get(column)

    def action_for_json_path(self, dotted_path: str) -> Action | None:
        return self.json_paths.get(dotted_path)

    @classmethod
    def default(cls) -> Policy:
        return cls()

    @classmethod
    def from_file(cls, path: str | Path) -> Policy:
        p = Path(path)
        text = p.read_text(encoding="utf-8")
        if p.suffix == ".json":
            data: dict[str, Any] = json.loads(text)
        elif p.suffix == ".toml":
            data = tomllib.loads(text)
        else:
            raise ValueError(f"Unsupported policy file extension: {p.suffix}")
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        actions = dict(DEFAULT_ACTIONS)
        raw_actions = data.get("detectors", {})
        for name, action in raw_actions.items():
            _validate_action(name, action)
            actions[name] = action

        csv_columns: dict[str, Action] = {}
        for name, action in data.get("csv_columns", {}).items():
            _validate_action(name, action)
            csv_columns[name] = action

        json_paths: dict[str, Action] = {}
        for name, action in data.get("json_paths", {}).items():
            _validate_action(name, action)
            json_paths[name] = action

        return cls(
            actions=actions,
            csv_columns=csv_columns,
            json_paths=json_paths,
            keep_private_ips=bool(data.get("keep_private_ips", False)),
            salt=data.get("salt"),
        )


def _validate_action(name: str, action: str) -> None:
    if action not in _VALID_ACTIONS:
        raise ValueError(
            f"Invalid action {action!r} for {name!r}; must be one of {sorted(_VALID_ACTIONS)}"
        )
