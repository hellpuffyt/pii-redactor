"""Reversible token mapping, persisted to a file kept separate from the
redacted output.

The mapping file is as sensitive as the original, un-redacted data -- it
lets anyone reverse every `tokenise`-action replacement back to the real
value. Callers must store it separately (different access controls,
different retention policy) from the redacted output it belongs to.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MAPPING_FILE_WARNING = (
    "WARNING: this file lets anyone recover the original PII values for every "
    "tokenised entry below. Treat it with at least the same sensitivity as the "
    "source data, store it separately from the redacted output, and restrict "
    "access accordingly."
)


@dataclass
class TokenMap:
    """Bidirectional token <-> original-value map, one namespace per detector."""

    counters: dict[str, int] = field(default_factory=dict)
    forward: dict[str, dict[str, str]] = field(default_factory=dict)  # detector -> token -> value
    reverse: dict[str, dict[str, str]] = field(default_factory=dict)  # detector -> value -> token

    def tokenise(self, detector: str, value: str) -> str:
        """Return a stable token for `value`, minting a new one if unseen."""
        rev = self.reverse.setdefault(detector, {})
        if value in rev:
            return rev[value]
        count = self.counters.get(detector, 0) + 1
        self.counters[detector] = count
        token = f"{detector.upper()}_{count:03d}"
        rev[value] = token
        self.forward.setdefault(detector, {})[token] = value
        return token

    def resolve(self, detector: str, token: str) -> str | None:
        return self.forward.get(detector, {}).get(token)

    def to_dict(self) -> dict[str, object]:
        return {
            "warning": MAPPING_FILE_WARNING,
            "counters": self.counters,
            "forward": self.forward,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TokenMap:
        forward_raw: dict[str, Any] = data.get("forward", {})
        forward: dict[str, dict[str, str]] = {
            str(k): dict(v) for k, v in forward_raw.items()
        }
        reverse: dict[str, dict[str, str]] = {
            detector: {value: token for token, value in tokens.items()}
            for detector, tokens in forward.items()
        }
        counters_raw: dict[str, Any] = data.get("counters", {})
        counters = {str(k): int(v) for k, v in counters_raw.items()}
        return cls(counters=counters, forward=forward, reverse=reverse)

    def save(self, path: str | Path) -> None:
        p = Path(path)
        p.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> TokenMap:
        p = Path(path)
        if not p.exists():
            return cls()
        data = json.loads(p.read_text(encoding="utf-8"))
        return cls.from_dict(data)
