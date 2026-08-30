from pathlib import Path

from pii_redactor.mapping import TokenMap


class TestTokenMap:
    def test_tokenise_mints_sequential_tokens(self) -> None:
        tm = TokenMap()
        t1 = tm.tokenise("email", "a@example.com")
        t2 = tm.tokenise("email", "b@example.com")
        assert t1 == "EMAIL_001"
        assert t2 == "EMAIL_002"

    def test_tokenise_is_idempotent_for_same_value(self) -> None:
        tm = TokenMap()
        t1 = tm.tokenise("email", "a@example.com")
        t2 = tm.tokenise("email", "a@example.com")
        assert t1 == t2

    def test_namespaces_are_independent_per_detector(self) -> None:
        tm = TokenMap()
        t1 = tm.tokenise("email", "a@example.com")
        t2 = tm.tokenise("phone", "+14155550132")
        assert t1 == "EMAIL_001"
        assert t2 == "PHONE_001"

    def test_resolve_returns_original_value(self) -> None:
        tm = TokenMap()
        token = tm.tokenise("email", "a@example.com")
        assert tm.resolve("email", token) == "a@example.com"

    def test_resolve_unknown_token_returns_none(self) -> None:
        tm = TokenMap()
        assert tm.resolve("email", "EMAIL_999") is None

    def test_save_and_load_round_trip(self, tmp_path: Path) -> None:
        tm = TokenMap()
        token = tm.tokenise("email", "a@example.com")
        path = tmp_path / "mapping.json"
        tm.save(path)

        loaded = TokenMap.load(path)
        assert loaded.resolve("email", token) == "a@example.com"

    def test_save_includes_loud_warning(self, tmp_path: Path) -> None:
        tm = TokenMap()
        tm.tokenise("email", "a@example.com")
        path = tmp_path / "mapping.json"
        tm.save(path)
        content = path.read_text(encoding="utf-8")
        assert "WARNING" in content
        assert "sensitiv" in content.lower()

    def test_load_missing_file_returns_empty_map(self, tmp_path: Path) -> None:
        tm = TokenMap.load(tmp_path / "does_not_exist.json")
        assert tm.resolve("email", "EMAIL_001") is None

    def test_continues_numbering_after_reload(self, tmp_path: Path) -> None:
        tm = TokenMap()
        tm.tokenise("email", "a@example.com")
        path = tmp_path / "mapping.json"
        tm.save(path)

        reloaded = TokenMap.load(path)
        new_token = reloaded.tokenise("email", "b@example.com")
        assert new_token == "EMAIL_002"
