"""CLI safety regressions: data-loss guards, fail-closed configuration,
malformed input, and "the original values never reach output or logs"."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from pii_redactor.cli import main
from pii_redactor.detectors import DETECTORS
from tests.eval.corpus import CASES
from tests.test_detection_eval import KNOWN_LEAKS

EMAIL = "jane.doe@example.com"
CARD = "4111111111111111"


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def _redact_all_policy(tmp_path: Path, action: str = "redact") -> Path:
    body = "\n".join(f'{name} = "{action}"' for name in DETECTORS)
    return _write(tmp_path / "policy.toml", f'salt = "test-salt"\n[detectors]\n{body}\n')


# ----------------------------------------------------------------- data loss


def test_output_equal_to_input_is_refused_and_input_survives(tmp_path: Path) -> None:
    src = _write(tmp_path / "in.txt", f"mail {EMAIL}\n")
    assert main(["redact", str(src), "--format", "text", "-o", str(src)]) == 2
    assert src.read_text(encoding="utf-8") == f"mail {EMAIL}\n"


def test_mapping_file_equal_to_output_is_refused(tmp_path: Path) -> None:
    # Before: the mapping (all original values) overwrote the "redacted" file.
    src = _write(tmp_path / "in.txt", f"mail {EMAIL}\n")
    policy = _write(tmp_path / "p.toml", '[detectors]\nemail = "tokenise"\n')
    out = tmp_path / "out.txt"
    rc = main([
        "redact", str(src), "--format", "text", "--policy", str(policy),
        "--mapping-file", str(out), "-o", str(out),
    ])
    assert rc == 2
    assert not out.exists()


def test_mapping_file_equal_to_input_is_refused(tmp_path: Path) -> None:
    src = _write(tmp_path / "in.txt", f"mail {EMAIL}\n")
    rc = main(["redact", str(src), "--format", "text", "--mapping-file", str(src)])
    assert rc == 2
    assert src.read_text(encoding="utf-8") == f"mail {EMAIL}\n"


def test_failed_run_leaves_no_partial_output(tmp_path: Path) -> None:
    src = _write(tmp_path / "in.jsonl", json.dumps({"e": EMAIL}) + "\n{broken\n")
    out = tmp_path / "out.jsonl"
    assert main(["redact", str(src), "--format", "jsonl", "-o", str(out)]) == 2
    assert not out.exists()
    assert list(tmp_path.glob(".out.jsonl.*")) == []


def test_failed_run_does_not_clobber_existing_output(tmp_path: Path) -> None:
    src = _write(tmp_path / "in.jsonl", "{broken\n")
    out = _write(tmp_path / "out.jsonl", "previous good output\n")
    assert main(["redact", str(src), "--format", "jsonl", "-o", str(out)]) == 2
    assert out.read_text(encoding="utf-8") == "previous good output\n"


# ------------------------------------------------------------ fail closed


def test_unknown_detector_name_is_an_error_not_a_silent_no_op(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Before: "--detectors emails" ran nothing and printed the email unredacted.
    src = _write(tmp_path / "in.txt", f"mail {EMAIL}\n")
    assert main(["redact", str(src), "--format", "text", "--detectors", "emails"]) == 2
    captured = capsys.readouterr()
    assert EMAIL not in captured.out + captured.err
    assert "emails" in captured.err


def test_known_detector_subset_still_works(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    src = _write(tmp_path / "in.txt", f"mail {EMAIL} card {CARD}\n")
    assert main(["redact", str(src), "--format", "text", "--detectors", "email"]) == 0
    out = capsys.readouterr().out
    assert EMAIL not in out
    assert CARD in out  # only the requested detector ran


def test_policy_with_misspelled_detector_is_rejected(tmp_path: Path) -> None:
    src = _write(tmp_path / "in.txt", f"mail {EMAIL}\n")
    policy = _write(tmp_path / "p.toml", '[detectors]\nemial = "keep"\n')
    assert main(["redact", str(src), "--format", "text", "--policy", str(policy)]) == 2


def test_dry_run_with_tokenise_policy_and_no_mapping_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Before: crashed with "tokenise action requires a token_map".
    src = _write(tmp_path / "in.txt", f"mail {EMAIL}\n")
    policy = _write(tmp_path / "p.toml", '[detectors]\nemail = "tokenise"\n')
    rc = main(["redact", str(src), "--format", "text", "--policy", str(policy), "--dry-run"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "email: 1 (tokenise=1)" in captured.err
    assert EMAIL not in captured.out + captured.err
    assert list(tmp_path.glob("*.json")) == []


def test_hash_without_salt_warns(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    src = _write(tmp_path / "in.txt", f"mail {EMAIL}\n")
    policy = _write(tmp_path / "p.toml", '[detectors]\nemail = "hash"\n')
    assert main(["redact", str(src), "--format", "text", "--policy", str(policy)]) == 0
    assert "without a 'salt'" in capsys.readouterr().err


# ------------------------------------------------------------- JSON numbers


def test_json_numeric_values_are_scanned_and_forced_paths_apply(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Before: integers were never inspected, even under an explicit path policy.
    src = _write(
        tmp_path / "in.json",
        json.dumps({"user": {"ssn": 123456789, "card": int(CARD), "age": 42, "ok": True}}),
    )
    policy = _write(tmp_path / "p.toml", '[json_paths]\n"user.ssn" = "redact"\n')
    assert main(["redact", str(src), "--format", "json", "--policy", str(policy)]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["user"] == {"ssn": "[SSN]", "card": "[CREDIT_CARD]", "age": 42, "ok": True}


# ------------------------------------------------------------- mapping file


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_mapping_file_is_owner_only(tmp_path: Path) -> None:
    src = _write(tmp_path / "in.txt", f"mail {EMAIL}\n")
    policy = _write(tmp_path / "p.toml", '[detectors]\nemail = "tokenise"\n')
    mapping = _write(tmp_path / "m.json", "{}")
    os.chmod(mapping, 0o644)
    rc = main([
        "redact", str(src), "--format", "text", "--policy", str(policy),
        "--mapping-file", str(mapping), "-o", str(tmp_path / "out.txt"),
    ])
    assert rc == 0
    assert stat.S_IMODE(mapping.stat().st_mode) == 0o600


# ---------------------------------------------------------- malformed input


@pytest.mark.parametrize(
    ("fmt", "content"),
    [
        ("jsonl", json.dumps({"e": EMAIL}) + "\n" + "{" + EMAIL + "\n"),
        ("json", '{"e": "' + EMAIL + '", '),
        ("text", (f"mail {EMAIL} ").encode() + b"\xff\xfe\n"),
        ("csv", 'a,b\n"' + EMAIL + '\n'),
    ],
)
def test_malformed_input_fails_cleanly_without_echoing_content(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], fmt: str, content: str | bytes
) -> None:
    src = tmp_path / f"in.{fmt}"
    if isinstance(content, bytes):
        src.write_bytes(content)
    else:
        src.write_text(content, encoding="utf-8")
    out = tmp_path / "out"
    rc = main(["redact", str(src), "--format", fmt, "-o", str(out)])
    captured = capsys.readouterr()
    if fmt == "csv":
        # An unterminated quote is accepted by the stdlib reader (it reads to
        # EOF); what matters is that the value is redacted, not echoed.
        assert rc == 0
        assert EMAIL not in out.read_text(encoding="utf-8")
    else:
        assert rc == 2
        assert captured.err.startswith("error: ")
        assert not out.exists()
    assert EMAIL not in captured.out + captured.err
    assert "Traceback" not in captured.err


def test_missing_input_file_is_a_clean_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["redact", str(tmp_path / "nope.txt"), "--format", "text"]) == 2
    assert "input file not found" in capsys.readouterr().err


def test_corrupt_mapping_file_is_a_clean_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    mapping = _write(tmp_path / "m.json", "[not, a, map")
    rc = main(["resolve", "--mapping-file", str(mapping), "--detector", "email", "--token", "X"])
    assert rc == 2
    assert "cannot read mapping file" in capsys.readouterr().err


# ------------------------------------------- originals never reach outputs


def _corpus_positives() -> list[tuple[str, list[tuple[str, str]]]]:
    return [(text, gold) for text, gold in CASES if gold]


@pytest.mark.parametrize("action", ["redact", "hash", "tokenise", "partial"])
def test_text_output_and_stderr_never_contain_original_values(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], action: str
) -> None:
    cases = _corpus_positives()
    src = _write(tmp_path / "in.txt", "\n".join(text for text, _ in cases) + "\n")
    out = tmp_path / "out.txt"
    mapping = tmp_path / "map.json"
    rc = main([
        "redact", str(src), "--format", "text",
        "--policy", str(_redact_all_policy(tmp_path, action)),
        "--mapping-file", str(mapping), "-o", str(out),
    ])
    assert rc == 0
    captured = capsys.readouterr()
    redacted = out.read_text(encoding="utf-8")
    for _, gold in cases:
        for entity, value in gold:
            # Diagnostics never carry a value, not even an undetected one.
            assert value not in captured.out + captured.err
            if (entity, value) in KNOWN_LEAKS or action == "partial":
                continue
            assert value not in redacted, f"{entity} survived {action}"
    if action == "tokenise":
        # The originals live only in the separate mapping file.
        assert EMAIL not in redacted
        assert "jane.doe@example.com" in mapping.read_text(encoding="utf-8")


def test_dry_run_report_contains_counts_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cases = _corpus_positives()
    src = _write(tmp_path / "in.txt", "\n".join(text for text, _ in cases) + "\n")
    rc = main([
        "redact", str(src), "--format", "text", "--dry-run",
        "--policy", str(_redact_all_policy(tmp_path)),
    ])
    assert rc == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    for _, gold in cases:
        for _, value in gold:
            assert value not in captured.err


@pytest.mark.parametrize("fmt", ["csv", "jsonl", "json"])
def test_structured_formats_do_not_leak_detected_values(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], fmt: str
) -> None:
    cases = [(t, g) for t, g in _corpus_positives() if not set(g) & KNOWN_LEAKS]
    texts = [t for t, _ in cases]
    src = tmp_path / f"in.{fmt}"
    if fmt == "csv":
        import csv as _csv

        with src.open("w", encoding="utf-8", newline="") as f:
            w = _csv.writer(f)
            w.writerow(["id", "notes"])
            for i, t in enumerate(texts):
                w.writerow([str(i), t])
    elif fmt == "jsonl":
        _write(src, "".join(json.dumps({"n": {"notes": t}}) + "\n" for t in texts))
    else:
        _write(src, json.dumps({"rows": [{"notes": t} for t in texts]}))
    out = tmp_path / "out"
    rc = main([
        "redact", str(src), "--format", fmt, "-o", str(out),
        "--policy", str(_redact_all_policy(tmp_path)),
    ])
    assert rc == 0
    redacted = out.read_text(encoding="utf-8")
    captured = capsys.readouterr()
    for _, gold in cases:
        for entity, value in gold:
            assert value not in captured.out + captured.err
            # JSON escapes the apostrophe-free values verbatim; check raw text.
            assert value not in redacted, f"{entity} survived in {fmt}"
