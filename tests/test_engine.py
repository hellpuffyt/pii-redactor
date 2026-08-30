from pii_redactor.engine import redact_text, run_detectors
from pii_redactor.mapping import TokenMap
from pii_redactor.policy import Policy


class TestRunDetectors:
    def test_dedupes_overlapping_matches_preferring_confidence(self) -> None:
        text = "Contact james.miller@example.com about James Miller's account."
        matches = run_detectors(text)
        # The email should be one match; "James Miller" text (outside the
        # email) may also match person_name, but they must not overlap.
        spans = [(m.start, m.end) for m in matches]
        for i, (s1, e1) in enumerate(spans):
            for s2, e2 in spans[i + 1 :]:
                assert not (s1 < e2 and s2 < e1)

    def test_can_restrict_to_specific_detectors(self) -> None:
        text = "Email a@example.com and card 4111111111111111."
        matches = run_detectors(text, detector_names=["email"])
        assert all(m.detector == "email" for m in matches)
        assert len(matches) == 1

    def test_keep_private_ips_does_not_let_span_fall_through_to_phone(self) -> None:
        # Regression test: a private, dotted-quad IP address must not be
        # re-claimed by the phone detector once it is excluded by
        # keep_private_ips -- the span should simply be left alone, not
        # misclassified as a different detector type.
        text = "Internal build tagged version 10.20.30.40 was deployed."
        matches = run_detectors(text, keep_private_ips=True)
        assert matches == []


class TestApplyPolicyActions:
    def test_redact_action_replaces_with_marker(self) -> None:
        policy = Policy.default()
        policy.actions["email"] = "redact"
        text = "Contact a@example.com now."
        redacted, report = redact_text(text, policy)
        assert "[EMAIL]" in redacted
        assert "a@example.com" not in redacted
        assert report.counts["email"] == 1

    def test_hash_action_is_stable_for_same_salt(self) -> None:
        policy = Policy.default()
        policy.actions["email"] = "hash"
        policy.salt = "fixed-salt"
        text1 = "Contact a@example.com now."
        text2 = "Also a@example.com again."
        r1, _ = redact_text(text1, policy)
        r2, _ = redact_text(text2, policy)
        token1 = r1.split()[1]
        token2 = r2.split()[1]
        assert token1 == token2
        assert "a@example.com" not in r1

    def test_hash_action_differs_for_different_salt(self) -> None:
        text = "Contact a@example.com now."
        policy1 = Policy.default()
        policy1.actions["email"] = "hash"
        policy1.salt = "salt-one"
        policy2 = Policy.default()
        policy2.actions["email"] = "hash"
        policy2.salt = "salt-two"
        r1, _ = redact_text(text, policy1)
        r2, _ = redact_text(text, policy2)
        assert r1 != r2

    def test_tokenise_action_is_reversible_via_map(self) -> None:
        policy = Policy.default()
        policy.actions["email"] = "tokenise"
        token_map = TokenMap()
        text = "Contact a@example.com now."
        redacted, _ = redact_text(text, policy, token_map=token_map)
        token = redacted.split()[1]
        assert token_map.resolve("email", token) == "a@example.com"
        assert "a@example.com" not in redacted

    def test_tokenise_reuses_token_for_repeated_value(self) -> None:
        policy = Policy.default()
        policy.actions["email"] = "tokenise"
        token_map = TokenMap()
        text = "a@example.com wrote to a@example.com twice."
        redacted, _ = redact_text(text, policy, token_map=token_map)
        tokens = [w for w in redacted.replace(".", " ").split() if w.startswith("EMAIL_")]
        assert len(set(tokens)) == 1

    def test_tokenise_without_map_raises(self) -> None:
        policy = Policy.default()
        policy.actions["email"] = "tokenise"
        text = "Contact a@example.com now."
        import pytest

        with pytest.raises(ValueError):
            redact_text(text, policy)

    def test_partial_action_masks_email_locally(self) -> None:
        policy = Policy.default()
        policy.actions["email"] = "partial"
        text = "Contact jane@example.com now."
        redacted, _ = redact_text(text, policy)
        assert redacted.startswith("Contact j")
        assert "@example.com" in redacted
        assert "jane@" not in redacted

    def test_keep_action_leaves_value_untouched(self) -> None:
        policy = Policy.default()
        policy.actions["email"] = "keep"
        text = "Contact a@example.com now."
        redacted, report = redact_text(text, policy)
        assert redacted == text
        assert report.counts["email"] == 1
        assert report.action_counts["email"]["keep"] == 1


class TestRedactionReport:
    def test_report_never_exposes_values(self) -> None:
        policy = Policy.default()
        policy.actions["email"] = "redact"
        text = "Contact secret.person@example.com now."
        _, report = redact_text(text, policy)
        report_repr = repr(report)
        assert "secret.person" not in report_repr

    def test_merge_combines_counts(self) -> None:
        policy = Policy.default()
        policy.actions["email"] = "redact"
        _, r1 = redact_text("a@example.com", policy)
        _, r2 = redact_text("b@example.com c@example.com", policy)
        r1.merge(r2)
        assert r1.counts["email"] == 3
        assert r1.total == 3
