"""Measured detection quality on the labelled synthetic corpus.

These are regression *ceilings* on errors, recorded from an actual run of
``python -m tests.eval.metrics``. They are evidence of behaviour on this
corpus only -- not a guarantee about real-world data. If a detector change
lowers an error count, tighten the number here; if it raises one, that is a
regression to investigate, not a number to bump.
"""

from __future__ import annotations

import pytest

from tests.eval.corpus import CASES
from tests.eval.metrics import evaluate, gold_spans

# entity: (max false positives, max false negatives, max leaked values)
MEASURED_CEILINGS = {
    "email": (1, 0, 0),
    "phone": (5, 1, 1),
    "credit_card": (0, 0, 0),
    "iban": (0, 0, 0),
    "ip_address": (0, 0, 0),
    "national_id": (0, 2, 1),
    "date_of_birth": (0, 1, 1),
    "person_name": (2, 1, 1),
    "address": (1, 0, 0),
    "api_key": (1, 0, 0),
}

# The only gold values allowed to survive a redact-everything policy, each a
# documented limitation (see README "Limitations").
KNOWN_LEAKS = {
    ("phone", "4155550166"),  # bare 10-digit run: indistinguishable from an order id
    ("national_id", "612334455"),  # SSN without separators is not matched
    ("date_of_birth", "12 March 1991"),  # month-name dates are not matched
    ("person_name", "Siobhan Okafor"),  # first name not in the dictionary
}


@pytest.fixture(scope="module")
def scores():  # type: ignore[no-untyped-def]
    return evaluate()


def test_corpus_gold_labels_are_well_formed() -> None:
    for text, gold in CASES:
        gold_spans(text, gold)  # raises if a gold value is not in its text


@pytest.mark.parametrize("entity", sorted(MEASURED_CEILINGS))
def test_error_counts_do_not_regress(scores, entity: str) -> None:  # type: ignore[no-untyped-def]
    max_fp, max_fn, max_leaked = MEASURED_CEILINGS[entity]
    s = scores[entity]
    assert s.fp <= max_fp, f"{entity}: {s.fp} false positives (ceiling {max_fp})"
    assert s.fn <= max_fn, f"{entity}: {s.fn} false negatives (ceiling {max_fn})"
    assert s.leaked <= max_leaked, f"{entity}: {s.leaked} leaked (ceiling {max_leaked})"


def test_only_documented_misses_leak() -> None:
    from pii_redactor.detectors import DETECTORS
    from pii_redactor.engine import redact_text
    from pii_redactor.policy import Policy

    policy = Policy.from_dict({"detectors": {n: "redact" for n in DETECTORS}})
    leaked = set()
    for text, gold in CASES:
        out, _ = redact_text(text, policy)
        leaked |= {(entity, value) for entity, value in gold if value in out}
    assert leaked == KNOWN_LEAKS
