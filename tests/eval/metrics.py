"""Per-entity precision/recall over the labelled synthetic corpus.

Run ``python -m tests.eval.metrics`` from the repo root to print the table.

Scoring rules (deliberately strict):

* A prediction is a true positive only if its detector type matches the gold
  type AND its span is exactly the gold span.
* Any other prediction is a false positive for its own type (this includes a
  right-type prediction with the wrong boundaries, and a type confusion).
* Any gold span without an exact same-type prediction is a false negative.
* ``leaked`` counts gold values that still appear verbatim in the output of a
  policy that redacts *every* detector. It is the privacy-relevant number: a
  type confusion still redacts the value, a boundary error may not.
"""

from __future__ import annotations

from dataclasses import dataclass

from pii_redactor.detectors import DETECTORS
from pii_redactor.engine import redact_text, run_detectors
from pii_redactor.policy import Policy
from tests.eval.corpus import CASES


@dataclass
class Score:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    leaked: int = 0
    support: int = 0

    @property
    def precision(self) -> float | None:
        denom = self.tp + self.fp
        return None if denom == 0 else self.tp / denom

    @property
    def recall(self) -> float | None:
        return None if self.support == 0 else self.tp / self.support


def gold_spans(text: str, gold: list[tuple[str, str]]) -> set[tuple[str, int, int]]:
    spans: set[tuple[str, int, int]] = set()
    cursor: dict[str, int] = {}
    for entity, value in gold:
        start = text.find(value, cursor.get(value, 0))
        if start < 0:
            raise AssertionError(f"gold value not found in corpus text for {entity}")
        cursor[value] = start + len(value)
        spans.add((entity, start, start + len(value)))
    return spans


def evaluate() -> dict[str, Score]:
    scores = {name: Score() for name in DETECTORS}
    redact_all = Policy.from_dict({"detectors": {name: "redact" for name in DETECTORS}})
    for text, gold in CASES:
        expected = gold_spans(text, gold)
        predicted = {
            (m.detector, m.start, m.end) for m in run_detectors(text, keep_private_ips=False)
        }
        for entity, _, _ in expected:
            scores[entity].support += 1
        for span in predicted:
            if span in expected:
                scores[span[0]].tp += 1
            else:
                scores[span[0]].fp += 1
        for span in expected - predicted:
            scores[span[0]].fn += 1
        redacted, _ = redact_text(text, redact_all)
        for entity, value in gold:
            if value in redacted:
                scores[entity].leaked += 1
    return scores


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f}"


def render(scores: dict[str, Score]) -> str:
    lines = [
        "| entity | support | TP | FP | FN | precision | recall | leaked |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    total = Score()
    for name, s in scores.items():
        lines.append(
            f"| {name} | {s.support} | {s.tp} | {s.fp} | {s.fn} | "
            f"{_fmt(s.precision)} | {_fmt(s.recall)} | {s.leaked} |"
        )
        total.tp += s.tp
        total.fp += s.fp
        total.fn += s.fn
        total.leaked += s.leaked
        total.support += s.support
    lines.append(
        f"| **all** | {total.support} | {total.tp} | {total.fp} | {total.fn} | "
        f"{_fmt(total.precision)} | {_fmt(total.recall)} | {total.leaked} |"
    )
    lines.append(f"\n{len(CASES)} cases, {sum(1 for _, g in CASES if not g)} hard negatives.")
    return "\n".join(lines)


if __name__ == "__main__":
    print(render(evaluate()))
