from pathlib import Path

from agent_guard_eval.evaluation import evaluate


def test_bundled_corpus_has_expected_baseline() -> None:
    summary = evaluate(Path("data/evaluation.jsonl"))
    assert summary.total >= 8
    assert summary.accuracy >= 0.75
