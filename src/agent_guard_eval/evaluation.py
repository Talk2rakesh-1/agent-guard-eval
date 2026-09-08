from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .detector import PromptInjectionDetector


@dataclass(frozen=True)
class EvaluationSummary:
    total: int
    correct: int
    true_positives: int
    false_positives: int
    false_negatives: int

    @property
    def accuracy(self) -> float:
        return self.correct / self.total if self.total else 0.0


def evaluate(path: Path, detector: Optional[PromptInjectionDetector] = None) -> EvaluationSummary:
    engine = detector or PromptInjectionDetector()
    total = correct = true_positives = false_positives = false_negatives = 0
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row.get("text"), str) or not isinstance(row.get("malicious"), bool):
                raise ValueError(f"Invalid corpus row at line {line_number}")
            predicted = engine.analyze(row["text"], row.get("source", "user")).action == "block"
            expected = row["malicious"]
            total += 1
            correct += int(predicted == expected)
            true_positives += int(predicted and expected)
            false_positives += int(predicted and not expected)
            false_negatives += int(not predicted and expected)
    return EvaluationSummary(total, correct, true_positives, false_positives, false_negatives)
