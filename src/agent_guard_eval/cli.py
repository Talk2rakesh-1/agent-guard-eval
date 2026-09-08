from __future__ import annotations

import argparse
import json
from pathlib import Path

from .detector import PromptInjectionDetector
from .evaluation import evaluate


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="agent-guard", description="Analyze prompts or run a JSONL security evaluation"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze_parser = subparsers.add_parser("analyze")
    analyze_parser.add_argument("text")
    analyze_parser.add_argument(
        "--source", choices=("user", "retrieved", "tool_output"), default="user"
    )
    eval_parser = subparsers.add_parser("eval")
    eval_parser.add_argument("corpus", type=Path)
    args = parser.parse_args()
    if args.command == "analyze":
        print(PromptInjectionDetector().analyze(args.text, args.source).model_dump_json(indent=2))
        return
    summary = evaluate(args.corpus)
    print(json.dumps({**summary.__dict__, "accuracy": summary.accuracy}, indent=2))


if __name__ == "__main__":
    main()
