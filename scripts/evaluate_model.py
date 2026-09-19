#!/usr/bin/env python3
"""Evaluate SentinelUEBA across held-out synthetic generator seeds."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.evaluation import evaluate_demo_seeds  # noqa: E402


def main() -> None:
    output = ROOT / "artifacts"
    output.mkdir(parents=True, exist_ok=True)
    per_seed, summary = evaluate_demo_seeds()
    per_seed.to_csv(output / "evaluation_by_seed.csv", index=False)
    (output / "evaluation_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
