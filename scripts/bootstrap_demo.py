#!/usr/bin/env python3
"""Generate demo data, train the model, and save dashboard artifacts."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.workflow import bootstrap_demo  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true", help="regenerate data and model artifacts")
    args = parser.parse_args()
    metrics = bootstrap_demo(ROOT, force=args.force)
    print("SentinelUEBA demo is ready.")
    for key, value in metrics.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()

