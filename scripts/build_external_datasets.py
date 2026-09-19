#!/usr/bin/env python3
"""Normalize, model, and score the downloaded public Kaggle datasets."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.external_workflow import run_game_admin_workflow, run_network_workflow  # noqa: E402


def main() -> None:
    source = ROOT / "data" / "external" / "kaggle"
    output = ROOT / "artifacts" / "external"
    game = run_game_admin_workflow(source / "game_admin" / "game_admin_logs.csv", output)
    print("Game administrator dataset")
    print(json.dumps(game, indent=2))
    network = run_network_workflow(source / "network" / "train_data.csv", output)
    print("Network access dataset")
    print(json.dumps(network, indent=2))


if __name__ == "__main__":
    main()

