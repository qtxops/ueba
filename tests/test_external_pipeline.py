from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pandas as pd

from src.adapters import load_game_admin_events, load_network_events
from src.generic_features import build_generic_feature_table
from src.generic_modeling import score_generic_features, train_generic_model


class ExternalPipelineTest(unittest.TestCase):
    def test_game_admin_adapter_and_model(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "game.csv"
            rows = []
            for day in pd.date_range("2024-01-01", periods=15):
                for user in ["admin_1", "admin_2"]:
                    rows.append({
                        "timestamp": f"{day.date()} 09:00:00", "admin_id": user,
                        "action": "view_player_profile", "ip_address": "10.0.0.1",
                        "status": "Success", "is_attack": 0,
                    })
            rows.append({
                "timestamp": "2024-01-15 02:00:00", "admin_id": "admin_1",
                "action": "ban_player", "ip_address": "203.0.113.10",
                "status": "Fail", "is_attack": 1,
            })
            pd.DataFrame(rows).to_csv(path, index=False)
            events = load_game_admin_events(path)
            features = build_generic_feature_table(events)
            scored = score_generic_features(features, train_generic_model(features))
            self.assertEqual(events["is_malicious"].sum(), 1)
            self.assertTrue(scored["risk_score"].between(0, 100).all())
            self.assertTrue(scored["explanation"].str.len().gt(0).all())

    def test_network_adapter_preserves_groups_and_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "network.csv"
            frame = pd.DataFrame({
                "id": [1], "account": ["user@example.com"], "group": ["研发中心"],
                "IP": ["10.0.0.1"], "url": ["https://example.com"], "port": [443],
                "vlan": [700], "switchIP": ["10.0.0.2"], "time": ["2021/6/1 08:00"],
                "ret": [0.42],
            })
            frame.to_csv(path, index=False, encoding="gb18030")
            events = load_network_events(path)
            self.assertEqual(events.loc[0, "group"], "研发中心")
            self.assertAlmostEqual(events.loc[0, "provided_risk"], 0.42)


if __name__ == "__main__":
    unittest.main()
