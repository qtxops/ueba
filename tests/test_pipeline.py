from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.demo_data import generate_demo_logs
from src.features import build_feature_table
from src.modeling import evaluate, score_features, train_model


class PipelineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.raw_dir = Path(cls.temp_dir.name) / "raw"
        generate_demo_logs(cls.raw_dir)
        cls.features = build_feature_table(cls.raw_dir)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp_dir.cleanup()

    def test_feature_table_has_expected_shape_and_labels(self) -> None:
        self.assertGreater(len(self.features), 500)
        self.assertEqual(int(self.features["is_malicious"].sum()), 3)
        self.assertIn("personal_z_file_access_count", self.features.columns)
        self.assertFalse(self.features["user"].isna().any())

    def test_model_produces_bounded_explainable_risk(self) -> None:
        bundle = train_model(self.features)
        scored = score_features(self.features, bundle)
        self.assertTrue(scored["risk_score"].between(0, 100).all())
        self.assertTrue(scored["explanation"].str.len().gt(0).all())
        malicious_mean = scored.loc[scored["is_malicious"] == 1, "risk_score"].mean()
        normal_mean = scored.loc[scored["is_malicious"] == 0, "risk_score"].mean()
        self.assertGreater(malicious_mean, normal_mean)

    def test_evaluation_detects_demo_attacks(self) -> None:
        bundle = train_model(self.features)
        scored = score_features(self.features, bundle)
        metrics = evaluate(scored, bundle["split_day"])
        self.assertGreaterEqual(metrics["recall"], 0.66)
        self.assertGreaterEqual(metrics["malicious_in_top_10"], 2)
        self.assertIn("baseline_recall", metrics)
        self.assertGreaterEqual(metrics["baseline_recall"], 0.33)


if __name__ == "__main__":
    unittest.main()
