from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pandas as pd

from src.adapters import load_cert_events
from src.demo_data import generate_demo_logs
from src.generic_features import build_generic_feature_table
from src.generic_modeling import score_generic_features, train_generic_model
from src.incidents import (
    apply_policy,
    correlate_alerts,
    create_suppression,
    ensure_policy,
    list_incidents,
    list_suppressions,
    promote_incident_to_case,
)
from src.modeling import evaluate
from src.engine import process_event_batch
from src.model_registry import build_candidate, list_models, promote_model
from src.storage import (
    connect_database,
    database_summary,
    get_case,
    ingest_events,
    list_alerts,
    list_cases,
    persist_model_run,
    record_feedback,
    update_case,
)


class PipelineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.raw_dir = Path(cls.temp_dir.name) / "raw"
        generate_demo_logs(cls.raw_dir)
        cls.events = load_cert_events(cls.raw_dir)
        cls.features = build_generic_feature_table(cls.events)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp_dir.cleanup()

    def test_feature_table_has_expected_shape_and_labels(self) -> None:
        self.assertGreater(len(self.features), 500)
        self.assertEqual(int(self.features["is_malicious"].sum()), 15)
        self.assertIn("personal_z_file_access_count", self.features.columns)
        self.assertIn("rolling_7d_sensitive_file_count", self.features.columns)
        self.assertFalse(self.features["user"].isna().any())

    def test_model_produces_bounded_explainable_risk(self) -> None:
        bundle = train_generic_model(self.features)
        scored = score_generic_features(self.features, bundle)
        self.assertTrue(scored["risk_score"].between(0, 100).all())
        self.assertTrue(scored["rule_score"].between(0, 100).all())
        self.assertTrue((scored["risk_score"] == scored["ml_risk_score"]).all())
        self.assertTrue(scored["explanation"].str.len().gt(0).all())
        malicious_mean = scored.loc[scored["is_malicious"] == 1, "risk_score"].mean()
        normal_mean = scored.loc[scored["is_malicious"] == 0, "risk_score"].mean()
        self.assertGreater(malicious_mean, normal_mean)

    def test_evaluation_detects_demo_attacks(self) -> None:
        bundle = train_generic_model(self.features)
        scored = score_generic_features(self.features, bundle)
        metrics = evaluate(scored, bundle["split_day"])
        self.assertGreaterEqual(metrics["recall"], 0.50)
        self.assertGreaterEqual(metrics["malicious_in_top_10"], 2)
        self.assertIn("baseline_recall", metrics)
        self.assertGreaterEqual(metrics["baseline_recall"], 0.33)

    def test_sqlite_ingestion_is_idempotent_and_scores_are_persisted(self) -> None:
        bundle = train_generic_model(self.features)
        scored = score_generic_features(self.features, bundle)
        with tempfile.TemporaryDirectory() as directory:
            with connect_database(Path(directory) / "ueba.db") as connection:
                first = ingest_events(connection, self.events)
                second = ingest_events(connection, self.events)
                persist_model_run(connection, bundle, scored, {}, "cert_style", "test-v2")
                ensure_policy(connection, "cert_style")
                apply_policy(connection, "cert_style")
                correlation = correlate_alerts(connection)
                incidents = list_incidents(connection)
                summary = database_summary(connection)
                incident_id = int(incidents.iloc[0]["incident_id"])
                case_id = promote_incident_to_case(connection, incident_id, "analyst-1")
                _, linked_alerts = get_case(connection, case_id)[:2]
                alert_id = int(linked_alerts.iloc[0]["alert_id"])
                record_feedback(connection, alert_id, "confirmed_threat", "analyst-1", "Validated in test")
                update_case(connection, case_id, "resolved", "analyst-1", "confirmed_threat", "Contained")
                case, case_alerts, feedback = get_case(connection, case_id)
                cases = list_cases(connection)
                suppression_user = str(list_alerts(connection).iloc[0]["user_id"])
                create_suppression(connection, "cert_style", "Expected automation", suppression_user)
                suppressions = list_suppressions(connection)
        self.assertEqual(first, len(self.events))
        self.assertEqual(second, 0)
        self.assertEqual(summary["events"], len(self.events))
        self.assertEqual(summary["entity_scores"], len(scored))
        self.assertGreater(summary["alerts"], 0)
        self.assertEqual(case["status"], "resolved")
        self.assertGreaterEqual(len(case_alerts), 1)
        self.assertEqual(len(feedback), 1)
        self.assertEqual(len(cases), 1)
        self.assertGreater(correlation["newly_correlated_alerts"], 0)
        self.assertGreater(len(incidents), 0)
        self.assertEqual(len(suppressions), 1)

    def test_incremental_engine_ignores_duplicate_batches(self) -> None:
        events = self.events.copy()
        events["source_dataset"] = "incremental_test"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = process_event_batch(events, root / "ueba.db", root / "artifacts", retrain=True)
            second = process_event_batch(events, root / "ueba.db", root / "artifacts")
            next_event = events.tail(1).copy()
            next_event["event_id"] = "incremental-new-event"
            next_event["event_time"] = next_event["event_time"] + pd.Timedelta(days=1)
            third = process_event_batch(next_event, root / "ueba.db", root / "artifacts")
        self.assertEqual(first["inserted_events"], len(events))
        self.assertTrue(first["model_retrained"])
        self.assertGreater(first["open_incidents"], 0)
        self.assertEqual(second["inserted_events"], 0)
        self.assertFalse(second["rescored"])
        self.assertEqual(third["inserted_events"], 1)
        self.assertFalse(third["model_retrained"])

    def test_candidate_model_requires_explicit_promotion(self) -> None:
        events = self.events.copy()
        events["source_dataset"] = "registry_test"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "ueba.db"
            artifacts = root / "artifacts"
            process_event_batch(events, database, artifacts, retrain=True)
            candidate = build_candidate(database, artifacts, "registry_test")
            before = list_models(database, "registry_test")
            result = promote_model(
                database, artifacts, candidate["model_version"], "test-admin"
            )
            second_candidate = build_candidate(database, artifacts, "registry_test")
            promote_model(database, artifacts, second_candidate["model_version"], "test-admin")
            rollback = promote_model(
                database, artifacts, candidate["model_version"], "test-admin"
            )
            after = list_models(database, "registry_test")
        self.assertEqual(before[0]["status"], "candidate")
        self.assertEqual(result["promoted_model"], candidate["model_version"])
        self.assertEqual(rollback["promoted_model"], candidate["model_version"])
        statuses = {model["model_version"]: model["status"] for model in after}
        self.assertEqual(statuses[candidate["model_version"]], "active")
        self.assertEqual(statuses[second_candidate["model_version"]], "archived")


if __name__ == "__main__":
    unittest.main()
