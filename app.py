"""SentinelUEBA Streamlit investigation dashboard."""

from __future__ import annotations

import json
import sqlite3
import tempfile
from datetime import date, timedelta
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.adapters import load_cert_events
from src.engine import process_event_batch
from src.incidents import (
    apply_policy,
    calibrate_policy,
    correlate_alerts,
    create_suppression,
    deactivate_suppression,
    get_incident,
    list_incidents,
    list_policies,
    list_suppressions,
    operations_metrics,
    promote_incident_to_case,
)
from src.storage import (
    connect_database,
    create_case,
    get_case,
    list_alerts,
    list_cases,
    record_feedback,
    update_case,
)
from src.workflow import bootstrap_demo

ROOT = Path(__file__).resolve().parent
ARTIFACTS = ROOT / "artifacts"
EXTERNAL_ARTIFACTS = ARTIFACTS / "external"

st.set_page_config(page_title="SentinelUEBA", page_icon="🛡️", layout="wide")


@st.cache_resource
def ensure_demo() -> dict:
    return bootstrap_demo(ROOT)


@st.cache_data
def load_results(artifact_version: int) -> tuple[pd.DataFrame, dict]:
    del artifact_version  # Cache key that changes whenever the scored file changes.
    frame = pd.read_csv(ARTIFACTS / "scored_activity.csv", parse_dates=["day"])
    metrics = json.loads((ARTIFACTS / "metrics.json").read_text(encoding="utf-8"))
    return frame, metrics


@st.cache_data
def load_external_results(dataset: str, artifact_version: int) -> tuple[pd.DataFrame, dict]:
    """Load precomputed public-dataset results without rebuilding on page refresh."""
    del artifact_version
    stem = "game_admin" if dataset == "Game administrator activity" else "network"
    frame = pd.read_csv(EXTERNAL_ARTIFACTS / f"{stem}_scored.csv", parse_dates=["day"])
    metrics = json.loads((EXTERNAL_ARTIFACTS / f"{stem}_metrics.json").read_text(encoding="utf-8"))
    return frame, metrics


@st.cache_data(ttl=5)
def load_system_status() -> tuple[dict, pd.DataFrame, pd.DataFrame]:
    database_path = ARTIFACTS / "sentinel_ueba.db"
    if not database_path.exists():
        return {}, pd.DataFrame(), pd.DataFrame()
    with sqlite3.connect(database_path) as connection:
        counts = {
            table: int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in ["events", "model_runs", "entity_scores", "alerts", "incidents", "cases", "suppressions"]
        }
        runs = pd.read_sql_query(
            "SELECT model_version, source_dataset, trained_at, split_day, train_rows FROM model_runs ORDER BY trained_at DESC",
            connection,
        )
        alerts = pd.read_sql_query(
            """SELECT source_dataset, alert_type, status, COUNT(*) AS alert_count,
                      MAX(score) AS highest_score
               FROM alerts GROUP BY source_dataset, alert_type, status
               ORDER BY source_dataset, alert_type""",
            connection,
        )
    return counts, runs, alerts


ensure_demo()
data, metrics = load_results((ARTIFACTS / "scored_activity.csv").stat().st_mtime_ns)

st.markdown(
    """
    <style>
    .block-container {padding-top: 1.6rem; padding-bottom: 2rem;}
    [data-testid="stMetric"] {background:#101a2d; border:1px solid #263653; padding:14px; border-radius:12px;}
    </style>
    """,
    unsafe_allow_html=True,
)

st.sidebar.title("🛡️ SentinelUEBA")
st.sidebar.caption("Behavioral anomaly detection for insider-threat investigation")
page = st.sidebar.radio(
    "Navigate",
    [
        "Security overview",
        "Incident queue",
        "Alert investigation",
        "Case management",
        "User profile",
        "Public dataset lab",
        "System status",
        "Analyze logs",
        "Model performance",
        "About",
    ],
)
split_day = pd.Timestamp(metrics["split_day"])
test_data = data[data["day"] >= split_day].copy()

if page == "Security overview":
    st.title("Security overview")
    st.caption(f"Evaluation window beginning {split_day.date()} · synthetic CERT-style demonstration")
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Users monitored", test_data["user"].nunique())
    c2.metric("User-days analyzed", f"{len(test_data):,}")
    c3.metric("ML alerts", int(test_data["ml_alert"].sum()))
    c4.metric("Rule alerts", int(test_data["rule_alert"].sum()))
    c5.metric("Highest priority", f"{int(test_data['case_priority_score'].max())}/100")

    left, right = st.columns([1.5, 1])
    with left:
        daily_risk = test_data.groupby("day", as_index=False)[["ml_risk_score", "rule_score"]].max()
        daily_risk = daily_risk.melt("day", var_name="signal", value_name="score")
        fig = px.line(daily_risk, x="day", y="score", color="signal", markers=True, title="Independent daily risk signals")
        fig.add_hline(y=70, line_dash="dash", line_color="#ff6b6b", annotation_text="Alert threshold")
        st.plotly_chart(fig, width="stretch")
    with right:
        counts = test_data["case_severity"].value_counts().reindex(["Critical", "High", "Medium", "Low"], fill_value=0)
        fig = px.bar(x=counts.index, y=counts.values, color=counts.index, title="Risk distribution",
                     color_discrete_map={"Critical":"#d62728", "High":"#ff7f0e", "Medium":"#f2c94c", "Low":"#2ca02c"})
        fig.update_layout(showlegend=False, xaxis_title=None, yaxis_title="User-days")
        st.plotly_chart(fig, width="stretch")

    st.subheader("Highest-priority entities")
    top = test_data.nlargest(10, "case_priority_score")[[
        "day", "user", "ml_risk_score", "rule_score", "case_priority_score",
        "case_severity", "explanation", "rule_explanation", "scenario",
    ]]
    st.dataframe(top, width="stretch", hide_index=True)

elif page == "Incident queue":
    st.title("Incident queue")
    st.caption("Related alerts are correlated into multi-day entity incidents before analyst review.")
    database_path = ARTIFACTS / "sentinel_ueba.db"
    with connect_database(database_path) as connection:
        operational = operations_metrics(connection)
        i1, i2, i3, i4 = st.columns(4)
        i1.metric("Active raw alerts", f"{operational['open_alerts']:,}")
        i2.metric("Open incidents", f"{operational['open_incidents']:,}")
        i3.metric("Compression", f"{operational['compression_ratio']:.1f}×")
        i4.metric("Suppressed alerts", f"{operational['suppressed_alerts']:,}")

        incidents = list_incidents(connection)
        if incidents.empty:
            st.success("There are no open correlated incidents.")
        else:
            source_options = sorted(incidents["source_dataset"].unique())
            selected_sources = st.multiselect("Incident sources", source_options, default=source_options)
            minimum_priority = st.slider("Minimum incident priority", 0, 100, 50)
            incident_view = incidents[
                incidents["source_dataset"].isin(selected_sources)
                & incidents["priority_score"].ge(minimum_priority)
            ]
            st.dataframe(incident_view, width="stretch", hide_index=True)
            if not incident_view.empty:
                incident_id = st.selectbox("Inspect incident", incident_view["incident_id"].astype(int).tolist())
                incident, incident_alerts = get_incident(connection, int(incident_id))
                st.info(incident["summary"])
                st.dataframe(incident_alerts, width="stretch", hide_index=True)
                assignee = st.text_input("Assign promoted case to", placeholder="Analyst name or team")
                if st.button("Promote incident to investigation case", type="primary"):
                    try:
                        case_id = promote_incident_to_case(connection, int(incident_id), assignee)
                        st.success(f"Incident #{incident_id} was promoted to case #{case_id}.")
                        st.cache_data.clear()
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Incident could not be promoted: {exc}")

                with st.expander("Create a temporary suppression"):
                    suppress_all_users = st.checkbox("Apply to every entity in this source", value=False)
                    suppression_type = st.selectbox(
                        "Signal type", ["All signals", "ML anomaly", "Rule match"]
                    )
                    suppression_reason = st.text_input("Suppression reason")
                    suppression_expiry = st.date_input(
                        "Expires", value=date.today() + timedelta(days=30), min_value=date.today()
                    )
                    if st.button("Create suppression", disabled=not suppression_reason.strip()):
                        type_value = {
                            "All signals": "", "ML anomaly": "ml_anomaly", "Rule match": "rule_match"
                        }[suppression_type]
                        try:
                            suppression_id = create_suppression(
                                connection,
                                incident["source_dataset"],
                                suppression_reason,
                                "" if suppress_all_users else incident["user_id"],
                                type_value,
                                suppression_expiry.isoformat(),
                            )
                            st.success(f"Created suppression #{suppression_id} with a recorded reason and expiry.")
                            st.cache_data.clear()
                            st.rerun()
                        except Exception as exc:
                            st.error(f"Suppression could not be created: {exc}")

        with st.expander("Detection policies"):
            policies = list_policies(connection)
            st.dataframe(policies, width="stretch", hide_index=True)
            if not policies.empty:
                policy_source = st.selectbox("Configure source", policies["source_dataset"].tolist())
                current = policies[policies["source_dataset"] == policy_source].iloc[0]
                budget_percent = st.slider(
                    "Historical review budget (%)", 0.5, 20.0,
                    float(current["review_budget_fraction"] * 100), 0.5,
                )
                rule_enabled = st.checkbox("Enable deterministic rule alerts", bool(current["rule_enabled"]))
                rule_threshold = st.slider("Rule threshold", 1, 100, int(current["rule_threshold"]))
                correlation_window = st.slider(
                    "Correlation window (days)", 1, 30, int(current["correlation_window_days"])
                )
                if st.button("Calibrate and apply policy"):
                    try:
                        calibration = calibrate_policy(
                            connection,
                            policy_source,
                            budget_percent / 100,
                            rule_enabled,
                            rule_threshold,
                            correlation_window,
                        )
                        applied = apply_policy(connection, policy_source)
                        correlated = correlate_alerts(connection)
                        st.success(
                            f"Policy applied at ML threshold {calibration['ml_threshold']}; "
                            f"{applied['open_ml_alerts']} ML and {applied['open_rule_alerts']} rule alerts remain open. "
                            f"The queue now contains {correlated['open_incidents']} incidents."
                        )
                        st.cache_data.clear()
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Policy could not be applied: {exc}")

        with st.expander("Suppression registry"):
            suppressions = list_suppressions(connection)
            st.dataframe(suppressions, width="stretch", hide_index=True)
            active_suppressions = suppressions[suppressions["active"].eq(1)] if not suppressions.empty else suppressions
            if not active_suppressions.empty:
                suppression_to_disable = st.selectbox(
                    "Deactivate suppression", active_suppressions["suppression_id"].astype(int).tolist()
                )
                if st.button("Deactivate selected suppression"):
                    deactivate_suppression(connection, int(suppression_to_disable))
                    st.success("Suppression deactivated. Previously suppressed alerts remain in the audit trail.")
                    st.cache_data.clear()
                    st.rerun()

elif page == "Alert investigation":
    st.title("Alert investigation")
    ranking = st.selectbox("Ranking", ["Case priority", "ML anomaly", "Rule match"])
    score_column = {"Case priority": "case_priority_score", "ML anomaly": "ml_risk_score", "Rule match": "rule_score"}[ranking]
    min_risk = st.slider("Minimum risk score", 0, 100, 45)
    severities = st.multiselect("Severity", ["Critical", "High", "Medium", "Low"], default=["Critical", "High", "Medium"])
    filtered = test_data[(test_data[score_column] >= min_risk) & test_data["case_severity"].isin(severities)]
    st.caption(f"Showing {len(filtered)} of {len(test_data)} user-days")
    st.dataframe(
        filtered.sort_values(score_column, ascending=False)[
            ["day", "user", "ml_risk_score", "rule_score", "case_priority_score", "case_severity",
             "explanation", "rule_explanation", "is_malicious", "scenario"]
        ],
        width="stretch",
        hide_index=True,
    )

elif page == "Case management":
    st.title("Case management")
    st.caption("Create investigations from persisted alerts and record the analyst decision trail.")
    database_path = ARTIFACTS / "sentinel_ueba.db"
    with connect_database(database_path) as connection:
        queue_tab, cases_tab = st.tabs(["Alert queue", "Investigation cases"])
        with queue_tab:
            queue = list_alerts(connection, status="open", limit=1000)
            if queue.empty:
                st.success("There are no untriaged alerts in the queue.")
            else:
                source_filter = st.multiselect(
                    "Sources", sorted(queue["source_dataset"].unique()),
                    default=sorted(queue["source_dataset"].unique()),
                )
                queue_view = queue[queue["source_dataset"].isin(source_filter)].copy()
                st.dataframe(queue_view, width="stretch", hide_index=True)
                if queue_view.empty:
                    st.info("No open alerts match the selected sources.")
                else:
                    user_options = sorted(queue_view["user_id"].unique())
                    selected_user = st.selectbox("Entity to investigate", user_options)
                    user_alerts = queue_view[queue_view["user_id"] == selected_user]
                    alert_options = user_alerts["alert_id"].astype(int).tolist()
                    selected_alerts = st.multiselect(
                        "Alerts to include", alert_options,
                        default=alert_options[: min(5, len(alert_options))],
                    )
                    case_title = st.text_input("Case title", value=f"Investigate anomalous activity for {selected_user}")
                    assigned_to = st.text_input("Assign to", placeholder="Analyst name or team")
                    if st.button("Create investigation case", type="primary", disabled=not selected_alerts):
                        try:
                            case_id = create_case(connection, selected_alerts, case_title, assigned_to)
                            st.success(f"Created case #{case_id} with {len(selected_alerts)} alert(s).")
                            st.cache_data.clear()
                            st.rerun()
                        except Exception as exc:
                            st.error(f"Case could not be created: {exc}")

        with cases_tab:
            cases = list_cases(connection)
            if cases.empty:
                st.info("No investigation cases have been created yet.")
            else:
                st.dataframe(cases, width="stretch", hide_index=True)
                selected_case_id = st.selectbox("Open case", cases["case_id"].astype(int).tolist())
                case, case_alerts, feedback = get_case(connection, int(selected_case_id))
                status_options = ["open", "investigating", "resolved", "closed"]
                disposition_options = ["", "confirmed_threat", "false_positive", "benign_expected", "inconclusive"]
                status = st.selectbox("Status", status_options, index=status_options.index(case["status"]))
                assignee = st.text_input("Assigned analyst", value=case.get("assigned_to", ""))
                current_disposition = case.get("disposition") or ""
                disposition = st.selectbox(
                    "Disposition", disposition_options,
                    index=disposition_options.index(current_disposition),
                )
                notes = st.text_area("Investigation notes", value=case.get("analyst_notes", ""), height=140)
                if st.button("Save case"):
                    try:
                        update_case(connection, int(selected_case_id), status, assignee, disposition, notes)
                        st.success("Case updated.")
                        st.cache_data.clear()
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Case could not be updated: {exc}")

                st.subheader("Linked alerts")
                st.dataframe(case_alerts, width="stretch", hide_index=True)
                if not case_alerts.empty:
                    feedback_alert = st.selectbox("Alert for analyst verdict", case_alerts["alert_id"].astype(int).tolist())
                    verdict = st.selectbox(
                        "Verdict",
                        ["needs_more_information", "confirmed_threat", "false_positive", "benign_expected"],
                    )
                    feedback_analyst = st.text_input("Analyst recording verdict", value=assignee)
                    feedback_comment = st.text_area("Verdict evidence", height=100)
                    if st.button("Record analyst verdict"):
                        try:
                            record_feedback(
                                connection, int(feedback_alert), verdict, feedback_analyst, feedback_comment
                            )
                            st.success("Analyst verdict recorded in the audit trail.")
                            st.cache_data.clear()
                            st.rerun()
                        except Exception as exc:
                            st.error(f"Verdict could not be recorded: {exc}")
                if not feedback.empty:
                    st.subheader("Feedback history")
                    st.dataframe(feedback, width="stretch", hide_index=True)

elif page == "User profile":
    st.title("Entity profile")
    default_user = test_data.nlargest(1, "risk_score")["user"].iloc[0]
    users = sorted(data["user"].unique())
    selected = st.selectbox("Select user", users, index=users.index(default_user))
    user_data = data[data["user"] == selected].sort_values("day")
    peak = user_data.loc[user_data["risk_score"].idxmax()]
    c1, c2, c3 = st.columns(3)
    c1.metric("Peak priority", f"{int(user_data['case_priority_score'].max())}/100")
    c2.metric("Peak severity", user_data.loc[user_data["case_priority_score"].idxmax(), "case_severity"])
    c3.metric("ML / rule alerts", f"{int(user_data['ml_alert'].sum())} / {int(user_data['rule_alert'].sum())}")
    st.info(f"Top explanation: {peak['explanation']}")

    risk_history = user_data.melt(
        id_vars="day", value_vars=["ml_risk_score", "rule_score", "case_priority_score"],
        var_name="signal", value_name="score",
    )
    fig = px.line(risk_history, x="day", y="score", color="signal", markers=True, title=f"Risk history for {selected}")
    fig.add_hline(y=70, line_dash="dash", line_color="#ff6b6b")
    st.plotly_chart(fig, width="stretch")
    behavior_columns = ["file_access_count", "sensitive_file_count", "removable_file_count", "after_hours_logons"]
    melted = user_data.melt(id_vars="day", value_vars=behavior_columns, var_name="behavior", value_name="events")
    st.plotly_chart(px.line(melted, x="day", y="events", color="behavior", title="Behavioral activity"), width="stretch")
    st.dataframe(
        user_data.sort_values("day", ascending=False)[[
            "day", "ml_risk_score", "rule_score", "case_priority_score", "case_severity",
            "explanation", "rule_explanation", "scenario",
        ]],
        width="stretch",
        hide_index=True,
    )

elif page == "Public dataset lab":
    st.title("Public dataset lab")
    st.caption("The same behavior-first pipeline applied to the two public Kaggle datasets selected for this project.")
    dataset_name = st.selectbox(
        "Dataset",
        ["Game administrator activity", "Enterprise network access"],
    )
    review_threshold = st.slider(
        "Analyst review threshold",
        min_value=0,
        max_value=100,
        value=70,
        help="Lower values catch more unusual behavior but send more cases to analysts.",
    )
    stem = "game_admin" if dataset_name == "Game administrator activity" else "network"
    required = [EXTERNAL_ARTIFACTS / f"{stem}_scored.csv", EXTERNAL_ARTIFACTS / f"{stem}_metrics.json"]
    if not all(path.exists() for path in required):
        st.warning("External artifacts have not been built yet. Run `python scripts/build_external_datasets.py`.")
        st.stop()

    external, external_metrics = load_external_results(
        dataset_name,
        (EXTERNAL_ARTIFACTS / f"{stem}_scored.csv").stat().st_mtime_ns,
    )
    external_test = external[external["day"] >= pd.Timestamp(external_metrics["split_day"])].copy()
    external_test["review_alert"] = (external_test["risk_score"] >= review_threshold).astype(int)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Raw events", f"{external_metrics['event_rows']:,}")
    c2.metric("Users", f"{external_metrics['users']:,}")
    c3.metric("User-days", f"{len(external):,}")
    c4.metric("Review alerts", f"{int(external_test['review_alert'].sum()):,}")

    left, right = st.columns([1.45, 1])
    with left:
        daily = external_test.groupby("day", as_index=False).agg(
            maximum_risk=("risk_score", "max"),
            alerts=("review_alert", "sum"),
        )
        risk_figure = px.line(
            daily,
            x="day",
            y="maximum_risk",
            markers=True,
            title="Maximum daily risk in the evaluation window",
        )
        risk_figure.add_hline(
            y=review_threshold,
            line_dash="dash",
            line_color="#ff6b6b",
            annotation_text="Review threshold",
        )
        st.plotly_chart(risk_figure, width="stretch")
    with right:
        severity_counts = external_test["severity"].value_counts().reindex(
            ["Critical", "High", "Medium", "Low"], fill_value=0
        )
        severity_figure = px.bar(
            x=severity_counts.index,
            y=severity_counts.values,
            color=severity_counts.index,
            title="Risk distribution",
            color_discrete_map={"Critical": "#d62728", "High": "#ff7f0e", "Medium": "#f2c94c", "Low": "#2ca02c"},
        )
        severity_figure.update_layout(showlegend=False, xaxis_title=None, yaxis_title="User-days")
        st.plotly_chart(severity_figure, width="stretch")

    if dataset_name == "Game administrator activity":
        st.subheader("Label-based evaluation")
        st.caption("Attack labels are held out of model training and used only to evaluate ranked alerts.")
        labels = external_test["is_malicious"].astype(bool)
        predictions = external_test["review_alert"].astype(bool)
        true_positives = int((labels & predictions).sum())
        false_positives = int((~labels & predictions).sum())
        false_negatives = int((labels & ~predictions).sum())
        current_precision = true_positives / max(1, true_positives + false_positives)
        current_recall = true_positives / max(1, true_positives + false_negatives)
        current_f1 = 2 * current_precision * current_recall / max(1e-12, current_precision + current_recall)
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Precision", f"{current_precision:.1%}")
        m2.metric("Recall", f"{current_recall:.1%}")
        m3.metric("F1", f"{current_f1:.3f}")
        m4.metric("PR-AUC", f"{external_metrics['pr_auc']:.3f}")
        st.info(
            f"At threshold {review_threshold}, the model raised {int(predictions.sum())} alerts for "
            f"{external_metrics['malicious_rows']} malicious user-days in the evaluation window. "
            f"That includes {true_positives} detected attacks, {false_positives} false alerts, and "
            f"{false_negatives} missed attacks. Move the threshold to explore the operational tradeoff."
        )
    else:
        st.subheader("Unlabeled exploratory evaluation")
        st.warning(
            "This dataset has no documented attack label. Its `ret` column is not used for training or presented "
            "as ground truth. The displayed alerts are candidates for analyst review, not confirmed attacks."
        )
        st.caption(
            f"Spearman association between our daily risk and the supplied daily mean `ret`: "
            f"{external_metrics['risk_ret_spearman']:.3f}. A negative value reinforces that `ret` should not be "
            "assumed to mean attack probability without source documentation."
        )

    st.subheader("Highest-risk behavior")
    visible_columns = [
        "day", "user", "group", "ml_risk_score", "rule_score", "case_priority_score",
        "case_severity", "event_count", "after_hours_count",
        "unique_ips", "unique_resources", "new_ip_count", "explanation",
    ]
    if dataset_name == "Game administrator activity":
        visible_columns.insert(5, "is_malicious")
    st.dataframe(
        external_test.nlargest(25, "risk_score")[visible_columns],
        width="stretch",
        hide_index=True,
    )

elif page == "System status":
    st.title("System status")
    st.caption("Persistent state from the local SentinelUEBA SQLite backend.")
    counts, runs, stored_alerts = load_system_status()
    if not counts:
        st.warning("The persistent database has not been initialized.")
    else:
        count_items = list(counts.items())
        for start in range(0, len(count_items), 4):
            columns = st.columns(4)
            for column, (label, value) in zip(columns, count_items[start:start + 4]):
                column.metric(label.replace("_", " ").title(), f"{value:,}")
        st.subheader("Registered model runs")
        st.dataframe(runs, width="stretch", hide_index=True)
        st.subheader("Persistent alert inventory")
        st.dataframe(stored_alerts, width="stretch", hide_index=True)
        with sqlite3.connect(ARTIFACTS / "sentinel_ueba.db") as connection:
            ingestion_runs = pd.read_sql_query(
                """SELECT ingestion_id, source_dataset, started_at, completed_at, received_events,
                          inserted_events, status, message
                   FROM ingestion_runs ORDER BY ingestion_id DESC LIMIT 25""",
                connection,
            )
        st.subheader("Recent ingestion runs")
        st.dataframe(ingestion_runs, width="stretch", hide_index=True)
        st.info(
            "Event ingestion is idempotent: importing the same source event twice does not duplicate it. "
            "ML anomaly alerts and deterministic rule alerts remain separate records."
        )

elif page == "Analyze logs":
    st.title("Analyze compatible logs")
    st.markdown(
        "Upload login, device, and file CSVs using the schemas in the README. "
        "Normalized events are stored in the local database; repeat uploads are deduplicated by event ID."
    )
    source_name = st.text_input("Source name", value="uploaded_cert", help="Stable identifier used for deduplication and model reuse.")
    logon_upload = st.file_uploader("logon.csv", type="csv", key="logon")
    device_upload = st.file_uploader("device.csv", type="csv", key="device")
    file_upload = st.file_uploader("file.csv", type="csv", key="file")
    admin_upload = st.file_uploader("admin.csv (optional)", type="csv", key="admin")
    label_upload = st.file_uploader("labels.csv (optional, evaluation only)", type="csv", key="labels")
    retrain_uploaded = st.checkbox("Retrain this source's model", value=False)
    if st.button("Ingest and score events", type="primary", disabled=not all([logon_upload, device_upload, file_upload])):
        try:
            with st.spinner("Persisting events and updating behavioral scores..."):
                with tempfile.TemporaryDirectory(prefix="sentinel-ueba-") as temp_dir:
                    raw = Path(temp_dir)
                    for name, upload in {
                        "logon.csv": logon_upload,
                        "device.csv": device_upload,
                        "file.csv": file_upload,
                        "admin.csv": admin_upload,
                        "labels.csv": label_upload,
                    }.items():
                        if upload is not None:
                            (raw / name).write_bytes(upload.getvalue())
                    uploaded_events = load_cert_events(raw)
                    uploaded_events["source_dataset"] = source_name.strip() or "uploaded_cert"
                    ingestion = process_event_batch(
                        uploaded_events,
                        ARTIFACTS / "sentinel_ueba.db",
                        ARTIFACTS / "live",
                        retrain=retrain_uploaded,
                    )
            st.session_state["ingestion_result"] = ingestion
            if ingestion.get("rescored") is False:
                st.info("Every event in this upload was already stored; no rescore was necessary.")
            else:
                uploaded_results = pd.read_csv(ingestion["scores_path"], parse_dates=["day"])
                st.session_state["uploaded_results"] = uploaded_results
                st.success(
                    f"Stored {ingestion['inserted_events']:,} new events and scored "
                    f"{ingestion['scored_user_days']:,} user-days."
                )
            st.cache_data.clear()
        except Exception as exc:
            st.error(f"Ingestion could not be completed: {exc}")

    if "ingestion_result" in st.session_state:
        st.subheader("Latest ingestion")
        st.json(st.session_state["ingestion_result"])

    if "uploaded_results" in st.session_state:
        uploaded_results = st.session_state["uploaded_results"]
        uploaded_alerts = uploaded_results[uploaded_results["is_alert"] == 1].sort_values("risk_score", ascending=False)
        st.subheader("Highest-risk uploaded activity")
        st.dataframe(
            uploaded_alerts[["day", "user", "risk_score", "severity", "explanation"]],
            width="stretch",
            hide_index=True,
        )
        st.download_button(
            "Download scored results",
            uploaded_results.to_csv(index=False).encode("utf-8"),
            file_name="sentinel_ueba_results.csv",
            mime="text/csv",
        )

elif page == "Model performance":
    st.title("Model performance")
    st.caption("Labels are used only for evaluation, never as model training targets.")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Precision", f"{metrics['precision']:.1%}")
    c2.metric("Recall", f"{metrics['recall']:.1%}")
    c3.metric("F1 score", f"{metrics['f1']:.1%}")
    c4.metric("PR-AUC", f"{metrics['pr_auc']:.3f}")

    actual = test_data["is_malicious"].astype(int)
    predicted = test_data["is_alert"].astype(int)
    matrix = pd.DataFrame(
        [[int(((actual == 0) & (predicted == 0)).sum()), int(((actual == 0) & (predicted == 1)).sum())],
         [int(((actual == 1) & (predicted == 0)).sum()), int(((actual == 1) & (predicted == 1)).sum())]],
        index=["Actually normal", "Actually malicious"],
        columns=["Predicted normal", "Predicted alert"],
    )
    left, right = st.columns(2)
    with left:
        heatmap = go.Figure(data=go.Heatmap(z=matrix.values, x=matrix.columns, y=matrix.index, text=matrix.values, texttemplate="%{text}", colorscale="Purples"))
        heatmap.update_layout(title="Confusion matrix")
        st.plotly_chart(heatmap, width="stretch")
    with right:
        st.subheader("Evaluation details")
        comparison = pd.DataFrame(
            {
                "Approach": ["Isolation Forest anomaly ranking", "Fixed-threshold rules"],
                "Precision": [metrics["precision"], metrics["baseline_precision"]],
                "Recall": [metrics["recall"], metrics["baseline_recall"]],
                "F1": [metrics["f1"], metrics["baseline_f1"]],
                "Alerts": [metrics["alerts"], metrics["baseline_alerts"]],
            }
        )
        st.dataframe(comparison, width="stretch", hide_index=True)
        st.markdown("The chronological split prevents future activity from leaking into training. The fixed-rule baseline is intentionally rigid: it may be precise for known scenarios, but does not personalize thresholds or identify unknown behavioral patterns.")

    evaluation_path = ARTIFACTS / "evaluation_summary.json"
    if evaluation_path.exists():
        repeated = json.loads(evaluation_path.read_text(encoding="utf-8"))
        st.subheader("Held-out generator seeds")
        st.caption(f"Results across {repeated['runs']} independently generated datasets: {repeated['seeds']}")
        e1, e2, e3, e4 = st.columns(4)
        e1.metric("Mean PR-AUC", f"{repeated['mean']['pr_auc']:.3f}", help=f"σ {repeated['std']['pr_auc']:.3f}")
        e2.metric("Mean recall", f"{repeated['mean']['recall']:.1%}", help=f"Minimum {repeated['minimum']['recall']:.1%}")
        e3.metric("Incident recall", f"{repeated['mean']['incident_recall']:.1%}")
        e4.metric("Mean review budget", f"{repeated['mean']['alert_budget_fraction']:.1%}")

else:
    st.title("About SentinelUEBA")
    st.markdown(
        """
        **SentinelUEBA** is an operational lab-scale User and Entity Behavior Analytics
        system. It builds behavioral baselines from user activity, persists alerts,
        and supports analyst investigation cases and verdicts.

        The model evaluates login timing, computer usage, removable devices, file
        volume, sensitive-file access, executable access, and deviations from both
        personal and organization baselines. A high score means *unusual*, not
        necessarily *malicious*.

        **Pipeline:** raw logs → canonical events → rolling behavioral features →
        independent ML and rule scores → correlated incidents → investigation cases.

        This bundled demonstration uses deterministic synthetic data. It deliberately
        includes ground-truth attack scenarios so performance can be measured safely.

        The **Public dataset lab** page runs the same core approach on both selected
        Kaggle datasets. Only the game-administrator dataset has explicit attack labels;
        the network dataset is treated as unlabeled because its `ret` field is not documented.
        """
    )
