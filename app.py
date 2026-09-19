"""SentinelUEBA Streamlit investigation dashboard."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.features import build_feature_table
from src.modeling import score_features, train_model
from src.workflow import bootstrap_demo

ROOT = Path(__file__).resolve().parent
ARTIFACTS = ROOT / "artifacts"

st.set_page_config(page_title="SentinelUEBA", page_icon="🛡️", layout="wide")


@st.cache_resource
def ensure_demo() -> dict:
    return bootstrap_demo(ROOT)


@st.cache_data
def load_results() -> tuple[pd.DataFrame, dict]:
    frame = pd.read_csv(ARTIFACTS / "scored_activity.csv", parse_dates=["day"])
    metrics = json.loads((ARTIFACTS / "metrics.json").read_text(encoding="utf-8"))
    return frame, metrics


ensure_demo()
data, metrics = load_results()

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
page = st.sidebar.radio("Navigate", ["Security overview", "Alert investigation", "User profile", "Analyze logs", "Model performance", "About"])
split_day = pd.Timestamp(metrics["split_day"])
test_data = data[data["day"] >= split_day].copy()

if page == "Security overview":
    st.title("Security overview")
    st.caption(f"Evaluation window beginning {split_day.date()} · synthetic CERT-style demonstration")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Users monitored", test_data["user"].nunique())
    c2.metric("User-days analyzed", f"{len(test_data):,}")
    c3.metric("High-risk alerts", int(test_data["is_alert"].sum()))
    c4.metric("Highest risk", f"{int(test_data['risk_score'].max())}/100")

    left, right = st.columns([1.5, 1])
    with left:
        daily_risk = test_data.groupby("day", as_index=False)["risk_score"].max()
        fig = px.line(daily_risk, x="day", y="risk_score", markers=True, title="Maximum daily entity risk")
        fig.add_hline(y=70, line_dash="dash", line_color="#ff6b6b", annotation_text="Alert threshold")
        st.plotly_chart(fig, use_container_width=True)
    with right:
        counts = test_data["severity"].value_counts().reindex(["Critical", "High", "Medium", "Low"], fill_value=0)
        fig = px.bar(x=counts.index, y=counts.values, color=counts.index, title="Risk distribution",
                     color_discrete_map={"Critical":"#d62728", "High":"#ff7f0e", "Medium":"#f2c94c", "Low":"#2ca02c"})
        fig.update_layout(showlegend=False, xaxis_title=None, yaxis_title="User-days")
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Highest-priority entities")
    top = test_data.nlargest(10, "risk_score")[["day", "user", "risk_score", "severity", "explanation", "scenario"]]
    st.dataframe(top, use_container_width=True, hide_index=True)

elif page == "Alert investigation":
    st.title("Alert investigation")
    min_risk = st.slider("Minimum risk score", 0, 100, 45)
    severities = st.multiselect("Severity", ["Critical", "High", "Medium", "Low"], default=["Critical", "High", "Medium"])
    filtered = test_data[(test_data["risk_score"] >= min_risk) & test_data["severity"].isin(severities)]
    st.caption(f"Showing {len(filtered)} of {len(test_data)} user-days")
    st.dataframe(
        filtered.sort_values("risk_score", ascending=False)[
            ["day", "user", "risk_score", "severity", "explanation", "is_malicious", "scenario"]
        ],
        use_container_width=True,
        hide_index=True,
    )

elif page == "User profile":
    st.title("Entity profile")
    default_user = test_data.nlargest(1, "risk_score")["user"].iloc[0]
    users = sorted(data["user"].unique())
    selected = st.selectbox("Select user", users, index=users.index(default_user))
    user_data = data[data["user"] == selected].sort_values("day")
    peak = user_data.loc[user_data["risk_score"].idxmax()]
    c1, c2, c3 = st.columns(3)
    c1.metric("Peak risk", f"{int(peak['risk_score'])}/100")
    c2.metric("Peak severity", peak["severity"])
    c3.metric("Alerts", int(user_data["is_alert"].sum()))
    st.info(f"Top explanation: {peak['explanation']}")

    fig = px.line(user_data, x="day", y="risk_score", markers=True, title=f"Risk history for {selected}")
    fig.add_hline(y=70, line_dash="dash", line_color="#ff6b6b")
    st.plotly_chart(fig, use_container_width=True)
    behavior_columns = ["file_access_count", "sensitive_file_count", "removable_file_count", "after_hours_logons"]
    melted = user_data.melt(id_vars="day", value_vars=behavior_columns, var_name="behavior", value_name="events")
    st.plotly_chart(px.line(melted, x="day", y="events", color="behavior", title="Behavioral activity"), use_container_width=True)
    st.dataframe(
        user_data.sort_values("day", ascending=False)[["day", "risk_score", "severity", "explanation", "scenario"]],
        use_container_width=True,
        hide_index=True,
    )

elif page == "Analyze logs":
    st.title("Analyze compatible logs")
    st.markdown(
        "Upload login, device, and file CSVs using the schemas in the README. "
        "Files are processed in a temporary directory and are not retained by the app."
    )
    logon_upload = st.file_uploader("logon.csv", type="csv", key="logon")
    device_upload = st.file_uploader("device.csv", type="csv", key="device")
    file_upload = st.file_uploader("file.csv", type="csv", key="file")
    label_upload = st.file_uploader("labels.csv (optional, evaluation only)", type="csv", key="labels")
    if st.button("Run behavioral analysis", type="primary", disabled=not all([logon_upload, device_upload, file_upload])):
        try:
            with st.spinner("Building behavioral profiles and training the model..."):
                with tempfile.TemporaryDirectory(prefix="sentinel-ueba-") as temp_dir:
                    raw = Path(temp_dir)
                    for name, upload in {
                        "logon.csv": logon_upload,
                        "device.csv": device_upload,
                        "file.csv": file_upload,
                        "labels.csv": label_upload,
                    }.items():
                        if upload is not None:
                            (raw / name).write_bytes(upload.getvalue())
                    uploaded_features = build_feature_table(raw)
                    uploaded_bundle = train_model(uploaded_features)
                    uploaded_results = score_features(uploaded_features, uploaded_bundle)
            st.session_state["uploaded_results"] = uploaded_results
            st.success(f"Analyzed {len(uploaded_results):,} user-days across {uploaded_results['user'].nunique()} users.")
        except Exception as exc:
            st.error(f"Analysis could not be completed: {exc}")

    if "uploaded_results" in st.session_state:
        uploaded_results = st.session_state["uploaded_results"]
        uploaded_alerts = uploaded_results[uploaded_results["is_alert"] == 1].sort_values("risk_score", ascending=False)
        st.subheader("Highest-risk uploaded activity")
        st.dataframe(
            uploaded_alerts[["day", "user", "risk_score", "severity", "explanation"]],
            use_container_width=True,
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
        st.plotly_chart(heatmap, use_container_width=True)
    with right:
        st.subheader("Evaluation details")
        comparison = pd.DataFrame(
            {
                "Approach": ["Isolation Forest + risk layer", "Fixed-threshold rules"],
                "Precision": [metrics["precision"], metrics["baseline_precision"]],
                "Recall": [metrics["recall"], metrics["baseline_recall"]],
                "F1": [metrics["f1"], metrics["baseline_f1"]],
                "Alerts": [metrics["alerts"], metrics["baseline_alerts"]],
            }
        )
        st.dataframe(comparison, use_container_width=True, hide_index=True)
        st.markdown("The chronological split prevents future activity from leaking into training. The fixed-rule baseline is intentionally rigid: it may be precise for known scenarios, but does not personalize thresholds or identify unknown behavioral patterns.")

else:
    st.title("About SentinelUEBA")
    st.markdown(
        """
        **SentinelUEBA** is an explainable, unsupervised anomaly-detection prototype.
        It builds behavioral baselines from user activity and ranks unusual user-days
        for analyst investigation.

        The model evaluates login timing, computer usage, removable devices, file
        volume, sensitive-file access, executable access, and deviations from both
        personal and organization baselines. A high score means *unusual*, not
        necessarily *malicious*.

        **Pipeline:** raw logs → daily aggregation → behavioral features → Isolation
        Forest → contextual risk score → explanations → investigation dashboard.

        This bundled demonstration uses deterministic synthetic data. It deliberately
        includes ground-truth attack scenarios so performance can be measured safely.
        """
    )
