"""API-only analyst console used by the containerized deployment."""

from __future__ import annotations

import os

import pandas as pd
import streamlit as st

from src.api_client import SentinelApiClient, SentinelApiError


API_URL = os.getenv("SENTINEL_API_URL", "http://127.0.0.1:8000")

st.set_page_config(page_title="SentinelUEBA Operations", page_icon="🛡️", layout="wide")
st.title("SentinelUEBA Operations")
st.caption("Authenticated incident response console · behavior analytics and explainable anomaly ranking")


def login_screen() -> None:
    st.subheader("Sign in")
    st.write("Use an analyst or administrator account issued by your SentinelUEBA administrator.")
    with st.form("login"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Sign in", type="primary")
    if submitted:
        try:
            token = SentinelApiClient(API_URL).login(username, password)
            st.session_state["token"] = token
            st.rerun()
        except SentinelApiError as exc:
            st.error(str(exc))


if "token" not in st.session_state:
    login_screen()
    st.stop()

client = SentinelApiClient(API_URL, st.session_state["token"])
try:
    identity = client.get("/auth/me")
except SentinelApiError as exc:
    st.session_state.pop("token", None)
    st.error(f"Your session could not be validated: {exc}")
    st.stop()

with st.sidebar:
    st.success(f"{identity['username']} · {identity['role']}")
    page = st.radio("Workspace", ["Overview", "Incidents", "Cases", "System"])
    if st.button("Sign out"):
        st.session_state.pop("token", None)
        st.rerun()

try:
    if page == "Overview":
        metrics = client.get("/system/metrics")
        columns = st.columns(5)
        for column, label, key in zip(
            columns,
            ["Events", "Open alerts", "Open incidents", "Cases", "Compression"],
            ["events", "open_alerts", "open_incidents", "cases", "compression_ratio"],
        ):
            value = metrics.get(key, 0)
            column.metric(label, f"{value:.1f}×" if key == "compression_ratio" else value)
        st.subheader("Detection policies")
        policies = pd.DataFrame(client.get("/policies"))
        st.dataframe(policies, width="stretch", hide_index=True)

    elif page == "Incidents":
        st.subheader("Incident queue")
        status_filter = st.selectbox("Status", ["open", "all"])
        incidents = pd.DataFrame(
            client.get("/incidents", status=None if status_filter == "all" else status_filter)
        )
        if incidents.empty:
            st.info("No incidents match this filter.")
        else:
            st.dataframe(incidents, width="stretch", hide_index=True)
            incident_id = st.selectbox("Investigate incident", incidents["incident_id"].astype(int))
            detail = client.get(f"/incidents/{incident_id}")
            st.write(detail["incident"])
            st.dataframe(pd.DataFrame(detail["alerts"]), width="stretch", hide_index=True)
            assigned_to = st.text_input("Assign promoted case to", value=identity["username"])
            if st.button("Promote to case", type="primary"):
                result = client.post(
                    f"/incidents/{incident_id}/promote", {"assigned_to": assigned_to}
                )
                st.success(f"Created case {result['case_id']}")
            if identity["role"] == "admin":
                with st.expander("Suppress this entity's alerts"):
                    reason = st.text_input("Suppression reason")
                    expires_at = st.date_input("Expires on", value=None)
                    if st.button("Create suppression"):
                        if not reason.strip():
                            st.error("A suppression reason is required")
                        else:
                            payload = {
                                "source_dataset": detail["incident"]["source_dataset"],
                                "user_id": detail["incident"]["user_id"],
                                "reason": reason,
                                "expires_at": expires_at.isoformat() if expires_at else None,
                            }
                            result = client.post("/suppressions", payload)
                            st.success(f"Created suppression {result['suppression_id']}")

    elif page == "Cases":
        st.subheader("Investigation cases")
        cases = pd.DataFrame(client.get("/cases"))
        if cases.empty:
            st.info("No cases have been created.")
        else:
            st.dataframe(cases, width="stretch", hide_index=True)
            case_id = st.selectbox("Open case", cases["case_id"].astype(int))
            detail = client.get(f"/cases/{case_id}")
            case = detail["case"]
            with st.form("case-update"):
                status_value = st.selectbox(
                    "Status", ["open", "investigating", "resolved", "closed"],
                    index=["open", "investigating", "resolved", "closed"].index(case["status"]),
                )
                assigned_to = st.text_input("Assigned to", value=case.get("assigned_to", ""))
                dispositions = ["", "confirmed_threat", "false_positive", "benign_expected", "inconclusive"]
                current_disposition = case.get("disposition") or ""
                disposition = st.selectbox("Disposition", dispositions, index=dispositions.index(current_disposition))
                notes = st.text_area("Analyst notes", value=case.get("analyst_notes", ""))
                save = st.form_submit_button("Save case", type="primary")
            if save:
                client.patch(
                    f"/cases/{case_id}",
                    {"status": status_value, "assigned_to": assigned_to,
                     "disposition": disposition, "analyst_notes": notes},
                )
                st.success("Case updated")
            st.dataframe(pd.DataFrame(detail["alerts"]), width="stretch", hide_index=True)
            alerts = pd.DataFrame(detail["alerts"])
            if not alerts.empty:
                with st.form("alert-feedback"):
                    alert_id = st.selectbox("Alert for analyst verdict", alerts["alert_id"].astype(int))
                    verdict = st.selectbox(
                        "Verdict",
                        ["confirmed_threat", "false_positive", "benign_expected", "needs_more_information"],
                    )
                    comment = st.text_area("Feedback comment")
                    submit_feedback = st.form_submit_button("Record verdict")
                if submit_feedback:
                    client.post(
                        f"/alerts/{alert_id}/feedback",
                        {"verdict": verdict, "comment": comment},
                    )
                    st.success("Analyst verdict recorded")

    else:
        st.subheader("Service status")
        health = SentinelApiClient(API_URL).get("/health")
        st.json(health)
        st.subheader("Operational counters")
        st.json(client.get("/system/metrics"))
        if identity["role"] == "admin":
            st.subheader("Access management")
            st.dataframe(pd.DataFrame(client.get("/users")), width="stretch", hide_index=True)
            with st.form("create-user"):
                new_username = st.text_input("New username")
                new_password = st.text_input("Password", type="password")
                new_role = st.selectbox("Role", ["analyst", "admin"])
                create_account = st.form_submit_button("Create account")
            if create_account:
                created = client.post(
                    "/users",
                    {"username": new_username, "password": new_password, "role": new_role},
                )
                st.success(f"Created {created['role']} account {created['username']}")
            st.subheader("Model lifecycle")
            policies = client.get("/policies")
            sources = [policy["source_dataset"] for policy in policies]
            if sources:
                source = st.selectbox("Source to retrain", sources)
                if st.button("Train candidate"):
                    candidate = client.post(f"/models/{source}/retrain")
                    st.success(f"Candidate {candidate['model_version']} is ready for review")
            models = pd.DataFrame(client.get("/models"))
            if not models.empty:
                st.dataframe(models, width="stretch", hide_index=True)
                promotable = models.loc[models["status"].isin(["candidate", "archived"]), "model_version"]
                if not promotable.empty:
                    model_version = st.selectbox("Candidate or rollback version", promotable)
                    if st.button("Promote selected model", type="primary"):
                        result = client.post(f"/models/{model_version}/promote")
                        st.success(f"Activated {result['promoted_model']}")
            st.subheader("Recent audit events")
            st.dataframe(pd.DataFrame(client.get("/audit")), width="stretch", hide_index=True)

except SentinelApiError as exc:
    st.error(str(exc))
