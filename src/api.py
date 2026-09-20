"""Authenticated REST API for SentinelUEBA operational workflows."""

import sqlite3
from contextlib import asynccontextmanager
from typing import Annotated, Any

import jwt
import pandas as pd
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field

from .auth import authenticate_user, create_access_token, create_user, decode_access_token, write_audit
from .engine import process_event_batch
from .incidents import (
    create_suppression,
    get_incident,
    list_incidents,
    list_policies,
    operations_metrics,
    promote_incident_to_case,
)
from .model_registry import build_candidate, list_models, promote_model
from .service_config import ServiceSettings
from .storage import (
    connect_database,
    database_summary,
    get_case,
    list_cases,
    record_feedback,
    update_case,
)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


class EventBatch(BaseModel):
    source_dataset: str = Field(min_length=1, max_length=100)
    events: list[dict[str, Any]] = Field(min_length=1)
    retrain: bool = False


class PromoteRequest(BaseModel):
    assigned_to: str = ""


class CaseUpdate(BaseModel):
    status: str
    assigned_to: str = ""
    disposition: str = ""
    analyst_notes: str = ""


class FeedbackRequest(BaseModel):
    verdict: str
    comment: str = ""


class SuppressionRequest(BaseModel):
    source_dataset: str
    reason: str
    user_id: str = ""
    alert_type: str = ""
    expires_at: str | None = None


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=10, max_length=256)
    role: str = "analyst"


def create_app(settings: ServiceSettings | None = None) -> FastAPI:
    config = settings or ServiceSettings.from_environment()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        if config.require_secure_config and (
            not config.production_safe
            or len(config.admin_password) < 10
            or config.admin_password.startswith("replace-")
        ):
            raise RuntimeError(
                "Secure deployment requires a random 32+ character secret and a non-placeholder admin password"
            )
        with connect_database(config.database_path) as connection:
            existing_admin = connection.execute(
                "SELECT 1 FROM users WHERE username = ?", (config.admin_username,)
            ).fetchone()
            if config.admin_password and existing_admin is None:
                create_user(connection, config.admin_username, config.admin_password, "admin")
        yield

    app = FastAPI(
        title="SentinelUEBA API",
        version="5.0.0",
        description="Authenticated ingestion, incident, case, and model operations.",
        lifespan=lifespan,
    )

    def database():
        with connect_database(config.database_path) as connection:
            yield connection

    def current_user(
        token: Annotated[str, Depends(oauth2_scheme)],
        connection: Annotated[sqlite3.Connection, Depends(database)],
    ) -> dict[str, Any]:
        credentials_error = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
        try:
            payload = decode_access_token(token, config.secret_key)
            username = str(payload.get("sub", ""))
        except jwt.InvalidTokenError as exc:
            raise credentials_error from exc
        row = connection.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row is None or int(row["disabled"]):
            raise credentials_error
        return dict(row)

    def require_admin(user: Annotated[dict[str, Any], Depends(current_user)]) -> dict[str, Any]:
        if user["role"] != "admin":
            raise HTTPException(status_code=403, detail="Administrator role required")
        return user

    @app.get("/health")
    def health(connection: Annotated[sqlite3.Connection, Depends(database)]):
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        return {
            "status": "ok" if integrity == "ok" else "degraded",
            "database": integrity,
            "production_secret_configured": config.production_safe,
        }

    @app.post("/auth/token")
    def login(
        form: Annotated[OAuth2PasswordRequestForm, Depends()],
        connection: Annotated[sqlite3.Connection, Depends(database)],
    ):
        user = authenticate_user(connection, form.username, form.password)
        if user is None:
            raise HTTPException(status_code=401, detail="Incorrect username or password")
        return {
            "access_token": create_access_token(
                user["username"], user["role"], config.secret_key, config.token_minutes
            ),
            "token_type": "bearer",
        }

    @app.get("/auth/me")
    def me(user: Annotated[dict[str, Any], Depends(current_user)]):
        return {"username": user["username"], "role": user["role"]}

    @app.get("/users")
    def users(
        user: Annotated[dict[str, Any], Depends(require_admin)],
        connection: Annotated[sqlite3.Connection, Depends(database)],
    ):
        rows = connection.execute(
            "SELECT username, role, disabled, created_at FROM users ORDER BY username"
        ).fetchall()
        return [dict(row) for row in rows]

    @app.post("/users", status_code=201)
    def add_user(
        request: UserCreate,
        user: Annotated[dict[str, Any], Depends(require_admin)],
        connection: Annotated[sqlite3.Connection, Depends(database)],
    ):
        try:
            create_user(connection, request.username, request.password, request.role)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        write_audit(
            connection, user["username"], "create_user", "user", request.username,
            {"role": request.role},
        )
        return {"username": request.username, "role": request.role}

    @app.get("/system/metrics")
    def system_metrics(
        user: Annotated[dict[str, Any], Depends(current_user)],
        connection: Annotated[sqlite3.Connection, Depends(database)],
    ):
        return {**database_summary(connection), **operations_metrics(connection)}

    @app.get("/policies")
    def policies(
        user: Annotated[dict[str, Any], Depends(current_user)],
        connection: Annotated[sqlite3.Connection, Depends(database)],
    ):
        return list_policies(connection).to_dict(orient="records")

    @app.get("/incidents")
    def incidents(
        user: Annotated[dict[str, Any], Depends(current_user)],
        connection: Annotated[sqlite3.Connection, Depends(database)],
        incident_status: str | None = Query("open", alias="status"),
    ):
        return list_incidents(connection, incident_status).to_dict(orient="records")

    @app.get("/incidents/{incident_id}")
    def incident_detail(
        incident_id: int,
        user: Annotated[dict[str, Any], Depends(current_user)],
        connection: Annotated[sqlite3.Connection, Depends(database)],
    ):
        try:
            incident, alerts = get_incident(connection, incident_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"incident": incident, "alerts": alerts.to_dict(orient="records")}

    @app.post("/incidents/{incident_id}/promote", status_code=201)
    def promote_incident(
        incident_id: int,
        request: PromoteRequest,
        user: Annotated[dict[str, Any], Depends(current_user)],
        connection: Annotated[sqlite3.Connection, Depends(database)],
    ):
        try:
            case_id = promote_incident_to_case(connection, incident_id, request.assigned_to)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        write_audit(connection, user["username"], "promote_incident", "incident", incident_id, {"case_id": case_id})
        return {"case_id": case_id}

    @app.get("/cases")
    def cases(
        user: Annotated[dict[str, Any], Depends(current_user)],
        connection: Annotated[sqlite3.Connection, Depends(database)],
    ):
        return list_cases(connection).to_dict(orient="records")

    @app.get("/cases/{case_id}")
    def case_detail(
        case_id: int,
        user: Annotated[dict[str, Any], Depends(current_user)],
        connection: Annotated[sqlite3.Connection, Depends(database)],
    ):
        try:
            case, alerts, feedback = get_case(connection, case_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"case": case, "alerts": alerts.to_dict(orient="records"), "feedback": feedback.to_dict(orient="records")}

    @app.patch("/cases/{case_id}")
    def patch_case(
        case_id: int,
        request: CaseUpdate,
        user: Annotated[dict[str, Any], Depends(current_user)],
        connection: Annotated[sqlite3.Connection, Depends(database)],
    ):
        try:
            update_case(
                connection, case_id, request.status, request.assigned_to,
                request.disposition, request.analyst_notes,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        write_audit(connection, user["username"], "update_case", "case", case_id, request.model_dump())
        return {"updated": True}

    @app.post("/alerts/{alert_id}/feedback", status_code=201)
    def feedback(
        alert_id: int,
        request: FeedbackRequest,
        user: Annotated[dict[str, Any], Depends(current_user)],
        connection: Annotated[sqlite3.Connection, Depends(database)],
    ):
        try:
            record_feedback(connection, alert_id, request.verdict, user["username"], request.comment)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        write_audit(connection, user["username"], "record_feedback", "alert", alert_id, request.model_dump())
        return {"recorded": True}

    @app.post("/suppressions", status_code=201)
    def suppress(
        request: SuppressionRequest,
        user: Annotated[dict[str, Any], Depends(require_admin)],
        connection: Annotated[sqlite3.Connection, Depends(database)],
    ):
        try:
            suppression_id = create_suppression(connection, **request.model_dump())
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        write_audit(connection, user["username"], "create_suppression", "suppression", suppression_id, request.model_dump())
        return {"suppression_id": suppression_id}

    @app.post("/events/ingest")
    def ingest(
        request: EventBatch,
        user: Annotated[dict[str, Any], Depends(require_admin)],
        connection: Annotated[sqlite3.Connection, Depends(database)],
    ):
        frame = pd.DataFrame(request.events)
        frame["source_dataset"] = request.source_dataset
        try:
            result = process_event_batch(frame, config.database_path, config.artifact_dir, request.retrain)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        write_audit(connection, user["username"], "ingest_events", "source", request.source_dataset, result)
        return result

    @app.post("/models/{source_dataset}/retrain")
    def retrain(
        source_dataset: str,
        user: Annotated[dict[str, Any], Depends(require_admin)],
        connection: Annotated[sqlite3.Connection, Depends(database)],
    ):
        try:
            result = build_candidate(config.database_path, config.artifact_dir, source_dataset)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        write_audit(connection, user["username"], "train_candidate", "source", source_dataset, result)
        return result

    @app.get("/models")
    def models(
        user: Annotated[dict[str, Any], Depends(current_user)],
        source_dataset: str | None = None,
    ):
        return list_models(config.database_path, source_dataset)

    @app.post("/models/{model_version}/promote")
    def promote_registered_model(
        model_version: str,
        user: Annotated[dict[str, Any], Depends(require_admin)],
        connection: Annotated[sqlite3.Connection, Depends(database)],
    ):
        try:
            result = promote_model(
                config.database_path, config.artifact_dir, model_version, user["username"]
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        write_audit(connection, user["username"], "promote_model", "model", model_version, result)
        return result

    @app.get("/audit")
    def audit_log(
        user: Annotated[dict[str, Any], Depends(require_admin)],
        connection: Annotated[sqlite3.Connection, Depends(database)],
    ):
        rows = connection.execute("SELECT * FROM audit_log ORDER BY audit_id DESC LIMIT 500").fetchall()
        return [dict(row) for row in rows]

    return app


app = create_app()
