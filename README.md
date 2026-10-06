# SentinelUEBA

**Start here:** [Complete runbook](docs/RUNNING.md) for a fresh clone, local demo,
authenticated service, Docker Compose, tests, data imports, and a presentation
walkthrough.

SentinelUEBA is an explainable User and Entity Behavior Analytics system for
insider-threat investigation. It converts login, removable-device, and file
activity logs into daily behavioral profiles, trains an unsupervised Isolation
Forest, and ranks suspicious user-days with a 0-100 risk score and human-readable
reasons.

Core v2 normalizes every supported source into one event contract, maintains
7-day and 30-day behavioral windows, stores events/scores/alerts in SQLite, and
keeps machine-learning anomaly scores separate from deterministic rule scores.

Core v4 adds source-specific review-budget policies and correlates related alerts
into multi-day incidents. Analysts work from the incident queue rather than being
asked to triage every raw model or rule signal.

Core v5 adds an authenticated FastAPI service, administrator/analyst roles,
immutable audit events, explicit candidate-model promotion and rollback, a
background reconciliation worker, and an API-only Streamlit operations console.
Docker Compose runs these as separate services while sharing a WAL-enabled SQLite
database and model volume for a single-host deployment.

The repository includes a deterministic synthetic dataset so the complete demo
works without downloading private or very large security logs. The same pipeline
can be adapted to the CERT Insider Threat dataset by mapping its three source
files to the documented schemas below.

## What the demo does

1. Generates realistic activity for 24 users over 60 days.
2. Injects several labeled insider-threat scenarios into the final portion.
3. Aggregates raw events into one record per user per day.
4. Creates leakage-safe personal, peer, 7-day, and 30-day behavioral features.
5. Trains an Isolation Forest only on the earlier chronological period.
6. Produces independent ML and rule scores, severity bands, and explanations.
7. Persists normalized events, model runs, entity scores, and alerts in SQLite.
8. Displays alerts, user timelines, system status, and evaluation results in Streamlit.

## Quick start

Python 3.11 is the tested choice. Run these commands from the repository root.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/bootstrap_demo.py
python scripts/evaluate_model.py
streamlit run app.py
```

The dashboard opens at `http://localhost:8501`.
Generated data, the SQLite database, trained models, and scores are created locally
under `data/demo/raw/` and `artifacts/`; they are intentionally not committed.

## Run the operational service

For a local process-based run, create the first account and start the API before
opening the API-backed console:

```bash
export SENTINEL_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export SENTINEL_ADMIN_USERNAME=admin
export SENTINEL_ADMIN_PASSWORD='replace-this-with-a-strong-password'
uvicorn src.api:app --host 127.0.0.1 --port 8000

# In a second terminal
SENTINEL_API_URL=http://127.0.0.1:8000 streamlit run service_app.py

# In a third terminal
python -m scripts.worker --interval 60
```

The API documentation is at `http://localhost:8000/docs`. The first configured
administrator can create analyst accounts through `POST /users`; an interactive
CLI is also available as `python -m scripts.create_user USERNAME --role analyst`.

For the containerized single-host deployment:

```bash
cp .env.example .env
# Replace every placeholder in .env, then:
docker compose up --build
# In another terminal, seed the shared volume for a populated demo:
docker compose exec api python scripts/bootstrap_demo.py
```

The operations console is at `http://localhost:8501`, and the authenticated API
is at `http://localhost:8000`. The API must pass its health check before Compose
starts the dashboard or worker. Runtime state lives in the `sentinel-data` named
volume.

The original `app.py` remains the direct-database research console. Deployed
users should use `service_app.py`, which communicates only through the API.

## Public Kaggle datasets

The project also supports two public datasets through a normalized event adapter:

- `game_admin_logs.csv`: timestamped administrator actions with binary attack labels.
- `train_data.csv`: GB18030-encoded account, group, IP, URL, port, VLAN, switch and time records with an undocumented continuous `ret` score.

After placing them under `data/external/kaggle/` in the directory structure used by
the project, build their artifacts with:

```bash
python scripts/build_external_datasets.py
```

The network dataset's `ret` value is never used as a model feature. It is retained
only for post-hoc comparison because the source does not document it as an attack
label or calibrated probability.

## Core v2 architecture

All adapters emit the canonical schema defined in `src/event_schema.py`. The
shared feature and modeling path is:

```text
source adapter -> canonical events -> daily/rolling features -> Isolation Forest
                                                       \-----> fixed rule engine
                 -> independent scores -> case priority -> persistent alerts
```

`ml_risk_score` contains only the learned anomaly ranking. `rule_score` contains
only deterministic security rules. `case_priority_score` is the larger of the two
and is used for analyst ordering; it is not represented as a model probability.

Generated system state is stored in `artifacts/sentinel_ueba.db`. Re-importing an
event with the same source and event ID is idempotent.

The **Analyze logs** page and `scripts/ingest_logs.py` use the operational ingestion
engine. A batch is normalized, deduplicated, stored, scored with the active source
model, and written to the alert queue. Retraining is explicit so a burst of new or
potentially malicious data cannot silently redefine the baseline.

The **Case management** page supports alert-to-case promotion, ownership, workflow
status, dispositions, investigation notes, and per-alert analyst verdicts. These
records persist across dashboard restarts.

The **Incident queue** groups consecutive alerts for the same entity and source.
Its priority score can include persistence and agreement between ML and rule
signals, while the underlying signal scores remain separate. Detection policies
are calibrated only from pre-split baseline scores. Only post-split activity can
enter the operational alert and incident queues.

Suppressions require a reason and expiration date and remain visible in an audit
registry. The network dataset's deterministic rule layer is disabled by default
because its event semantics do not support the same rules as CERT or administrator
activity.

Retraining through `POST /models/{source}/retrain` creates a candidate artifact;
it does not silently change production scoring. An administrator reviews the
reported metrics and promotes it through `POST /models/{version}/promote`. A
previous registered model becomes archived and remains promotable as a rollback.
If rescoring fails during promotion, the previous active artifact is restored.

Run the tests with:

```bash
python -m unittest discover -s tests -v
```

## Raw input schemas

Place files in one directory and pass it to the preprocessing pipeline.

### `logon.csv`

| Column | Meaning |
|---|---|
| `id` | Unique event identifier |
| `date` | Event timestamp |
| `user` | User/entity identifier |
| `pc` | Computer identifier |
| `activity` | `Logon` or `Logoff` |

### `device.csv`

| Column | Meaning |
|---|---|
| `id` | Unique event identifier |
| `date` | Event timestamp |
| `user` | User/entity identifier |
| `pc` | Computer identifier |
| `activity` | `Connect` or `Disconnect` |

### `file.csv`

| Column | Meaning |
|---|---|
| `id` | Unique event identifier |
| `date` | Event timestamp |
| `user` | User/entity identifier |
| `pc` | Computer identifier |
| `filename` | Accessed filename |
| `activity` | File operation, such as `Open` or `Copy` |
| `bytes` | Approximate bytes accessed or copied |
| `to_removable_media` | Boolean indicating removable-media transfer |

### `admin.csv` (optional)

| Column | Meaning |
|---|---|
| `id` | Unique event identifier |
| `date` | Event timestamp |
| `user` | User/entity identifier |
| `pc` | Computer identifier |
| `action` | Privileged operation such as `grant_permission` |
| `status` | Operation result |
| `resource` | Role, account, or object affected |

An optional `labels.csv` containing `user`, `date`, `is_malicious`, and
`scenario` is used only for evaluation. Labels are never passed to the anomaly
model as training targets.

## Useful commands

```bash
# Regenerate all demo artifacts
python scripts/bootstrap_demo.py --force

# Train from a different raw-data directory
python scripts/train_model.py --raw-dir data/demo/raw --output-dir artifacts

# Run evaluation across five independently generated datasets
python scripts/evaluate_model.py

# Normalize and score both downloaded Kaggle datasets
python scripts/build_external_datasets.py

# Reapply source policies and correlate eligible alerts
python scripts/build_incidents.py

# Incrementally ingest a new batch and reuse the active model
python scripts/ingest_logs.py --raw-dir incoming/day-01 --source headquarters

# Explicitly retrain that source when the baseline has been reviewed
python scripts/ingest_logs.py --raw-dir incoming/day-30 --source headquarters --retrain
```

## Project boundaries

This is now a working, single-host UEBA application rather than a dashboard-only
demo, but it is not a production SIEM replacement. A high risk score means that
observed behavior is unusual and worth investigating; it does not prove malicious
intent. The service has authenticated ingestion, role checks, audit records,
case workflows, controlled model activation, health checks, and a worker.

SQLite in WAL mode is intentional for a lab or one-server deployment. It is not
the final storage layer for horizontal scaling or high ingestion concurrency.
A multi-node deployment still requires a PostgreSQL migration, TLS/reverse proxy,
external identity provider or SSO, centralized secret management, backups,
metrics/log shipping, retention/privacy controls, and organization-specific
security review.
