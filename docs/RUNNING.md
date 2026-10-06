# Running SentinelUEBA

Run commands from the repository root. This guide covers the research dashboard
(`app.py`) and the authenticated operations console (`service_app.py`). Both can
use the same local SQLite database, but the Docker setup keeps its database in a
separate named volume.

## Prerequisites

- Git and Python 3.11 (the version used to verify this repository).
- A browser and ports 8501 (Streamlit) and 8000 (API) available.
- Docker with Compose only if using the container option.

The demo needs no downloaded dataset or external service. It generates synthetic
CERT-style logon, device, file, and administrator activity. The optional public
datasets are described below.

## 1. Fresh clone and local research demo

```bash
git clone https://github.com/qtxops/ueba.git
cd ueba
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python scripts/bootstrap_demo.py
python scripts/evaluate_model.py
streamlit run app.py
```

Open <http://localhost:8501>. Stop Streamlit with Ctrl+C. On Windows, activate
the environment with `.venv\Scripts\activate` and use `py -3.11` to create it.
If `python3.11` is unavailable, install Python 3.11 first or try another version
supported by the pinned dependency ranges.

`bootstrap_demo.py` creates raw CSVs in `data/demo/raw/`, model and score files in
`artifacts/`, and `artifacts/sentinel_ueba.db`. It reuses existing outputs on
later runs. `evaluate_model.py` runs five independently generated synthetic
datasets and writes `artifacts/evaluation_summary.json` and
`artifacts/evaluation_by_seed.csv`. All these outputs are ignored by Git and can
be recreated from the committed source. Avoid `--force` during a live demo: it
replaces the demo source's persisted records.

### Suggested demo walkthrough

1. Open **Security overview** and point out ranked suspicious user-days.
2. Open **Incident queue** to show correlated alerts and their explanations.
3. Open **Alert investigation** or **User profile** to show the underlying
   behavior and the separate ML and rule scores.
4. Open **Model performance** to discuss the held-out evaluation and baseline.
5. Open **System status** to show the persisted events, scores, and alerts.

The default synthetic evaluation has 432 held-out user-days, including 15 labeled
malicious days. The saved run reports 100% recall and about 29% precision; the
five-seed evaluation averages about 98.7% recall and 32.2% precision. These are
results on generated scenarios, not evidence of real-world detection accuracy.
The 0–100 risk score ranks unusual activity; it is not a probability of malice.

## 2. Local authenticated service

Complete the local demo setup above first if you want a populated incident
queue. Start each command below in a separate terminal, from the repository root
with the virtual environment activated.

Terminal 1 — set credentials and start the API:

```bash
export SENTINEL_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export SENTINEL_ADMIN_USERNAME=admin
export SENTINEL_ADMIN_PASSWORD='choose-a-unique-password-at-least-10-characters'
uvicorn src.api:app --host 127.0.0.1 --port 8000
```

Terminal 2 — start the API-backed console:

```bash
SENTINEL_API_URL=http://127.0.0.1:8000 streamlit run service_app.py
```

Terminal 3 — optional periodic policy and incident reconciliation:

```bash
python -m scripts.worker --interval 60
```

Open <http://localhost:8501> and sign in with the administrator credentials.
The API health check is at <http://127.0.0.1:8000/health> and the interactive API
documentation is at <http://127.0.0.1:8000/docs>. The API creates the initial
admin account on its first startup if it does not already exist. After that, the
database holds the password hash; changing the environment password does not
change an existing account. To create an analyst account, use the **System** page
as an admin or run `python -m scripts.create_user analyst --role analyst` and
enter a password when prompted. The worker is optional for the demo because
ingestion also applies policy and incident correlation.

The research dashboard reads the database directly. The operations console
accesses it through the API and exposes incidents, cases, system status, users,
model lifecycle, and audit events according to the signed-in role.

## 3. Docker Compose

Docker Compose runs the API, operations console, and worker together. The first
startup creates an empty database; seed the volume to see demo incidents.

```bash
cp .env.example .env
# Edit .env: replace both placeholder values with a random 32+ character
# SENTINEL_SECRET_KEY and a unique admin password of at least 10 characters.
docker compose up --build -d
docker compose ps
docker compose exec api python scripts/bootstrap_demo.py
```

Open <http://localhost:8501> and sign in using `.env`. The API is at
<http://localhost:8000/docs>. To inspect logs, run `docker compose logs -f api
dashboard worker`; to stop, run `docker compose down`. Data persists in the
`sentinel-data` named volume after `down`. The `.env` file is private and ignored
by Git; `.env.example` is the committed template. The configured secure mode
rejects placeholder credentials at startup.

## 4. Verification and common commands

```bash
python -m unittest discover -s tests -v
python scripts/bootstrap_demo.py
python scripts/evaluate_model.py
python -m scripts.worker --once
```

The first command checks adapters, feature/model behavior, ingestion,
idempotency, incident/case handling, model promotion, authentication, and role
boundaries. The bootstrap and evaluation commands print metrics and save JSON in
`artifacts/`. `worker --once` records one reconciliation run and exits.

For your own CERT-style logs, put `logon.csv`, `device.csv`, and `file.csv` in one
directory using the [input schemas in the README](../README.md#raw-input-schemas).
`admin.csv` and `labels.csv` are optional. Then run:

```bash
python scripts/ingest_logs.py --raw-dir /path/to/logs --source my_source --retrain
# Later batches for the same source reuse the active model unless retraining is requested:
python scripts/ingest_logs.py --raw-dir /path/to/new-logs --source my_source
```

The first batch needs enough history to train: at least ten distinct activity
days. `--source` is a stable source identifier used for event deduplication and
model reuse. For service-side ingestion, administrators can send normalized
events to `POST /events/ingest` through `/docs`; the endpoint expects the
canonical fields defined in `src/event_schema.py` and a `source_dataset`.
Retraining through the API creates a **candidate** model. It becomes active only
after administrator promotion; archived models can be promoted again for
rollback.

Optional public datasets are not included in the repository. Place
`game_admin_logs.csv` at
`data/external/kaggle/game_admin/game_admin_logs.csv` and `train_data.csv` at
`data/external/kaggle/network/train_data.csv`, then run
`python scripts/build_external_datasets.py`. The network file is read as
GB18030. Its undocumented `ret` field is retained only for post-hoc comparison;
it is not a training feature or a known attack label. Results appear under
`artifacts/external/` and in the research dashboard's **Public dataset lab**.

## 5. Troubleshooting

| Symptom | Check |
|---|---|
| `ModuleNotFoundError` | Activate `.venv` and install `requirements.txt` from the repo root. |
| Port 8501 or 8000 is busy | Stop the other process or select a different Streamlit/API port and update `SENTINEL_API_URL`. |
| Empty operations console | Run `bootstrap_demo.py` for the local database, or `docker compose exec api python scripts/bootstrap_demo.py` for the Docker volume. |
| Login fails | Confirm the account was created and use its original password; environment changes do not reset existing accounts. |
| Compose rejects configuration | Replace placeholder values in `.env`; `SENTINEL_SECRET_KEY` needs at least 32 characters. |
| External dataset command fails | Verify both files exist at the exact paths above and use the expected columns. |

## Project boundaries

This is a single-host prototype with SQLite in WAL mode. The synthetic benchmark
is useful for a reproducible demonstration but does not establish accuracy on
an organization's real users. A deployment at larger scale would need stronger
external validation, a scalable database, TLS, SSO, backup, monitoring, and data
retention controls.
