# SentinelUEBA viva script and project status

**Prepared for the Milestone 1 viva — 6 October 2026.** This is a speaking guide
for the team, not a claim that every future requirement is finished. The exact
milestone rubric was not provided, so the completion assessment below is based
on the implemented repository, its tests, and the current demo.

For installation commands, use [the runbook](docs/RUNNING.md). For input CSV
columns, use [the README](README.md#raw-input-schemas).

## 1. The short answer to “What have you built?”

> We built SentinelUEBA, a user and entity behavior analytics prototype for
> insider-threat investigation. It takes login, removable-device, file, and
> optional administrator activity, converts them into daily user behavior,
> learns an earlier period with Isolation Forest, and ranks unusual user-days.
> It also keeps explicit security rules separate from the ML score. An analyst
> can see explanations, correlated incidents, and case history in a dashboard.
> We tested the complete synthetic pipeline and added an authenticated API and
> operations console for a single-host deployment.

If asked what **UEBA** means: *User and Entity Behavior Analytics*. In this
project the principal entity is a user, and the unit that receives a score is
one **user-day**. An alert is a signal about a user-day; an incident can group
related alerts across days; a case is the analyst's investigation record.

## 2. Why this problem and why this design?

**Problem statement.** An insider may use a legitimate account, so a simple
“login succeeded” rule can miss concerning behavior. The useful question is
whether a user's current activity differs from their earlier behavior and from
peers, especially across several days. Security analysts also need a manageable
queue and reasons they can investigate.

**Our design choices.**

| Choice | Why we made it | Where it appears |
|---|---|---|
| One canonical event schema | Login, device, file, administrator, and network sources can use the same feature pipeline. | [`src/event_schema.py`](src/event_schema.py), [`src/adapters.py`](src/adapters.py) |
| Deterministic synthetic data | Anyone can run the demo without private organization logs or a large download. It supplies labels for repeatable evaluation. | [`src/demo_data.py`](src/demo_data.py) |
| User-day aggregation and rolling windows | A single unusual event may be harmless; daily totals and 7/30-day trends show changed habits and accumulation. | [`src/generic_features.py`](src/generic_features.py) |
| Isolation Forest | The core detector learns a baseline without requiring a large labeled attack set. | [`src/generic_modeling.py`](src/generic_modeling.py), [`src/modeling.py`](src/modeling.py) |
| Separate ML and rule scores | A learned anomaly and a known security pattern are different evidence. We display both and use their maximum for case ordering. | [`src/generic_modeling.py`](src/generic_modeling.py) |
| Source-specific review policies | Teams have limited review capacity; thresholds are calibrated from the earlier baseline rather than from the evaluation labels. | [`src/incidents.py`](src/incidents.py) |
| Persistent incident and case workflow | Analysts need to group repeated signals, record a verdict, and return to an investigation later. | [`src/storage.py`](src/storage.py), [`src/incidents.py`](src/incidents.py) |
| Authenticated service layer | The operations console should reach stored data through an API with roles and audit records. | [`src/api.py`](src/api.py), [`service_app.py`](service_app.py) |

## 3. What we did, in order

This is the development sequence visible in the Git history; it is a useful
answer to “How did the project evolve?”

1. **Prototype (`df88c23`, 19 September).** Built the synthetic CERT-style
   dataset, the original feature/model workflow, a Streamlit investigation
   dashboard, and initial tests. This proved an end-to-end idea before adding
   operational complexity.
2. **Operational UEBA (`41dab07`, 19 September).** Added adapters and a canonical
   event format, rolling and peer features, separate model and rule evidence,
   SQLite persistence, incremental ingestion, source policies, incident
   correlation, cases, suppressions, external dataset workflows, and tests.
   This changed the project from a one-off model demo into a usable analyst flow.
3. **Service layer (`e61be52`, 20 September).** Added the FastAPI API,
   administrator/analyst roles, audit log, candidate-model promotion and
   rollback, reconciliation worker, API-only console, Docker Compose, and API
   tests. This made the operations path more realistic for a single host.
4. **Reproducibility (`49c9147`, 6 October).** Committed `.env.example`, fixed
   its Git ignore rule, and wrote the complete runbook. Generated datasets,
   model files, and local databases remain reproducible local outputs.

These are repository milestones. They do **not** imply that a production
deployment or an institution's final assessment has been completed.

## 4. Technical explanation to speak through

### 4.1 Data and labels

**Say:** “We start with login, USB/device, file, and optional administrator
events. Our generator simulates 24 users over 60 days and inserts three insider
scenarios late in the timeline: slow removable-media exfiltration, gradual
privilege escalation, and low-volume activity from a new host. It writes a
separate `labels.csv` for evaluation.”

**How it works:** [`src/demo_data.py`](src/demo_data.py) produces the CSVs.
[`src/adapters.py`](src/adapters.py) maps source columns into
[`src/event_schema.py`](src/event_schema.py)'s event contract. Normalization
parses timestamps, fills optional fields, validates numeric/boolean values,
generates missing event IDs, and removes duplicate `(source_dataset, event_id)`
pairs. For external data, adapters also handle a labeled administrator dataset
and a GB18030 network access dataset.

**Why:** The common representation lets downstream code operate on one event
shape. Labels are evaluation information, not model features or training
targets. The network dataset's `ret` field has undocumented meaning, so we do
not present it as an attack label or train on it.

### 4.2 Feature engineering

**Say:** “Each user-day becomes one behavior record. We count logons, after-hours
and failed actions, unique IPs/resources/devices, file and sensitive-file
activity, bytes, privileged actions, and activity bursts. We then add 7- and
30-day windows, personal deviations from the user's earlier days, and peer
deviations from the same group's activity.”

**How it works:** [`src/generic_features.py`](src/generic_features.py) sorts
events by user and time, marks first-seen values, aggregates by user and day,
and fills zero-activity calendar days so rolling windows represent days rather
than just active records. Personal deviation features use a **shifted**
expanding history; the current day's value is compared with earlier days. The
same-day peer comparison uses group mean and standard deviation. The 7/30-day
windows include the current day because they describe the activity being
scored. Missing or zero-variance deviations are filled safely.

**Why:** Absolute counts alone are unfair: twenty file accesses may be ordinary
for one user and unusual for another. Personal and peer context makes that
difference visible. Do not claim every feature is a causal explanation; these
are behavioral indicators.

### 4.3 Model, scores, rules, and explanations

**Say:** “We split chronologically: the earlier 70% of days trains the model,
and later days are held out for evaluation. A median imputer, RobustScaler,
and 350-tree Isolation Forest form the pipeline. We turn its anomaly ranking
into a bounded 0–100 `ml_risk_score` using quantiles from training scores.
We also compute a separate 0–100 `rule_score` for known indicators such as
removable-media and sensitive-file activity. The displayed case priority is the
larger of the two.”

**How it works:** [`src/generic_modeling.py`](src/generic_modeling.py) trains on
records before `split_day`. The raw anomaly score is scaled with the 5th and
99th percentile of training scores; the final ML score includes a small
contribution from the previous three anomaly values. Fixed rules derive their
own score. `ml_alert` and `rule_alert` are separate flags. A human-readable ML
reason lists up to three strong personal/peer deviations; a rule reason names
its strongest component. [`src/modeling.py`](src/modeling.py) computes test
metrics. Labels are not in `GENERIC_MODEL_FEATURES`.

**Why:** Unsupervised detection can find unusual combinations, while explicit
rules preserve recognizable security signals. A score of 90 means higher
relative concern in this model's scale; it does **not** mean a 90% probability
of malicious intent. The explanation is a description of unusual features,
not a formal causal explanation of each Isolation Forest tree.

### 4.4 Policies, alerts, incidents, and cases

**Say:** “Raw high scores can create too many items. We set a source-specific
review budget using only pre-split scores, create operational alerts for later
activity, and group related alerts for the same user and source into incidents.
An analyst can promote an incident to a case, add notes and a disposition,
record feedback, or suppress a known benign pattern with a reason and expiry.”

**How it works:** [`src/incidents.py`](src/incidents.py) calibrates the ML
threshold from baseline scores. Defaults are a 5% review budget for CERT-style
activity, 10% for administrator activity, and 2% for network activity; network
rules are disabled by default because those events do not support the same
semantics. Correlation uses a source-specific window (usually 2–3 days).
[`src/storage.py`](src/storage.py) stores events, model runs, user-day scores,
alerts, incidents, cases, feedback, suppressions, and job history in SQLite.

**Why:** A ranked incident queue is more useful than an unbounded list of every
model and rule signal. Analysts still need to inspect underlying alerts before
deciding whether an incident is real. An anomaly is a lead, not proof.

### 4.5 Ingestion, model lifecycle, and service

**Say:** “New events are deduplicated by source and event ID. Ingestion scores
them using the source's current model, so one suspicious batch does not
silently redefine the normal baseline. The service also supports explicit
candidate retraining, administrator promotion, and rollback to an archived
model. The dashboard's operational version talks only to an authenticated API.”

**How it works:** [`src/engine.py`](src/engine.py) records ingestion runs,
persists new events, rebuilds affected features/scores, and refreshes alerts
and incidents. For a new source with no active artifact, it trains an initial
model; otherwise ordinary ingestion reuses the saved model. The explicit API
retrain endpoint in [`src/model_registry.py`](src/model_registry.py) creates a
candidate; promotion copies it to the active path and rescoring must succeed
before the registry switches status. The API in [`src/api.py`](src/api.py)
checks bearer tokens and admin/analyst roles. [`scripts/worker.py`](scripts/worker.py)
periodically reconciles policies and incident state. [`compose.yaml`](compose.yaml)
runs the API, console, and worker against one named volume.

**Nuance:** The ingest CLI's `--retrain` option and the administrator ingestion
API's `retrain: true` flag explicitly retrain the active model as part of that
ingestion call. The separate `/models/{source}/retrain` API route follows the
candidate-and-promotion path. Ordinary ingestion does neither.

**Caveat:** The research dashboard [`app.py`](app.py) reads the local database
directly and has the fullest exploratory views. The authenticated operations
console [`service_app.py`](service_app.py) is narrower and uses the API. Do not
tell an examiner these two interfaces have identical pages.

## 5. Results: numbers to know and how to explain them

These figures come from the current local generated artifacts. The artifacts
are ignored by Git and can be regenerated with the runbook commands. Metrics
can change if the code, seed, or threshold changes.

| Evaluation | What we measured | Current result | Honest interpretation |
|---|---|---:|---|
| Default synthetic run (seed 42) | 432 held-out user-days, 15 malicious days | 51 ML alerts; precision 29.4%; recall 100%; F1 45.5%; 9 malicious days in top 10 | Catches all generated malicious days in this run, with 36 false alerts; analyst review is still needed. |
| Five synthetic seeds | Mean across seeds 7, 19, 42, 91, 123 | Recall 98.7%; precision 32.2%; F1 48.3%; PR-AUC 0.690 | More repeatable than reporting one lucky run, but all five use the same generator design. |
| Rule-only baseline on those seeds | Separate deterministic alert | Recall 33.3%; precision 83.3%; F1 47.6% | Rules are more selective and miss many generated malicious days. Our ML gains recall at the cost of more alerts; the F1 improvement is small. |
| Labeled administrator sample | 45 held-out user-days, 15 malicious | Precision 92.9%; recall 86.7%; F1 89.7% | Encouraging on a small, source-specific public sample. Do not generalize this rate to all real organizations. |
| Network access data | 528,690 events; 151 users | Scored and explored; no attack precision/recall | Its `ret` is undocumented, so it is not treated as a verified binary attack label. |

**Definitions to memorize:** Precision = true alerts / all raised alerts.
Recall = detected malicious days / all labeled malicious days. F1 balances
precision and recall. PR-AUC summarizes precision–recall ranking over
thresholds. “Top 10” measures how many labeled malicious user-days appear in
the ten highest-ranked held-out records.

**Be precise about thresholds.** The evaluation above uses the model's
`ml_alert` threshold of 70. The operational incident queue applies a separate
source-specific review-budget policy. Therefore, do not equate “51 ML alerts”
with the current number of open incidents or all stored database alerts. The
shared local SQLite database may also contain optional external datasets from
earlier imports. The numbers in its overall counter are not all from the
default 24-user synthetic run.

## 6. How complete are we?

The safest answer is based on scope rather than an invented percentage.

| Scope | Status on this repo | Evidence / next step |
|---|---|---|
| Milestone 1 runnable prototype | **Implemented and demo ready** | Local bootstrap runs; research dashboard and scoring pipeline exist; 12 automated tests pass. |
| Core detection and analyst workflow | **Implemented for single-host use** | Canonical ingestion, features, ML/rules, policies, incidents, cases, feedback, and persistent state are in code. |
| Reproducible evaluation | **Implemented on synthetic scenarios; limited external check** | One default run and five-seed summary; labeled administrator sample; network source explored without a verified attack label. |
| Authenticated operations path | **Implemented; API tests pass** | FastAPI roles, audit, model lifecycle, worker, and API-only console exist. A full live Docker stack smoke test was not completed in the recent verification. |
| Viva delivery | **Needs team rehearsal** | Agree on speakers, open the demo beforehand, and rehearse the metrics and limitations. The code alone cannot prove the team's verbal readiness. |
| Broad real-world or production deployment | **Future work** | Validate on representative organizational data; tune alert burden; add scalability, TLS/SSO, backup, monitoring, retention/privacy controls, and security review. |

**Suggested viva wording:** “Our Milestone 1 proof of concept is functionally
complete and testable. We have not completed real-world validation or a
multi-node production deployment. Our next milestone should focus on quality
of detection in representative data, analyst feedback, and deployment
hardening.” Adjust this if your official milestone rubric says otherwise.

## 7. A 6–8 minute presentation script

### 0:00–0:45 — Problem and goal

> Insider activity often uses valid credentials, so access alone is not enough
> to identify risk. Our goal is to surface unusual user behavior early and give
> an analyst a reasoned, manageable queue. We call the project SentinelUEBA.

### 0:45–1:30 — Data

> We can reproduce the project without private logs. Our generator creates
> 24 users across 60 days with three injected scenarios. The adapters also
> accept CERT-style CSVs and two optional public dataset formats. Every source
> is normalized to the same event contract before analysis.

### 1:30–2:30 — Features and model

> We aggregate one record per user per day and calculate activity counts,
> seven- and thirty-day trends, personal deviations, and peer deviations.
> We train an Isolation Forest on the earlier 70% of dates and evaluate on the
> later 30%. This suits limited labels and avoids training on the evaluation
> period. We keep explicit rules as separate evidence.

### 2:30–3:15 — Operational workflow

> The output is a 0–100 anomaly ranking with readable reasons. A policy sets
> how many alerts a source can reasonably send for review. Related alerts are
> correlated into incidents. Analysts can open a case, record a verdict and
> notes, or create a justified temporary suppression.

### 3:15–5:15 — Live demo

1. Launch the research dashboard using the runbook. Show **Security overview**
   and explain that highest risk means “investigate first.”
2. Open **Incident queue**. Choose one incident and show its related alerts and
   time span. State how correlation reduces repeated items.
3. Open **User profile** or **Alert investigation**. Point to the behavior and
   explanation. Identify the separate ML and rule scores.
4. Open **Model performance**. State one-run and five-seed results, then state
   the false-alert tradeoff.
5. If asked about deployment, switch to the operations console or show the
   API documentation; describe roles and the model promotion flow.

### 5:15–6:30 — Validation and limits

> Twelve automated tests cover the main pipeline, ingestion deduplication,
> incidents/cases, model promotion, authentication, and roles. On five
> synthetic runs we averaged 98.7% recall and 32.2% precision. This is a
> high-recall prototype that still produces false alerts. The synthetic
> generator limits what we can claim; next we need representative data and
> analyst evaluation.

### 6:30–7:00 — Closing

> For Milestone 1 we have a runnable end-to-end prototype, repeatable
> evaluation, and an investigation workflow. The next phase is to validate
> usefulness and alert volume on realistic data, then harden deployment.

**Demo fallback:** If a browser view fails, show the saved
`artifacts/metrics.json`, `artifacts/evaluation_summary.json`, the tests, and
the pipeline diagram below. Do not regenerate with `--force` during the viva.

```text
CSV logs / optional public data
  -> source adapters -> normalized events
  -> user-day + rolling + personal/peer features
  -> Isolation Forest ML score ----\
  -> deterministic rule score -----+-> policy alerts -> correlated incidents
                                              -> analyst cases and feedback
  -> SQLite persistence -> research dashboard or authenticated API console
```

## 8. Likely viva questions and direct answers

**Why not train a supervised classifier?** We have a few generated labels for
evaluation but real insider-threat labels are scarce and incomplete. The core
model is unsupervised so it can learn ordinary patterns. A supervised approach
could be compared later if reliable labels become available.

**What exactly is an anomaly here?** A user-day whose engineered features
receive a high Isolation Forest anomaly score relative to the earlier training
data. It does not automatically mean malicious behavior.

**How do you avoid training on test labels?** Training uses feature columns
only and a chronological split. `is_malicious` and `scenario` are retained for
evaluation and presentation but are not included in `GENERIC_MODEL_FEATURES`.

**Why compare with personal and peer behavior?** Different users have different
normal workloads. Personal history detects a change for that user, while peer
comparison gives context within a group.

**Are your rolling features leakage safe?** Personal historical averages are
shifted so they exclude the scored day. Rolling windows include the scored day
because its observed activity is the signal being classified. The model fit
uses only pre-split dates. This is a batch retrospective prototype; prospective
deployment should audit all feature timing against event arrival times.

**What happens with a new user or a short history?** Features can be built,
but personal deviation estimates are weak until enough earlier days exist.
Missing deviations are filled with zero. This is a cold-start limitation.

**Why both rules and ML?** Rules catch explicit known patterns; ML can notice
unusual combinations. Keeping scores separate helps the analyst see which
kind of evidence raised an item. The rule-only baseline has higher precision
but much lower recall on the generated attacks.

**What does the 0–100 score mean?** It is a bounded ranking based on training
score quantiles and a small persistence component. It is neither a calibrated
attack probability nor a confidence interval.

**Why so many false alerts?** Unusual legitimate behavior also receives a high
anomaly score. In the default synthetic holdout, 51 ML alerts include 15 labeled
malicious days and 36 other days. Policy thresholds, incident grouping, and
analyst feedback help manage this, but lowering false-alert burden is still
future work.

**Does the baseline beat the model?** It has higher precision and, for the
default seed, a slightly higher F1 (47.6% versus 45.5%). It detects only
one-third of malicious days while the model detects all in that run. Across
five seeds, mean ML F1 is about 48.3% versus the baseline's 47.6%. We should
not claim a large overall F1 improvement.

**Are the external results proof of generalization?** No. The labeled
administrator sample is small. The network dataset lacks a documented binary
attack label, so precision/recall cannot be computed honestly there. Real
organizational data and an independent evaluation are needed.

**How does ingestion avoid duplicate events?** Normalization deduplicates
within a batch, and SQLite uses `(source_dataset, event_id)` as the event
primary key. Re-ingesting the same batch inserts zero new events.

**Does a new batch retrain the model?** Normally it reuses the active saved
artifact. A new source needs an initial model. The dedicated model-retrain
endpoint creates a candidate for administrator promotion; the separate
explicit ingest `retrain` flag retrains during ingestion.

**How do you secure the application?** The operational path has token
authentication, administrator/analyst roles, password hashes, audit records,
and API-only access from the operations console. This is a single-host
prototype; TLS, external identity, centralized secrets, and a broader security
review remain future work.

**Why SQLite?** It is simple, reproducible, and sufficient for a lab or one
server. WAL mode helps concurrent local readers/writers. We would move to a
scalable database for high-volume or multi-node operation.

**What are the biggest remaining risks?** Synthetic-data bias, alert volume,
limited external validation, cold starts, and single-host deployment. A good
next study would test on representative logs, review top alerts with analysts,
and measure precision at a fixed daily review budget.

## 9. Team rehearsal checklist

- Every teammate can say the short project description without reading.
- Assign one speaker each for problem/data, features/model, demo/workflow,
  evaluation/limitations; everyone should still know the full path.
- Run [the setup commands](docs/RUNNING.md) before the viva and keep the
  dashboard, API docs, and metrics file ready.
- Practice the difference among `ml_risk_score`, `rule_score`, and
  `case_priority_score`, and among alert, incident, and case.
- Memorize the default synthetic numbers **and** the five-seed average.
- Say “synthetic proof of concept” when discussing detection accuracy.
- Know the next-step answer: representative validation, reduced alert burden,
  analyst feedback, and deployment hardening.

## 10. Repository map

| Area | Main files |
|---|---|
| Run and architecture docs | [`README.md`](README.md), [`docs/RUNNING.md`](docs/RUNNING.md) |
| Demo data and adapters | [`src/demo_data.py`](src/demo_data.py), [`src/adapters.py`](src/adapters.py), [`src/event_schema.py`](src/event_schema.py) |
| Features and model | [`src/generic_features.py`](src/generic_features.py), [`src/generic_modeling.py`](src/generic_modeling.py), [`src/modeling.py`](src/modeling.py), [`src/evaluation.py`](src/evaluation.py) |
| Storage and investigation flow | [`src/storage.py`](src/storage.py), [`src/incidents.py`](src/incidents.py), [`src/engine.py`](src/engine.py) |
| Service and deployment | [`src/api.py`](src/api.py), [`src/auth.py`](src/auth.py), [`src/model_registry.py`](src/model_registry.py), [`service_app.py`](service_app.py), [`compose.yaml`](compose.yaml) |
| Local research UI | [`app.py`](app.py) |
| Automated tests | [`tests/`](tests/) |
