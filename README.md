# HiveMind 

<p align="center">
  <img src="assets/hivemind_overview.jpg" alt="HiveMind Overview" width="100%" />
</p>

> **SAFETY NOTICE: STRICTLY READ-ONLY**
> HiveMind is an offline, read-only incident investigation and remediation proposal tool.
> It **never** connects to live Kubernetes clusters or cloud APIs, never applies or mutates infrastructure, and never executes arbitrary scripts or model output. All remediation proposals are unified diffs intended strictly for human review.

---

## 1. What HiveMind Does and Does Not Do

### What it does:
- Ingests structured, versioned incident YAML files containing telemetry signals, recent deployment/configuration changes, topology dependencies, and sanitized log excerpts.
- Applies deterministic, auditable correlation rules across a configurable time-window.
- Computes an auditable **Evidence Score** (0.0 to 1.0) with explicit additive breakdowns and exact citations pointing to input records.
- Identifies and cites contradictory evidence (e.g. changes occurring after anomaly inception, or healthy dependency status).
- Recognizes missing telemetry and yields an explicit `INCONCLUSIVE` status instead of hallucinating diagnoses.
- Generates constrained, human-reviewable Kubernetes `apps/v1` `Deployment` remediation diffs (reverting memory limits or rolling back to an explicit prior known-good revision).
- Runs deterministic static policy checks (blocking privilege escalation, host mounts, RBAC mutations, and unbounded values).
- Provides a human-readable CLI (`hivemind analyze`) and local HTTP API (`GET /healthz`, `POST /analyze`).

### What it does NOT do:
- It does **not** connect to Kubernetes clusters, cloud providers, or remote hosts.
- It does **not** execute `kubectl apply`, Helm upgrades, shell scripts, or production mutations.
- It does **not** rely on paid external LLMs for local analysis.
- It does **not** run distributed infrastructure (no Kafka, Neo4j, TimescaleDB, Qdrant, Temporal).
- It does **not** claim to provide statistical "causal proof"; all reasoning is rule-based and transparently documented.

---

## 2. Installation and Local Setup

### Requirements:
- Python 3.11+ (verified on Python 3.13)
- pip

### Install in editable mode:
```bash
python -m pip install -e .
```

### Install development dependencies:
```bash
python -m pip install -e ".[dev]"
```

---

## 3. Usage: CLI and API

### CLI Usage:
Analyze an incident file with terminal formatted output:
```bash
hivemind analyze fixtures/incident_diagnosable.yaml
```

Analyze with machine-readable JSON output:
```bash
hivemind analyze fixtures/incident_diagnosable.yaml --format json
```

Inspect an inconclusive incident with missing evidence:
```bash
hivemind analyze fixtures/incident_inconclusive_missing_evidence.yaml
```

Inspect an incident with contradictory evidence:
```bash
hivemind analyze fixtures/incident_contradictory_evidence.yaml
```

### Local API Usage:
Start the local FastAPI server:
```bash
uvicorn hivemind.api:app --host 127.0.0.1 --port 8000
```

Process health probe:
```bash
curl http://127.0.0.1:8000/healthz
```
*Response:*
```json
{
  "status": "ok",
  "read_only": true,
  "mutation_enabled": false,
  "version": "0.1.0",
  "supported_schema_version": "hivemind.io/v1alpha1"
}
```

Post an incident payload for analysis:
```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/x-yaml" \
  --data-binary @fixtures/incident_diagnosable.yaml
```

---

## 4. Input Schema Contract

Incident documents must conform to schema version `hivemind.io/v1alpha1`:

```yaml
schema_version: "hivemind.io/v1alpha1"
incident_id: "inc-20261024-001"
detection_timestamp: "2026-10-24T14:30:00Z" # Timezone-aware ISO 8601 required
environment: "production"
affected_services:
  - "payment-service"
analysis_window_minutes: 60                 # Lookback window [T - 60m, T]

changes:
  - change_id: "chg-901"
    service: "payment-service"
    timestamp: "2026-10-24T14:10:00Z"
    change_type: "resource_limit"           # deployment, configmap, resource_limit
    identifier: "rev-104"
    prior_known_good_identifier: "rev-103"  # Required for rollback proposals
    details:
      memory_limit: "256Mi"
      previous_memory_limit: "512Mi"

signals:
  - signal_id: "sig-001"
    service: "payment-service"
    timestamp: "2026-10-24T14:18:00Z"
    name: "oom_killed"
    value: "1"
    threshold: "0"
    severity: "critical"

dependencies:
  - source_service: "payment-service"
    target_service: "payment-db"
    dependency_type: "database"
    critical: true

log_excerpts:
  - log_id: "log-101"
    service: "payment-service"
    timestamp: "2026-10-24T14:18:05Z"
    message: "Out of memory: Kill process 2819"
```

---

## 5. Evidence Score & Analysis Window Logic

### Analysis Window:
The lookback window spans `[detection_timestamp - analysis_window_minutes, detection_timestamp]`. Records outside this interval are excluded from causal scoring.

### Evidence Scoring Rubric:
Evidence scores range from **0.0 to 1.0** and represent an additive weight:
- **Base Change Relevance**: `+0.40` if a deployment/config change occurred on the affected service in the window.
- **Temporal Proximity Bonus**: `+0.20` if the change occurred within 15 minutes before the earliest anomaly signal (`+0.10` if within 30 minutes).
- **Metric Signature Match**: `+0.25` if change attributes match signal types (e.g. memory reduction followed by `oom_killed` or image deploy followed by `crash_loop`).
- **Log Corroboration**: `+0.10` if relevant service logs corroborate the failure.
- **Dependency Cascading Base**: `+0.35` if a declared dependency reported an anomaly.
- **Critical Dependency Weight**: `+0.25` if the dependency is flagged `critical: true`.
- **Temporal Precedence**: `+0.20` if dependency failure preceded client service anomaly.
- **Client Log Corroboration**: `+0.10` if client service logs reference downstream target service.
- **Contradiction Penalties**:
  - `-0.40` if change occurred *after* the anomaly started.
  - `-0.35` if target dependency reported healthy status checks during the incident window.

### Diagnosis vs. Inconclusive Status:
- `DIAGNOSED`: Top candidate score $\ge 0.60$, with at least a $0.15$ score lead over any competing candidate, and zero unresolved contradictions. Audit notes `inconclusive_reasons` are empty (`[]`); any non-fatal telemetry gaps (such as unmonitored downstream dependencies) are recorded in `telemetry_warnings`.
- `INCONCLUSIVE`: Top score $< 0.60$, or competing hypotheses within $0.15$, or unresolved contradictions, or missing vital telemetry. Gaps and audit reasons are recorded in `inconclusive_reasons`.

---

## 6. Constrained Proposals & Policy Checks

Remediation proposals are generated **only** for diagnosed causes meeting safe, explicit criteria:
1. Target must be `apps/v1` `Deployment`.
2. Rollback requires an explicit, non-identical `prior_known_good_identifier` from input telemetry.
3. Resource limit adjustments require explicit `previous_memory_limit` and current `memory_limit` in change details. HiveMind never infers historical values or applies default fallbacks.
4. Proposed resource limits must fall within configured policy bounds (e.g., memory between 64Mi and 4Gi). Note that static policy compliance does not imply operational production safety.

### Mandatory Policy Check Guardrails:
Every proposal passes through `DeterministicPolicyValidator`:
- `target_resource_allowlist`: Enforces `apps/v1:Deployment` only. Rejects RBAC, DaemonSets, StatefulSets, Secrets, CRDs.
- `privilege_escalation_guardrail`: Rejects manifests containing `privileged: true`, `hostNetwork: true`, `hostPID: true`, `hostIPC: true`, `hostPath`, `SYS_ADMIN`, or `allowPrivilegeEscalation: true`.
- `valid_yaml_syntax`: Ensures proposed output parses cleanly.
- `explicit_rollback_target`: Verifies rollback target revision is provided.
- `resource_bounds_check`: Enforces configured policy bounds on memory limits.

---

## 7. Data Handling & Redaction Boundaries

- **Automatic Secret Redaction**: HiveMind applies best-effort regex redaction on log messages to replace common patterns (Bearer tokens, `password=...`, `token: ...`, `api_key=...`, `sk-...`, `ghp-...`) with `[REDACTED]`.
- **User Responsibility**: Automatic redaction is heuristic and best-effort. Operators must ensure secrets are not included in incident telemetry submissions.

---

## 8. Verification & Test Commands

Run the full automated test suite:
```bash
python -m pytest tests/ -v
```

Run code formatting and linter checks:
```bash
python -m ruff check src/ tests/
```

Run static type checking:
```bash
python -m mypy src/
```
