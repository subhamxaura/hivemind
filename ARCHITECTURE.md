# HiveMind Architecture & Safety Specification

## 1. System Overview

HiveMind is architected as an offline, deterministic evaluation pipeline:

```
[ Incident YAML Input ]
          │
          ▼
┌─────────────────────────┐
│   Pydantic v2 Models    │  --> Strict schema validation, extra=forbid,
│   & Secret Redaction    │      timezone-aware verification, best-effort redaction
└──────────┬──────────────┘
          │ Validated IncidentEvent
          ▼
┌─────────────────────────┐
│ Deterministic Engine    │  --> Time-window bounds filtering [T-W, T]
│ & Correlation Rules     │  --> Score calculations with auditable breakdowns
│                         │  --> Contradiction & missing evidence detection
└──────────┬──────────────┘
          │ Diagnosed / Inconclusive Report
          ▼
┌─────────────────────────┐
│ Constrained Proposal &  │  --> Restricted to apps/v1 Deployment
│ Deterministic Policies  │  --> Privilege escalation guardrails
│                         │  --> Unified diff generation
└──────────┬──────────────┘
          │
          ├──> CLI (human-readable table/json, exit codes 0/1/2)
          └──> Local FastAPI (/healthz, /analyze, read_only=true)
```

## 2. Safety Boundaries & Threat Model

1. **No Outbound Network or Mutating Cluster Access**:
   HiveMind contains zero production-mutating code paths, cluster connection clients (`kubernetes`, `pykube`), or cloud provider SDKs.

2. **Model Output & Input as Untrusted**:
   All incident inputs and generated proposals are treated as untrusted data. Validation fails closed:
   - Unknown fields raise validation errors (`extra="forbid"`).
   - Any proposal containing forbidden security keywords (`privileged`, `hostNetwork`, `hostPID`, `hostIPC`, RBAC verbs) fails deterministic policy checks.

3. **Status Invariant**:
   Proposals carry an immutable `status: "NOT_APPLIED"`. Any attempt to set a status indicating automatic execution fails model validation.

4. **Transparent Auditability**:
   No black-box scores or opaque inferences. Every candidate cause cites exact input IDs (`record_id`), and provides a deterministic arithmetic breakdown of its score.
