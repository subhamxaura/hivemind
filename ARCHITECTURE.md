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
│ Constrained Proposal &  │  --> k8s_manifest: parse, identity, validation
│ Deterministic Policies  │  --> security: privilege escalation guardrails
│ (Split Modules)         │  --> policy: deterministic policy validator
│                         │  --> proposal: diff & proposal generation
└──────────┬──────────────┘
          │
          ├──> CLI (human-readable table/json, exit codes 0/1/2)
          └──> FastAPI (/healthz, /readyz, /metrics, /analyze, read_only=true)
```

## 2. Safety Boundaries & Threat Model

1. **No Application-Level External Integration or Mutating Cluster Access**:
   The API contains no outbound-call feature, production-mutating code path, cluster connection client (`kubernetes`, `pykube`), or cloud provider SDK. Network egress is controlled by deployment configuration: the Compose bridge network uses internal: false to support local Docker Desktop port publishing while binding all exposed service ports strictly to loopback (127.0.0.1), and the optional Kubernetes NetworkPolicy denies API egress.

2. **Model Output & Input as Untrusted**:
   All incident inputs and generated proposals are treated as untrusted data. Validation fails closed:
   - Unknown fields raise validation errors (`extra="forbid"`).
   - Proposals require complete, explicitly supplied source state; HiveMind does not synthesize Deployments or infer image tags from revision identifiers.
   - Both source and proposed manifests must be structurally valid `apps/v1` Deployments with the same exact resource identity.
   - Security guardrails inspect parsed pod-spec fields rather than matching words anywhere in YAML text, and any policy failure suppresses proposal generation.
   - Memory proposals must match the input baseline and change only the named container's memory limit. Rollbacks require source/prior snapshots stamped with matching `hivemind.io/revision` annotations and an unchanged Deployment selector.
   - Proposal evidence references must resolve to the source change and same-service supporting signals/logs in the incident input; stale or fabricated citations suppress the proposal.
   - Every report carries a typed proposal-generation status and reason code. Structured operational logs contain outcome counts and reason codes, not manifests, raw telemetry, or exception text.

3. **Status Invariant**:
   Proposals carry an immutable `status: "NOT_APPLIED"`. Any attempt to set a status indicating automatic execution fails model validation.

4. **Transparent Auditability**:
   No black-box scores or opaque inferences. Every candidate cause cites exact input IDs (`record_id`), and provides a deterministic arithmetic breakdown of its score.

5. **Proposal Provenance Limitation**:
   Manifest snapshots and revision annotations are supplied by the incident data provider and are not independently retrieved, authenticated, or proven to match a live cluster. Diffs are advisory only; passing deterministic checks does not establish Kubernetes admission-policy or operational safety.

## 6. Production Deployment & Observability

- The container runs the API as a non-root UID with a read-only root filesystem. Kubernetes examples drop Linux capabilities, use the `RuntimeDefault` seccomp profile, disable service-account token mounting, and expose only an internal `ClusterIP` Service.
- `/healthz` is the liveness probe, `/readyz` is the readiness probe, and `/metrics` exposes Prometheus instrumentation on the same listener as `/analyze`. The API has no authentication; the example keeps the endpoint private and does not provide a public Ingress.
- HTTP metrics use a fixed route allowlist, bounded method/status labels, and typed proposal-generation status/reason labels. User-provided incident identifiers, service names, telemetry, manifests, and exception messages are not metric labels.
- `deploy/` contains Docker Compose, Prometheus/Grafana provisioning, Kubernetes resources, and optional Prometheus Operator resources. The example alert rules evaluate conditions but do not configure Alertmanager notification receivers, organization identity, public TLS, or backup destinations.
- The checked-in resource requests/limits and image versions are example baselines. Production operators must validate capacity with representative load, update and verify base images, use immutable image digests where required, configure registry pulls and secrets, and adapt authorization/network policy to their cluster.

HiveMind remains advisory and non-mutating: the deployment manifests grant no Kubernetes API permissions, mount no service-account token, and contain no cluster client. Deployment does not make proposal diffs safe to apply automatically.
