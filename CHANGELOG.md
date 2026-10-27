# Changelog

All notable changes to HiveMind are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-10-25

### Added
- **Deterministic Correlation Engine**: Rule-based investigation pipeline that scores anomaly signals, deployment changes, and topology dependencies within time-window boundaries without black-box inference or external network calls.
- **Constrained Remediation Proposals**: Deterministic proposal generation for `apps/v1` Deployments covering revision rollbacks and bounded container memory limit adjustments.
- **Fail-Closed Policy Validation**: Deterministic checks verifying YAML syntax, Deployment structure, resource identity allowlists, and privilege escalation guards (prohibiting `hostNetwork`, `hostPID`, `hostIPC`, `hostPath`, `privileged`, `allowPrivilegeEscalation`, and `SYS_ADMIN`/`ALL` capabilities).
- **Read-Only Invariant**: Mandatory `status: "NOT_APPLIED"` on all remediation proposals. No Kubernetes cluster client or mutating route exists in the codebase.
- **Telemetry Secret Redaction**: Automatic sanitization of sensitive tokens and passwords in incident logs, exception details, and CLI terminal output.
- **FastAPI HTTP Service**: Stateless inspection API featuring `/healthz` liveness, `/readyz` readiness, `/metrics` Prometheus instrumentation, and `/analyze` incident evaluation.
- **Click CLI**: Command-line tool providing formatted terminal investigation reports with candidate root causes, score breakdowns, and unified diff output.
- **Production Hardening & Deployment Manifests**: Rootless container setup running with read-only root filesystems, drop-all Linux capabilities, Kubernetes PSA restricted pod security profiles, loopback-bound Docker Compose stacks, and internal-only ClusterIP services.
- **CI/CD Automation**: GitHub Actions workflow for multi-arch GHCR image publishing with cryptographic digest verification.
- **Documentation & Evaluation**: System architecture specifications, security threat models, and shadow evaluation runbooks.
