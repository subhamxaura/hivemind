# Findings & Decisions

## Requirements
- Add production-oriented Docker and Kubernetes configuration without deploying to a live cluster.
- Add enterprise-style application monitoring with Prometheus-compatible metrics and usable Grafana provisioning.
- Keep secrets, incident identifiers, raw telemetry, and untrusted inputs out of metric labels.
- Explain that ingress authentication/TLS, registry identity, storage, alert routing, and resource sizing require environment-specific decisions.

## Research Findings
- HiveMind is a FastAPI service with `/healthz` and `/analyze`; no metrics endpoint, Docker image, or deployment artifacts existed before P3.
- The API has no authentication. Telemetry may contain sensitive data, so examples must not expose the API, Prometheus, or Grafana publicly by default.
- Package metadata supports Python 3.11+, and the P2 CI workflow checks Python 3.11/3.12.
- Official Prometheus download page listed 3.13.5 as the LTS release on 2026-10-21: https://prometheus.io/download/ (also https://github.com/prometheus/prometheus/releases/tag/v3.13.5).
- Official Grafana releases listed 13.2.4 as the current latest version on 2026-10-13: https://github.com/grafana/grafana/releases/tag/v13.2.4.
- Docker Official Image listing included Python 3.12.15-slim-bookworm: https://hub.docker.com/_/python.
- GitHub's official Dependabot ecosystem reference supports `docker-compose` and says Docker ecosystem entries can update image tags in Kubernetes manifests: https://docs.github.com/en/code-security/reference/supply-chain-security/supported-ecosystems-and-repositories.
- Docker Compose documents `internal: true` as creating an externally isolated network: https://docs.docker.com/reference/compose-file/networks/.
- Local `py.exe` exists but reports `No installed Python found`; Docker, kubectl, kustomize, pytest, Ruff, and mypy commands are not found. Python tests, container build, Promtool, and Kubernetes-schema checks could not be run locally.
- The Grafana dashboard JSON was parsed successfully with PowerShell; `git diff --check` passed. GitHub-hosted CI is configured but has not run from this local worktree.

## Technical Decisions
| Decision | Rationale |
|----------|-----------|
| Use the official Prometheus LTS tag and current Grafana release tag verified on 2026-10-25 | Prefer fixed, traceable versions over `latest`; revisit updates before release |
| Add `prometheus-client` and route-template labels | Native Prometheus exposition with bounded cardinality |
| Compose ports bind to `127.0.0.1`; monitoring bridge is internal; Kubernetes Service is `ClusterIP` | Avoid public exposure of unauthenticated incident analysis and block unnecessary Compose egress |
| Kubernetes pod runs non-root, read-only root filesystem, dropped capabilities, seccomp `RuntimeDefault`, and no token mount | Baseline defense-in-depth for a stateless read-only API |
| Monitoring examples use persistent Prometheus storage and provisioned Grafana datasource/dashboard | Gives a working local reference without storing credentials in source control |
| Add weekly Dependabot entries for pip, Dockerfile, Docker Compose, Kubernetes manifests, and GitHub Actions | Creates reviewable update PRs; official ecosystem naming was verified |
| CI parses configuration, runs Promtool, validates Compose, builds the image, and smoke-tests an incident analysis | Makes hosted verification repeatable; local runtimes are unavailable |

## Production Limitations
- The API has no authentication, authorization, TLS termination, rate limiting, or request-body limit. Do not expose it directly; deploy behind an organization-approved gateway and apply edge protections.
- Alert rules evaluate, but the stack does not provision Alertmanager receivers or external paging destinations.
- Resource requests/limits and retention are sample values. Validate with representative load, set storage/backup policies, and use immutable image digests if required.
- Kubernetes NetworkPolicy is optional and requires a NetworkPolicy-capable CNI plus environment-specific labels; operator CRDs and selectors must be aligned.
- The GHCR image is only published when a version tag matching `pyproject.toml` is pushed and the hosted workflow succeeds. No image was published or cluster deployment attempted in this task.

## Resources
- https://prometheus.io/download/
- https://github.com/prometheus/prometheus/releases/tag/v3.13.5
- https://github.com/grafana/grafana/releases/tag/v13.2.4
- https://hub.docker.com/_/python
- https://docs.github.com/en/code-security/reference/supply-chain-security/supported-ecosystems-and-repositories
- https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference
- https://docs.docker.com/reference/compose-file/networks/
- `src/hivemind/api.py`
- `pyproject.toml`
- `Dockerfile`
- `deploy/`
