# Findings & Decisions

## Audit Scope
Repository-only static review of the current HiveMind API, models, engine, proposal generator, tests, Docker/Compose/Kubernetes deployment files, and CI. No live endpoint, cluster, registry, or third-party target was scanned. No exploit, destructive payload, or load test was run.

## Prioritized Findings
1. **High, conditional reachability — unauthenticated API with optional Kubernetes network isolation.** `src/hivemind/api.py` has no auth middleware; the checked-in Service is ClusterIP, but `deploy/kubernetes/networkpolicy.yaml` is separate/optional and README instructs applying it separately. Kubernetes says pods are non-isolated by default, allowing ingress/egress absent applicable policy. Impact depends on cluster reachability; this is not evidence of a public endpoint.
2. **High — unbounded request and analysis resources.** `api.py:114-124` buffers/parses the entire request. Model list/string/map fields lack maximum sizes/counts (`models.py:51-59, 99-119`). Engine loops correlate each change/dependency against signal/log collections (`engine.py:169-254, 304-385`), allowing large synthetic records to consume memory and quadratic CPU. No app rate limit or body cap appears in API/Compose/Kubernetes.
3. **Medium — validation errors reflect untrusted values despite heuristic redaction.** `models.py:121-126` embeds rejected schema_version text in an exception; `api.py:142-144` returns `err['msg']` after `redact_secrets`, which only matches a finite pattern set (`redaction.py:5-21`). Parser exceptions are also sent back after best-effort redaction (`api.py:121-130`).
4. **Medium — proposal output reproduces complete, unredacted source manifests.** `proposal.py:1019-1051` serializes full before/after Deployment snapshots and a diff. Inline credentials accidentally placed in manifest env values/annotations can be propagated in the response and downstream reports. This is a data-minimization issue, not evidence that the app exfiltrates submitted data.
5. **Medium — proposal policy guardrail is narrower than Kubernetes Restricted.** `proposal.py:269-312` rejects host network/PID/IPC, hostPath, privileged, allowPrivilegeEscalation=true, and SYS_ADMIN/ALL, but does not enforce non-root, drop-ALL/add-only-NET_BIND_SERVICE, seccomp, hostPort, or read-only root filesystem. Rollback snapshots can therefore propose fields outside the production pod profile. Proposals remain NOT_APPLIED and require human review.
6. **Medium — release supply chain is not fully immutable.** `pyproject.toml:14-28` uses open-ended version ranges with no lock/hashes; Docker images use mutable version tags rather than digests; `.github/workflows/ci.yml` references actions by major tags instead of full commit SHAs. Current CI builds an SBOM/provenance, but does not show dependency/image scanning or signature verification.
7. **Medium/low — in-cluster transport and metrics boundary depend on environment controls.** API listens on plain HTTP (`Dockerfile:29`) and `/metrics` shares port 8000 (`api.py:97-100`). The optional NetworkPolicy is Layer-4/port based, so approved namespace peers can reach both `/analyze` and `/metrics`. Use gateway/mesh TLS and narrow scrape/client policy if needed.
8. **Low — operational endpoints and docs are not explicitly hidden.** FastAPI app setup does not override the default docs/OpenAPI URLs; `/healthz` discloses version/schema (`api.py:79-88`). Keep behind trusted network or disable/protect discovery endpoints where not required.

## Official Research
- OWASP WSTG project lists version 4.2 as the versioned release and version 5.0 as in development: https://owasp.org/projects/web-security-testing-guide.
- OWASP API4:2023 describes missing execution/memory/body/record/frequency limits and recommends bounding payloads and arrays, resource controls, and throttling: https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/.
- OWASP API8:2023 covers hardening, TLS, allowed verbs/content types, uniform request handling, and safe error schemas: https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/.
- NIST SP 800-115 supports planning/conducting technical tests, analyzing findings, and developing mitigations; published 2008: https://csrc.nist.gov/pubs/sp/800/115/final.
- Kubernetes NetworkPolicy documentation says pods are non-isolated by default; CNI support is required, policies are additive, and node traffic has special handling: https://kubernetes.io/docs/concepts/services-networking/network-policies/.
- Kubernetes Restricted Pod Security Standard requires non-root, no privilege escalation, explicit seccomp, dropping all capabilities, and only `NET_BIND_SERVICE` as an added capability: https://kubernetes.io/docs/concepts/security/pod-security-standards/.

## Test Plan Decisions
- Use an isolated staging namespace/host with synthetic incidents and no production secrets.
- Set explicit body, concurrency, and run-time limits before any traffic test; ramp gradually and stop on predefined CPU, memory, latency, or error thresholds.
- Test both gateway-denied and authorized paths; verify NetworkPolicy behavior using a CNI that enforces it.
- Treat any proposal as an output to inspect only; never apply it to a cluster as part of this assessment.
- Capture request IDs, sanitized outputs, resource graphs, policy decisions and image digests; avoid retaining submitted secrets.

## Known Verification Limits
Prior environment check: `py.exe` exists but no Python runtime is installed; Docker, kubectl, kustomize, pytest, Ruff and mypy are unavailable. No test suite, image build, Promtool, live scan, or cluster test was executed for this audit.
