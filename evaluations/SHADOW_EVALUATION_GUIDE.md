# HiveMind Shadow Evaluation Guide

## 1. Purpose and Boundaries

This guide describes the methodology for conducting a small-scale, offline, read-only shadow evaluation of the HiveMind MVP using 10–20 historical incident events.

> **CRITICAL SAFETY BOUNDARY: READ-ONLY SHADOW EVALUATION**
> - HiveMind operates completely offline and read-only.
> - **Never** apply, deploy, or automate proposed remediation diffs on any cluster or environment.
> - **Never** connect HiveMind to live production cluster credentials or cloud APIs.
> - This shadow evaluation evaluates diagnostic correlation and proposal generation for human review only. It is **not** statistical proof of production readiness or calibrated probability.

---

## 2. Telemetry Sanitization Protocol

To prevent accidental disclosure of sensitive operational data, **strictly sanitize** all historical incident data before translating it into the HiveMind `hivemind.io/v1alpha1` YAML schema.

### Strict Redaction Rules:
1. **No Production Credentials or Secrets**:
   - Scrub all passwords, API keys, private keys, bearer tokens, HMAC secrets, and database connection strings.
   - Do **not** rely solely on HiveMind's automated regex redaction; manual pre-scrubbing is mandatory.
2. **Scrub Customer Identifiers & PII**:
   - Remove customer names, email addresses, phone numbers, UUIDs, billing account IDs, and user IP addresses.
3. **Anonymize Internal Infrastructure & Hostnames**:
   - Replace internal DNS records, VPC IDs, AWS ARNs, and private IPs with generic synthetic identifiers (e.g. `service-payment`, `db-cluster-01`, `10.0.0.12`).
4. **Timestamp & Clock Normalization**:
   - Ensure all timestamps in the incident file use ISO 8601 format with explicit timezone offsets (e.g. `2026-10-24T14:00:00Z`).
   - Preserve the exact relative time deltas between events (e.g. change applied at $T-15\text{m}$, anomaly observed at $T-5\text{m}$).
5. **No Real Sensitive Data in Version Control**:
   - Do **not** commit real or partially-sanitized internal operational logs to this git repository. Evaluation test files should be stored locally in an uncommitted or ephemeral directory.

---

## 3. Blinded Evaluation Protocol

To avoid confirmation bias, the evaluation follows a blinded pre-registration workflow:

```
┌─────────────────────────────────┐
│ Step 1: Pre-Registration (SRE)  │
│ - Inspect past post-mortem      │
│ - Record Ground Truth Cause     │
│ - Record Supporting Evidence    │
│ - Record Expected Remediation   │
└────────────────┬────────────────┘
                 │ (Baseline sealed in template)
                 ▼
┌─────────────────────────────────┐
│ Step 2: Independent Run         │
│ - Run HiveMind CLI / API on     │
│   sanitized YAML input          │
└────────────────┬────────────────┘
                 │ (HiveMind output captured)
                 ▼
┌─────────────────────────────────┐
│ Step 3: Comparison & Audit      │
│ - Compare Top-1 & Top-3 rank    │
│ - Audit citation accuracy       │
│ - Verify policy checks & diff   │
│ - Log any unsafe/misleading out │
└─────────────────────────────────┘
```

### Detailed Steps:
1. **Pre-Registration (SRE)**:
   - An SRE reviews the original incident post-mortem report and records the ground-truth cause, evidence, and whether the incident had sufficient data or was fundamentally ambiguous.
   - Complete the **Ground Truth Baseline** columns in [`evaluations/incident_results_template.md`](incident_results_template.md) before running HiveMind.
2. **Execution**:
   - Execute HiveMind on the sanitized incident file:
     ```bash
     hivemind analyze path/to/sanitized_incident.yaml --format json > run_output.json
     ```
3. **Comparison & Scoring**:
   - Record HiveMind's diagnostic status (`DIAGNOSED` vs `INCONCLUSIVE`), top candidates, evidence scores, and generated proposal.
   - Evaluate against the scoring dimensions described in Section 4.

---

## 4. Evaluation Tracking Dimensions

For each incident in the sample (10–20 incidents), track:

1. **Top-1 Diagnostic Accuracy**:
   - Was the SRE ground-truth root cause ranked #1 by HiveMind?
2. **Top-3 Diagnostic Accuracy**:
   - Was the ground-truth root cause included in HiveMind's top 3 candidates?
3. **Appropriate Inconclusive / Abstention Behavior**:
   - If telemetry was incomplete, contradictory, or absent, did HiveMind correctly output `INCONCLUSIVE`?
   - Did HiveMind avoid hallucinating unsupported root causes when evidence was insufficient?
4. **Evidence Citation Precision & Relevance**:
   - Did the citations in `supporting_evidence` directly correlate with the incident cause?
   - Did all cited record IDs (`signal_id`, `change_id`, `log_id`) exist in the input?
5. **Contradiction Detection**:
   - Did HiveMind detect conflicting signals (e.g. changes occurring after anomaly start, healthy dependency telemetry) and apply documented penalties?
6. **Proposal Validity, Boundedness, and Utility**:
   - Was a proposal generated only when safe and appropriate?
   - Did all deterministic policy checks pass (`target_resource_allowlist`, `privilege_escalation_guardrail`, `resource_bounds_check`)?
   - Is the proposal unified diff clear, properly bounded, and useful to a human reviewer?
7. **Unsafe or Misleading Output**:
   - Did HiveMind emit any dangerous configurations (`privileged: true`, host mounts, RBAC permissions)?
   - Did it clearly stamp `status: NOT_APPLIED`?

---

## 5. Scope and Statistical Limitations

- **Small Sample Size**: A 10–20 incident evaluation provides qualitative directional validation of deterministic correlation rules. It is not a statistically significant sample of all production failure modes.
- **Heuristic Evidence Score**: The evidence score ($0.0$ to $1.0$) is an additive heuristic weight based on temporal proximity and metric signatures. It is **not** a calibrated posterior probability or confidence interval.
- **Read-Only Human Review Tool**: HiveMind proposals are advisory diffs intended solely to accelerate human triage. All remediation decisions remain the responsibility of human operators.
