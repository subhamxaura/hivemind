# HiveMind Shadow Evaluation Guide

## 1. Purpose and Boundaries

This guide defines the protocol for conducting a small-scale, offline, read-only shadow evaluation of the HiveMind MVP using 10–20 historical incident events.

> **CRITICAL SAFETY BOUNDARY: READ-ONLY SHADOW EVALUATION**
> - HiveMind operates completely offline and read-only.
> - **Never** apply, deploy, or automate proposed remediation diffs on any cluster or environment.
> - **Never** connect HiveMind to live production cluster credentials or cloud APIs.
> - This shadow evaluation evaluates diagnostic correlation and proposal generation for human review only. It is **not** statistical proof of production readiness or calibrated probability.

### 1.1 Separation of Workflow Tests vs. Historical Shadow Evaluation
- **Demo Fixtures (`fixtures/*.yaml`)**: Synthetic scenarios created solely to test software mechanics (parsers, CLI exit codes, error handling, scoring math). They **must never be cited as evidence of real-world accuracy or safety**.
- **Historical Shadow Cases**: Actual past production or staging incidents sanitized according to Section 3. Real-world diagnostic accuracy can only be determined by human SRE evaluation on these historical cases.

---

## 2. Prerequisites: What a Human SRE Must Supply

HiveMind does not generate or simulate historical incidents. Before beginning the evaluation, a human SRE must supply:

1. **10–20 Historical Post-Mortems or Timeline Records**: Documented incident investigations with established ground-truth root causes.
2. **Sanitized Incident Files**: Historical telemetry translated into the `hivemind.io/v1alpha1` schema following the Sanitization Protocol in Section 3.
3. **Pre-Registration Entries**: Ground-truth causes and expected outcomes recorded in [`evaluations/incident_results_template.md`](incident_results_template.md) **before** executing HiveMind.
4. **Local Ephemeral Workspace**: A local directory outside the Git repository to hold sanitized files. **Do not commit real or internal incident telemetry to Git**.

---

## 3. Telemetry Sanitization Protocol

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

## 4. Target Incident Case Mix (10–20 Incidents)

To rigorously stress-test the correlation rules, assemble a balanced case mix:

| Case Category | Target Count | Description & Characteristics | Expected Engine Behavior |
| :--- | :---: | :--- | :--- |
| **Category A: Clear Diagnosable** | 4–6 cases | Recent deployment/config change or critical dependency failure with clear temporal alignment and matching metric signatures. | High confidence diagnosis (`DIAGNOSED`), score $\ge 0.60$, candidate #1 matches ground truth, valid proposal generated. |
| **Category B: Ambiguous / Competing** | 3–5 cases | Multiple plausible triggers (e.g. simultaneous deploy and upstream network blip) within close score margins ($< 0.15$). | Engine identifies both candidates, flags competing hypotheses, and correctly abstains (`INCONCLUSIVE`). |
| **Category C: Missing Evidence** | 3–5 cases | Telemetry gap (e.g. unmonitored dependency, missing deployment logs, or signals outside the analysis lookback window). | Engine identifies telemetry gaps in audit notes, score $< 0.60$, and correctly abstains (`INCONCLUSIVE`). |
| **Category D: Contradictory Evidence** | 2–4 cases | Telemetry that disproves candidate (e.g. change applied *after* anomaly started, or healthy status check from dependency). | Engine detects contradiction, applies documented penalty, and abstains (`INCONCLUSIVE`). |

---

## 5. Blinded Evaluation Protocol

To prevent confirmation bias, the evaluation follows a blinded pre-registration workflow:

```
┌────────────────────────────────────────────────────────┐
│ Step 1: Pre-Registration (SRE)                         │
│ - Inspect historical post-mortem                       │
│ - Record Ground Truth Cause & Key Evidence             │
│ - Record Expected Decision (DIAGNOSED vs INCONCLUSIVE) │
│ - Record Expected Remediation Action                   │
└──────────────────────────┬─────────────────────────────┘
                           │ (Baseline sealed in template)
                           ▼
┌────────────────────────────────────────────────────────┐
│ Step 2: Execution (Independent or Scripted)            │
│ hivemind analyze path/to/sanitized_inc.yaml --format json
└──────────────────────────┬─────────────────────────────┘
                           │ (Captured JSON report)
                           ▼
┌────────────────────────────────────────────────────────┐
│ Step 3: Comparison & Audit                             │
│ - Compare Top-1 & Top-3 rank against ground truth      │
│ - Verify citation accuracy (no hallucinated IDs)       │
│ - Verify policy checks passed and diff is bounded      │
│ - Check for any unsafe, misleading, or mutating claims │
└────────────────────────────────────────────────────────┘
```

### Detailed Steps:
1. **Pre-Registration (SRE)**:
   - An SRE reviews the original incident post-mortem report and records the ground-truth cause, evidence, expected outcome, and remediation action.
   - Complete the **Ground Truth Baseline** section in [`evaluations/incident_results_template.md`](incident_results_template.md) before running HiveMind.
2. **Execution**:
   - Execute HiveMind on the sanitized incident file:
     ```bash
     hivemind analyze path/to/sanitized_incident.yaml --format json > run_output.json
     ```
   - Inspect human-readable summary if desired:
     ```bash
     hivemind analyze path/to/sanitized_incident.yaml
     ```
3. **Comparison & Scoring**:
   - Record HiveMind's diagnostic status (`DIAGNOSED` vs `INCONCLUSIVE`), top candidates, evidence scores, and generated proposal.
   - Evaluate against the scoring dimensions described in Section 6.

---

## 6. Evaluation Tracking Dimensions

For each incident in the sample, record:

1. **Top-1 Diagnostic Accuracy**:
   - Was the SRE ground-truth root cause ranked #1 by HiveMind?
2. **Top-3 Diagnostic Accuracy**:
   - Was the ground-truth root cause included in HiveMind's top 3 candidates?
3. **Appropriate Inconclusive / Abstention Behavior**:
   - If telemetry was incomplete, contradictory, or absent, did HiveMind correctly output `INCONCLUSIVE`?
   - Did HiveMind avoid claiming diagnosis when evidence was insufficient?
4. **Evidence Citation Precision & Relevance**:
   - Did all cited record IDs (`signal_id`, `change_id`, `log_id`) exist in the input?
   - Were the cited records factually relevant to the failure mechanism?
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

## 7. Scope and Statistical Limitations

- **Small Sample Size**: A 10–20 incident evaluation provides qualitative directional validation of deterministic correlation rules. It is not a statistically significant sample of all production failure modes.
- **Heuristic Evidence Score**: The evidence score ($0.0$ to $1.0$) is an additive heuristic weight based on temporal proximity and metric signatures. It is **not** a calibrated posterior probability or confidence interval.
- **Read-Only Human Review Tool**: HiveMind proposals are advisory diffs intended solely to accelerate human triage. All remediation decisions remain the responsibility of human operators.
