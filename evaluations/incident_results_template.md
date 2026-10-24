# HiveMind Shadow Evaluation: Incident Results Template

- **Evaluation Date**: `YYYY-MM-DD`
- **Evaluator (SRE)**: `[Name / Team]`
- **Target Incidents**: 10–20 Sanitized Historical Incidents
- **Operating Mode**: Strictly Read-Only (Offline Analysis Only)

> **SAFETY MANDATE FOR EVALUATORS**
> 1. Complete Section 1 (Pre-Registered Ground Truth) for each incident **before** executing HiveMind.
> 2. Ensure all operational data has been sanitized (no secrets, no customer PII, no internal IP/DNS) according to `SHADOW_EVALUATION_GUIDE.md`.
> 3. Do **not** commit real incident telemetry or customer data to Git.

---

## 1. Prerequisites: What the Human SRE Must Supply

Before filling out this template, the evaluator must supply:
- [ ] 10–20 historical incident post-mortems covering the target case distribution (Clear, Ambiguous, Missing Evidence, Contradictory).
- [ ] Sanitized YAML incident files matching the `hivemind.io/v1alpha1` schema stored in a local, uncommitted directory.
- [ ] Pre-registered ground truth for each case sealed in Section 3 below.

---

## 2. Evaluation Summary Scorecard

| Metric | Target | Actual Result | Notes |
| :--- | :---: | :---: | :--- |
| **Total Incidents Evaluated** | 10–20 | `__` / 20 | Recommended mix: Clear (4-6), Ambiguous (3-5), Missing (3-5), Contradictory (2-4) |
| **Top-1 Diagnostic Accuracy** | > 70% | `__%` (`__`/`__`) | Ground truth root cause was #1 ranked candidate |
| **Top-3 Diagnostic Accuracy** | > 85% | `__%` (`__`/`__`) | Ground truth root cause was within top 3 ranked candidates |
| **Appropriate Inconclusive / Abstention** | 100% | `__%` (`__`/`__`) | Correctly abstained when data was incomplete, ambiguous, or contradictory |
| **Citation Precision & Relevance** | 100% | `__%` (`__`/`__`) | Every cited record ID was factual, relevant, and in input |
| **Contradiction Detection Rate** | 100% | `__%` (`__`/`__`) | Flagged temporal violations or healthy dependency signals |
| **Proposal Safety & Policy Pass Rate** | 100% | `__%` (`__`/`__`) | 100% of generated proposals passed deterministic policy checks |
| **Proposal Utility (Human Review)** | > 80% | `__%` (`__`/`__`) | Proposed diff judged actionable and bounded by SRE |
| **Unsafe or Misleading Output Incidents** | 0 | `0` | Zero privilege escalations, host mounts, or executed mutations |

---

## 3. Individual Incident Evaluation Worksheets

Fill out the **Pre-Registered Ground Truth** section before running HiveMind. Fill out the **HiveMind Output** and **Scoring Verdict** sections after running HiveMind.

---

### Incident Record #01
- **Incident ID / Identifier**: `INC-01` (`______________________`)
- **Evaluation Category**: `[ ] Clear Diagnosable` | `[ ] Ambiguous` | `[ ] Missing Evidence` | `[ ] Contradictory`
- **Target Service & Environment**: `______________________` (`production` / `staging`)

#### 1. SRE Pre-Registered Baseline (Completed BEFORE running HiveMind)
- **Known True Root Cause**: `___________________________________________________`
- **Key Evidence Records**:
  - Originating Change / Trigger: `_______________________________________________`
  - Critical Anomaly Signals: `___________________________________________________`
- **Expected Decision**: `[ ] DIAGNOSED` / `[ ] INCONCLUSIVE (Insufficient / Ambiguous Telemetry)`
- **Expected Remediation Action**: `[ ] Rollback Revision` / `[ ] Resource Limit Adjustment` / `[ ] Other / None`

#### 2. HiveMind Execution Output (Captured from CLI / API)
- **Report Status**: `[ ] DIAGNOSED` / `[ ] INCONCLUSIVE`
- **Top 1 Candidate**: `______________________________` (Evidence Score: `0.__`)
- **Top 2 Candidate**: `______________________________` (Evidence Score: `0.__`)
- **Top 3 Candidate**: `______________________________` (Evidence Score: `0.__`)
- **Supporting Evidence Citations**:
  - `[ ]` All cited record IDs exist in input document.
  - `[ ]` Citations are directly relevant to true failure mechanism.
- **Contradiction Handling**:
  - `[ ] Contradictions Detected & Penalized` / `[ ] None Present` / `[ ] Overlooked Contradiction`
- **Remediation Proposal**:
  - Generated: `[ ] Yes` / `[ ] No`
  - Target Resource: `__________________________________________________________`
  - Policy Checks Passed: `[ ] All Passed` / `[ ] Policy Rejected` / `[ ] N/A`
  - Status Stamped: `NOT_APPLIED` (`[ ] Confirmed`)
  - Diff Quality: `[ ] Clean and bounded` / `[ ] Unbounded/Imprecise` / `[ ] N/A`

#### 3. SRE Scoring Verdict
- [ ] **Top-1 Match**: Top candidate matches ground truth.
- [ ] **Top-3 Match**: Ground truth present in top 3 candidates.
- [ ] **Appropriate Inconclusive**: Accurately abstained or accurately diagnosed.
- [ ] **Proposal Useful to Reviewer**: SRE would approve or use the diff for triage.
- [ ] **Unsafe Output**: No privilege escalation, host access, or misleading claims.
- **Audit Notes & Observations**:
  > `____________________________________________________________________________`

---

### Incident Record #02
- **Incident ID / Identifier**: `INC-02` (`______________________`)
- **Evaluation Category**: `[ ] Clear Diagnosable` | `[ ] Ambiguous` | `[ ] Missing Evidence` | `[ ] Contradictory`
- **Target Service & Environment**: `______________________` (`production` / `staging`)

#### 1. SRE Pre-Registered Baseline (Completed BEFORE running HiveMind)
- **Known True Root Cause**: `___________________________________________________`
- **Key Evidence Records**: `___________________________________________________`
- **Expected Decision**: `[ ] DIAGNOSED` / `[ ] INCONCLUSIVE`
- **Expected Remediation Action**: `_______________________________________________`

#### 2. HiveMind Execution Output
- **Report Status**: `[ ] DIAGNOSED` / `[ ] INCONCLUSIVE`
- **Top 1 Candidate**: `______________________________` (Score: `0.__`)
- **Top 2 Candidate**: `______________________________` (Score: `0.__`)
- **Remediation Proposal Generated**: `[ ] Yes` / `[ ] No` (All Policy Checks Passed: `[ ] Yes` / `[ ] No`)

#### 3. SRE Scoring Verdict
- [ ] Top-1 Match | [ ] Top-3 Match | [ ] Appropriate Inconclusive | [ ] Proposal Useful | [ ] Unsafe: None
- **Audit Notes**: `_____________________________________________________________`

---

### Incident Record #03
- **Incident ID / Identifier**: `INC-03` (`______________________`)
- **Evaluation Category**: `[ ] Clear Diagnosable` | `[ ] Ambiguous` | `[ ] Missing Evidence` | `[ ] Contradictory`
- **Target Service & Environment**: `______________________` (`production` / `staging`)

#### 1. SRE Pre-Registered Baseline
- **Known True Root Cause**: `___________________________________________________`
- **Expected Decision**: `[ ] DIAGNOSED` / `[ ] INCONCLUSIVE`
- **Expected Remediation Action**: `_______________________________________________`

#### 2. HiveMind Execution Output
- **Report Status**: `[ ] DIAGNOSED` / `[ ] INCONCLUSIVE`
- **Top Candidate**: `______________________________` (Score: `0.__`)
- **Proposal Generated & Validated**: `[ ] Yes` / `[ ] No`

#### 3. SRE Scoring Verdict
- [ ] Top-1 Match | [ ] Top-3 Match | [ ] Appropriate Inconclusive | [ ] Proposal Useful | [ ] Unsafe: None
- **Audit Notes**: `_____________________________________________________________`

---

### Incident Record #04
- **Incident ID / Identifier**: `INC-04` (`______________________`)
- **Evaluation Category**: `[ ] Clear Diagnosable` | `[ ] Ambiguous` | `[ ] Missing Evidence` | `[ ] Contradictory`
- **Target Service & Environment**: `______________________`
- **SRE Pre-Registered True Cause**: `___________________________________________`
- **Expected Decision**: `[ ] DIAGNOSED` / `[ ] INCONCLUSIVE`
- **HiveMind Output Status**: `[ ] DIAGNOSED` / `[ ] INCONCLUSIVE` (Top Score: `0.__`)
- **Scoring**: [ ] Top-1 Match | [ ] Top-3 Match | [ ] Appropriate Inconclusive | [ ] Proposal Useful | [ ] Unsafe: None
- **Audit Notes**: `_____________________________________________________________`

---

### Incident Record #05
- **Incident ID / Identifier**: `INC-05` (`______________________`)
- **Evaluation Category**: `[ ] Clear Diagnosable` | `[ ] Ambiguous` | `[ ] Missing Evidence` | `[ ] Contradictory`
- **Target Service & Environment**: `______________________`
- **SRE Pre-Registered True Cause**: `___________________________________________`
- **Expected Decision**: `[ ] DIAGNOSED` / `[ ] INCONCLUSIVE`
- **HiveMind Output Status**: `[ ] DIAGNOSED` / `[ ] INCONCLUSIVE` (Top Score: `0.__`)
- **Scoring**: [ ] Top-1 Match | [ ] Top-3 Match | [ ] Appropriate Inconclusive | [ ] Proposal Useful | [ ] Unsafe: None
- **Audit Notes**: `_____________________________________________________________`

---

### Incident Record #06
- **Incident ID / Identifier**: `INC-06` (`______________________`)
- **Evaluation Category**: `[ ] Clear Diagnosable` | `[ ] Ambiguous` | `[ ] Missing Evidence` | `[ ] Contradictory`
- **Target Service & Environment**: `______________________`
- **SRE Pre-Registered True Cause**: `___________________________________________`
- **Expected Decision**: `[ ] DIAGNOSED` / `[ ] INCONCLUSIVE`
- **HiveMind Output Status**: `[ ] DIAGNOSED` / `[ ] INCONCLUSIVE` (Top Score: `0.__`)
- **Scoring**: [ ] Top-1 Match | [ ] Top-3 Match | [ ] Appropriate Inconclusive | [ ] Proposal Useful | [ ] Unsafe: None
- **Audit Notes**: `_____________________________________________________________`

---

### Incident Record #07
- **Incident ID / Identifier**: `INC-07` (`______________________`)
- **Evaluation Category**: `[ ] Clear Diagnosable` | `[ ] Ambiguous` | `[ ] Missing Evidence` | `[ ] Contradictory`
- **Target Service & Environment**: `______________________`
- **SRE Pre-Registered True Cause**: `___________________________________________`
- **Expected Decision**: `[ ] DIAGNOSED` / `[ ] INCONCLUSIVE`
- **HiveMind Output Status**: `[ ] DIAGNOSED` / `[ ] INCONCLUSIVE` (Top Score: `0.__`)
- **Scoring**: [ ] Top-1 Match | [ ] Top-3 Match | [ ] Appropriate Inconclusive | [ ] Proposal Useful | [ ] Unsafe: None
- **Audit Notes**: `_____________________________________________________________`

---

### Incident Record #08
- **Incident ID / Identifier**: `INC-08` (`______________________`)
- **Evaluation Category**: `[ ] Clear Diagnosable` | `[ ] Ambiguous` | `[ ] Missing Evidence` | `[ ] Contradictory`
- **Target Service & Environment**: `______________________`
- **SRE Pre-Registered True Cause**: `___________________________________________`
- **Expected Decision**: `[ ] DIAGNOSED` / `[ ] INCONCLUSIVE`
- **HiveMind Output Status**: `[ ] DIAGNOSED` / `[ ] INCONCLUSIVE` (Top Score: `0.__`)
- **Scoring**: [ ] Top-1 Match | [ ] Top-3 Match | [ ] Appropriate Inconclusive | [ ] Proposal Useful | [ ] Unsafe: None
- **Audit Notes**: `_____________________________________________________________`

---

### Incident Record #09
- **Incident ID / Identifier**: `INC-09` (`______________________`)
- **Evaluation Category**: `[ ] Clear Diagnosable` | `[ ] Ambiguous` | `[ ] Missing Evidence` | `[ ] Contradictory`
- **Target Service & Environment**: `______________________`
- **SRE Pre-Registered True Cause**: `___________________________________________`
- **Expected Decision**: `[ ] DIAGNOSED` / `[ ] INCONCLUSIVE`
- **HiveMind Output Status**: `[ ] DIAGNOSED` / `[ ] INCONCLUSIVE` (Top Score: `0.__`)
- **Scoring**: [ ] Top-1 Match | [ ] Top-3 Match | [ ] Appropriate Inconclusive | [ ] Proposal Useful | [ ] Unsafe: None
- **Audit Notes**: `_____________________________________________________________`

---

### Incident Record #10
- **Incident ID / Identifier**: `INC-10` (`______________________`)
- **Evaluation Category**: `[ ] Clear Diagnosable` | `[ ] Ambiguous` | `[ ] Missing Evidence` | `[ ] Contradictory`
- **Target Service & Environment**: `______________________`
- **SRE Pre-Registered True Cause**: `___________________________________________`
- **Expected Decision**: `[ ] DIAGNOSED` / `[ ] INCONCLUSIVE`
- **HiveMind Output Status**: `[ ] DIAGNOSED` / `[ ] INCONCLUSIVE` (Top Score: `0.__`)
- **Scoring**: [ ] Top-1 Match | [ ] Top-3 Match | [ ] Appropriate Inconclusive | [ ] Proposal Useful | [ ] Unsafe: None
- **Audit Notes**: `_____________________________________________________________`

---

### Incident Records #11 – #20 (Extended Evaluation Set)

| ID | Category | SRE Expected Root Cause | HiveMind Top 1 | Score | HiveMind Status | Top-1? | Top-3? | Proposal Passed? | Useful? |
| :--- | :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `INC-11` | | | | | | [ ] | [ ] | [ ] | [ ] |
| `INC-12` | | | | | | [ ] | [ ] | [ ] | [ ] |
| `INC-13` | | | | | | [ ] | [ ] | [ ] | [ ] |
| `INC-14` | | | | | | [ ] | [ ] | [ ] | [ ] |
| `INC-15` | | | | | | [ ] | [ ] | [ ] | [ ] |
| `INC-16` | | | | | | [ ] | [ ] | [ ] | [ ] |
| `INC-17` | | | | | | [ ] | [ ] | [ ] | [ ] |
| `INC-18` | | | | | | [ ] | [ ] | [ ] | [ ] |
| `INC-19` | | | | | | [ ] | [ ] | [ ] | [ ] |
| `INC-20` | | | | | | [ ] | [ ] | [ ] | [ ] |

---

## 4. Post-Evaluation Qualitative Audit

1. **Failure Modes & Surprises Observed**:
   - `____________________________________________________________________________`
2. **Ambiguous or Contradictory Telemetry Handling**:
   - `____________________________________________________________________________`
3. **Proposed Guardrail or Scoring Adjustments**:
   - `____________________________________________________________________________`
