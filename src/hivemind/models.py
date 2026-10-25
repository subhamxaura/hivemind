"""Strict domain models for HiveMind incident telemetry, analysis, and proposals."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from hivemind.redaction import redact_secrets

CURRENT_SCHEMA_VERSION = "hivemind.io/v1alpha1"


class StrictBaseModel(BaseModel):
    """Base model that forbids unexpected fields to ensure schema integrity."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class AnomalySignal(StrictBaseModel):
    """Observable telemetry anomaly or alert event."""

    signal_id: str = Field(..., description="Unique signal identifier")
    service: str = Field(..., description="Name of the reporting service")
    timestamp: datetime = Field(..., description="Timezone-aware detection timestamp")
    name: str = Field(..., description="Signal or metric name (e.g. oom_killed, error_rate)")
    value: float | str = Field(..., description="Observed value or status")
    threshold: float | str | None = Field(default=None, description="Expected threshold or baseline")
    severity: str = Field(default="warning", description="Severity level: info, warning, critical")

    @field_validator("timestamp")
    @classmethod
    def validate_tz(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("Timestamps must be timezone-aware (e.g. UTC ISO-8601 with Z or offset)")
        return v


class DeploymentChange(StrictBaseModel):
    """Recent deployment, rollout, or configuration change."""

    change_id: str = Field(..., description="Unique change identifier")
    service: str = Field(..., description="Target service affected by change")
    timestamp: datetime = Field(..., description="Timezone-aware change application timestamp")
    change_type: str = Field(..., description="Type of change: deployment, configmap, resource_limit")
    identifier: str = Field(..., description="Revision or release tag (e.g. rev-42, sha-1234)")
    prior_known_good_identifier: str | None = Field(
        default=None,
        description="Explicit prior known-good revision if rollback is allowed",
    )
    details: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Structured change details. Proposal generation additionally requires a complete "
            "current_manifest; memory adjustments require target_container and explicit current/prior "
            "memory limits, while deployment rollbacks require a complete previous_manifest with "
            "matching hivemind.io/revision annotations."
        ),
    )

    @field_validator("timestamp")
    @classmethod
    def validate_tz(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("Timestamps must be timezone-aware")
        return v


class TopologyDependency(StrictBaseModel):
    """Service-to-service runtime dependency relation."""

    source_service: str = Field(..., description="Calling service")
    target_service: str = Field(..., description="Downstream service called by source")
    dependency_type: str = Field(default="sync_http", description="sync_http, database, queue, cache")
    critical: bool = Field(default=True, description="Whether failure of target degrades source")


class LogExcerpt(StrictBaseModel):
    """Sanitized log message snippet related to incident."""

    log_id: str = Field(..., description="Unique log line identifier")
    service: str = Field(..., description="Source service")
    timestamp: datetime = Field(..., description="Timezone-aware log timestamp")
    message: str = Field(..., description="Log message text (subject to best-effort secret redaction)")

    @field_validator("timestamp")
    @classmethod
    def validate_tz(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("Timestamps must be timezone-aware")
        return v

    @field_validator("message")
    @classmethod
    def redact_message(cls, v: str) -> str:
        return redact_secrets(v)


class IncidentEvent(StrictBaseModel):
    """Root structured incident telemetry document."""

    schema_version: str = Field(
        ...,
        description=f"Schema version contract, must equal '{CURRENT_SCHEMA_VERSION}'",
    )
    incident_id: str = Field(..., description="Unique incident identifier")
    detection_timestamp: datetime = Field(..., description="Timezone-aware incident detection time")
    environment: str = Field(..., description="Deployment environment (e.g. production, staging)")
    affected_services: list[str] = Field(..., min_length=1, description="Primary affected services")
    analysis_window_minutes: int = Field(
        default=60,
        gt=0,
        le=1440,
        description="Analysis lookback window in minutes before detection timestamp",
    )
    signals: list[AnomalySignal] = Field(default_factory=list)
    changes: list[DeploymentChange] = Field(default_factory=list)
    dependencies: list[TopologyDependency] = Field(default_factory=list)
    log_excerpts: list[LogExcerpt] = Field(default_factory=list)

    @field_validator("schema_version")
    @classmethod
    def validate_schema(cls, v: str) -> str:
        if v != CURRENT_SCHEMA_VERSION:
            raise ValueError(f"Unsupported schema_version '{v}'. Expected '{CURRENT_SCHEMA_VERSION}'")
        return v

    @field_validator("detection_timestamp")
    @classmethod
    def validate_tz(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("detection_timestamp must be timezone-aware")
        return v

    @model_validator(mode="after")
    def validate_record_ids_unique(self) -> "IncidentEvent":
        ids: set[str] = set()
        for s in self.signals:
            if s.signal_id in ids:
                raise ValueError(f"Duplicate record identifier: {s.signal_id}")
            ids.add(s.signal_id)
        for c in self.changes:
            if c.change_id in ids:
                raise ValueError(f"Duplicate record identifier: {c.change_id}")
            ids.add(c.change_id)
        for log_item in self.log_excerpts:
            if log_item.log_id in ids:
                raise ValueError(f"Duplicate record identifier: {log_item.log_id}")
            ids.add(log_item.log_id)
        return self


class EvidenceReference(StrictBaseModel):
    """Pointer to a specific record in the incident input."""

    record_type: str = Field(..., description="signal, change, dependency, or log")
    record_id: str = Field(..., description="Exact ID of cited record in input")
    summary: str = Field(..., description="Brief factual summary of what record indicates")


class CandidateCause(StrictBaseModel):
    """Ranked diagnosis candidate supported by deterministic evidence."""

    candidate_id: str = Field(..., description="Deterministic candidate identifier")
    title: str = Field(..., description="Short diagnostic title")
    description: str = Field(..., description="Clear explanation of the candidate root cause")
    evidence_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Deterministic evidence score (0.0 to 1.0) calculated from rule weights",
    )
    scoring_breakdown: dict[str, float] = Field(
        ...,
        description="Auditable additive breakdown of weights that produced evidence_score",
    )
    supporting_evidence: list[EvidenceReference] = Field(
        ...,
        description="Exact input records supporting this candidate",
    )
    contradicting_evidence: list[EvidenceReference] = Field(
        default_factory=list,
        description="Exact input records that conflict with or weaken this candidate",
    )
    rationale: str = Field(..., description="Traceable rationale derived strictly from cited evidence")
    uncertainty: str = Field(..., description="Known gaps, assumptions, or alternative explanations")
    missing_evidence: list[str] = Field(
        default_factory=list,
        description="List of telemetry or data points that would be needed for higher certainty",
    )


class PolicyCheckResult(StrictBaseModel):
    """Result of a single deterministic policy check on a proposal."""

    check_name: str = Field(..., description="Identifier of the policy check")
    passed: bool = Field(..., description="Whether the check succeeded")
    details: str = Field(..., description="Explanation of check result or rejection reason")


class RemediationProposal(StrictBaseModel):
    """Constrained, human-reviewable remediation diff for Kubernetes resources."""

    proposal_id: str = Field(..., description="Unique proposal identifier")
    operation: str = Field(..., description="ROLLBACK_REVISION or ADJUST_RESOURCE_LIMITS")
    target_resource: str = Field(..., description="Format: <apiVersion>:<kind>/<namespace>/<name>")
    before_manifest: str = Field(..., description="Current YAML manifest snippet")
    after_manifest: str = Field(..., description="Proposed YAML manifest snippet")
    diff: str = Field(..., description="Unified diff showing proposed modification")
    evidence_references: list[EvidenceReference] = Field(
        ...,
        description="Evidence records justifying this proposal",
    )
    rationale: str = Field(..., description="Explanation of why this proposal addresses the diagnosis")
    assumptions_and_limitations: list[str] = Field(
        default_factory=list,
        description="Explicit boundaries, side effects, and rollback notes",
    )
    policy_checks: list[PolicyCheckResult] = Field(
        default_factory=list,
        description="Deterministic policy check verdicts",
    )
    all_policy_checks_passed: bool = Field(
        ...,
        description="True only if every deterministic policy check passed",
    )
    status: str = Field(
        default="NOT_APPLIED",
        description="Proposal execution state. Always NOT_APPLIED for HiveMind MVP",
    )

    @field_validator("status")
    @classmethod
    def validate_not_applied(cls, v: str) -> str:
        if v != "NOT_APPLIED":
            raise ValueError("HiveMind is read-only: proposal status must strictly be 'NOT_APPLIED'")
        return v


class AnalysisStatus(str, Enum):
    DIAGNOSED = "DIAGNOSED"
    INCONCLUSIVE = "INCONCLUSIVE"


class ProposalGenerationStatus(str, Enum):
    GENERATED = "GENERATED"
    NOT_GENERATED = "NOT_GENERATED"
    NOT_ATTEMPTED = "NOT_ATTEMPTED"


class ProposalGenerationReasonCode(str, Enum):
    GENERATED = "GENERATED"
    DIAGNOSIS_NOT_CONFIRMED = "DIAGNOSIS_NOT_CONFIRMED"
    UNSUPPORTED_CAUSE = "UNSUPPORTED_CAUSE"
    CHANGE_NOT_FOUND = "CHANGE_NOT_FOUND"
    SOURCE_MANIFEST_MISSING = "SOURCE_MANIFEST_MISSING"
    SOURCE_MANIFEST_INVALID = "SOURCE_MANIFEST_INVALID"
    TARGET_IDENTITY_INVALID = "TARGET_IDENTITY_INVALID"
    MEMORY_EVIDENCE_MISSING = "MEMORY_EVIDENCE_MISSING"
    MEMORY_QUANTITY_INVALID = "MEMORY_QUANTITY_INVALID"
    MEMORY_BASELINE_MISMATCH = "MEMORY_BASELINE_MISMATCH"
    MEMORY_NO_OP = "MEMORY_NO_OP"
    PRIOR_MANIFEST_MISSING = "PRIOR_MANIFEST_MISSING"
    REVISION_MISMATCH = "REVISION_MISMATCH"
    SELECTOR_MISMATCH = "SELECTOR_MISMATCH"
    TELEMETRY_REFERENCE_INVALID = "TELEMETRY_REFERENCE_INVALID"
    POLICY_REJECTED = "POLICY_REJECTED"
    SERIALIZATION_FAILED = "SERIALIZATION_FAILED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class ProposalGenerationOutcome(StrictBaseModel):
    """Safe summary explaining whether a remediation proposal was produced."""

    status: ProposalGenerationStatus
    reason_code: ProposalGenerationReasonCode
    message: str
    failed_policy_checks: list[str] = Field(default_factory=list)
    telemetry_evidence_count: int = Field(default=0, ge=0)


class IncidentAnalysisReport(StrictBaseModel):
    """Complete auditable incident investigation report."""

    incident_id: str = Field(..., description="ID of analyzed incident")
    environment: str = Field(..., description="Environment of the incident")
    status: AnalysisStatus = Field(..., description="DIAGNOSED or INCONCLUSIVE")
    summary: str = Field(..., description="High-level narrative of findings")
    analysis_window_start: datetime = Field(..., description="Start of lookback window")
    analysis_window_end: datetime = Field(..., description="Detection timestamp (window end)")
    ranked_candidates: list[CandidateCause] = Field(
        default_factory=list,
        description="Candidate causes ranked by evidence score descending",
    )
    proposal: RemediationProposal | None = Field(
        default=None,
        description="Constrained remediation proposal if criteria met, else None",
    )
    proposal_generation: ProposalGenerationOutcome = Field(
        default_factory=lambda: ProposalGenerationOutcome(
            status=ProposalGenerationStatus.NOT_ATTEMPTED,
            reason_code=ProposalGenerationReasonCode.DIAGNOSIS_NOT_CONFIRMED,
            message="Proposal generation was not attempted.",
        ),
        description="Structured reason and telemetry-evidence summary for proposal generation",
    )
    inconclusive_reasons: list[str] = Field(
        default_factory=list,
        description="Explicit reasons if investigation yielded INCONCLUSIVE",
    )
    telemetry_warnings: list[str] = Field(
        default_factory=list,
        description="Non-fatal telemetry gaps or warnings noted when status is DIAGNOSED",
    )
    safety_notice: str = Field(
        default=(
            "HiveMind is strictly READ-ONLY. No changes were applied to any Kubernetes cluster "
            "or infrastructure. Proposals must be reviewed, tested, and applied manually by operators."
        ),
        description="Unchanging mandatory safety declaration",
    )
