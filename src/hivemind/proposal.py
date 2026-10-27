"""Constrained, read-only Kubernetes Deployment proposal generation.

Proposals are derived from complete, explicitly supplied Deployment manifests.
HiveMind never invents workload fields or applies the resulting diff.
"""

from __future__ import annotations

import copy
import difflib
import logging
from collections.abc import Mapping
from datetime import timedelta
from typing import Any

import yaml

from hivemind.k8s_manifest import (
    _find_container,
    _get_memory_limit,
    _manifest_identity,
    _parse_manifest,
    _parse_memory_to_bytes,
    _resource_reference,
    _revision,
    _set_memory_limit,
    _UniqueKeySafeLoader,
    _valid_dns_name,
    _validate_deployment_structure,
)
from hivemind.models import (
    CandidateCause,
    DeploymentChange,
    EvidenceReference,
    IncidentEvent,
    ProposalGenerationOutcome,
    ProposalGenerationReasonCode,
    ProposalGenerationStatus,
    RemediationProposal,
)
from hivemind.policy import (
    DeterministicPolicyValidator,
    _only_target_memory_limit_changed,
    _ProposalPolicyFailure,
)
from hivemind.security import _security_violations

logger = logging.getLogger(__name__)

# Re-exports for backward compatibility
__all__ = [
    "RemediationProposalGenerator",
    "DeterministicPolicyValidator",
    "_ProposalPolicyFailure",
    "_parse_memory_to_bytes",
    "_UniqueKeySafeLoader",
    "_parse_manifest",
    "_manifest_identity",
    "_resource_reference",
    "_valid_dns_name",
    "_validate_deployment_structure",
    "_find_container",
    "_get_memory_limit",
    "_set_memory_limit",
    "_revision",
    "_security_violations",
    "_only_target_memory_limit_changed",
]


class RemediationProposalGenerator:
    """Create source-grounded proposals with traceable telemetry and safe failure outcomes."""

    @classmethod
    def generate(
        cls,
        incident: IncidentEvent,
        candidate: CandidateCause,
    ) -> RemediationProposal | None:
        """Backward-compatible proposal-only interface."""
        proposal, _ = cls.generate_with_outcome(incident, candidate)
        return proposal

    @classmethod
    def generate_with_outcome(
        cls,
        incident: IncidentEvent,
        candidate: CandidateCause,
    ) -> tuple[RemediationProposal | None, ProposalGenerationOutcome]:
        try:
            failure = cls._preflight(incident, candidate)
            if failure is not None:
                return None, cls._finish(failure)

            proposal = cls._build_proposal(incident, candidate)
            if proposal is None:
                outcome = cls._outcome(
                    ProposalGenerationStatus.NOT_GENERATED,
                    ProposalGenerationReasonCode.POLICY_REJECTED,
                    "One or more deterministic policy checks rejected the proposed change.",
                )
                return None, cls._finish(outcome)

            telemetry_count = len(
                {
                    (reference.record_type, reference.record_id)
                    for reference in proposal.evidence_references
                    if reference.record_type in {"signal", "log"}
                }
            )
            outcome = cls._outcome(
                ProposalGenerationStatus.GENERATED,
                ProposalGenerationReasonCode.GENERATED,
                "Proposal generated from the supplied source manifest and cited incident telemetry.",
                telemetry_evidence_count=telemetry_count,
            )
            return proposal, cls._finish(outcome)
        except _ProposalPolicyFailure as exc:
            outcome = cls._outcome(
                ProposalGenerationStatus.NOT_GENERATED,
                ProposalGenerationReasonCode.POLICY_REJECTED,
                "One or more deterministic policy checks rejected the proposed change.",
                failed_policy_checks=exc.failed_checks,
            )
            return None, cls._finish(outcome)
        except (yaml.YAMLError, ValueError, TypeError, KeyError, OverflowError):
            outcome = cls._outcome(
                ProposalGenerationStatus.NOT_GENERATED,
                ProposalGenerationReasonCode.SERIALIZATION_FAILED,
                "Proposal data could not be safely validated or serialized.",
            )
            return None, cls._finish(outcome)
        except Exception as exc:
            logger.error(
                "Unexpected proposal-generation failure",
                extra={"proposal_exception_type": type(exc).__name__},
            )
            outcome = cls._outcome(
                ProposalGenerationStatus.NOT_GENERATED,
                ProposalGenerationReasonCode.INTERNAL_ERROR,
                "An internal error prevented proposal generation; no change was applied.",
            )
            return None, cls._finish(outcome)

    @staticmethod
    def _outcome(
        status: ProposalGenerationStatus,
        reason_code: ProposalGenerationReasonCode,
        message: str,
        *,
        failed_policy_checks: list[str] | None = None,
        telemetry_evidence_count: int = 0,
    ) -> ProposalGenerationOutcome:
        return ProposalGenerationOutcome(
            status=status,
            reason_code=reason_code,
            message=message,
            failed_policy_checks=failed_policy_checks or [],
            telemetry_evidence_count=telemetry_evidence_count,
        )

    @staticmethod
    def _finish(outcome: ProposalGenerationOutcome) -> ProposalGenerationOutcome:
        logger.info(
            "Proposal generation completed",
            extra={
                "proposal_status": outcome.status.value,
                "proposal_reason_code": outcome.reason_code.value,
                "proposal_telemetry_evidence_count": outcome.telemetry_evidence_count,
                "proposal_failed_policy_check_count": len(outcome.failed_policy_checks),
            },
        )
        return outcome

    @classmethod
    def _preflight(
        cls,
        incident: IncidentEvent,
        candidate: CandidateCause,
    ) -> ProposalGenerationOutcome | None:
        if not candidate.candidate_id.startswith("cause-change-"):
            return cls._outcome(
                ProposalGenerationStatus.NOT_GENERATED,
                ProposalGenerationReasonCode.UNSUPPORTED_CAUSE,
                "This diagnosis type does not have a supported remediation proposal.",
            )
        change_id = candidate.candidate_id.removeprefix("cause-change-")
        change = next((item for item in incident.changes if item.change_id == change_id), None)
        if change is None:
            return cls._outcome(
                ProposalGenerationStatus.NOT_GENERATED,
                ProposalGenerationReasonCode.CHANGE_NOT_FOUND,
                "The change record referenced by the diagnosis is not present in the incident input.",
            )

        telemetry_error = cls._validate_candidate_evidence(incident, candidate, change)
        if telemetry_error is not None:
            return telemetry_error

        current_raw = change.details.get("current_manifest")
        if not isinstance(current_raw, Mapping):
            return cls._outcome(
                ProposalGenerationStatus.NOT_GENERATED,
                ProposalGenerationReasonCode.SOURCE_MANIFEST_MISSING,
                "A complete current_manifest is required; no workload manifest was inferred.",
            )
        current_manifest = copy.deepcopy(dict(current_raw))
        if _validate_deployment_structure(current_manifest, "Source manifest"):
            return cls._outcome(
                ProposalGenerationStatus.NOT_GENERATED,
                ProposalGenerationReasonCode.SOURCE_MANIFEST_INVALID,
                "The supplied current_manifest is not a structurally valid Deployment for proposal use.",
            )
        if _resource_reference(current_manifest) is None:
            return cls._outcome(
                ProposalGenerationStatus.NOT_GENERATED,
                ProposalGenerationReasonCode.TARGET_IDENTITY_INVALID,
                "The source Deployment does not have a valid exact Kubernetes resource identity.",
            )

        details = change.details
        is_resource_change = (
            change.change_type == "resource_limit"
            or "previous_memory_limit" in details
            or "memory_limit" in details
        )
        if is_resource_change:
            target_container = details.get("target_container")
            if not isinstance(target_container, str) or not target_container.strip():
                return cls._outcome(
                    ProposalGenerationStatus.NOT_GENERATED,
                    ProposalGenerationReasonCode.MEMORY_EVIDENCE_MISSING,
                    "Memory proposals require an explicit target_container and current/prior memory values.",
                )
            current_memory = details.get("memory_limit")
            previous_memory = details.get("previous_memory_limit")
            if current_memory is None or previous_memory is None:
                return cls._outcome(
                    ProposalGenerationStatus.NOT_GENERATED,
                    ProposalGenerationReasonCode.MEMORY_EVIDENCE_MISSING,
                    "Memory proposals require both memory_limit and previous_memory_limit in the change record.",
                )
            container = _find_container(current_manifest, target_container.strip())
            manifest_memory = _get_memory_limit(container) if container else None
            try:
                if manifest_memory is None:
                    raise ValueError("missing target memory limit")
                current_bytes = _parse_memory_to_bytes(current_memory)
                previous_bytes = _parse_memory_to_bytes(previous_memory)
                manifest_bytes = _parse_memory_to_bytes(manifest_memory)
            except (TypeError, ValueError):
                return cls._outcome(
                    ProposalGenerationStatus.NOT_GENERATED,
                    ProposalGenerationReasonCode.MEMORY_QUANTITY_INVALID,
                    "The target container or its memory quantities are missing or unsupported.",
                )
            if current_bytes != manifest_bytes:
                return cls._outcome(
                    ProposalGenerationStatus.NOT_GENERATED,
                    ProposalGenerationReasonCode.MEMORY_BASELINE_MISMATCH,
                    "The source manifest memory limit does not match the incident change record.",
                )
            if current_bytes == previous_bytes:
                return cls._outcome(
                    ProposalGenerationStatus.NOT_GENERATED,
                    ProposalGenerationReasonCode.MEMORY_NO_OP,
                    "The current and previous memory values are identical; no proposal is needed.",
                )
        elif change.change_type == "deployment":
            previous_raw = details.get("previous_manifest")
            if not isinstance(previous_raw, Mapping):
                return cls._outcome(
                    ProposalGenerationStatus.NOT_GENERATED,
                    ProposalGenerationReasonCode.PRIOR_MANIFEST_MISSING,
                    "A complete previous_manifest is required for a deployment rollback.",
                )
            previous_manifest = copy.deepcopy(dict(previous_raw))
            if _validate_deployment_structure(previous_manifest, "Prior known-good manifest"):
                return cls._outcome(
                    ProposalGenerationStatus.NOT_GENERATED,
                    ProposalGenerationReasonCode.SOURCE_MANIFEST_INVALID,
                    "The supplied previous_manifest is not a structurally valid Deployment.",
                )
            if _resource_reference(previous_manifest) != _resource_reference(current_manifest):
                return cls._outcome(
                    ProposalGenerationStatus.NOT_GENERATED,
                    ProposalGenerationReasonCode.TARGET_IDENTITY_INVALID,
                    "Current and previous Deployment snapshots do not identify the same resource.",
                )
            prior_identifier = change.prior_known_good_identifier
            if (
                not isinstance(prior_identifier, str)
                or not prior_identifier.strip()
                or prior_identifier.strip() == change.identifier.strip()
                or _revision(current_manifest) != change.identifier.strip()
                or _revision(previous_manifest) != prior_identifier.strip()
            ):
                return cls._outcome(
                    ProposalGenerationStatus.NOT_GENERATED,
                    ProposalGenerationReasonCode.REVISION_MISMATCH,
                    "Manifest revision annotations do not match the current and prior-known-good identifiers.",
                )
            current_spec = current_manifest.get("spec")
            previous_spec = previous_manifest.get("spec")
            if (
                not isinstance(current_spec, dict)
                or not isinstance(previous_spec, dict)
                or current_spec.get("selector") != previous_spec.get("selector")
            ):
                return cls._outcome(
                    ProposalGenerationStatus.NOT_GENERATED,
                    ProposalGenerationReasonCode.SELECTOR_MISMATCH,
                    "Rollback snapshots must preserve the Deployment's immutable selector.",
                )
        elif change.change_type not in {"resource_limit", "deployment"}:
            return cls._outcome(
                ProposalGenerationStatus.NOT_GENERATED,
                ProposalGenerationReasonCode.UNSUPPORTED_CAUSE,
                "This change type does not have a supported remediation proposal.",
            )
        return None

    @classmethod
    def _validate_candidate_evidence(
        cls,
        incident: IncidentEvent,
        candidate: CandidateCause,
        change: DeploymentChange,
    ) -> ProposalGenerationOutcome | None:
        records: dict[str, dict[str, Any]] = {
            "change": {item.change_id: item for item in incident.changes},
            "signal": {item.signal_id: item for item in incident.signals},
            "log": {item.log_id: item for item in incident.log_excerpts},
        }
        seen: set[tuple[str, str]] = set()
        has_change = False
        has_signal = False
        window_start = incident.detection_timestamp - timedelta(
            minutes=incident.analysis_window_minutes
        )
        for reference in candidate.supporting_evidence:
            record_type = reference.record_type
            record = records.get(record_type, {}).get(reference.record_id)
            if record is None:
                return cls._outcome(
                    ProposalGenerationStatus.NOT_GENERATED,
                    ProposalGenerationReasonCode.TELEMETRY_REFERENCE_INVALID,
                    "A diagnosis evidence citation does not resolve to a record in the incident input.",
                )
            if record_type == "change" and reference.record_id != change.change_id:
                return cls._outcome(
                    ProposalGenerationStatus.NOT_GENERATED,
                    ProposalGenerationReasonCode.TELEMETRY_REFERENCE_INVALID,
                    "A proposal may cite only the change record it is intended to remediate.",
                )
            if record_type in {"signal", "log"} and (
                record.service != change.service
                or not window_start <= record.timestamp <= incident.detection_timestamp
            ):
                return cls._outcome(
                    ProposalGenerationStatus.NOT_GENERATED,
                    ProposalGenerationReasonCode.TELEMETRY_REFERENCE_INVALID,
                    "A diagnosis telemetry citation is outside the analysis window or belongs to another service.",
                )
            identity = (record_type, reference.record_id)
            if identity in seen:
                continue
            seen.add(identity)
            has_change = has_change or (record_type == "change" and reference.record_id == change.change_id)
            has_signal = has_signal or record_type == "signal"
        if not has_change or not has_signal:
            return cls._outcome(
                ProposalGenerationStatus.NOT_GENERATED,
                ProposalGenerationReasonCode.TELEMETRY_REFERENCE_INVALID,
                "A proposal requires resolvable citations to its source change and at least one supporting signal.",
            )
        return None

    @classmethod
    def _build_proposal(
        cls,
        incident: IncidentEvent,
        candidate: CandidateCause,
    ) -> RemediationProposal | None:
        if not candidate.candidate_id.startswith("cause-change-"):
            return None

        change_id = candidate.candidate_id.removeprefix("cause-change-")
        change: DeploymentChange | None = next(
            (item for item in incident.changes if item.change_id == change_id), None
        )
        if change is None:
            return None

        details = change.details
        current_raw = details.get("current_manifest")
        if not isinstance(current_raw, Mapping):
            return None
        before_obj = copy.deepcopy(dict(current_raw))
        if _validate_deployment_structure(before_obj, "Source manifest"):
            return None

        target_resource = _resource_reference(before_obj)
        if target_resource is None:
            return None

        assumptions = [
            "The complete source manifest and revision metadata were supplied by the incident data provider; HiveMind did not independently retrieve or authenticate cluster state.",
            "The proposal is an untrusted recommendation requiring human review, validation, and testing.",
            "Deterministic policy checks do not establish operational safety or Kubernetes admission-policy compliance.",
            "HiveMind did not connect to a cluster or mutate any live resource.",
        ]

        operation: str
        after_obj: dict[str, Any]
        target_container: str | None = None
        current_memory: Any | None = None
        previous_memory: Any | None = None
        prior_identifier: str | None = None
        current_identifier: str | None = None
        rationale: str

        is_resource_change = (
            change.change_type == "resource_limit"
            or "previous_memory_limit" in details
            or "memory_limit" in details
        )
        if is_resource_change:
            target_container_raw = details.get("target_container")
            if not isinstance(target_container_raw, str) or not target_container_raw.strip():
                return None
            target_container = target_container_raw.strip()
            current_memory = details.get("memory_limit")
            previous_memory = details.get("previous_memory_limit")
            if current_memory is None or previous_memory is None:
                return None

            container = _find_container(before_obj, target_container)
            manifest_memory = _get_memory_limit(container) if container else None
            try:
                if manifest_memory is None:
                    return None
                current_bytes = _parse_memory_to_bytes(current_memory)
                prior_bytes = _parse_memory_to_bytes(previous_memory)
                manifest_bytes = _parse_memory_to_bytes(manifest_memory)
            except (TypeError, ValueError):
                return None
            if current_bytes == prior_bytes or manifest_bytes != current_bytes:
                return None

            operation = "ADJUST_RESOURCE_LIMITS"
            after_obj = copy.deepcopy(before_obj)
            if not _set_memory_limit(after_obj, target_container, previous_memory):
                return None
            rationale = (
                f"Restore the explicitly recorded memory limit for container {target_container} on "
                f"{target_resource} from {current_memory} to {previous_memory}."
            )
        elif change.change_type == "deployment":
            prior_identifier = change.prior_known_good_identifier
            current_identifier = change.identifier
            if (
                not isinstance(prior_identifier, str)
                or not prior_identifier.strip()
                or prior_identifier.strip() == current_identifier.strip()
            ):
                return None
            previous_raw = details.get("previous_manifest")
            if not isinstance(previous_raw, Mapping):
                return None
            after_obj = copy.deepcopy(dict(previous_raw))
            if _validate_deployment_structure(after_obj, "Prior known-good manifest"):
                return None
            if _resource_reference(after_obj) != target_resource:
                return None
            if _revision(before_obj) != current_identifier.strip():
                return None
            if _revision(after_obj) != prior_identifier.strip():
                return None
            before_spec = before_obj.get("spec")
            after_spec = after_obj.get("spec")
            if not isinstance(before_spec, dict) or not isinstance(after_spec, dict):
                return None
            if before_spec.get("selector") != after_spec.get("selector"):
                return None
            operation = "ROLLBACK_REVISION"
            rationale = (
                f"Restore the explicitly supplied previous Deployment snapshot {prior_identifier.strip()} "
                f"for {target_resource}; the source snapshot is stamped {current_identifier.strip()}."
            )
        else:
            return None

        evidence_refs: list[EvidenceReference] = []
        for reference in candidate.supporting_evidence:
            if reference.record_type == "change" and reference.record_id == change.change_id:
                if operation == "ADJUST_RESOURCE_LIMITS":
                    summary = (
                        f"{reference.summary}; manifest memory_limit={current_memory}; "
                        f"explicit previous_memory_limit={previous_memory} for {target_container}"
                    )
                else:
                    summary = (
                        f"{reference.summary}; explicit prior known-good revision="
                        f"{prior_identifier.strip() if prior_identifier else ''}"
                    )
                evidence_refs.append(
                    EvidenceReference(
                        record_type=reference.record_type,
                        record_id=reference.record_id,
                        summary=summary,
                    )
                )
            else:
                evidence_refs.append(reference)

        before_text = yaml.safe_dump(before_obj, sort_keys=False, allow_unicode=True)
        after_text = yaml.safe_dump(after_obj, sort_keys=False, allow_unicode=True)
        checks, all_passed = DeterministicPolicyValidator.validate(
            operation=operation,
            target_resource=target_resource,
            before_manifest=before_text,
            after_manifest=after_text,
            prior_known_good=prior_identifier,
            current_identifier=current_identifier,
            target_container=target_container,
            current_memory_limit=current_memory,
            previous_memory_limit=previous_memory,
        )
        if not all_passed:
            raise _ProposalPolicyFailure(
                [check.check_name for check in checks if not check.passed]
            )

        diff_text = "".join(
            difflib.unified_diff(
                before_text.splitlines(keepends=True),
                after_text.splitlines(keepends=True),
                fromfile=f"a/{target_resource}.yaml",
                tofile=f"b/{target_resource}.yaml",
            )
        )
        return RemediationProposal(
            proposal_id=f"proposal-{change.change_id}",
            operation=operation,
            target_resource=target_resource,
            before_manifest=before_text,
            after_manifest=after_text,
            diff=diff_text,
            evidence_references=evidence_refs,
            rationale=rationale,
            assumptions_and_limitations=assumptions,
            policy_checks=checks,
            all_policy_checks_passed=True,
            status="NOT_APPLIED",
        )
