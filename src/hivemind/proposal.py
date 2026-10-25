"""Constrained, read-only Kubernetes Deployment proposal generation.

Proposals are derived from complete, explicitly supplied Deployment manifests.
HiveMind never invents workload fields or applies the resulting diff.
"""

from __future__ import annotations

import copy
import difflib
import logging
import re
from collections.abc import Mapping
from datetime import timedelta
from typing import Any

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode

from hivemind.models import (
    CandidateCause,
    DeploymentChange,
    EvidenceReference,
    IncidentEvent,
    PolicyCheckResult,
    ProposalGenerationOutcome,
    ProposalGenerationReasonCode,
    ProposalGenerationStatus,
    RemediationProposal,
)

MIB = 1024 * 1024
MIN_MEMORY_BYTES = 64 * MIB
MAX_MEMORY_BYTES = 4096 * MIB
REVISION_ANNOTATION = "hivemind.io/revision"
ALLOWED_OPERATIONS = {"ROLLBACK_REVISION", "ADJUST_RESOURCE_LIMITS"}
logger = logging.getLogger(__name__)


class _ProposalPolicyFailure(Exception):
    """Internal signal carrying only safe policy-check identifiers."""

    def __init__(self, failed_checks: list[str]) -> None:
        super().__init__("Proposal rejected by deterministic policy checks")
        self.failed_checks = failed_checks


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys instead of hiding data."""


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader,
    node: MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _parse_memory_to_bytes(memory: Any) -> int:
    """Parse a conservative subset of Kubernetes memory quantities into exact bytes.

    Accepted suffixes are binary Ki/Mi/Gi/Ti/Pi/Ei, decimal k/K/M/G/T/P/E,
    and B/b. A suffix-free integer is interpreted as bytes. Unsupported,
    fractional, negative, boolean, or non-integral forms fail closed.
    """
    if isinstance(memory, bool):
        raise ValueError("Boolean values are not valid memory quantities")
    raw = str(memory).strip()
    match = re.fullmatch(r"(\d+)(Ki|Mi|Gi|Ti|Pi|Ei|k|K|M|G|T|P|E|B|b)?", raw)
    if not match:
        raise ValueError(f"Invalid or unsupported Kubernetes memory quantity: {memory!r}")

    value = int(match.group(1))
    suffix = match.group(2) or ""
    multipliers = {
        "": 1,
        "B": 1,
        "b": 1,
        "k": 1000,
        "K": 1000,
        "M": 1000**2,
        "G": 1000**3,
        "T": 1000**4,
        "P": 1000**5,
        "E": 1000**6,
        "Ki": 1024,
        "Mi": 1024**2,
        "Gi": 1024**3,
        "Ti": 1024**4,
        "Pi": 1024**5,
        "Ei": 1024**6,
    }
    return value * multipliers[suffix]


def _manifest_identity(manifest: Mapping[str, Any]) -> tuple[str, str] | None:
    if manifest.get("apiVersion") != "apps/v1" or manifest.get("kind") != "Deployment":
        return None
    metadata = manifest.get("metadata")
    if not isinstance(metadata, Mapping):
        return None
    name = metadata.get("name")
    namespace = metadata.get("namespace")
    if not isinstance(name, str) or not _valid_dns_name(name, allow_dots=True, max_length=253):
        return None
    if not isinstance(namespace, str) or not _valid_dns_name(namespace, allow_dots=False, max_length=63):
        return None
    return namespace, name


def _valid_dns_name(value: str, *, allow_dots: bool, max_length: int) -> bool:
    if not value or len(value) > max_length:
        return False
    labels = value.split(".") if allow_dots else [value]
    return all(
        0 < len(label) <= 63
        and re.fullmatch(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", label) is not None
        for label in labels
    )


def _resource_reference(manifest: Mapping[str, Any]) -> str | None:
    identity = _manifest_identity(manifest)
    if identity is None:
        return None
    namespace, name = identity
    return f"apps/v1:Deployment/{namespace}/{name}"


def _validate_deployment_structure(manifest: Any, label: str) -> list[str]:
    """Validate the Kubernetes Deployment fields this tool relies on."""
    problems: list[str] = []
    if not isinstance(manifest, dict):
        return [f"{label} must be a YAML mapping"]
    if manifest.get("apiVersion") != "apps/v1" or manifest.get("kind") != "Deployment":
        problems.append(f"{label} must be an apps/v1 Deployment")

    metadata = manifest.get("metadata")
    if not isinstance(metadata, dict):
        problems.append(f"{label}.metadata must be a mapping")
    else:
        for field in ("name", "namespace"):
            value = metadata.get(field)
            if not isinstance(value, str) or not value.strip():
                problems.append(f"{label}.metadata.{field} must be a non-empty string")
            elif field == "name" and not _valid_dns_name(value, allow_dots=True, max_length=253):
                problems.append(f"{label}.metadata.name must be a valid Kubernetes DNS subdomain")
            elif field == "namespace" and not _valid_dns_name(value, allow_dots=False, max_length=63):
                problems.append(f"{label}.metadata.namespace must be a valid Kubernetes DNS label")

    spec = manifest.get("spec")
    if not isinstance(spec, dict):
        problems.append(f"{label}.spec must be a mapping")
        return problems

    selector = spec.get("selector")
    match_labels = selector.get("matchLabels") if isinstance(selector, dict) else None
    if not isinstance(match_labels, dict) or not match_labels:
        problems.append(f"{label}.spec.selector.matchLabels must be a non-empty mapping")

    template = spec.get("template")
    if not isinstance(template, dict):
        problems.append(f"{label}.spec.template must be a mapping")
        return problems
    template_metadata = template.get("metadata")
    labels = template_metadata.get("labels") if isinstance(template_metadata, dict) else None
    if not isinstance(labels, dict):
        problems.append(f"{label}.spec.template.metadata.labels must be a mapping")
    elif isinstance(match_labels, dict) and any(labels.get(k) != v for k, v in match_labels.items()):
        problems.append(f"{label}.spec.template labels must satisfy spec.selector.matchLabels")

    pod_spec = template.get("spec")
    if not isinstance(pod_spec, dict):
        problems.append(f"{label}.spec.template.spec must be a mapping")
        return problems
    containers = pod_spec.get("containers")
    if not isinstance(containers, list) or not containers:
        problems.append(f"{label}.spec.template.spec.containers must be a non-empty list")
        return problems

    names: list[str] = []
    for index, container in enumerate(containers):
        if not isinstance(container, dict):
            problems.append(f"{label} container at index {index} must be a mapping")
            continue
        name = container.get("name")
        if not isinstance(name, str) or not name.strip():
            problems.append(f"{label} container at index {index} must have a non-empty name")
        else:
            names.append(name)
        image = container.get("image")
        if not isinstance(image, str) or not image.strip():
            problems.append(f"{label} container at index {index} must have a non-empty image")
    if len(names) != len(set(names)):
        problems.append(f"{label} container names must be unique")
    return problems


def _find_container(manifest: Mapping[str, Any], container_name: str) -> dict[str, Any] | None:
    spec = manifest.get("spec")
    template = spec.get("template") if isinstance(spec, dict) else None
    pod_spec = template.get("spec") if isinstance(template, dict) else None
    containers = pod_spec.get("containers") if isinstance(pod_spec, dict) else None
    if not isinstance(containers, list):
        return None
    matches = [
        container
        for container in containers
        if isinstance(container, dict) and container.get("name") == container_name
    ]
    return matches[0] if len(matches) == 1 else None


def _get_memory_limit(container: Mapping[str, Any]) -> Any:
    resources = container.get("resources")
    limits = resources.get("limits") if isinstance(resources, dict) else None
    return limits.get("memory") if isinstance(limits, dict) else None


def _set_memory_limit(manifest: dict[str, Any], container_name: str, value: Any) -> bool:
    container = _find_container(manifest, container_name)
    if container is None:
        return False
    resources = container.get("resources")
    if resources is None:
        resources = {}
        container["resources"] = resources
    if not isinstance(resources, dict):
        return False
    limits = resources.get("limits")
    if limits is None:
        limits = {}
        resources["limits"] = limits
    if not isinstance(limits, dict):
        return False
    limits["memory"] = value
    return True


def _security_violations(manifest: Mapping[str, Any]) -> list[str]:
    violations: list[str] = []
    spec = manifest.get("spec")
    template = spec.get("template") if isinstance(spec, dict) else None
    pod_spec = template.get("spec") if isinstance(template, dict) else None
    if not isinstance(pod_spec, dict):
        return ["Deployment pod spec is not a mapping"]

    for field in ("hostNetwork", "hostPID", "hostIPC"):
        if pod_spec.get(field) is True:
            violations.append(f"pod spec {field}: true")

    volumes = pod_spec.get("volumes", [])
    if not isinstance(volumes, list):
        violations.append("pod spec volumes must be a list")
    else:
        for index, volume in enumerate(volumes):
            if isinstance(volume, dict) and "hostPath" in volume:
                violations.append(f"pod volume at index {index} uses hostPath")

    for collection_name in ("containers", "initContainers", "ephemeralContainers"):
        containers = pod_spec.get(collection_name, [])
        if not isinstance(containers, list):
            violations.append(f"pod spec {collection_name} must be a list")
            continue
        for index, container in enumerate(containers):
            if not isinstance(container, dict):
                continue
            security_context = container.get("securityContext", {})
            if not isinstance(security_context, dict):
                violations.append(f"{collection_name}[{index}].securityContext must be a mapping")
                continue
            if security_context.get("privileged") is True:
                violations.append(f"{collection_name}[{index}] sets privileged: true")
            if security_context.get("allowPrivilegeEscalation") is True:
                violations.append(f"{collection_name}[{index}] sets allowPrivilegeEscalation: true")
            capabilities = security_context.get("capabilities", {})
            if isinstance(capabilities, dict):
                added = capabilities.get("add", [])
                if not isinstance(added, list):
                    violations.append(f"{collection_name}[{index}] capabilities.add must be a list")
                elif any(str(cap).upper() in {"SYS_ADMIN", "ALL"} for cap in added):
                    violations.append(f"{collection_name}[{index}] adds SYS_ADMIN or ALL capabilities")
    return violations


def _parse_manifest(text: str) -> dict[str, Any]:
    loaded = yaml.load(text, Loader=_UniqueKeySafeLoader)
    if not isinstance(loaded, dict):
        raise ValueError("manifest must be a YAML mapping")
    return loaded


def _revision(manifest: Mapping[str, Any]) -> str | None:
    metadata = manifest.get("metadata")
    annotations = metadata.get("annotations") if isinstance(metadata, dict) else None
    value = annotations.get(REVISION_ANNOTATION) if isinstance(annotations, dict) else None
    return value.strip() if isinstance(value, str) and value.strip() else None


class DeterministicPolicyValidator:
    """Fail-closed checks for the narrowly supported Deployment proposal types."""

    @classmethod
    def validate(
        cls,
        operation: str,
        target_resource: str,
        before_manifest: str,
        after_manifest: str,
        prior_known_good: str | None = None,
        *,
        current_identifier: str | None = None,
        target_container: str | None = None,
        current_memory_limit: Any | None = None,
        previous_memory_limit: Any | None = None,
    ) -> tuple[list[PolicyCheckResult], bool]:
        checks: list[PolicyCheckResult] = []
        try:
            before_obj = _parse_manifest(before_manifest)
            after_obj = _parse_manifest(after_manifest)
        except (yaml.YAMLError, ValueError, TypeError) as exc:
            checks.append(
                PolicyCheckResult(
                    check_name="valid_yaml_syntax",
                    passed=False,
                    details=f"Source and proposed manifests must be valid YAML mappings with unique keys: {exc}",
                )
            )
            return checks, False
        checks.append(
            PolicyCheckResult(
                check_name="valid_yaml_syntax",
                passed=True,
                details="Source and proposed manifests are valid YAML mappings with unique keys.",
            )
        )

        structure_errors = _validate_deployment_structure(before_obj, "Source manifest")
        structure_errors.extend(_validate_deployment_structure(after_obj, "Proposed manifest"))
        checks.append(
            PolicyCheckResult(
                check_name="deployment_structure",
                passed=not structure_errors,
                details=(
                    "Both manifests contain the required apps/v1 Deployment identity, selector, template, and containers."
                    if not structure_errors
                    else "; ".join(structure_errors)
                ),
            )
        )

        before_ref = _resource_reference(before_obj)
        after_ref = _resource_reference(after_obj)
        same_identity = before_ref is not None and before_ref == after_ref
        exact_target = same_identity and target_resource == after_ref
        checks.append(
            PolicyCheckResult(
                check_name="target_resource_allowlist",
                passed=exact_target,
                details=(
                    f"Both manifests match the exact requested target '{target_resource}'."
                    if exact_target
                    else f"Requested target '{target_resource}' must exactly match the same source and proposed Deployment identity (source={before_ref!r}, proposed={after_ref!r})."
                ),
            )
        )

        security_errors = _security_violations(after_obj)
        checks.append(
            PolicyCheckResult(
                check_name="privilege_escalation_guardrail",
                passed=not security_errors,
                details=(
                    "No prohibited host access, hostPath mount, or privilege-escalation settings were found in the proposed pod spec."
                    if not security_errors
                    else "; ".join(security_errors)
                ),
            )
        )

        if operation not in ALLOWED_OPERATIONS:
            checks.append(
                PolicyCheckResult(
                    check_name="operation_allowlist",
                    passed=False,
                    details=f"Unsupported proposal operation '{operation}'.",
                )
            )
            return checks, False
        checks.append(
            PolicyCheckResult(
                check_name="operation_allowlist",
                passed=True,
                details=f"Operation '{operation}' is explicitly supported.",
            )
        )

        if operation == "ROLLBACK_REVISION":
            prior = prior_known_good.strip() if isinstance(prior_known_good, str) else ""
            current = current_identifier.strip() if isinstance(current_identifier, str) else ""
            revision_check = bool(
                prior
                and current
                and prior != current
                and _revision(before_obj) == current
                and _revision(after_obj) == prior
            )
            checks.append(
                PolicyCheckResult(
                    check_name="explicit_rollback_target",
                    passed=revision_check,
                    details=(
                        f"Source and rollback snapshots are explicitly stamped with current revision '{current}' and prior known-good revision '{prior}'."
                        if revision_check
                        else f"Both snapshots must carry {REVISION_ANNOTATION}: source='{_revision(before_obj)}', proposed='{_revision(after_obj)}', expected source='{current}', expected prior='{prior}'."
                    ),
                )
            )
            before_spec = before_obj.get("spec")
            after_spec = after_obj.get("spec")
            selector_unchanged = (
                isinstance(before_spec, dict)
                and isinstance(after_spec, dict)
                and before_spec.get("selector") == after_spec.get("selector")
            )
            checks.append(
                PolicyCheckResult(
                    check_name="deployment_selector_unchanged",
                    passed=selector_unchanged,
                    details=(
                        "The immutable Deployment selector is identical in both snapshots."
                        if selector_unchanged
                        else "Rollback snapshots must have the same Deployment selector."
                    ),
                )
            )

        if operation == "ADJUST_RESOURCE_LIMITS":
            container_name = target_container.strip() if isinstance(target_container, str) else ""
            before_container = _find_container(before_obj, container_name) if container_name else None
            after_container = _find_container(after_obj, container_name) if container_name else None
            old_memory = _get_memory_limit(before_container) if before_container else None
            new_memory = _get_memory_limit(after_container) if after_container else None
            try:
                telemetry_current_matches = (
                    old_memory is not None
                    and current_memory_limit is not None
                    and _parse_memory_to_bytes(old_memory) == _parse_memory_to_bytes(current_memory_limit)
                )
                different_memory = (
                    old_memory is not None
                    and new_memory is not None
                    and _parse_memory_to_bytes(old_memory) != _parse_memory_to_bytes(new_memory)
                )
                target_previous_matches = (
                    new_memory is not None
                    and previous_memory_limit is not None
                    and _parse_memory_to_bytes(new_memory) == _parse_memory_to_bytes(previous_memory_limit)
                )
                proposed_bytes = _parse_memory_to_bytes(new_memory)
                within_bounds = MIN_MEMORY_BYTES <= proposed_bytes <= MAX_MEMORY_BYTES
                if not within_bounds:
                    bounds_detail = (
                        f"Proposed memory limit is outside [{MIN_MEMORY_BYTES // MIB}Mi, {MAX_MEMORY_BYTES // MIB}Mi]."
                    )
                else:
                    bounds_detail = f"Proposed memory limit is within configured policy bounds [{MIN_MEMORY_BYTES // MIB}Mi, {MAX_MEMORY_BYTES // MIB}Mi]."
            except (ValueError, TypeError):
                telemetry_current_matches = False
                different_memory = False
                target_previous_matches = False
                within_bounds = False
                bounds_detail = "Memory quantities are missing or invalid; resource bounds could not be verified."

            exact_memory_target = bool(container_name and before_container and after_container)
            checks.append(
                PolicyCheckResult(
                    check_name="explicit_memory_target_and_baseline",
                    passed=exact_memory_target and telemetry_current_matches,
                    details=(
                        f"Container '{container_name}' exists exactly once and its source memory limit matches the incident record."
                        if exact_memory_target and telemetry_current_matches
                        else "A named target_container and an exact source-manifest memory limit matching details.memory_limit are required."
                    ),
                )
            )
            checks.append(
                PolicyCheckResult(
                    check_name="explicit_prior_memory_limit",
                    passed=target_previous_matches and different_memory,
                    details=(
                        "The proposed memory limit matches the explicitly supplied previous_memory_limit."
                        if target_previous_matches and different_memory
                        else "The proposed memory limit must match an explicit previous_memory_limit and differ from the current value."
                    ),
                )
            )
            checks.append(
                PolicyCheckResult(
                    check_name="bounded_memory_change",
                    passed=bool(
                        before_container
                        and after_container
                        and container_name
                        and _only_target_memory_limit_changed(
                            before_obj,
                            after_obj,
                            container_name,
                        )
                    ),
                    details=(
                        f"Only {container_name}'s memory limit differs between source and proposal."
                        if before_container
                        and after_container
                        and container_name
                        and _only_target_memory_limit_changed(before_obj, after_obj, container_name)
                        else "A resource-limit proposal may change only the explicitly targeted container's memory limit."
                    ),
                )
            )
            checks.append(
                PolicyCheckResult(
                    check_name="resource_bounds_check",
                    passed=within_bounds,
                    details=bounds_detail,
                )
            )

        return checks, all(check.passed for check in checks)


def _only_target_memory_limit_changed(
    before_obj: Mapping[str, Any],
    after_obj: Mapping[str, Any],
    container_name: str,
) -> bool:
    """Compare complete objects after applying just the requested memory-limit change."""
    before_copy = copy.deepcopy(dict(before_obj))
    after_copy = copy.deepcopy(dict(after_obj))
    after_container = _find_container(after_copy, container_name)
    proposed_memory = _get_memory_limit(after_container) if after_container else None
    if proposed_memory is None or not _set_memory_limit(before_copy, container_name, proposed_memory):
        return False
    return before_copy == after_copy


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
