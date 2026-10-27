"""Deterministic Kubernetes Deployment proposal policy validation."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from typing import Any

import yaml

from hivemind.k8s_manifest import (
    REVISION_ANNOTATION,
    _find_container,
    _get_memory_limit,
    _parse_manifest,
    _parse_memory_to_bytes,
    _resource_reference,
    _revision,
    _set_memory_limit,
    _validate_deployment_structure,
)
from hivemind.models import PolicyCheckResult
from hivemind.security import _security_violations

MIB = 1024 * 1024
MIN_MEMORY_BYTES = 64 * MIB
MAX_MEMORY_BYTES = 4096 * MIB
ALLOWED_OPERATIONS = {"ROLLBACK_REVISION", "ADJUST_RESOURCE_LIMITS"}


class _ProposalPolicyFailure(Exception):
    """Internal signal carrying only safe policy-check identifiers."""

    def __init__(self, failed_checks: list[str]) -> None:
        super().__init__("Proposal rejected by deterministic policy checks")
        self.failed_checks = failed_checks


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
