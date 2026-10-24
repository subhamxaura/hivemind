"""Constrained Kubernetes remediation proposal generation and deterministic policy checks.

Strictly read-only: Generates structured YAML unified diffs for human review.
Does not mutate or apply changes to any cluster or API.
"""

import difflib
import re
from typing import Any

import yaml

from hivemind.models import (
    CandidateCause,
    DeploymentChange,
    EvidenceReference,
    IncidentEvent,
    PolicyCheckResult,
    RemediationProposal,
)

# Safe bounds for memory/cpu adjustments
MIN_MEMORY_MB = 64
MAX_MEMORY_MB = 4096


def _parse_memory_to_mb(mem_str: str) -> int:
    """Parses standard Kubernetes memory string (e.g. '256Mi', '1Gi') to megabytes."""
    match = re.match(r"^(\d+)([A-Za-z]+)?$", str(mem_str).strip())
    if not match:
        raise ValueError(f"Invalid memory format: {mem_str}")
    val, unit = int(match.group(1)), (match.group(2) or "").lower()
    if unit in ("mi", "m"):
        return val
    if unit in ("gi", "g"):
        return val * 1024
    if unit in ("ki", "k"):
        return val // 1024
    if unit in ("", "b"):
        return val // (1024 * 1024)
    raise ValueError(f"Unsupported memory unit in: {mem_str}")


class DeterministicPolicyValidator:
    """Enforces strict, non-negotiable policy guardrails on remediation proposals."""

    FORBIDDEN_KEYS = {
        "privileged",
        "hostnetwork",
        "hostpid",
        "hostipc",
        "hostpath",
        "sys_admin",
        "allowprivilegeescalation",
        "clusterrole",
        "rolebinding",
        "clusterrolebinding",
    }

    @classmethod
    def validate(
        cls,
        operation: str,
        target_resource: str,
        before_manifest: str,
        after_manifest: str,
        prior_known_good: str | None = None,
    ) -> tuple[list[PolicyCheckResult], bool]:
        """Runs deterministic static checks on proposed manifests."""
        checks: list[PolicyCheckResult] = []

        # 1. Target resource must be apps/v1:Deployment
        if not target_resource.startswith("apps/v1:Deployment/"):
            checks.append(
                PolicyCheckResult(
                    check_name="target_resource_allowlist",
                    passed=False,
                    details=f"Target '{target_resource}' is not in allowlist (only 'apps/v1:Deployment/*' allowed).",
                )
            )
        else:
            checks.append(
                PolicyCheckResult(
                    check_name="target_resource_allowlist",
                    passed=True,
                    details="Target resource is an allowed apps/v1 Deployment.",
                )
            )

        # 2. Check for dangerous security escalation keywords in raw manifests
        raw_after_lower = after_manifest.lower()
        found_forbidden = [k for k in cls.FORBIDDEN_KEYS if k in raw_after_lower]
        if found_forbidden:
            checks.append(
                PolicyCheckResult(
                    check_name="privilege_escalation_guardrail",
                    passed=False,
                    details=f"Manifest contains forbidden security configurations: {', '.join(found_forbidden)}.",
                )
            )
        else:
            checks.append(
                PolicyCheckResult(
                    check_name="privilege_escalation_guardrail",
                    passed=True,
                    details="No privilege escalation or host access fields detected.",
                )
            )

        # 3. Check parsed YAML validity
        try:
            after_obj = yaml.safe_load(after_manifest)
            checks.append(
                PolicyCheckResult(
                    check_name="valid_yaml_syntax",
                    passed=True,
                    details="Proposed manifest is valid, parsable YAML.",
                )
            )
        except Exception as e:
            checks.append(
                PolicyCheckResult(
                    check_name="valid_yaml_syntax",
                    passed=False,
                    details=f"YAML parsing failed: {e}",
                )
            )
            return checks, False

        # 4. Rollback safety: Prior known-good revision required
        if operation == "ROLLBACK_REVISION":
            if not prior_known_good or not prior_known_good.strip():
                checks.append(
                    PolicyCheckResult(
                        check_name="explicit_rollback_target",
                        passed=False,
                        details="Rollback operation requested but prior_known_good_identifier is missing or empty.",
                    )
                )
            else:
                checks.append(
                    PolicyCheckResult(
                        check_name="explicit_rollback_target",
                        passed=True,
                        details=f"Explicit prior revision confirmed: '{prior_known_good}'.",
                    )
                )

        # 5. Resource bounds check if adjusting limits
        if operation == "ADJUST_RESOURCE_LIMITS":
            try:
                # Traverse to memory limit in after_obj
                limits = (
                    after_obj.get("spec", {})
                    .get("template", {})
                    .get("spec", {})
                    .get("containers", [{}])[0]
                    .get("resources", {})
                    .get("limits", {})
                )
                mem = limits.get("memory")
                if mem:
                    mb = _parse_memory_to_mb(mem)
                    if MIN_MEMORY_MB <= mb <= MAX_MEMORY_MB:
                        checks.append(
                            PolicyCheckResult(
                                check_name="resource_bounds_check",
                                passed=True,
                                details=f"Proposed memory limit ({mb}Mi) is within safe bounds [{MIN_MEMORY_MB}Mi, {MAX_MEMORY_MB}Mi].",
                            )
                        )
                    else:
                        checks.append(
                            PolicyCheckResult(
                                check_name="resource_bounds_check",
                                passed=False,
                                details=f"Proposed memory limit ({mb}Mi) violates safe bounds [{MIN_MEMORY_MB}Mi, {MAX_MEMORY_MB}Mi].",
                            )
                        )
                else:
                    checks.append(
                        PolicyCheckResult(
                            check_name="resource_bounds_check",
                            passed=False,
                            details="No memory limit found in proposed manifest spec.",
                        )
                    )
            except Exception as e:
                checks.append(
                    PolicyCheckResult(
                        check_name="resource_bounds_check",
                        passed=False,
                        details=f"Failed to inspect resource bounds: {e}",
                    )
                )

        all_passed = all(c.passed for c in checks)
        return checks, all_passed


class RemediationProposalGenerator:
    """Generates constrained, human-reviewable remediation diffs for diagnosed causes."""

    @classmethod
    def generate(
        cls,
        incident: IncidentEvent,
        candidate: CandidateCause,
    ) -> RemediationProposal | None:
        """Generates a proposal if the candidate corresponds to a safe, supported remediation pattern."""
        if not candidate.candidate_id.startswith("cause-change-"):
            return None

        # Find the specific change record
        change_id = candidate.candidate_id.replace("cause-change-", "")
        change: DeploymentChange | None = next(
            (c for c in incident.changes if c.change_id == change_id), None
        )
        if not change:
            return None

        service = change.service
        target_resource = f"apps/v1:Deployment/{incident.environment}/{service}"

        operation: str
        before_manifest_dict: dict[str, Any]
        after_manifest_dict: dict[str, Any]
        evidence_refs: list[EvidenceReference] = [
            EvidenceReference(
                record_type="change",
                record_id=change.change_id,
                summary=f"Originating change: {change.identifier} on {change.service}",
            )
        ]
        rationale: str
        assumptions: list[str] = [
            "Proposal is an untrusted recommendation requiring human review and verification.",
            "Proposal was validated against deterministic policy checks only.",
            "HiveMind did not connect to any cluster or mutate any live resource.",
        ]

        # Case 1: Memory reduction causing OOMKilled -> Revert or increase memory limit
        details = change.details
        if "previous_memory_limit" in details and (
            "memory" in details or "memory_limit" in details or change.change_type == "resource_limit"
        ):
            operation = "ADJUST_RESOURCE_LIMITS"
            prev_mem = details.get("previous_memory_limit", "512Mi")
            curr_mem = details.get("memory_limit", details.get("memory", "256Mi"))

            before_manifest_dict = {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": service, "namespace": incident.environment},
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "name": service,
                                    "resources": {
                                        "limits": {"memory": str(curr_mem)},
                                        "requests": {"memory": "128Mi"},
                                    },
                                }
                            ]
                        }
                    }
                },
            }
            after_manifest_dict = {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": service, "namespace": incident.environment},
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "name": service,
                                    "resources": {
                                        "limits": {"memory": str(prev_mem)},
                                        "requests": {"memory": "128Mi"},
                                    },
                                }
                            ]
                        }
                    }
                },
            }
            rationale = (
                f"Revert memory limit for {service} from {curr_mem} back to prior known-good "
                f"value {prev_mem} to mitigate OOMKilled terminations."
            )

        # Case 2: Code deployment causing crash/5xx -> Rollback to prior known good
        elif change.prior_known_good_identifier:
            operation = "ROLLBACK_REVISION"
            current_id = change.identifier
            prior_id = change.prior_known_good_identifier

            before_manifest_dict = {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": service, "namespace": incident.environment},
                "spec": {
                    "template": {
                        "metadata": {"labels": {"app": service, "revision": current_id}},
                        "spec": {
                            "containers": [
                                {
                                    "name": service,
                                    "image": f"{service}:{current_id}",
                                }
                            ]
                        },
                    }
                },
            }
            after_manifest_dict = {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": service, "namespace": incident.environment},
                "spec": {
                    "template": {
                        "metadata": {"labels": {"app": service, "revision": prior_id}},
                        "spec": {
                            "containers": [
                                {
                                    "name": service,
                                    "image": f"{service}:{prior_id}",
                                }
                            ]
                        },
                    }
                },
            }
            rationale = (
                f"Roll back {service} deployment from revision {current_id} to explicitly provided "
                f"prior known-good revision {prior_id}."
            )
        else:
            # Cannot safely generate a proposal without explicit rollback or resource details
            return None

        before_str = yaml.dump(before_manifest_dict, sort_keys=False)
        after_str = yaml.dump(after_manifest_dict, sort_keys=False)

        # Generate unified diff
        diff_lines = list(
            difflib.unified_diff(
                before_str.splitlines(keepends=True),
                after_str.splitlines(keepends=True),
                fromfile=f"a/{service}-deployment.yaml",
                tofile=f"b/{service}-deployment.yaml",
            )
        )
        diff_text = "".join(diff_lines)

        # Run deterministic policy validation
        checks, all_passed = DeterministicPolicyValidator.validate(
            operation=operation,
            target_resource=target_resource,
            before_manifest=before_str,
            after_manifest=after_str,
            prior_known_good=change.prior_known_good_identifier,
        )

        return RemediationProposal(
            proposal_id=f"proposal-{change.change_id}",
            operation=operation,
            target_resource=target_resource,
            before_manifest=before_str,
            after_manifest=after_str,
            diff=diff_text,
            evidence_references=evidence_refs,
            rationale=rationale,
            assumptions_and_limitations=assumptions,
            policy_checks=checks,
            all_policy_checks_passed=all_passed,
            status="NOT_APPLIED",
        )
