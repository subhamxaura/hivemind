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

# Configured policy bounds for memory/cpu adjustments
MIN_MEMORY_MB = 64
MAX_MEMORY_MB = 4096


def _parse_memory_to_mb(mem_str: str) -> int:
    """Parses standard Kubernetes memory string (e.g. '256Mi', '1Gi') to megabytes.

    Explicitly accepted units:
    - 'Mi', 'M' (Megabytes)
    - 'Gi', 'G' (Gigabytes)
    - 'Ki', 'K', 'k' (Kilobytes)
    - plain integer, 'B', 'b' (Bytes)
    All other units (including 'm' milli, 'Ti', 's', negative, decimals) raise ValueError.
    """
    raw = str(mem_str).strip()
    match = re.match(r"^(\d+)([A-Za-z]+)?$", raw)
    if not match:
        raise ValueError(f"Invalid memory format: {mem_str}")
    val = int(match.group(1))
    suffix = match.group(2) or ""

    if suffix in ("Mi", "M"):
        return val
    if suffix in ("Gi", "G"):
        return val * 1024
    if suffix in ("Ki", "K", "k"):
        return val // 1024
    if suffix in ("", "B", "b"):
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

        # 1. Parse and validate YAML syntax first
        try:
            after_obj = yaml.safe_load(after_manifest)
            if not isinstance(after_obj, dict):
                checks.append(
                    PolicyCheckResult(
                        check_name="valid_yaml_syntax",
                        passed=False,
                        details=f"Proposed manifest must be a YAML mapping, received {type(after_obj).__name__}.",
                    )
                )
                return checks, False
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

        # 2. Target resource and manifest structure must strictly be apps/v1 Deployment
        manifest_api = after_obj.get("apiVersion")
        manifest_kind = after_obj.get("kind")

        if (
            not target_resource.startswith("apps/v1:Deployment/")
            or manifest_api != "apps/v1"
            or manifest_kind != "Deployment"
        ):
            checks.append(
                PolicyCheckResult(
                    check_name="target_resource_allowlist",
                    passed=False,
                    details=(
                        f"Target resource or manifest kind rejected: target='{target_resource}', "
                        f"apiVersion='{manifest_api}', kind='{manifest_kind}' (only 'apps/v1:Deployment' allowed)."
                    ),
                )
            )
        else:
            checks.append(
                PolicyCheckResult(
                    check_name="target_resource_allowlist",
                    passed=True,
                    details="Target resource and manifest structure are confirmed apps/v1 Deployment.",
                )
            )

        # 3. Structured security verification + keyword defense-in-depth
        violations: list[str] = []

        # Structured traversal of Deployment spec
        pod_spec = after_obj.get("spec", {}).get("template", {}).get("spec", {})
        if isinstance(pod_spec, dict):
            if pod_spec.get("hostNetwork") is True:
                violations.append("hostNetwork: true")
            if pod_spec.get("hostPID") is True:
                violations.append("hostPID: true")
            if pod_spec.get("hostIPC") is True:
                violations.append("hostIPC: true")

            volumes = pod_spec.get("volumes", [])
            if isinstance(volumes, list):
                for vol in volumes:
                    if isinstance(vol, dict) and "hostPath" in vol:
                        violations.append("volumes contain hostPath mount")

            containers = pod_spec.get("containers", [])
            if isinstance(containers, list):
                for ctr in containers:
                    if isinstance(ctr, dict):
                        sc = ctr.get("securityContext", {})
                        if isinstance(sc, dict):
                            if sc.get("privileged") is True:
                                violations.append("container securityContext.privileged: true")
                            if sc.get("allowPrivilegeEscalation") is True:
                                violations.append("container securityContext.allowPrivilegeEscalation: true")
                            caps = sc.get("capabilities", {})
                            if isinstance(caps, dict):
                                added = [str(c).upper() for c in caps.get("add", [])]
                                if "SYS_ADMIN" in added or "ALL" in added:
                                    violations.append(f"capabilities.add contains forbidden privilege: {added}")

        # Text keyword defense-in-depth
        raw_after_lower = after_manifest.lower()
        found_forbidden = [k for k in cls.FORBIDDEN_KEYS if k in raw_after_lower]
        if found_forbidden:
            violations.append(f"forbidden keys in manifest text: {', '.join(found_forbidden)}")

        if violations:
            checks.append(
                PolicyCheckResult(
                    check_name="privilege_escalation_guardrail",
                    passed=False,
                    details=f"Manifest contains forbidden security configurations: {'; '.join(violations)}.",
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
                                details=f"Proposed memory limit ({mb}Mi) is within configured policy bounds [{MIN_MEMORY_MB}Mi, {MAX_MEMORY_MB}Mi].",
                            )
                        )
                    else:
                        checks.append(
                            PolicyCheckResult(
                                check_name="resource_bounds_check",
                                passed=False,
                                details=f"Proposed memory limit ({mb}Mi) violates configured policy bounds [{MIN_MEMORY_MB}Mi, {MAX_MEMORY_MB}Mi].",
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
            "Proposal was evaluated against deterministic static policy checks only; policy compliance does not guarantee operational safety.",
            "HiveMind did not connect to any cluster or mutate any live resource.",
        ]

        # Case 1: Memory adjustment (e.g. reduction causing OOMKilled) -> Revert to explicit prior known-good memory limit
        details = change.details
        is_resource_change = (
            change.change_type == "resource_limit"
            or "previous_memory_limit" in details
            or "memory_limit" in details
            or "memory" in details
        )

        if is_resource_change:
            raw_prev = details.get("previous_memory_limit")
            raw_curr = details.get("memory_limit") or details.get("memory")
            if not raw_prev or not raw_curr:
                return None

            raw_prev_str = str(raw_prev).strip()
            raw_curr_str = str(raw_curr).strip()
            if not raw_prev_str or not raw_curr_str:
                return None

            try:
                prev_mb = _parse_memory_to_mb(raw_prev_str)
                curr_mb = _parse_memory_to_mb(raw_curr_str)
            except ValueError:
                return None

            if prev_mb == curr_mb:
                return None

            operation = "ADJUST_RESOURCE_LIMITS"
            prev_mem = raw_prev_str
            curr_mem = raw_curr_str

            evidence_refs.append(
                EvidenceReference(
                    record_type="change",
                    record_id=change.change_id,
                    summary=f"Explicit prior known-good memory limit: {prev_mem}",
                )
            )

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
                                        "limits": {"memory": curr_mem},
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
                                        "limits": {"memory": prev_mem},
                                        "requests": {"memory": "128Mi"},
                                    },
                                }
                            ]
                        }
                    }
                },
            }
            rationale = (
                f"Revert memory limit for {service} from {curr_mem} back to explicitly cited prior known-good "
                f"value {prev_mem} to mitigate OOMKilled terminations."
            )

        # Case 2: Code deployment causing crash/5xx -> Rollback to explicit prior known-good revision
        elif (
            change.change_type == "deployment"
            and change.prior_known_good_identifier
            and change.prior_known_good_identifier.strip()
            and change.prior_known_good_identifier.strip() != change.identifier.strip()
        ):
            operation = "ROLLBACK_REVISION"
            current_id = change.identifier.strip()
            prior_id = change.prior_known_good_identifier.strip()

            evidence_refs.append(
                EvidenceReference(
                    record_type="change",
                    record_id=change.change_id,
                    summary=f"Explicit prior known-good revision: {prior_id}",
                )
            )

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
