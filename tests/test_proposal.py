"""Tests for source-grounded Kubernetes proposals and deterministic policy checks."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest
import yaml

from hivemind.engine import DeterministicCorrelationEngine
from hivemind.models import (
    CURRENT_SCHEMA_VERSION,
    AnomalySignal,
    DeploymentChange,
    EvidenceReference,
    IncidentEvent,
    LogExcerpt,
)
from hivemind.proposal import (
    DeterministicPolicyValidator,
    RemediationProposalGenerator,
    _parse_memory_to_bytes,
)


def deployment_manifest(
    *,
    name: str = "worker",
    namespace: str = "production",
    revision: str = "rev-current",
    memory: str = "256Mi",
    image: str = "example/worker:v2",
) -> dict:
    """Return a complete, valid Deployment fixture with stable selector labels."""
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "annotations": {"hivemind.io/revision": revision},
        },
        "spec": {
            "replicas": 3,
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": {"labels": {"app": name}},
                "spec": {
                    "containers": [
                        {
                            "name": "worker-container",
                            "image": image,
                            "resources": {
                                "requests": {"memory": "128Mi"},
                                "limits": {"memory": memory, "cpu": "500m"},
                            },
                        }
                    ]
                },
            },
        },
    }


def make_incident(change: DeploymentChange) -> IncidentEvent:
    now = datetime.now(timezone.utc)
    signal_name = "oom_killed" if change.change_type == "resource_limit" else "crash_loop"
    return IncidentEvent(
        schema_version=CURRENT_SCHEMA_VERSION,
        incident_id="inc-proposal-test",
        detection_timestamp=now,
        environment="production",
        affected_services=[change.service],
        changes=[change],
        signals=[
            AnomalySignal(
                signal_id="sig-failure",
                service=change.service,
                timestamp=now - timedelta(minutes=5),
                name=signal_name,
                value=1,
                severity="critical",
            )
        ],
        log_excerpts=[
            LogExcerpt(
                log_id="log-failure",
                service=change.service,
                timestamp=now - timedelta(minutes=4),
                message="fatal error in affected workload",
            )
        ],
    )


def make_report(change: DeploymentChange):
    return DeterministicCorrelationEngine(make_incident(change)).analyze()


def check_by_name(checks, name: str):
    return next(check for check in checks if check.check_name == name)


def test_resource_proposal_preserves_full_manifest_and_changes_only_target_memory():
    current = deployment_manifest(memory="256Mi")
    original = deepcopy(current)
    change = DeploymentChange(
        change_id="chg-res",
        service="worker-service",
        timestamp=datetime.now(timezone.utc) - timedelta(minutes=10),
        change_type="resource_limit",
        identifier="cfg-02",
        details={
            "memory_limit": "256Mi",
            "previous_memory_limit": "512Mi",
            "target_container": "worker-container",
            "current_manifest": current,
        },
    )

    report = make_report(change)
    assert report.proposal is not None
    proposal = report.proposal
    before = yaml.safe_load(proposal.before_manifest)
    after = yaml.safe_load(proposal.after_manifest)

    assert proposal.operation == "ADJUST_RESOURCE_LIMITS"
    assert proposal.target_resource == "apps/v1:Deployment/production/worker"
    assert proposal.all_policy_checks_passed is True
    assert proposal.status == "NOT_APPLIED"
    assert report.proposal_generation.status.value == "GENERATED"
    assert report.proposal_generation.telemetry_evidence_count == 2
    assert {item.record_id for item in proposal.evidence_references} >= {
        "chg-res",
        "sig-failure",
        "log-failure",
    }
    assert before == original
    assert before["spec"]["replicas"] == 3
    assert before["spec"]["template"]["spec"]["containers"][0]["image"] == "example/worker:v2"
    assert after["spec"]["template"]["spec"]["containers"][0]["resources"] == {
        "requests": {"memory": "128Mi"},
        "limits": {"memory": "512Mi", "cpu": "500m"},
    }
    assert check_by_name(proposal.policy_checks, "bounded_memory_change").passed
    assert "memory: 256Mi" in proposal.diff
    assert "memory: 512Mi" in proposal.diff
    assert any("did not independently retrieve or authenticate" in item for item in proposal.assumptions_and_limitations)


def test_resource_proposal_requires_manifest_container_and_matching_current_value():
    missing_manifest = DeploymentChange(
        change_id="chg-no-manifest",
        service="worker",
        timestamp=datetime.now(timezone.utc) - timedelta(minutes=10),
        change_type="resource_limit",
        identifier="cfg-01",
        details={
            "memory_limit": "256Mi",
            "previous_memory_limit": "512Mi",
            "target_container": "worker-container",
        },
    )
    missing_report = make_report(missing_manifest)
    assert missing_report.proposal is None
    assert missing_report.proposal_generation.status.value == "NOT_GENERATED"
    assert missing_report.proposal_generation.reason_code.value == "SOURCE_MANIFEST_MISSING"

    unknown_container = DeploymentChange(
        change_id="chg-unknown-container",
        service="worker",
        timestamp=datetime.now(timezone.utc) - timedelta(minutes=10),
        change_type="resource_limit",
        identifier="cfg-02",
        details={
            "memory_limit": "256Mi",
            "previous_memory_limit": "512Mi",
            "target_container": "not-in-manifest",
            "current_manifest": deployment_manifest(),
        },
    )
    assert make_report(unknown_container).proposal is None

    mismatch = DeploymentChange(
        change_id="chg-source-mismatch",
        service="worker",
        timestamp=datetime.now(timezone.utc) - timedelta(minutes=10),
        change_type="resource_limit",
        identifier="cfg-03",
        details={
            "memory_limit": "128Mi",
            "previous_memory_limit": "512Mi",
            "target_container": "worker-container",
            "current_manifest": deployment_manifest(memory="256Mi"),
        },
    )
    assert make_report(mismatch).proposal is None


def test_rollback_uses_explicit_full_snapshots_and_matching_revision_annotations():
    current = deployment_manifest(revision="v2.0.1", image="example/worker:v2.0.1")
    previous = deployment_manifest(revision="v2.0.0", image="example/worker:v2.0.0")
    change = DeploymentChange(
        change_id="chg-deploy",
        service="worker-service",
        timestamp=datetime.now(timezone.utc) - timedelta(minutes=10),
        change_type="deployment",
        identifier="v2.0.1",
        prior_known_good_identifier="v2.0.0",
        details={"current_manifest": current, "previous_manifest": previous},
    )

    report = make_report(change)
    assert report.proposal is not None
    proposal = report.proposal
    before = yaml.safe_load(proposal.before_manifest)
    after = yaml.safe_load(proposal.after_manifest)

    assert proposal.operation == "ROLLBACK_REVISION"
    assert proposal.target_resource == "apps/v1:Deployment/production/worker"
    assert before == current
    assert after == previous
    assert after["spec"]["template"]["spec"]["containers"][0]["image"] == "example/worker:v2.0.0"
    assert proposal.all_policy_checks_passed is True
    assert proposal.status == "NOT_APPLIED"
    assert "previous Deployment snapshot" in proposal.rationale


def test_rollback_fails_closed_without_matching_prior_snapshot_or_revision():
    current = deployment_manifest(revision="v2.0.1")
    prior_with_wrong_revision = deployment_manifest(revision="unverified")
    missing_previous = DeploymentChange(
        change_id="chg-no-prior-manifest",
        service="worker",
        timestamp=datetime.now(timezone.utc) - timedelta(minutes=10),
        change_type="deployment",
        identifier="v2.0.1",
        prior_known_good_identifier="v2.0.0",
        details={"current_manifest": current},
    )
    missing_report = make_report(missing_previous)
    assert missing_report.proposal is None
    assert missing_report.proposal_generation.reason_code.value == "PRIOR_MANIFEST_MISSING"

    wrong_prior = DeploymentChange(
        change_id="chg-wrong-prior",
        service="worker",
        timestamp=datetime.now(timezone.utc) - timedelta(minutes=10),
        change_type="deployment",
        identifier="v2.0.1",
        prior_known_good_identifier="v2.0.0",
        details={"current_manifest": current, "previous_manifest": prior_with_wrong_revision},
    )
    wrong_prior_report = make_report(wrong_prior)
    assert wrong_prior_report.proposal is None
    assert wrong_prior_report.proposal_generation.reason_code.value == "REVISION_MISMATCH"

    wrong_current = DeploymentChange(
        change_id="chg-wrong-current",
        service="worker",
        timestamp=datetime.now(timezone.utc) - timedelta(minutes=10),
        change_type="deployment",
        identifier="v2.0.1",
        prior_known_good_identifier="v2.0.0",
        details={
            "current_manifest": deployment_manifest(revision="different-current"),
            "previous_manifest": deployment_manifest(revision="v2.0.0"),
        },
    )
    wrong_current_report = make_report(wrong_current)
    assert wrong_current_report.proposal is None
    assert wrong_current_report.proposal_generation.reason_code.value == "REVISION_MISMATCH"


def test_rollback_fails_closed_when_selector_changes_between_snapshots():
    current = deployment_manifest(revision="v2.0.1")
    previous = deployment_manifest(revision="v2.0.0")
    previous["spec"]["selector"]["matchLabels"] = {"app": "other"}
    previous["spec"]["template"]["metadata"]["labels"] = {"app": "other"}
    change = DeploymentChange(
        change_id="chg-selector",
        service="worker",
        timestamp=datetime.now(timezone.utc) - timedelta(minutes=10),
        change_type="deployment",
        identifier="v2.0.1",
        prior_known_good_identifier="v2.0.0",
        details={"current_manifest": current, "previous_manifest": previous},
    )
    report = make_report(change)
    assert report.proposal is None
    assert report.proposal_generation.reason_code.value == "SELECTOR_MISMATCH"


def test_policy_validator_rejects_non_deployment_kind_and_wrong_target():
    valid = deployment_manifest()
    invalid_kind = deepcopy(valid)
    invalid_kind["kind"] = "ClusterRole"
    checks, passed = DeterministicPolicyValidator.validate(
        operation="ROLLBACK_REVISION",
        target_resource="apps/v1:Deployment/production/worker",
        before_manifest=yaml.safe_dump(valid),
        after_manifest=yaml.safe_dump(invalid_kind),
        prior_known_good="rev-prior",
        current_identifier="rev-current",
    )
    assert passed is False
    assert check_by_name(checks, "deployment_structure").passed is False
    assert check_by_name(checks, "target_resource_allowlist").passed is False

    checks, passed = DeterministicPolicyValidator.validate(
        operation="ROLLBACK_REVISION",
        target_resource="apps/v1:Deployment/production/other",
        before_manifest=yaml.safe_dump(valid),
        after_manifest=yaml.safe_dump(valid),
        prior_known_good="rev-current",
        current_identifier="rev-current",
    )
    assert passed is False
    assert check_by_name(checks, "target_resource_allowlist").passed is False


def test_policy_validator_rejects_missing_deployment_selector_and_duplicate_yaml_keys():
    incomplete = deployment_manifest()
    del incomplete["spec"]["selector"]
    checks, passed = DeterministicPolicyValidator.validate(
        operation="ROLLBACK_REVISION",
        target_resource="apps/v1:Deployment/production/worker",
        before_manifest=yaml.safe_dump(incomplete),
        after_manifest=yaml.safe_dump(incomplete),
        prior_known_good="rev-prior",
        current_identifier="rev-current",
    )
    assert passed is False
    assert check_by_name(checks, "deployment_structure").passed is False

    duplicate = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: first
  name: second
"""
    checks, passed = DeterministicPolicyValidator.validate(
        operation="ADJUST_RESOURCE_LIMITS",
        target_resource="apps/v1:Deployment/production/worker",
        before_manifest=duplicate,
        after_manifest=duplicate,
    )
    assert passed is False
    assert check_by_name(checks, "valid_yaml_syntax").passed is False


def test_security_check_inspects_structured_fields_without_raw_text_false_positives():
    safe = deployment_manifest()
    safe["metadata"]["annotations"]["note"] = "hostNetwork privileged hostPath are words, not settings"
    checks, passed = DeterministicPolicyValidator.validate(
        operation="ADJUST_RESOURCE_LIMITS",
        target_resource="apps/v1:Deployment/production/worker",
        before_manifest=yaml.safe_dump(safe),
        after_manifest=yaml.safe_dump(safe),
        target_container="worker-container",
        current_memory_limit="256Mi",
        previous_memory_limit="256Mi",
    )
    assert check_by_name(checks, "privilege_escalation_guardrail").passed is True
    assert passed is False  # A no-op limit change is not a valid proposal.

    dangerous = deepcopy(safe)
    dangerous["spec"]["template"]["spec"]["initContainers"] = [
        {
            "name": "setup",
            "image": "example/setup:v1",
            "securityContext": {"privileged": True},
        }
    ]
    checks, passed = DeterministicPolicyValidator.validate(
        operation="ROLLBACK_REVISION",
        target_resource="apps/v1:Deployment/production/worker",
        before_manifest=yaml.safe_dump(safe),
        after_manifest=yaml.safe_dump(dangerous),
        prior_known_good="rev-current",
        current_identifier="rev-current",
    )
    assert passed is False
    assert check_by_name(checks, "privilege_escalation_guardrail").passed is False


def test_policy_validator_rejects_host_path_and_forbidden_capabilities():
    dangerous = deployment_manifest()
    pod_spec = dangerous["spec"]["template"]["spec"]
    pod_spec["volumes"] = [{"name": "host-root", "hostPath": {"path": "/"}}]
    pod_spec["containers"][0]["securityContext"] = {
        "capabilities": {"add": ["SYS_ADMIN"]}
    }
    checks, passed = DeterministicPolicyValidator.validate(
        operation="ADJUST_RESOURCE_LIMITS",
        target_resource="apps/v1:Deployment/production/worker",
        before_manifest=yaml.safe_dump(deployment_manifest()),
        after_manifest=yaml.safe_dump(dangerous),
        target_container="worker-container",
        current_memory_limit="256Mi",
        previous_memory_limit="512Mi",
    )
    assert passed is False
    assert check_by_name(checks, "privilege_escalation_guardrail").passed is False


def test_policy_validator_rejects_unknown_operations_and_unbounded_values():
    manifest = deployment_manifest(memory="16Gi")
    checks, passed = DeterministicPolicyValidator.validate(
        operation="APPLY_TO_CLUSTER",
        target_resource="apps/v1:Deployment/production/worker",
        before_manifest=yaml.safe_dump(deployment_manifest()),
        after_manifest=yaml.safe_dump(manifest),
    )
    assert passed is False
    assert check_by_name(checks, "operation_allowlist").passed is False

    checks, passed = DeterministicPolicyValidator.validate(
        operation="ADJUST_RESOURCE_LIMITS",
        target_resource="apps/v1:Deployment/production/worker",
        before_manifest=yaml.safe_dump(deployment_manifest()),
        after_manifest=yaml.safe_dump(manifest),
        target_container="worker-container",
        current_memory_limit="256Mi",
        previous_memory_limit="16Gi",
    )
    assert passed is False
    assert check_by_name(checks, "resource_bounds_check").passed is False


def test_memory_quantities_use_exact_binary_and_decimal_units():
    assert _parse_memory_to_bytes("256Mi") == 256 * 1024**2
    assert _parse_memory_to_bytes("1Gi") == 1024**3
    assert _parse_memory_to_bytes("256M") == 256 * 1000**2
    assert _parse_memory_to_bytes("65536Ki") == 64 * 1024**2
    assert _parse_memory_to_bytes("1048576") == 1024**2

    for invalid in ("256m", "256MB", "-512Mi", "1.5Gi", "invalid", True):
        with pytest.raises(ValueError):
            _parse_memory_to_bytes(invalid)


def test_resource_generator_fails_closed_on_missing_noop_or_malformed_prior_value():
    current = deployment_manifest(memory="256Mi")
    base = {
        "target_container": "worker-container",
        "current_manifest": current,
        "memory_limit": "256Mi",
    }
    cases = [
        {**base},
        {**base, "previous_memory_limit": "256Mi"},
        {**base, "previous_memory_limit": "512BogusUnit"},
        {**base, "previous_memory_limit": "16Gi"},
    ]
    for index, details in enumerate(cases):
        change = DeploymentChange(
            change_id=f"chg-bad-{index}",
            service="worker",
            timestamp=datetime.now(timezone.utc) - timedelta(minutes=10),
            change_type="resource_limit",
            identifier=f"cfg-{index}",
            details=details,
        )
        assert make_report(change).proposal is None


def test_memory_policy_requires_only_the_selected_container_memory_to_change():
    before = deployment_manifest(memory="256Mi")
    after = deepcopy(before)
    after["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["memory"] = "512Mi"
    after["spec"]["replicas"] = 9
    checks, passed = DeterministicPolicyValidator.validate(
        operation="ADJUST_RESOURCE_LIMITS",
        target_resource="apps/v1:Deployment/production/worker",
        before_manifest=yaml.safe_dump(before),
        after_manifest=yaml.safe_dump(after),
        target_container="worker-container",
        current_memory_limit="256Mi",
        previous_memory_limit="512Mi",
    )
    assert passed is False
    assert check_by_name(checks, "bounded_memory_change").passed is False


def test_proposal_rejects_unresolvable_candidate_telemetry_citations():
    change = DeploymentChange(
        change_id="chg-evidence",
        service="worker",
        timestamp=datetime.now(timezone.utc) - timedelta(minutes=10),
        change_type="resource_limit",
        identifier="cfg-04",
        details={
            "memory_limit": "256Mi",
            "previous_memory_limit": "512Mi",
            "target_container": "worker-container",
            "current_manifest": deployment_manifest(),
        },
    )
    incident = make_incident(change)
    report = DeterministicCorrelationEngine(incident).analyze()
    candidate = report.ranked_candidates[0].model_copy(
        update={
            "supporting_evidence": [
                *report.ranked_candidates[0].supporting_evidence,
                EvidenceReference(
                    record_type="signal",
                    record_id="sig-does-not-exist",
                    summary="Untrusted or stale citation",
                ),
            ]
        }
    )

    proposal, outcome = RemediationProposalGenerator.generate_with_outcome(incident, candidate)
    assert proposal is None
    assert outcome.reason_code.value == "TELEMETRY_REFERENCE_INVALID"
    assert outcome.telemetry_evidence_count == 0
    assert "sig-does-not-exist" not in outcome.message


def test_proposal_outcome_lists_failed_policy_checks():
    change = DeploymentChange(
        change_id="chg-policy-reject",
        service="worker",
        timestamp=datetime.now(timezone.utc) - timedelta(minutes=10),
        change_type="resource_limit",
        identifier="cfg-05",
        details={
            "memory_limit": "256Mi",
            "previous_memory_limit": "16Gi",
            "target_container": "worker-container",
            "current_manifest": deployment_manifest(),
        },
    )
    report = make_report(change)
    assert report.proposal is None
    assert report.proposal_generation.reason_code.value == "POLICY_REJECTED"
    assert report.proposal_generation.failed_policy_checks == ["resource_bounds_check"]


def test_unexpected_proposal_error_is_safely_reported_without_exception_text(monkeypatch, caplog):
    change = DeploymentChange(
        change_id="chg-internal-error",
        service="worker",
        timestamp=datetime.now(timezone.utc) - timedelta(minutes=10),
        change_type="resource_limit",
        identifier="cfg-06",
        details={
            "memory_limit": "256Mi",
            "previous_memory_limit": "512Mi",
            "target_container": "worker-container",
            "current_manifest": deployment_manifest(),
        },
    )
    incident = make_incident(change)
    report = DeterministicCorrelationEngine(incident).analyze()
    candidate = report.ranked_candidates[0]

    def fail_builder(cls, incident_arg, candidate_arg):
        raise RuntimeError("sensitive incident payload")

    monkeypatch.setattr(RemediationProposalGenerator, "_build_proposal", classmethod(fail_builder))
    with caplog.at_level("ERROR"):
        proposal, outcome = RemediationProposalGenerator.generate_with_outcome(incident, candidate)

    assert proposal is None
    assert outcome.reason_code.value == "INTERNAL_ERROR"
    assert "sensitive incident payload" not in caplog.text
