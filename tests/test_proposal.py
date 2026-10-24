"""Tests for constrained Kubernetes remediation proposal generation and deterministic policy checks."""

from datetime import datetime, timedelta, timezone

import pytest

from hivemind.engine import DeterministicCorrelationEngine
from hivemind.models import (
    CURRENT_SCHEMA_VERSION,
    AnomalySignal,
    DeploymentChange,
    IncidentEvent,
)
from hivemind.proposal import (
    DeterministicPolicyValidator,
    _parse_memory_to_mb,
)


def test_remediation_proposal_rollback_success():
    now = datetime.now(timezone.utc)
    change = DeploymentChange(
        change_id="chg-app",
        service="order-api",
        timestamp=now - timedelta(minutes=10),
        change_type="deployment",
        identifier="v2.0.1",
        prior_known_good_identifier="v2.0.0",
        details={"image": "order-api:v2.0.1"},
    )
    signal = AnomalySignal(
        signal_id="sig-err",
        service="order-api",
        timestamp=now - timedelta(minutes=5),
        name="crash_loop",
        value=10,
        severity="critical",
    )
    incident = IncidentEvent(
        schema_version=CURRENT_SCHEMA_VERSION,
        incident_id="inc-prop-01",
        detection_timestamp=now,
        environment="production",
        affected_services=["order-api"],
        changes=[change],
        signals=[signal],
    )
    engine = DeterministicCorrelationEngine(incident)
    report = engine.analyze()
    assert report.proposal is not None
    p = report.proposal
    assert p.operation == "ROLLBACK_REVISION"
    assert p.target_resource == "apps/v1:Deployment/production/order-api"
    assert p.all_policy_checks_passed is True
    assert p.status == "NOT_APPLIED"
    assert "--- a/order-api-deployment.yaml" in p.diff
    assert "+++ b/order-api-deployment.yaml" in p.diff
    assert "-        image: order-api:v2.0.1" in p.diff or "order-api:v2.0.1" in p.diff
    assert "+        image: order-api:v2.0.0" in p.diff or "order-api:v2.0.0" in p.diff


def test_remediation_proposal_resource_adjustment():
    now = datetime.now(timezone.utc)
    change = DeploymentChange(
        change_id="chg-res",
        service="worker",
        timestamp=now - timedelta(minutes=10),
        change_type="resource_limit",
        identifier="cfg-02",
        prior_known_good_identifier="cfg-01",
        details={"memory_limit": "256Mi", "previous_memory_limit": "512Mi"},
    )
    signal = AnomalySignal(
        signal_id="sig-oom",
        service="worker",
        timestamp=now - timedelta(minutes=5),
        name="oom_killed",
        value=1,
        severity="critical",
    )
    incident = IncidentEvent(
        schema_version=CURRENT_SCHEMA_VERSION,
        incident_id="inc-prop-02",
        detection_timestamp=now,
        environment="production",
        affected_services=["worker"],
        changes=[change],
        signals=[signal],
    )
    engine = DeterministicCorrelationEngine(incident)
    report = engine.analyze()
    assert report.proposal is not None
    p = report.proposal
    assert p.operation == "ADJUST_RESOURCE_LIMITS"
    assert p.all_policy_checks_passed is True
    assert "-            memory: 256Mi" in p.diff
    assert "+            memory: 512Mi" in p.diff
    bounds_check = next(c for c in p.policy_checks if c.check_name == "resource_bounds_check")
    assert "within configured policy bounds" in bounds_check.details
    assert "safe bounds" not in bounds_check.details
    assert any("policy compliance does not guarantee operational safety" in a for a in p.assumptions_and_limitations)
    assert any("512Mi" in e.summary for e in p.evidence_references)


def test_policy_validator_rejects_forbidden_kind():
    checks, all_passed = DeterministicPolicyValidator.validate(
        operation="ROLLBACK_REVISION",
        target_resource="rbac.authorization.k8s.io/v1:ClusterRole/admin",
        before_manifest="kind: ClusterRole",
        after_manifest="kind: ClusterRole",
        prior_known_good="v1",
    )
    assert all_passed is False
    allowlist_check = next(c for c in checks if c.check_name == "target_resource_allowlist")
    assert allowlist_check.passed is False


def test_policy_validator_rejects_privilege_escalation():
    dangerous_manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      containers:
      - name: api
        securityContext:
          privileged: true
          hostNetwork: true
"""
    checks, all_passed = DeterministicPolicyValidator.validate(
        operation="ADJUST_RESOURCE_LIMITS",
        target_resource="apps/v1:Deployment/prod/api",
        before_manifest="kind: Deployment",
        after_manifest=dangerous_manifest,
    )
    assert all_passed is False
    priv_check = next(c for c in checks if c.check_name == "privilege_escalation_guardrail")
    assert priv_check.passed is False


def test_policy_validator_rejects_rollback_missing_prior_revision():
    checks, all_passed = DeterministicPolicyValidator.validate(
        operation="ROLLBACK_REVISION",
        target_resource="apps/v1:Deployment/prod/api",
        before_manifest="kind: Deployment",
        after_manifest="kind: Deployment\nmetadata:\n  name: api",
        prior_known_good=None,
    )
    assert all_passed is False
    rollback_check = next(c for c in checks if c.check_name == "explicit_rollback_target")
    assert rollback_check.passed is False


def test_policy_validator_rejects_excessive_resource_limits():
    excessive_manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: worker
spec:
  template:
    spec:
      containers:
      - name: worker
        resources:
          limits:
            memory: "16Gi"
"""
    checks, all_passed = DeterministicPolicyValidator.validate(
        operation="ADJUST_RESOURCE_LIMITS",
        target_resource="apps/v1:Deployment/prod/worker",
        before_manifest="kind: Deployment",
        after_manifest=excessive_manifest,
    )
    assert all_passed is False
    bounds_check = next(c for c in checks if c.check_name == "resource_bounds_check")
    assert bounds_check.passed is False
    assert "violates configured policy bounds" in bounds_check.details


def test_policy_validator_rejects_hostpath_and_sysadmin():
    hostpath_manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: worker
spec:
  template:
    spec:
      volumes:
      - name: host-root
        hostPath:
          path: /
"""
    checks, all_passed = DeterministicPolicyValidator.validate(
        operation="ADJUST_RESOURCE_LIMITS",
        target_resource="apps/v1:Deployment/prod/worker",
        before_manifest="kind: Deployment",
        after_manifest=hostpath_manifest,
    )
    assert all_passed is False
    priv_check = next(c for c in checks if c.check_name == "privilege_escalation_guardrail")
    assert priv_check.passed is False
    assert "hostpath" in priv_check.details


def test_memory_parsing_valid_and_malformed_fail_closed():
    # Valid units
    assert _parse_memory_to_mb("256Mi") == 256
    assert _parse_memory_to_mb("256M") == 256
    assert _parse_memory_to_mb("1Gi") == 1024
    assert _parse_memory_to_mb("65536Ki") == 64

    # Malformed / unsupported units raise ValueError
    with pytest.raises(ValueError):
        _parse_memory_to_mb("256XYZ")

    with pytest.raises(ValueError):
        _parse_memory_to_mb("256m")  # 'm' is milli in Kubernetes, invalid for memory

    with pytest.raises(ValueError):
        _parse_memory_to_mb("256MB")  # Kubernetes rejects 'MB', requires 'M' or 'Mi'

    with pytest.raises(ValueError):
        _parse_memory_to_mb("-512Mi")

    with pytest.raises(ValueError):
        _parse_memory_to_mb("invalid")

    # Verify that malformed unit in manifest causes policy check to fail closed
    malformed_unit_manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: worker
spec:
  template:
    spec:
      containers:
      - name: worker
        resources:
          limits:
            memory: "512UnknownUnit"
"""
    checks, all_passed = DeterministicPolicyValidator.validate(
        operation="ADJUST_RESOURCE_LIMITS",
        target_resource="apps/v1:Deployment/prod/worker",
        before_manifest="kind: Deployment",
        after_manifest=malformed_unit_manifest,
    )
    assert all_passed is False
    bounds_check = next(c for c in checks if c.check_name == "resource_bounds_check")
    assert bounds_check.passed is False


def test_structured_policy_checks_reject_mismatched_kind():
    pod_manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: worker
spec:
  containers:
  - name: worker
    image: worker:v1
"""
    checks, all_passed = DeterministicPolicyValidator.validate(
        operation="ROLLBACK_REVISION",
        target_resource="apps/v1:Deployment/prod/worker",
        before_manifest="kind: Deployment",
        after_manifest=pod_manifest,
        prior_known_good="v1",
    )
    assert all_passed is False
    kind_check = next(c for c in checks if c.check_name == "target_resource_allowlist")
    assert kind_check.passed is False


def test_structured_policy_checks_reject_allow_privilege_escalation():
    escalation_manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: worker
spec:
  template:
    spec:
      containers:
      - name: worker
        securityContext:
          allowPrivilegeEscalation: true
"""
    checks, all_passed = DeterministicPolicyValidator.validate(
        operation="ROLLBACK_REVISION",
        target_resource="apps/v1:Deployment/prod/worker",
        before_manifest="kind: Deployment",
        after_manifest=escalation_manifest,
        prior_known_good="v1",
    )
    assert all_passed is False
    priv_check = next(c for c in checks if c.check_name == "privilege_escalation_guardrail")
    assert priv_check.passed is False


def test_remediation_proposal_rejects_missing_or_empty_prior_memory_limit():
    """Generator must not infer prior state or fall back to defaults when prior memory limit is missing."""
    now = datetime.now(timezone.utc)
    change = DeploymentChange(
        change_id="chg-no-prev",
        service="worker",
        timestamp=now - timedelta(minutes=10),
        change_type="resource_limit",
        identifier="cfg-03",
        prior_known_good_identifier="cfg-02",
        details={"memory_limit": "256Mi"},  # previous_memory_limit deliberately omitted
    )
    signal = AnomalySignal(
        signal_id="sig-oom-2",
        service="worker",
        timestamp=now - timedelta(minutes=5),
        name="oom_killed",
        value=1,
        severity="critical",
    )
    incident = IncidentEvent(
        schema_version=CURRENT_SCHEMA_VERSION,
        incident_id="inc-prop-no-prev",
        detection_timestamp=now,
        environment="production",
        affected_services=["worker"],
        changes=[change],
        signals=[signal],
    )
    engine = DeterministicCorrelationEngine(incident)
    report = engine.analyze()
    # Diagnosed, but cannot safely construct proposal without explicit prior value
    assert report.proposal is None


def test_remediation_proposal_rejects_malformed_or_identical_prior_memory_limit():
    """Generator must reject malformed memory units or no-op identical memory values."""
    now = datetime.now(timezone.utc)
    # Case A: Identical values (256Mi -> 256Mi)
    change_same = DeploymentChange(
        change_id="chg-same",
        service="worker",
        timestamp=now - timedelta(minutes=10),
        change_type="resource_limit",
        identifier="cfg-same",
        details={"memory_limit": "256Mi", "previous_memory_limit": "256Mi"},
    )
    signal = AnomalySignal(
        signal_id="sig-oom-same",
        service="worker",
        timestamp=now - timedelta(minutes=5),
        name="oom_killed",
        value=1,
        severity="critical",
    )
    incident_same = IncidentEvent(
        schema_version=CURRENT_SCHEMA_VERSION,
        incident_id="inc-prop-same",
        detection_timestamp=now,
        environment="production",
        affected_services=["worker"],
        changes=[change_same],
        signals=[signal],
    )
    engine_same = DeterministicCorrelationEngine(incident_same)
    assert engine_same.analyze().proposal is None

    # Case B: Malformed unit
    change_bad = DeploymentChange(
        change_id="chg-bad",
        service="worker",
        timestamp=now - timedelta(minutes=10),
        change_type="resource_limit",
        identifier="cfg-bad",
        details={"memory_limit": "256Mi", "previous_memory_limit": "512BogusUnit"},
    )
    incident_bad = IncidentEvent(
        schema_version=CURRENT_SCHEMA_VERSION,
        incident_id="inc-prop-bad",
        detection_timestamp=now,
        environment="production",
        affected_services=["worker"],
        changes=[change_bad],
        signals=[signal],
    )
    engine_bad = DeterministicCorrelationEngine(incident_bad)
    assert engine_bad.analyze().proposal is None


def test_remediation_proposal_rejects_missing_or_identical_prior_revision():
    """Rollback proposal must reject missing, empty, or self-referential revisions."""
    now = datetime.now(timezone.utc)
    change_self = DeploymentChange(
        change_id="chg-self",
        service="web",
        timestamp=now - timedelta(minutes=10),
        change_type="deployment",
        identifier="v1.0.0",
        prior_known_good_identifier="v1.0.0",  # Same as current
        details={"image": "web:v1.0.0"},
    )
    signal = AnomalySignal(
        signal_id="sig-web-err",
        service="web",
        timestamp=now - timedelta(minutes=5),
        name="crash_loop",
        value=1,
        severity="critical",
    )
    incident = IncidentEvent(
        schema_version=CURRENT_SCHEMA_VERSION,
        incident_id="inc-prop-self",
        detection_timestamp=now,
        environment="production",
        affected_services=["web"],
        changes=[change_self],
        signals=[signal],
    )
    engine = DeterministicCorrelationEngine(incident)
    assert engine.analyze().proposal is None
