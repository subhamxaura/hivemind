"""Tests for constrained Kubernetes remediation proposal generation and deterministic policy checks."""

from datetime import datetime, timedelta, timezone

from hivemind.engine import DeterministicCorrelationEngine
from hivemind.models import (
    CURRENT_SCHEMA_VERSION,
    AnomalySignal,
    DeploymentChange,
    IncidentEvent,
)
from hivemind.proposal import (
    DeterministicPolicyValidator,
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
