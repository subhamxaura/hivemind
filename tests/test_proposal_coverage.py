"""Comprehensive test suite for edge cases, failure modes, and branch coverage.

Targets ≥95% statement and ≥85% branch coverage across the split proposal modules:
- k8s_manifest.py
- security.py
- policy.py
- proposal.py
"""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest
import yaml

from hivemind.k8s_manifest import (
    _find_container,
    _get_memory_limit,
    _manifest_identity,
    _parse_manifest,
    _parse_memory_to_bytes,
    _resource_reference,
    _set_memory_limit,
    _UniqueKeySafeLoader,
    _validate_deployment_structure,
)
from hivemind.models import (
    CURRENT_SCHEMA_VERSION,
    AnomalySignal,
    CandidateCause,
    DeploymentChange,
    EvidenceReference,
    IncidentEvent,
    LogExcerpt,
    ProposalGenerationReasonCode,
)
from hivemind.policy import (
    DeterministicPolicyValidator,
    _only_target_memory_limit_changed,
)
from hivemind.proposal import RemediationProposalGenerator
from hivemind.security import _security_violations


def base_deployment(
    *,
    name: str = "web",
    namespace: str = "prod",
    revision: str = "rev-1",
    memory: str = "256Mi",
    image: str = "example/web:v1",
) -> dict:
    """Return a structurally valid deployment dictionary."""
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "annotations": {"hivemind.io/revision": revision},
        },
        "spec": {
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": {"labels": {"app": name}},
                "spec": {
                    "containers": [
                        {
                            "name": "web-container",
                            "image": image,
                            "resources": {"limits": {"memory": memory}},
                        }
                    ]
                },
            },
        },
    }


def make_test_incident(change: DeploymentChange) -> IncidentEvent:
    now = datetime(2026, 10, 24, 15, 0, 0, tzinfo=timezone.utc)
    return IncidentEvent(
        schema_version=CURRENT_SCHEMA_VERSION,
        incident_id="inc-cov-test",
        detection_timestamp=now,
        environment="production",
        affected_services=[change.service],
        analysis_window_minutes=60,
        changes=[change],
        signals=[
            AnomalySignal(
                signal_id="sig-oom",
                timestamp=now - timedelta(minutes=10),
                service=change.service,
                name="oom_killed",
                severity="critical",
                value=1.0,
            )
        ],
        log_excerpts=[
            LogExcerpt(
                log_id="log-oom",
                timestamp=now - timedelta(minutes=10),
                service=change.service,
                message="Container killed due to OOM limit",
            )
        ],
        dependencies=[],
    )


# ==============================================================================
# 1. Security Violations Coverage
# ==============================================================================

def test_security_violations_pod_spec_and_volume_edges():
    # Pod spec not a mapping
    assert _security_violations({"spec": {"template": {"spec": "not-a-dict"}}}) == [
        "Deployment pod spec is not a mapping"
    ]

    # Host namespaces (network, PID, IPC)
    doc = {
        "spec": {
            "template": {
                "spec": {
                    "hostNetwork": True,
                    "hostPID": True,
                    "hostIPC": True,
                    "volumes": "not-a-list",
                    "containers": "not-a-list",
                }
            }
        }
    }
    violations = _security_violations(doc)
    assert "pod spec hostNetwork: true" in violations
    assert "pod spec hostPID: true" in violations
    assert "pod spec hostIPC: true" in violations
    assert "pod spec volumes must be a list" in violations
    assert "pod spec containers must be a list" in violations


def test_security_violations_container_collections_and_capabilities():
    # Test initContainers and ephemeralContainers with SYS_ADMIN and ALL
    doc = {
        "spec": {
            "template": {
                "spec": {
                    "initContainers": [
                        "not-a-dict",  # non-dict container skipped
                        {
                            "name": "init-bad",
                            "securityContext": {
                                "privileged": True,
                                "allowPrivilegeEscalation": True,
                                "capabilities": {"add": ["SYS_ADMIN"]},
                            },
                        },
                        {
                            "name": "init-bad-caps",
                            "securityContext": {
                                "capabilities": {"add": "not-a-list"},
                            },
                        },
                    ],
                    "ephemeralContainers": [
                        {
                            "name": "debug-all",
                            "securityContext": {
                                "capabilities": {"add": ["ALL"]},
                            },
                        },
                        {
                            "name": "bad-sec-context",
                            "securityContext": "not-a-dict",
                        },
                    ],
                    "containers": [
                        {
                            "name": "main-good",
                            "securityContext": {},
                        }
                    ],
                }
            }
        }
    }
    v = _security_violations(doc)
    assert any("initContainers[1] sets privileged: true" in item for item in v)
    assert any("initContainers[1] sets allowPrivilegeEscalation: true" in item for item in v)
    assert any("initContainers[1] adds SYS_ADMIN or ALL capabilities" in item for item in v)
    assert any("initContainers[2] capabilities.add must be a list" in item for item in v)
    assert any("ephemeralContainers[0] adds SYS_ADMIN or ALL capabilities" in item for item in v)
    assert any("ephemeralContainers[1].securityContext must be a mapping" in item for item in v)


# ==============================================================================
# 2. k8s_manifest Structure Validation and Container Helpers
# ==============================================================================

def test_validate_deployment_structure_all_edge_branches():
    # Metadata name / namespace DNS label validation
    bad_meta = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "UPPER_NOT_ALLOWED", "namespace": "has.dots.not.allowed"},
    }
    errors = _validate_deployment_structure(bad_meta, "Test")
    assert any("metadata.name must be a valid Kubernetes DNS subdomain" in e for e in errors)
    assert any("metadata.namespace must be a valid Kubernetes DNS label" in e for e in errors)

    # Spec.template not a dict
    assert any(
        "spec.template must be a mapping" in e
        for e in _validate_deployment_structure(
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": "app", "namespace": "prod"},
                "spec": {"selector": {"matchLabels": {"app": "web"}}, "template": "not-a-dict"},
            },
            "Test",
        )
    )

    # Template metadata labels not a dict
    assert any(
        "spec.template.metadata.labels must be a mapping" in e
        for e in _validate_deployment_structure(
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": "app", "namespace": "prod"},
                "spec": {
                    "selector": {"matchLabels": {"app": "web"}},
                    "template": {"metadata": {"labels": "not-a-dict"}, "spec": {}},
                },
            },
            "Test",
        )
    )

    # Template.spec not a dict
    assert any(
        "spec.template.spec must be a mapping" in e
        for e in _validate_deployment_structure(
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": "app", "namespace": "prod"},
                "spec": {
                    "selector": {"matchLabels": {"app": "web"}},
                    "template": {
                        "metadata": {"labels": {"app": "web"}},
                        "spec": "not-a-dict",
                    },
                },
            },
            "Test",
        )
    )

    # Container missing name or image
    manifest_containers = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "app", "namespace": "prod"},
        "spec": {
            "selector": {"matchLabels": {"app": "web"}},
            "template": {
                "metadata": {"labels": {"app": "web"}},
                "spec": {
                    "containers": [
                        "not-a-dict",
                        {"name": "", "image": "img:v1"},
                        {"name": "c2", "image": ""},
                        {"name": "c2", "image": "img:v2"},  # duplicate name
                    ]
                },
            },
        },
    }
    container_errs = _validate_deployment_structure(manifest_containers, "Test")
    assert any("container at index 0 must be a mapping" in e for e in container_errs)
    assert any("container at index 1 must have a non-empty name" in e for e in container_errs)
    assert any("container at index 2 must have a non-empty image" in e for e in container_errs)
    assert any("container names must be unique" in e for e in container_errs)


def test_set_memory_limit_and_find_container_branches():
    # Containers not a list in _find_container
    assert _find_container({"spec": {"template": {"spec": {"containers": "bad"}}}}, "c") is None

    # _set_memory_limit when resources is None (creates dict)
    manifest = {
        "spec": {
            "template": {
                "spec": {
                    "containers": [{"name": "worker"}]
                }
            }
        }
    }
    assert _set_memory_limit(manifest, "worker", "1Gi") is True
    assert _get_memory_limit(manifest["spec"]["template"]["spec"]["containers"][0]) == "1Gi"

    # _set_memory_limit when resources is not a dict
    bad_resources = {
        "spec": {
            "template": {
                "spec": {
                    "containers": [{"name": "worker", "resources": "invalid"}]
                }
            }
        }
    }
    assert _set_memory_limit(bad_resources, "worker", "1Gi") is False

    # _set_memory_limit when limits is not a dict
    bad_limits = {
        "spec": {
            "template": {
                "spec": {
                    "containers": [{"name": "worker", "resources": {"limits": "invalid"}}]
                }
            }
        }
    }
    assert _set_memory_limit(bad_limits, "worker", "1Gi") is False


def test_parse_manifest_non_dict_and_unhashable_keys():
    with pytest.raises(ValueError, match="manifest must be a YAML mapping"):
        _parse_manifest("- item1\n- item2\n")

    # Unhashable mapping key in YAML
    unhashable_yaml = "{[1, 2]: val}"
    with pytest.raises(yaml.YAMLError):
        yaml.load(unhashable_yaml, Loader=_UniqueKeySafeLoader)


# ==============================================================================
# 3. Memory Parsing & Policy Validator Branches
# ==============================================================================

def test_parse_memory_to_bytes_floats_and_edge_values():
    with pytest.raises(ValueError):
        _parse_memory_to_bytes(3.14)
    with pytest.raises(ValueError):
        _parse_memory_to_bytes("not-a-number")


def test_policy_validator_adjust_resource_limits_branches():
    before = base_deployment(memory="256Mi")
    after = base_deployment(memory="512Mi")

    # YAML syntax error
    checks, passed = DeterministicPolicyValidator.validate(
        operation="ADJUST_RESOURCE_LIMITS",
        target_resource="apps/v1:Deployment/prod/web",
        before_manifest="invalid yaml: [",
        after_manifest=yaml.safe_dump(after),
    )
    assert not passed
    assert not checks[0].passed
    assert checks[0].check_name == "valid_yaml_syntax"

    # Unparseable memory quantities (ValueError / TypeError path)
    checks, passed = DeterministicPolicyValidator.validate(
        operation="ADJUST_RESOURCE_LIMITS",
        target_resource="apps/v1:Deployment/prod/web",
        before_manifest=yaml.safe_dump(before),
        after_manifest=yaml.safe_dump(after),
        target_container="web-container",
        current_memory_limit="invalid-memory",
        previous_memory_limit="512Mi",
    )
    assert not passed
    bound_check = next(c for c in checks if c.check_name == "resource_bounds_check")
    assert not bound_check.passed
    assert "could not be verified" in bound_check.details

    # Out of bounds proposed memory: 32Mi < 64Mi
    after_low = base_deployment(memory="32Mi")
    checks, passed = DeterministicPolicyValidator.validate(
        operation="ADJUST_RESOURCE_LIMITS",
        target_resource="apps/v1:Deployment/prod/web",
        before_manifest=yaml.safe_dump(before),
        after_manifest=yaml.safe_dump(after_low),
        target_container="web-container",
        current_memory_limit="256Mi",
        previous_memory_limit="32Mi",
    )
    assert not passed
    bound_check = next(c for c in checks if c.check_name == "resource_bounds_check")
    assert not bound_check.passed
    assert "outside [64Mi, 4096Mi]" in bound_check.details


def test_only_target_memory_limit_changed_false_branches():
    before = base_deployment(memory="256Mi")
    after_no_limits = deepcopy(before)
    # Remove limits entirely
    del after_no_limits["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]
    assert not _only_target_memory_limit_changed(before, after_no_limits, "web-container")


# ==============================================================================
# 4. RemediationProposalGenerator Edge Cases & Failures
# ==============================================================================

def test_proposal_preflight_and_rollback_different_namespaces():
    # Deployment rollback where previous_manifest has different namespace
    current = base_deployment(namespace="production", revision="rev-2")
    previous_different_ns = base_deployment(namespace="staging", revision="rev-1")

    change = DeploymentChange(
        change_id="chg-diff-ns",
        timestamp=datetime(2026, 10, 24, 14, 50, tzinfo=timezone.utc),
        service="web",
        change_type="deployment",
        identifier="rev-2",
        prior_known_good_identifier="rev-1",
        details={
            "current_manifest": current,
            "previous_manifest": previous_different_ns,
        },
    )
    incident = make_test_incident(change)
    candidate = CandidateCause(
        candidate_id="cause-change-chg-diff-ns",
        title="Faulty Deployment",
        description="Deployment test",
        evidence_score=0.9,
        scoring_breakdown={},
        supporting_evidence=[
            EvidenceReference(record_type="change", record_id="chg-diff-ns", summary="Change"),
            EvidenceReference(record_type="signal", record_id="sig-oom", summary="Signal"),
        ],
        rationale="Test rationale",
        uncertainty="None",
    )
    proposal, outcome = RemediationProposalGenerator.generate_with_outcome(incident, candidate)
    assert proposal is None
    assert outcome.reason_code == ProposalGenerationReasonCode.TARGET_IDENTITY_INVALID


def test_proposal_unsupported_change_type_configmap():
    # Change type is "configmap"
    change = DeploymentChange(
        change_id="chg-cfg",
        timestamp=datetime(2026, 10, 24, 14, 50, tzinfo=timezone.utc),
        service="web",
        change_type="configmap",
        identifier="cfg-v2",
        details={"current_manifest": base_deployment()},
    )
    incident = make_test_incident(change)
    candidate = CandidateCause(
        candidate_id="cause-change-chg-cfg",
        title="ConfigMap Change",
        description="Config change",
        evidence_score=0.9,
        scoring_breakdown={},
        supporting_evidence=[
            EvidenceReference(record_type="change", record_id="chg-cfg", summary="Change"),
            EvidenceReference(record_type="signal", record_id="sig-oom", summary="Signal"),
        ],
        rationale="Test rationale",
        uncertainty="None",
    )
    proposal, outcome = RemediationProposalGenerator.generate_with_outcome(incident, candidate)
    assert proposal is None
    assert outcome.reason_code == ProposalGenerationReasonCode.UNSUPPORTED_CAUSE


def test_proposal_non_change_cause_and_missing_change_id():
    change = DeploymentChange(
        change_id="chg-ok",
        timestamp=datetime(2026, 10, 24, 14, 50, tzinfo=timezone.utc),
        service="web",
        change_type="resource_limit",
        identifier="res-1",
        details={
            "target_container": "web-container",
            "memory_limit": "256Mi",
            "previous_memory_limit": "512Mi",
            "current_manifest": base_deployment(),
        },
    )
    incident = make_test_incident(change)

    # Candidate not starting with cause-change-
    non_change_cand = CandidateCause(
        candidate_id="cause-dep-web-to-db",
        title="Dependency",
        description="Dep",
        evidence_score=0.8,
        scoring_breakdown={},
        supporting_evidence=[],
        rationale="Test rationale",
        uncertainty="None",
    )
    _, outcome = RemediationProposalGenerator.generate_with_outcome(incident, non_change_cand)
    assert outcome.reason_code == ProposalGenerationReasonCode.UNSUPPORTED_CAUSE

    # Referenced change not in incident
    missing_chg_cand = CandidateCause(
        candidate_id="cause-change-not-found",
        title="Unknown Change",
        description="Not found",
        evidence_score=0.8,
        scoring_breakdown={},
        supporting_evidence=[],
        rationale="Test rationale",
        uncertainty="None",
    )
    _, outcome = RemediationProposalGenerator.generate_with_outcome(incident, missing_chg_cand)
    assert outcome.reason_code == ProposalGenerationReasonCode.CHANGE_NOT_FOUND


def test_proposal_evidence_validation_failures():
    change = DeploymentChange(
        change_id="chg-evidence-test",
        timestamp=datetime(2026, 10, 24, 14, 50, tzinfo=timezone.utc),
        service="web",
        change_type="resource_limit",
        identifier="res-1",
        details={
            "target_container": "web-container",
            "memory_limit": "256Mi",
            "previous_memory_limit": "512Mi",
            "current_manifest": base_deployment(),
        },
    )
    incident = make_test_incident(change)

    # Citation of wrong change
    other_change = DeploymentChange(
        change_id="chg-other",
        timestamp=datetime(2026, 10, 24, 14, 50, tzinfo=timezone.utc),
        service="web",
        change_type="resource_limit",
        identifier="res-other",
        details={},
    )
    incident.changes.append(other_change)

    cand_wrong_change = CandidateCause(
        candidate_id="cause-change-chg-evidence-test",
        title="Test",
        description="Desc",
        evidence_score=0.9,
        scoring_breakdown={},
        supporting_evidence=[
            EvidenceReference(record_type="change", record_id="chg-other", summary="Wrong change"),
            EvidenceReference(record_type="signal", record_id="sig-oom", summary="Signal"),
        ],
        rationale="Test rationale",
        uncertainty="None",
    )
    _, outcome = RemediationProposalGenerator.generate_with_outcome(incident, cand_wrong_change)
    assert outcome.reason_code == ProposalGenerationReasonCode.TELEMETRY_REFERENCE_INVALID
    assert "cite only the change record it is intended to remediate" in outcome.message

    # Log citation from wrong service
    wrong_svc_log = LogExcerpt(
        log_id="log-other-svc",
        timestamp=incident.detection_timestamp - timedelta(minutes=5),
        service="database",
        message="db connection lost",
    )
    incident.log_excerpts.append(wrong_svc_log)
    cand_wrong_log = CandidateCause(
        candidate_id="cause-change-chg-evidence-test",
        title="Test",
        description="Desc",
        evidence_score=0.9,
        scoring_breakdown={},
        supporting_evidence=[
            EvidenceReference(record_type="change", record_id="chg-evidence-test", summary="Change"),
            EvidenceReference(record_type="signal", record_id="sig-oom", summary="Signal"),
            EvidenceReference(record_type="log", record_id="log-other-svc", summary="Log"),
        ],
        rationale="Test rationale",
        uncertainty="None",
    )
    _, outcome = RemediationProposalGenerator.generate_with_outcome(incident, cand_wrong_log)
    assert outcome.reason_code == ProposalGenerationReasonCode.TELEMETRY_REFERENCE_INVALID
    assert "outside the analysis window or belongs to another service" in outcome.message

    # Signal citation outside analysis window
    stale_signal = AnomalySignal(
        signal_id="sig-stale",
        timestamp=incident.detection_timestamp - timedelta(minutes=120),  # > 60m
        service="web",
        name="crash",
        severity="critical",
        value=1.0,
    )
    incident.signals.append(stale_signal)
    cand_stale = CandidateCause(
        candidate_id="cause-change-chg-evidence-test",
        title="Test",
        description="Desc",
        evidence_score=0.9,
        scoring_breakdown={},
        supporting_evidence=[
            EvidenceReference(record_type="change", record_id="chg-evidence-test", summary="Change"),
            EvidenceReference(record_type="signal", record_id="sig-stale", summary="Signal"),
        ],
        rationale="Test rationale",
        uncertainty="None",
    )
    _, outcome = RemediationProposalGenerator.generate_with_outcome(incident, cand_stale)
    assert outcome.reason_code == ProposalGenerationReasonCode.TELEMETRY_REFERENCE_INVALID

    # Duplicate citations in evidence references are deduplicated safely
    cand_dups = CandidateCause(
        candidate_id="cause-change-chg-evidence-test",
        title="Test",
        description="Desc",
        evidence_score=0.9,
        scoring_breakdown={},
        supporting_evidence=[
            EvidenceReference(record_type="change", record_id="chg-evidence-test", summary="Change"),
            EvidenceReference(record_type="change", record_id="chg-evidence-test", summary="Duplicate"),
            EvidenceReference(record_type="signal", record_id="sig-oom", summary="Signal"),
            EvidenceReference(record_type="signal", record_id="sig-oom", summary="Duplicate Signal"),
        ],
        rationale="Test rationale",
        uncertainty="None",
    )
    prop, outcome = RemediationProposalGenerator.generate_with_outcome(incident, cand_dups)
    assert prop is not None
    assert outcome.reason_code == ProposalGenerationReasonCode.GENERATED


def test_proposal_builder_unexpected_exception_and_serialization_error(monkeypatch):
    change = DeploymentChange(
        change_id="chg-crash",
        timestamp=datetime(2026, 10, 24, 14, 50, tzinfo=timezone.utc),
        service="web",
        change_type="resource_limit",
        identifier="res-1",
        details={
            "target_container": "web-container",
            "memory_limit": "256Mi",
            "previous_memory_limit": "512Mi",
            "current_manifest": base_deployment(),
        },
    )
    incident = make_test_incident(change)
    candidate = CandidateCause(
        candidate_id="cause-change-chg-crash",
        title="Test",
        description="Desc",
        evidence_score=0.9,
        scoring_breakdown={},
        supporting_evidence=[
            EvidenceReference(record_type="change", record_id="chg-crash", summary="Change"),
            EvidenceReference(record_type="signal", record_id="sig-oom", summary="Signal"),
        ],
        rationale="Test rationale",
        uncertainty="None",
    )

    # Test backward-compatible generate interface
    prop = RemediationProposalGenerator.generate(incident, candidate)
    assert prop is not None

    # Test KeyError / Serialization error path
    def raise_keyerror(*args, **kwargs):
        raise KeyError("missing_key")

    monkeypatch.setattr(RemediationProposalGenerator, "_build_proposal", raise_keyerror)
    _, outcome = RemediationProposalGenerator.generate_with_outcome(incident, candidate)
    assert outcome.reason_code == ProposalGenerationReasonCode.SERIALIZATION_FAILED

    # Test _build_proposal returning None
    def return_none(*args, **kwargs):
        return None

    monkeypatch.setattr(RemediationProposalGenerator, "_build_proposal", return_none)
    _, outcome = RemediationProposalGenerator.generate_with_outcome(incident, candidate)
    assert outcome.reason_code == ProposalGenerationReasonCode.POLICY_REJECTED


def test_manifest_identity_invalid_namespace():
    assert _manifest_identity({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "app", "namespace": "INVALID_NS"}}) is None
    assert _resource_reference({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "app", "namespace": "INVALID_NS"}}) is None


def test_security_violations_volume_and_capabilities_branches():
    doc = {
        "spec": {
            "template": {
                "spec": {
                    "volumes": [
                        "not-a-dict",
                        {"name": "vol-empty", "emptyDir": {}},
                    ],
                    "containers": [
                        "not-a-dict",
                        {
                            "name": "c1",
                            "securityContext": {
                                "capabilities": "not-a-dict",
                            },
                        },
                    ],
                }
            }
        }
    }
    violations = _security_violations(doc)
    assert violations == []


def test_proposal_preflight_remaining_branches(monkeypatch):
    # 1. Invalid deployment structure in current_manifest
    bad_current = base_deployment()
    bad_current["kind"] = "ConfigMap"
    chg_bad_struct = DeploymentChange(
        change_id="chg-bad-struct",
        timestamp=datetime(2026, 10, 24, 14, 50, tzinfo=timezone.utc),
        service="web",
        change_type="resource_limit",
        identifier="res-1",
        details={
            "target_container": "web-container",
            "memory_limit": "256Mi",
            "previous_memory_limit": "512Mi",
            "current_manifest": bad_current,
        },
    )
    inc = make_test_incident(chg_bad_struct)
    cand = CandidateCause(
        candidate_id="cause-change-chg-bad-struct",
        title="Test",
        description="Desc",
        evidence_score=0.9,
        scoring_breakdown={},
        supporting_evidence=[
            EvidenceReference(record_type="change", record_id="chg-bad-struct", summary="Change"),
            EvidenceReference(record_type="signal", record_id="sig-oom", summary="Signal"),
        ],
        rationale="Test",
        uncertainty="None",
    )
    _, outcome = RemediationProposalGenerator.generate_with_outcome(inc, cand)
    assert outcome.reason_code == ProposalGenerationReasonCode.SOURCE_MANIFEST_INVALID

    # 2. _resource_reference returning None in _preflight
    chg_valid = DeploymentChange(
        change_id="chg-res-pre",
        timestamp=datetime(2026, 10, 24, 14, 50, tzinfo=timezone.utc),
        service="web",
        change_type="resource_limit",
        identifier="res-1",
        details={
            "target_container": "web-container",
            "memory_limit": "256Mi",
            "previous_memory_limit": "512Mi",
            "current_manifest": base_deployment(),
        },
    )
    inc_valid = make_test_incident(chg_valid)
    cand_valid = CandidateCause(
        candidate_id="cause-change-chg-res-pre",
        title="Test",
        description="Desc",
        evidence_score=0.9,
        scoring_breakdown={},
        supporting_evidence=[
            EvidenceReference(record_type="change", record_id="chg-res-pre", summary="Change"),
            EvidenceReference(record_type="signal", record_id="sig-oom", summary="Signal"),
        ],
        rationale="Test",
        uncertainty="None",
    )
    monkeypatch.setattr("hivemind.proposal._resource_reference", lambda *args, **kwargs: None)
    outcome_pre = RemediationProposalGenerator._preflight(inc_valid, cand_valid)
    assert outcome_pre is not None
    assert outcome_pre.reason_code == ProposalGenerationReasonCode.TARGET_IDENTITY_INVALID
    monkeypatch.undo()

    # 3. Empty target container string in resource change
    chg_empty_tc = DeploymentChange(
        change_id="chg-empty-tc",
        timestamp=datetime(2026, 10, 24, 14, 50, tzinfo=timezone.utc),
        service="web",
        change_type="resource_limit",
        identifier="res-1",
        details={
            "target_container": "   ",
            "memory_limit": "256Mi",
            "previous_memory_limit": "512Mi",
            "current_manifest": base_deployment(),
        },
    )
    inc_tc = make_test_incident(chg_empty_tc)
    cand_tc = CandidateCause(
        candidate_id="cause-change-chg-empty-tc",
        title="Test",
        description="Desc",
        evidence_score=0.9,
        scoring_breakdown={},
        supporting_evidence=[
            EvidenceReference(record_type="change", record_id="chg-empty-tc", summary="Change"),
            EvidenceReference(record_type="signal", record_id="sig-oom", summary="Signal"),
        ],
        rationale="Test",
        uncertainty="None",
    )
    outcome_tc = RemediationProposalGenerator._preflight(inc_tc, cand_tc)
    assert outcome_tc is not None
    assert outcome_tc.reason_code == ProposalGenerationReasonCode.MEMORY_EVIDENCE_MISSING

    # 4. Deployment rollback where previous_manifest has invalid structure
    bad_prev = base_deployment(revision="rev-1")
    bad_prev["kind"] = "StatefulSet"
    chg_bad_prev = DeploymentChange(
        change_id="chg-bad-prev",
        timestamp=datetime(2026, 10, 24, 14, 50, tzinfo=timezone.utc),
        service="web",
        change_type="deployment",
        identifier="rev-2",
        prior_known_good_identifier="rev-1",
        details={
            "current_manifest": base_deployment(revision="rev-2"),
            "previous_manifest": bad_prev,
        },
    )
    inc_prev = make_test_incident(chg_bad_prev)
    cand_prev = CandidateCause(
        candidate_id="cause-change-chg-bad-prev",
        title="Test",
        description="Desc",
        evidence_score=0.9,
        scoring_breakdown={},
        supporting_evidence=[
            EvidenceReference(record_type="change", record_id="chg-bad-prev", summary="Change"),
            EvidenceReference(record_type="signal", record_id="sig-oom", summary="Signal"),
        ],
        rationale="Test",
        uncertainty="None",
    )
    outcome_prev = RemediationProposalGenerator._preflight(inc_prev, cand_prev)
    assert outcome_prev is not None
    assert outcome_prev.reason_code == ProposalGenerationReasonCode.SOURCE_MANIFEST_INVALID

    # 5. Unsupported change_type with no memory keys
    chg_unknown = DeploymentChange(
        change_id="chg-unk",
        timestamp=datetime(2026, 10, 24, 14, 50, tzinfo=timezone.utc),
        service="web",
        change_type="unknown_custom",
        identifier="u-1",
        details={"current_manifest": base_deployment()},
    )
    inc_unk = make_test_incident(chg_unknown)
    cand_unk = CandidateCause(
        candidate_id="cause-change-chg-unk",
        title="Test",
        description="Desc",
        evidence_score=0.9,
        scoring_breakdown={},
        supporting_evidence=[
            EvidenceReference(record_type="change", record_id="chg-unk", summary="Change"),
            EvidenceReference(record_type="signal", record_id="sig-oom", summary="Signal"),
        ],
        rationale="Test",
        uncertainty="None",
    )
    outcome_unk = RemediationProposalGenerator._preflight(inc_unk, cand_unk)
    assert outcome_unk is not None
    assert outcome_unk.reason_code == ProposalGenerationReasonCode.UNSUPPORTED_CAUSE

    # 6. Candidate evidence has change citation but NO signal citation
    chg_good = DeploymentChange(
        change_id="chg-good-signal-test",
        timestamp=datetime(2026, 10, 24, 14, 50, tzinfo=timezone.utc),
        service="web",
        change_type="resource_limit",
        identifier="res-1",
        details={
            "target_container": "web-container",
            "memory_limit": "256Mi",
            "previous_memory_limit": "512Mi",
            "current_manifest": base_deployment(),
        },
    )
    cand_no_signal = CandidateCause(
        candidate_id="cause-change-chg-good-signal-test",
        title="Test",
        description="Desc",
        evidence_score=0.9,
        scoring_breakdown={},
        supporting_evidence=[
            EvidenceReference(record_type="change", record_id="chg-good-signal-test", summary="Change"),
        ],
        rationale="Test",
        uncertainty="None",
    )
    outcome_sig = RemediationProposalGenerator._validate_candidate_evidence(
        make_test_incident(chg_good), cand_no_signal, chg_good
    )
    assert outcome_sig is not None
    assert outcome_sig.reason_code == ProposalGenerationReasonCode.TELEMETRY_REFERENCE_INVALID


def test_build_proposal_direct_defensive_branches(monkeypatch):
    good_current = base_deployment(memory="256Mi")
    chg_res = DeploymentChange(
        change_id="chg-res-def",
        timestamp=datetime(2026, 10, 24, 14, 50, tzinfo=timezone.utc),
        service="web",
        change_type="resource_limit",
        identifier="res-1",
        details={
            "target_container": "web-container",
            "memory_limit": "256Mi",
            "previous_memory_limit": "512Mi",
            "current_manifest": good_current,
        },
    )
    inc = make_test_incident(chg_res)
    c_res = CandidateCause(
        candidate_id="cause-change-chg-res-def",
        title="T",
        description="D",
        evidence_score=0.8,
        scoring_breakdown={},
        supporting_evidence=[],
        rationale="R",
        uncertainty="U",
    )

    # 1. candidate_id not starting with cause-change-
    c_bad_prefix = CandidateCause(
        candidate_id="cause-signal-1",
        title="T",
        description="D",
        evidence_score=0.8,
        scoring_breakdown={},
        supporting_evidence=[],
        rationale="R",
        uncertainty="U",
    )
    assert RemediationProposalGenerator._build_proposal(inc, c_bad_prefix) is None

    # 2. change_id not in incident
    c_missing = CandidateCause(
        candidate_id="cause-change-nonexistent",
        title="T",
        description="D",
        evidence_score=0.8,
        scoring_breakdown={},
        supporting_evidence=[],
        rationale="R",
        uncertainty="U",
    )
    assert RemediationProposalGenerator._build_proposal(inc, c_missing) is None

    # 3. current_raw not mapping
    chg_no_raw = chg_res.model_copy(
        update={"details": {"target_container": "web-container", "current_manifest": "not-mapping"}}
    )
    assert RemediationProposalGenerator._build_proposal(make_test_incident(chg_no_raw), c_res) is None

    # 4. _validate_deployment_structure fails on before_obj
    chg_bad_struct = chg_res.model_copy(
        update={"details": {"target_container": "web-container", "current_manifest": {"kind": "Bad"}}}
    )
    assert RemediationProposalGenerator._build_proposal(make_test_incident(chg_bad_struct), c_res) is None

    # 5. _resource_reference is None
    monkeypatch.setattr("hivemind.proposal._resource_reference", lambda *args, **kwargs: None)
    assert RemediationProposalGenerator._build_proposal(inc, c_res) is None
    monkeypatch.undo()

    # 6. target_container not str or empty
    chg_tc_empty = chg_res.model_copy(
        update={
            "details": {
                "target_container": "",
                "memory_limit": "256Mi",
                "previous_memory_limit": "512Mi",
                "current_manifest": good_current,
            }
        }
    )
    assert RemediationProposalGenerator._build_proposal(make_test_incident(chg_tc_empty), c_res) is None

    # 7. current_memory or previous_memory None
    chg_mem_none = chg_res.model_copy(
        update={
            "details": {
                "target_container": "web-container",
                "memory_limit": None,
                "previous_memory_limit": "512Mi",
                "current_manifest": good_current,
            }
        }
    )
    assert RemediationProposalGenerator._build_proposal(make_test_incident(chg_mem_none), c_res) is None

    # 8. container missing / manifest_memory is None
    chg_wrong_c = chg_res.model_copy(
        update={
            "details": {
                "target_container": "non-existent-container",
                "memory_limit": "256Mi",
                "previous_memory_limit": "512Mi",
                "current_manifest": good_current,
            }
        }
    )
    assert RemediationProposalGenerator._build_proposal(make_test_incident(chg_wrong_c), c_res) is None

    # 9. memory parse exception
    chg_bad_mem = chg_res.model_copy(
        update={
            "details": {
                "target_container": "web-container",
                "memory_limit": "invalid-format",
                "previous_memory_limit": "512Mi",
                "current_manifest": good_current,
            }
        }
    )
    assert RemediationProposalGenerator._build_proposal(make_test_incident(chg_bad_mem), c_res) is None

    # 10. current_bytes == prior_bytes or manifest_bytes != current_bytes
    chg_same_bytes = chg_res.model_copy(
        update={
            "details": {
                "target_container": "web-container",
                "memory_limit": "256Mi",
                "previous_memory_limit": "256Mi",
                "current_manifest": good_current,
            }
        }
    )
    assert RemediationProposalGenerator._build_proposal(make_test_incident(chg_same_bytes), c_res) is None

    chg_mismatch_bytes = chg_res.model_copy(
        update={
            "details": {
                "target_container": "web-container",
                "memory_limit": "512Mi",
                "previous_memory_limit": "1Gi",
                "current_manifest": good_current,
            }
        }
    )
    assert RemediationProposalGenerator._build_proposal(make_test_incident(chg_mismatch_bytes), c_res) is None

    # 11. _set_memory_limit fails
    monkeypatch.setattr("hivemind.proposal._set_memory_limit", lambda *args, **kwargs: False)
    assert RemediationProposalGenerator._build_proposal(inc, c_res) is None
    monkeypatch.undo()

    # 12. Deployment rollback branches in _build_proposal:
    chg_dep = DeploymentChange(
        change_id="chg-dep-def",
        timestamp=datetime(2026, 10, 24, 14, 50, tzinfo=timezone.utc),
        service="web",
        change_type="deployment",
        identifier="rev-2",
        prior_known_good_identifier="rev-1",
        details={
            "current_manifest": base_deployment(revision="rev-2"),
            "previous_manifest": base_deployment(revision="rev-1"),
        },
    )
    c_dep = CandidateCause(
        candidate_id="cause-change-chg-dep-def",
        title="T",
        description="D",
        evidence_score=0.8,
        scoring_breakdown={},
        supporting_evidence=[],
        rationale="R",
        uncertainty="U",
    )

    # prior_identifier invalid / same as identifier
    chg_dep_same = chg_dep.model_copy(update={"prior_known_good_identifier": "rev-2"})
    assert RemediationProposalGenerator._build_proposal(make_test_incident(chg_dep_same), c_dep) is None

    # previous_raw not mapping
    chg_dep_no_prev = chg_dep.model_copy(
        update={"details": {"current_manifest": base_deployment(revision="rev-2"), "previous_manifest": "string"}}
    )
    assert RemediationProposalGenerator._build_proposal(make_test_incident(chg_dep_no_prev), c_dep) is None

    # previous_raw invalid deployment structure
    chg_dep_bad_prev = chg_dep.model_copy(
        update={"details": {"current_manifest": base_deployment(revision="rev-2"), "previous_manifest": {"kind": "Bad"}}}
    )
    assert RemediationProposalGenerator._build_proposal(make_test_incident(chg_dep_bad_prev), c_dep) is None

    # _resource_reference mismatch
    chg_dep_diff_res = chg_dep.model_copy(
        update={
            "details": {
                "current_manifest": base_deployment(revision="rev-2"),
                "previous_manifest": base_deployment(name="other-app", revision="rev-1"),
            }
        }
    )
    assert RemediationProposalGenerator._build_proposal(make_test_incident(chg_dep_diff_res), c_dep) is None

    # _revision(before_obj) != current_identifier
    chg_dep_rev1 = chg_dep.model_copy(update={"identifier": "rev-999"})
    assert RemediationProposalGenerator._build_proposal(make_test_incident(chg_dep_rev1), c_dep) is None

    # _revision(after_obj) != prior_identifier
    chg_dep_rev2 = chg_dep.model_copy(update={"prior_known_good_identifier": "rev-999"})
    assert RemediationProposalGenerator._build_proposal(make_test_incident(chg_dep_rev2), c_dep) is None

    # spec not dict / selector mismatch
    prev_sel_mismatch = base_deployment(revision="rev-1")
    prev_sel_mismatch["spec"]["selector"] = {"matchLabels": {"app": "other"}}
    chg_dep_sel = chg_dep.model_copy(
        update={
            "details": {
                "current_manifest": base_deployment(revision="rev-2"),
                "previous_manifest": prev_sel_mismatch,
            }
        }
    )
    assert RemediationProposalGenerator._build_proposal(make_test_incident(chg_dep_sel), c_dep) is None

    prev_no_spec = base_deployment(revision="rev-1")
    prev_no_spec["spec"] = "not-dict"
    chg_dep_no_spec = chg_dep.model_copy(
        update={
            "details": {
                "current_manifest": base_deployment(revision="rev-2"),
                "previous_manifest": prev_no_spec,
            }
        }
    )
    assert RemediationProposalGenerator._build_proposal(make_test_incident(chg_dep_no_spec), c_dep) is None

    # Unsupported change_type
    chg_unsupported = chg_dep.model_copy(update={"change_type": "configmap", "details": {}})
    assert RemediationProposalGenerator._build_proposal(make_test_incident(chg_unsupported), c_dep) is None
