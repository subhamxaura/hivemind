"""Tests for HiveMind strict data models and schema validation."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from hivemind.models import (
    CURRENT_SCHEMA_VERSION,
    AnomalySignal,
    DeploymentChange,
    IncidentEvent,
    LogExcerpt,
    RemediationProposal,
    TopologyDependency,
)


def test_valid_incident_event():
    now = datetime.now(timezone.utc)
    event = IncidentEvent(
        schema_version=CURRENT_SCHEMA_VERSION,
        incident_id="inc-test-01",
        detection_timestamp=now,
        environment="staging",
        affected_services=["auth-svc"],
        signals=[
            AnomalySignal(
                signal_id="sig-01",
                service="auth-svc",
                timestamp=now,
                name="http_5xx",
                value=5.0,
            )
        ],
        changes=[
            DeploymentChange(
                change_id="chg-01",
                service="auth-svc",
                timestamp=now,
                change_type="deployment",
                identifier="v1.2.0",
            )
        ],
        dependencies=[
            TopologyDependency(
                source_service="auth-svc",
                target_service="auth-db",
                critical=True,
            )
        ],
        log_excerpts=[
            LogExcerpt(
                log_id="log-01",
                service="auth-svc",
                timestamp=now,
                message="Connection failed with auth-db",
            )
        ],
    )
    assert event.incident_id == "inc-test-01"
    assert len(event.signals) == 1


def test_reject_unsupported_schema_version():
    now = datetime.now(timezone.utc)
    with pytest.raises(ValidationError) as exc_info:
        IncidentEvent(
            schema_version="v2beta",
            incident_id="inc-bad-schema",
            detection_timestamp=now,
            environment="prod",
            affected_services=["api"],
        )
    assert "Unsupported schema_version" in str(exc_info.value)


def test_reject_extra_unknown_fields():
    now = datetime.now(timezone.utc)
    with pytest.raises(ValidationError) as exc_info:
        IncidentEvent.model_validate(
            {
                "schema_version": CURRENT_SCHEMA_VERSION,
                "incident_id": "inc-extra",
                "detection_timestamp": now.isoformat(),
                "environment": "prod",
                "affected_services": ["api"],
                "unknown_hack_field": "injected_value",
            }
        )
    assert "extra_forbidden" in str(exc_info.value)


def test_reject_naive_timestamp():
    naive_dt = datetime(2026, 10, 24, 12, 0, 0)  # No tzinfo
    with pytest.raises(ValidationError) as exc_info:
        IncidentEvent(
            schema_version=CURRENT_SCHEMA_VERSION,
            incident_id="inc-naive",
            detection_timestamp=naive_dt,
            environment="prod",
            affected_services=["api"],
        )
    assert "timezone-aware" in str(exc_info.value)


def test_reject_duplicate_record_ids():
    now = datetime.now(timezone.utc)
    with pytest.raises(ValidationError) as exc_info:
        IncidentEvent(
            schema_version=CURRENT_SCHEMA_VERSION,
            incident_id="inc-dup",
            detection_timestamp=now,
            environment="prod",
            affected_services=["api"],
            signals=[
                AnomalySignal(
                    signal_id="sig-dup",
                    service="api",
                    timestamp=now,
                    name="sig1",
                    value=1,
                ),
                AnomalySignal(
                    signal_id="sig-dup",
                    service="api",
                    timestamp=now,
                    name="sig2",
                    value=2,
                ),
            ],
        )
    assert "Duplicate record identifier" in str(exc_info.value)


def test_secret_redaction_in_log_excerpt():
    now = datetime.now(timezone.utc)
    raw_message = (
        "User failed login password='SuperSecretPassword123' and bearer=Bearer eyJhbGciOiJIUzI1NiJ9 "
        "and api_key: sk-1234567890abcdef123456"
    )
    log = LogExcerpt(
        log_id="log-sec",
        service="api",
        timestamp=now,
        message=raw_message,
    )
    assert "SuperSecretPassword123" not in log.message
    assert "eyJhbGciOiJIUzI1NiJ9" not in log.message
    assert "sk-1234567890abcdef123456" not in log.message
    assert "[REDACTED]" in log.message


def test_remediation_proposal_rejects_mutation_status():
    with pytest.raises(ValidationError) as exc_info:
        RemediationProposal(
            proposal_id="prop-01",
            operation="ROLLBACK_REVISION",
            target_resource="apps/v1:Deployment/prod/api",
            before_manifest="spec: {}",
            after_manifest="spec: {}",
            diff="--- a\n+++ b",
            evidence_references=[],
            rationale="test",
            all_policy_checks_passed=True,
            status="APPLIED_AUTOMATICALLY",  # Strictly forbidden
        )
    assert "HiveMind is read-only" in str(exc_info.value)
