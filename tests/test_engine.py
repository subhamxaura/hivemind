"""Tests for deterministic correlation engine rules, time window logic, and scoring."""

from datetime import datetime, timedelta, timezone

from hivemind.engine import DeterministicCorrelationEngine
from hivemind.models import (
    CURRENT_SCHEMA_VERSION,
    AnalysisStatus,
    AnomalySignal,
    DeploymentChange,
    IncidentEvent,
    LogExcerpt,
    ProposalGenerationReasonCode,
    ProposalGenerationStatus,
    TopologyDependency,
)


def test_time_window_filtering():
    base_time = datetime(2026, 10, 24, 15, 0, 0, tzinfo=timezone.utc)
    # 60 minute window is 14:00 to 15:00

    out_of_window_signal = AnomalySignal(
        signal_id="sig-old",
        service="order-svc",
        timestamp=base_time - timedelta(minutes=75),  # 13:45, outside window
        name="oom_killed",
        value=1,
    )
    in_window_signal = AnomalySignal(
        signal_id="sig-valid",
        service="order-svc",
        timestamp=base_time - timedelta(minutes=10),  # 14:50, inside window
        name="oom_killed",
        value=1,
    )
    change = DeploymentChange(
        change_id="chg-01",
        service="order-svc",
        timestamp=base_time - timedelta(minutes=20),
        change_type="resource_limit",
        identifier="rev-5",
        prior_known_good_identifier="rev-4",
        details={"memory_limit": "256Mi", "previous_memory_limit": "512Mi"},
    )

    incident = IncidentEvent(
        schema_version=CURRENT_SCHEMA_VERSION,
        incident_id="inc-window-test",
        detection_timestamp=base_time,
        environment="prod",
        affected_services=["order-svc"],
        analysis_window_minutes=60,
        signals=[out_of_window_signal, in_window_signal],
        changes=[change],
    )

    engine = DeterministicCorrelationEngine(incident)
    assert len(engine.window_signals) == 1
    assert engine.window_signals[0].signal_id == "sig-valid"


def test_high_confidence_diagnosis_with_matching_signature():
    base_time = datetime(2026, 10, 24, 15, 0, 0, tzinfo=timezone.utc)
    change = DeploymentChange(
        change_id="chg-mem",
        service="billing-svc",
        timestamp=base_time - timedelta(minutes=15),
        change_type="resource_limit",
        identifier="rev-12",
        prior_known_good_identifier="rev-11",
        details={"memory_limit": "128Mi", "previous_memory_limit": "512Mi"},
    )
    signal = AnomalySignal(
        signal_id="sig-oom",
        service="billing-svc",
        timestamp=base_time - timedelta(minutes=10),
        name="oom_killed",
        value=1,
        severity="critical",
    )
    log = LogExcerpt(
        log_id="log-oom",
        service="billing-svc",
        timestamp=base_time - timedelta(minutes=9),
        message="Fatal: process killed due to OOM",
    )

    incident = IncidentEvent(
        schema_version=CURRENT_SCHEMA_VERSION,
        incident_id="inc-diag-test",
        detection_timestamp=base_time,
        environment="prod",
        affected_services=["billing-svc"],
        signals=[signal],
        changes=[change],
        log_excerpts=[log],
    )

    engine = DeterministicCorrelationEngine(incident)
    report = engine.analyze()

    assert report.status == AnalysisStatus.DIAGNOSED
    assert len(report.ranked_candidates) >= 1
    top = report.ranked_candidates[0]
    assert top.evidence_score >= 0.75
    assert "chg-mem" in [e.record_id for e in top.supporting_evidence]
    assert "sig-oom" in [e.record_id for e in top.supporting_evidence]
    assert "log-oom" in [e.record_id for e in top.supporting_evidence]


def test_temporal_sequence_violation_contradiction():
    base_time = datetime(2026, 10, 24, 15, 0, 0, tzinfo=timezone.utc)
    # Anomaly started at 14:20
    signal = AnomalySignal(
        signal_id="sig-early",
        service="cart-svc",
        timestamp=base_time - timedelta(minutes=40),
        name="http_5xx",
        value=50,
        severity="critical",
    )
    # Change was applied AFTER at 14:40
    change = DeploymentChange(
        change_id="chg-late",
        service="cart-svc",
        timestamp=base_time - timedelta(minutes=20),
        change_type="deployment",
        identifier="v2",
    )

    incident = IncidentEvent(
        schema_version=CURRENT_SCHEMA_VERSION,
        incident_id="inc-temporal-violation",
        detection_timestamp=base_time,
        environment="prod",
        affected_services=["cart-svc"],
        signals=[signal],
        changes=[change],
    )

    engine = DeterministicCorrelationEngine(incident)
    report = engine.analyze()

    assert report.status == AnalysisStatus.INCONCLUSIVE
    assert len(report.ranked_candidates) == 1
    cand = report.ranked_candidates[0]
    assert len(cand.contradicting_evidence) > 0
    assert "temporal_sequence_violation_penalty" in cand.scoring_breakdown


def test_cascading_dependency_failure():
    base_time = datetime(2026, 10, 24, 15, 0, 0, tzinfo=timezone.utc)
    dep = TopologyDependency(
        source_service="checkout-svc",
        target_service="payment-gateway",
        dependency_type="sync_http",
        critical=True,
    )
    target_signal = AnomalySignal(
        signal_id="sig-gateway-down",
        service="payment-gateway",
        timestamp=base_time - timedelta(minutes=20),
        name="connection_refused",
        value=100,
        severity="critical",
    )
    source_signal = AnomalySignal(
        signal_id="sig-checkout-err",
        service="checkout-svc",
        timestamp=base_time - timedelta(minutes=15),
        name="http_5xx",
        value=20,
        severity="critical",
    )

    incident = IncidentEvent(
        schema_version=CURRENT_SCHEMA_VERSION,
        incident_id="inc-dep-test",
        detection_timestamp=base_time,
        environment="prod",
        affected_services=["checkout-svc"],
        signals=[target_signal, source_signal],
        dependencies=[dep],
    )

    engine = DeterministicCorrelationEngine(incident)
    report = engine.analyze()

    assert len(report.ranked_candidates) >= 1
    dep_cand = next(c for c in report.ranked_candidates if "payment-gateway" in c.candidate_id)
    assert dep_cand.evidence_score >= 0.70
    assert "critical_dependency_weight" in dep_cand.scoring_breakdown
    assert "temporal_precedence_bonus" in dep_cand.scoring_breakdown


def test_diagnosed_status_separates_telemetry_warnings_from_inconclusive_reasons():
    """Diagnosed incidents must leave inconclusive_reasons empty and record caveats in telemetry_warnings."""
    base_time = datetime(2026, 10, 24, 15, 0, 0, tzinfo=timezone.utc)
    change = DeploymentChange(
        change_id="chg-mem",
        service="billing-svc",
        timestamp=base_time - timedelta(minutes=15),
        change_type="resource_limit",
        identifier="rev-12",
        prior_known_good_identifier="rev-11",
        details={"memory_limit": "128Mi", "previous_memory_limit": "512Mi"},
    )
    signal = AnomalySignal(
        signal_id="sig-oom",
        service="billing-svc",
        timestamp=base_time - timedelta(minutes=10),
        name="oom_killed",
        value=1,
        severity="critical",
    )
    log = LogExcerpt(
        log_id="log-oom",
        service="billing-svc",
        timestamp=base_time - timedelta(minutes=9),
        message="Fatal: process killed due to OOM",
    )
    unmonitored_dep = TopologyDependency(
        source_service="billing-svc",
        target_service="unmonitored-cache",
        dependency_type="cache",
        critical=False,
    )

    incident = IncidentEvent(
        schema_version=CURRENT_SCHEMA_VERSION,
        incident_id="inc-caveat-test",
        detection_timestamp=base_time,
        environment="prod",
        affected_services=["billing-svc"],
        signals=[signal],
        changes=[change],
        log_excerpts=[log],
        dependencies=[unmonitored_dep],
    )

    engine = DeterministicCorrelationEngine(incident)
    report = engine.analyze()

    assert report.status == AnalysisStatus.DIAGNOSED
    assert report.inconclusive_reasons == []
    assert len(report.telemetry_warnings) == 1
    assert "unmonitored-cache" in report.telemetry_warnings[0]


def test_inconclusive_status_populates_inconclusive_reasons_and_clears_telemetry_warnings():
    """Inconclusive incidents must aggregate audit failure reasons and keep telemetry_warnings empty."""
    base_time = datetime(2026, 10, 24, 15, 0, 0, tzinfo=timezone.utc)
    signal = AnomalySignal(
        signal_id="sig-early",
        service="cart-svc",
        timestamp=base_time - timedelta(minutes=40),
        name="http_5xx",
        value=50,
        severity="critical",
    )
    change = DeploymentChange(
        change_id="chg-late",
        service="cart-svc",
        timestamp=base_time - timedelta(minutes=20),
        change_type="deployment",
        identifier="v2",
    )
    unmonitored_dep = TopologyDependency(
        source_service="cart-svc",
        target_service="catalog-db",
        dependency_type="database",
        critical=True,
    )

    incident = IncidentEvent(
        schema_version=CURRENT_SCHEMA_VERSION,
        incident_id="inc-inconclusive-audit",
        detection_timestamp=base_time,
        environment="prod",
        affected_services=["cart-svc"],
        signals=[signal],
        changes=[change],
        dependencies=[unmonitored_dep],
    )

    engine = DeterministicCorrelationEngine(incident)
    report = engine.analyze()

    assert report.status == AnalysisStatus.INCONCLUSIVE
    assert report.telemetry_warnings == []
    assert len(report.inconclusive_reasons) >= 1
    assert any("catalog-db" in r for r in report.inconclusive_reasons)
    assert report.proposal_generation.status == ProposalGenerationStatus.NOT_ATTEMPTED
    assert report.proposal_generation.reason_code == ProposalGenerationReasonCode.DIAGNOSIS_NOT_CONFIRMED
