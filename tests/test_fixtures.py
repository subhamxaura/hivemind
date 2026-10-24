"""End-to-end tests validating every sample fixture file against HiveMind."""

from pathlib import Path

import yaml

from hivemind.engine import DeterministicCorrelationEngine
from hivemind.models import AnalysisStatus, IncidentEvent


def test_fixture_incident_diagnosable():
    path = Path("fixtures/incident_diagnosable.yaml")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    incident = IncidentEvent.model_validate(data)

    engine = DeterministicCorrelationEngine(incident)
    report = engine.analyze()

    assert report.status == AnalysisStatus.DIAGNOSED
    assert len(report.ranked_candidates) >= 1
    top = report.ranked_candidates[0]
    assert top.candidate_id == "cause-change-chg-901"
    assert top.evidence_score >= 0.75

    # Check proposal details
    assert report.proposal is not None
    assert report.proposal.operation == "ADJUST_RESOURCE_LIMITS"
    assert report.proposal.status == "NOT_APPLIED"
    assert report.proposal.all_policy_checks_passed is True


def test_fixture_incident_inconclusive_missing_evidence():
    path = Path("fixtures/incident_inconclusive_missing_evidence.yaml")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    incident = IncidentEvent.model_validate(data)

    engine = DeterministicCorrelationEngine(incident)
    report = engine.analyze()

    assert report.status == AnalysisStatus.INCONCLUSIVE
    assert report.proposal is None
    assert len(report.inconclusive_reasons) > 0
    assert any("No deployment or configuration change" in r for r in report.inconclusive_reasons)
    assert any("Telemetry missing for declared dependencies" in r for r in report.inconclusive_reasons)


def test_fixture_incident_contradictory_evidence():
    path = Path("fixtures/incident_contradictory_evidence.yaml")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    incident = IncidentEvent.model_validate(data)

    # Verify secret was redacted during model validation
    assert len(incident.log_excerpts) == 1
    assert "secret_auth_token_value_abc123" not in incident.log_excerpts[0].message
    assert "[REDACTED]" in incident.log_excerpts[0].message

    engine = DeterministicCorrelationEngine(incident)
    report = engine.analyze()

    assert report.status == AnalysisStatus.INCONCLUSIVE
    assert report.proposal is None
    # Check that contradictory evidence is explicitly recorded on candidates
    found_contradiction = any(
        len(c.contradicting_evidence) > 0 for c in report.ranked_candidates
    )
    assert found_contradiction is True
