"""Tests for configurable scoring weights, thresholds, and HiveMindConfig."""

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from hivemind.config import HiveMindConfig, ScoringWeights
from hivemind.engine import DeterministicCorrelationEngine
from hivemind.models import AnalysisStatus, IncidentEvent

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DIAGNOSABLE_FIXTURE = PROJECT_ROOT / "fixtures" / "incident_diagnosable.yaml"


def test_default_config_produces_identical_results_regression():
    """Verify that default config produces identical results to current baseline behavior."""
    raw_data = yaml.safe_load(DIAGNOSABLE_FIXTURE.read_text(encoding="utf-8"))
    incident = IncidentEvent.model_validate(raw_data)

    engine_default = DeterministicCorrelationEngine(incident)
    report_default = engine_default.analyze()

    config_explicit = HiveMindConfig()
    engine_explicit = DeterministicCorrelationEngine(incident, config=config_explicit)
    report_explicit = engine_explicit.analyze()

    assert report_default.status == AnalysisStatus.DIAGNOSED
    assert report_explicit.status == AnalysisStatus.DIAGNOSED
    assert report_default.ranked_candidates[0].evidence_score == 0.95
    assert report_explicit.ranked_candidates[0].evidence_score == 0.95
    assert report_default.model_dump() == report_explicit.model_dump()

    # Verify individual scoring component weights
    breakdown = report_default.ranked_candidates[0].scoring_breakdown
    assert breakdown["base_change_relevance"] == 0.40
    assert breakdown["temporal_proximity_bonus"] == 0.20
    assert breakdown["signature_match_bonus"] == 0.25
    assert breakdown["log_corroboration_bonus"] == 0.10


def test_env_var_override_changes_diagnosis_outcome(monkeypatch):
    """Verify overriding diagnosis_score_threshold via env var changes DIAGNOSED vs INCONCLUSIVE outcome."""
    raw_data = yaml.safe_load(DIAGNOSABLE_FIXTURE.read_text(encoding="utf-8"))
    incident = IncidentEvent.model_validate(raw_data)

    # Standard run: Diagnosed with score 0.95
    report_normal = DeterministicCorrelationEngine(incident, config=HiveMindConfig()).analyze()
    assert report_normal.status == AnalysisStatus.DIAGNOSED

    # Override threshold above candidate score (0.95 < 0.99)
    monkeypatch.setenv("HIVEMIND_DIAGNOSIS_SCORE_THRESHOLD", "0.99")
    config_overridden = HiveMindConfig()
    assert config_overridden.diagnosis_score_threshold == 0.99

    report_overridden = DeterministicCorrelationEngine(incident, config=config_overridden).analyze()
    assert report_overridden.status == AnalysisStatus.INCONCLUSIVE
    assert any("below the deterministic threshold (0.99)" in r for r in report_overridden.inconclusive_reasons)
    assert report_overridden.proposal is None


def test_config_immutability():
    """Verify HiveMindConfig and ScoringWeights are frozen models."""
    config = HiveMindConfig()
    with pytest.raises(ValidationError):
        config.diagnosis_score_threshold = 0.50  # type: ignore[misc]

    weights = ScoringWeights()
    with pytest.raises(ValidationError):
        weights.base_change_relevance = 0.50  # type: ignore[misc]
