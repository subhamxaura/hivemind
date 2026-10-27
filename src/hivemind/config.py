"""Global configuration for HiveMind investigation engine and API."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict
from pydantic_settings import BaseSettings, SettingsConfigDict


class ScoringWeights(BaseModel):
    """Scoring weights and bonuses/penalties for deterministic correlation."""

    model_config = ConfigDict(frozen=True)

    base_change_relevance: float = 0.40
    temporal_proximity_15m: float = 0.20
    temporal_proximity_30m: float = 0.10
    signature_match: float = 0.25
    log_corroboration: float = 0.10
    base_dependency_signal: float = 0.35
    critical_dependency_weight: float = 0.25
    temporal_precedence: float = 0.20
    client_log_correlation: float = 0.10
    temporal_violation_penalty: float = -0.40
    healthy_contradiction_penalty: float = -0.35


class HiveMindConfig(BaseSettings):
    """Global configuration for HiveMind investigation engine and API."""

    model_config = SettingsConfigDict(
        frozen=True,
        env_prefix="HIVEMIND_",
        env_nested_delimiter="__",
    )

    diagnosis_score_threshold: float = 0.60
    competitive_margin_threshold: float = 0.15
    scoring: ScoringWeights = ScoringWeights()
    max_request_body_bytes: int = 1_048_576
    max_yaml_depth: int = 20
    max_yaml_keys: int = 10_000
    analysis_concurrency: int = 4
