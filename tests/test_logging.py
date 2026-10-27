"""Tests for structured JSON logging configuration and output."""

import io
import json
from pathlib import Path

import yaml
from click.testing import CliRunner

from hivemind.cli import main
from hivemind.engine import DeterministicCorrelationEngine
from hivemind.logging_config import setup_logging
from hivemind.models import IncidentEvent

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DIAGNOSABLE_FIXTURE = PROJECT_ROOT / "fixtures" / "incident_diagnosable.yaml"


def test_structured_json_logging_for_proposal_generation():
    """Verify JSON log line from a proposal-generation event contains expected keys."""
    log_stream = io.StringIO()
    setup_logging(log_format="json", stream=log_stream)

    raw_data = yaml.safe_load(DIAGNOSABLE_FIXTURE.read_text(encoding="utf-8"))
    incident = IncidentEvent.model_validate(raw_data)
    engine = DeterministicCorrelationEngine(incident)
    report = engine.analyze()
    assert report.proposal is not None

    log_output = log_stream.getvalue().strip()
    assert log_output, "Expected structured JSON log lines"

    lines = [json.loads(line) for line in log_output.splitlines() if line.strip()]
    proposal_log = next(
        (entry for entry in lines if entry.get("message") == "Proposal generation completed"),
        None,
    )

    assert proposal_log is not None, f"Could not find proposal generation log entry in: {lines}"
    assert "timestamp" in proposal_log
    assert proposal_log["level"] == "INFO"
    assert proposal_log["logger"] == "hivemind.proposal"
    assert proposal_log["proposal_status"] == "GENERATED"
    assert proposal_log["proposal_reason_code"] == "GENERATED"
    assert proposal_log["proposal_telemetry_evidence_count"] == 3
    assert proposal_log["proposal_failed_policy_check_count"] == 0


def test_cli_accepts_log_format_option():
    """Verify CLI accepts --log-format json and --log-format plain."""
    runner = CliRunner()
    result_plain = runner.invoke(main, ["--log-format", "plain", "analyze", str(DIAGNOSABLE_FIXTURE)])
    assert result_plain.exit_code == 0

    result_json = runner.invoke(main, ["--log-format", "json", "analyze", str(DIAGNOSABLE_FIXTURE)])
    assert result_json.exit_code == 0
