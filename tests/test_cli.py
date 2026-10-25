"""Tests for HiveMind CLI commands, output formats, and exit codes."""

import json
from pathlib import Path

from click.testing import CliRunner

from hivemind.cli import main


def test_cli_analyze_diagnosable_text(tmp_path: Path):
    fixture_path = Path("fixtures/incident_diagnosable.yaml")
    runner = CliRunner()
    result = runner.invoke(main, ["analyze", str(fixture_path)])
    assert result.exit_code == 0
    assert "HIVEMIND INCIDENT INVESTIGATION REPORT (READ-ONLY MVP)" in result.output
    assert "READ-ONLY" in result.output
    assert "DIAGNOSED" in result.output
    assert "Faulty Change on payment-service" in result.output
    assert "REMEDIATION PROPOSAL" in result.output
    assert "Execution Status: NOT_APPLIED" in result.output
    assert "Generation      : GENERATED (GENERATED)" in result.output
    assert "Telemetry Evidence: 3 cited signal/log record(s)" in result.output
    assert "[SIGNAL:sig-001]" in result.output
    assert "[LOG:log-101]" in result.output
    assert "TELEMETRY WARNINGS & LIMITATIONS:" in result.output
    assert "payment-db" in result.output
    assert "INCONCLUSIVE AUDIT NOTES:" not in result.output
    assert "within configured policy bounds" in result.output


def test_cli_analyze_diagnosable_json(tmp_path: Path):
    fixture_path = Path("fixtures/incident_diagnosable.yaml")
    runner = CliRunner()
    result = runner.invoke(main, ["analyze", str(fixture_path), "--format", "json"])
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert parsed["incident_id"] == "inc-20261024-001"
    assert parsed["status"] == "DIAGNOSED"
    assert parsed["inconclusive_reasons"] == []
    assert len(parsed["telemetry_warnings"]) > 0
    assert any("payment-db" in w for w in parsed["telemetry_warnings"])
    assert parsed["proposal"]["status"] == "NOT_APPLIED"
    assert parsed["proposal_generation"]["status"] == "GENERATED"
    assert parsed["proposal_generation"]["telemetry_evidence_count"] == 3
    assert {item["record_id"] for item in parsed["proposal"]["evidence_references"]} >= {
        "sig-001",
        "log-101",
    }


def test_cli_analyze_inconclusive(tmp_path: Path):
    fixture_path = Path("fixtures/incident_inconclusive_missing_evidence.yaml")
    runner = CliRunner()
    result = runner.invoke(main, ["analyze", str(fixture_path)])
    assert result.exit_code == 0
    assert "INCONCLUSIVE" in result.output
    assert "INCONCLUSIVE AUDIT NOTES:" in result.output


def test_cli_invalid_yaml(tmp_path: Path):
    bad_file = tmp_path / "bad.yaml"
    bad_file.write_text("invalid_schema_content: true\n")
    runner = CliRunner()
    result = runner.invoke(main, ["analyze", str(bad_file)])
    assert result.exit_code == 1
    assert "Incident validation failed" in result.output


def test_cli_redacts_secret_in_malformed_file(tmp_path: Path):
    bad_file = tmp_path / "bad_secret.yaml"
    bad_file.write_text("broken_yaml: [unclosed password='my_super_secret_password_123'\n")
    runner = CliRunner()
    result = runner.invoke(main, ["analyze", str(bad_file)])
    assert result.exit_code == 1
    assert "my_super_secret_password_123" not in result.output
    assert "[REDACTED]" in result.output


def test_cli_missing_file():
    runner = CliRunner()
    result = runner.invoke(main, ["analyze", "non_existent_file.yaml"])
    assert result.exit_code != 0
