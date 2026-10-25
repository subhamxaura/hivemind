"""Cross-interface integration tests for the complete proposal-engine flow."""

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
import yaml
from click.testing import CliRunner
from fastapi.testclient import TestClient

from hivemind.api import app
from hivemind.cli import main
from hivemind.engine import DeterministicCorrelationEngine
from hivemind.models import IncidentEvent

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DIAGNOSABLE_FIXTURE = PROJECT_ROOT / "fixtures" / "incident_diagnosable.yaml"


def load_diagnosable_fixture() -> dict[str, Any]:
    data = yaml.safe_load(DIAGNOSABLE_FIXTURE.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def run_across_interfaces(
    incident_data: dict[str, Any],
    tmp_path: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    incident = IncidentEvent.model_validate(incident_data)
    engine_report = DeterministicCorrelationEngine(incident).analyze()
    expected = engine_report.model_dump(mode="json")

    incident_file = tmp_path / "incident.yaml"
    incident_file.write_text(
        yaml.safe_dump(incident_data, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    cli_result = CliRunner().invoke(main, ["analyze", str(incident_file), "--format", "json"])
    assert cli_result.exit_code == 0, cli_result.output
    cli_report = json.loads(cli_result.output)

    api_response = TestClient(app).post("/analyze", json=incident_data)
    assert api_response.status_code == 200, api_response.text
    api_report = api_response.json()
    return expected, cli_report, api_report


def test_proposal_success_is_consistent_across_engine_cli_and_api(tmp_path: Path):
    incident_data = load_diagnosable_fixture()
    source_manifest = deepcopy(incident_data["changes"][0]["details"]["current_manifest"])

    engine_report, cli_report, api_report = run_across_interfaces(incident_data, tmp_path)

    assert engine_report == cli_report == api_report
    assert engine_report["status"] == "DIAGNOSED"
    assert engine_report["proposal_generation"]["status"] == "GENERATED"
    assert engine_report["proposal_generation"]["reason_code"] == "GENERATED"
    assert engine_report["proposal_generation"]["telemetry_evidence_count"] == 3

    proposal = engine_report["proposal"]
    assert proposal is not None
    assert proposal["operation"] == "ADJUST_RESOURCE_LIMITS"
    assert proposal["target_resource"] == "apps/v1:Deployment/production/payment-service"
    assert proposal["status"] == "NOT_APPLIED"
    assert proposal["all_policy_checks_passed"] is True
    assert all(check["passed"] for check in proposal["policy_checks"])
    assert yaml.safe_load(proposal["before_manifest"]) == source_manifest

    expected_after = deepcopy(source_manifest)
    expected_after["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["memory"] = "512Mi"
    assert yaml.safe_load(proposal["after_manifest"]) == expected_after
    evidence_ids = {reference["record_id"] for reference in proposal["evidence_references"]}
    assert {"chg-901", "sig-001", "sig-002", "log-101"} <= evidence_ids


@pytest.mark.parametrize(
    ("defect", "expected_reason"),
    [
        ("missing_manifest", "SOURCE_MANIFEST_MISSING"),
        ("invalid_quantity", "MEMORY_QUANTITY_INVALID"),
        ("baseline_mismatch", "MEMORY_BASELINE_MISMATCH"),
    ],
)
def test_invalid_proposal_inputs_fail_closed_consistently_across_interfaces(
    defect: str,
    expected_reason: str,
    tmp_path: Path,
):
    incident_data = load_diagnosable_fixture()
    details = incident_data["changes"][0]["details"]
    if defect == "missing_manifest":
        details.pop("current_manifest")
    elif defect == "invalid_quantity":
        details["previous_memory_limit"] = "not-a-kubernetes-quantity"
    elif defect == "baseline_mismatch":
        details["memory_limit"] = "128Mi"
    else:
        raise AssertionError(f"Unrecognized integration-test defect: {defect}")

    engine_report, cli_report, api_report = run_across_interfaces(incident_data, tmp_path)

    assert engine_report == cli_report == api_report
    assert engine_report["status"] == "DIAGNOSED"
    assert engine_report["proposal"] is None
    assert engine_report["proposal_generation"]["status"] == "NOT_GENERATED"
    assert engine_report["proposal_generation"]["reason_code"] == expected_reason
