"""Tests for HiveMind FastAPI application and read-only endpoints."""

import sys

from fastapi.testclient import TestClient

from hivemind.api import app

client = TestClient(app)


def test_healthz_endpoint():
    response = client.get("/healthz")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["read_only"] is True
    assert data["mutation_enabled"] is False


def test_analyze_endpoint_success():
    with open("fixtures/incident_diagnosable.yaml", "r", encoding="utf-8") as f:
        fixture_content = f.read()

    response = client.post(
        "/analyze",
        content=fixture_content,
        headers={"Content-Type": "application/x-yaml"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["incident_id"] == "inc-20261024-001"
    assert data["status"] == "DIAGNOSED"
    assert data["proposal"]["status"] == "NOT_APPLIED"
    assert "READ-ONLY" in data["safety_notice"]


def test_analyze_endpoint_validation_failure():
    bad_payload = {"schema_version": "invalid.version"}
    response = client.post(
        "/analyze",
        json=bad_payload,
    )
    assert response.status_code == 422
    data = response.json()
    assert "error" in data
    assert "schema validation failed" in data["error"]


def test_no_mutating_routes_exist():
    """Verify strictly that no mutation routes (PUT, DELETE, PATCH, or apply/execute) exist."""
    disallowed_paths = ["apply", "mutate", "execute", "rollback", "deploy", "patch"]
    for route in app.routes:
        methods = getattr(route, "methods", set())
        path = getattr(route, "path", "")
        # Disallow non-read-only HTTP methods
        assert "PUT" not in methods
        assert "DELETE" not in methods
        assert "PATCH" not in methods
        # Disallow any path containing mutating verbs
        for bad_word in disallowed_paths:
            assert bad_word not in path.lower()


def test_no_cluster_client_imported():
    """Verify that no active Kubernetes cluster clients or cloud SDKs are loaded in memory."""
    loaded_modules = sys.modules.keys()
    disallowed_clients = [
        "kubernetes.client",
        "pykube",
        "boto3",
        "google.cloud.container",
        "azure.mgmt.containerservice",
    ]
    for client_name in disallowed_clients:
        assert client_name not in loaded_modules
