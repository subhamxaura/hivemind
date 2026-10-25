"""Structural validation for shipped container, monitoring, and Kubernetes configs."""

import json
import tomllib
from pathlib import Path
from typing import Any

import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _yaml_documents(relative_path: str) -> list[Any]:
    source = REPOSITORY_ROOT / relative_path
    return list(yaml.safe_load_all(source.read_text(encoding="utf-8")))


def _project_version() -> str:
    pyproject_path = REPOSITORY_ROOT / "pyproject.toml"
    data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def test_deployment_yaml_files_parse() -> None:
    yaml_paths = [
        ".github/workflows/ci.yml",
        ".github/workflows/release.yml",
        ".github/dependabot.yml",
        "deploy/compose.yaml",
        "deploy/prometheus/prometheus.yml",
        "deploy/prometheus/alerts.yml",
        "deploy/grafana/provisioning/datasources/prometheus.yaml",
        "deploy/grafana/provisioning/dashboards/hivemind.yaml",
        "deploy/kubernetes/hivemind.yaml",
        "deploy/kubernetes/networkpolicy.yaml",
        "deploy/kubernetes/servicemonitor.yaml",
        "deploy/kubernetes/prometheusrule.yaml",
    ]
    for relative_path in yaml_paths:
        documents = _yaml_documents(relative_path)
        assert documents, relative_path
        assert all(document is not None for document in documents), relative_path


def test_workflow_permissions_and_least_privilege() -> None:
    ci_workflow = _yaml_documents(".github/workflows/ci.yml")[0]
    assert isinstance(ci_workflow, dict)
    assert ci_workflow["permissions"] == {"contents": "read"}
    ci_triggers = ci_workflow.get("on") or ci_workflow.get(True)
    assert isinstance(ci_triggers, dict)
    assert ci_triggers["push"]["branches"] == ["main"]
    assert ci_triggers["pull_request"]["branches"] == ["main"]

    for job_name, job_data in ci_workflow.get("jobs", {}).items():
        assert job_data.get("permissions", {}).get("packages") != "write", f"Job {job_name} has packages: write"

    release_workflow = _yaml_documents(".github/workflows/release.yml")[0]
    assert isinstance(release_workflow, dict)
    assert release_workflow["permissions"] == {"contents": "read"}
    release_triggers = release_workflow.get("on") or release_workflow.get(True)
    assert isinstance(release_triggers, dict)
    assert "push" in release_triggers
    assert any("tags" in str(k) for k in release_triggers["push"])
    assert "workflow_dispatch" in release_triggers

    jobs = release_workflow["jobs"]
    assert "verify-release" in jobs
    assert (
        jobs["verify-release"].get("permissions") is None
        or "packages" not in jobs["verify-release"].get("permissions", {})
    )
    assert "publish-release" in jobs
    assert jobs["publish-release"]["permissions"]["packages"] == "write"
    assert jobs["publish-release"]["permissions"]["contents"] == "read"


def test_compose_keeps_services_loopback_bound_and_requires_a_grafana_secret() -> None:
    compose = _yaml_documents("deploy/compose.yaml")[0]
    assert isinstance(compose, dict)
    services = compose["services"]
    version = _project_version()
    assert services["api"]["image"] == f"hivemind:{version}"
    assert services["api"]["ports"] == ["127.0.0.1:8000:8000"]
    assert services["prometheus"]["ports"] == ["127.0.0.1:9090:9090"]
    assert services["grafana"]["ports"] == ["127.0.0.1:3000:3000"]
    assert "${GRAFANA_ADMIN_PASSWORD:?Set GRAFANA_ADMIN_PASSWORD in deploy/.env}" == services[
        "grafana"
    ]["environment"]["GF_SECURITY_ADMIN_PASSWORD"]
    assert services["api"]["read_only"] is True
    assert "ALL" in services["api"]["cap_drop"]
    assert compose["networks"]["monitoring"]["internal"] is False


def test_kubernetes_workload_is_internal_and_hardened() -> None:
    documents = [doc for doc in _yaml_documents("deploy/kubernetes/hivemind.yaml") if doc]
    namespace = next(doc for doc in documents if doc["kind"] == "Namespace")
    deployment = next(doc for doc in documents if doc["kind"] == "Deployment")
    service = next(doc for doc in documents if doc["kind"] == "Service")
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    version = _project_version()

    ns_labels = namespace["metadata"]["labels"]
    assert ns_labels.get("pod-security.kubernetes.io/enforce") == "restricted"
    assert ns_labels.get("pod-security.kubernetes.io/audit") == "restricted"
    assert ns_labels.get("pod-security.kubernetes.io/warn") == "restricted"

    assert deployment["metadata"]["labels"]["app.kubernetes.io/version"] == version
    assert container["image"] == f"ghcr.io/subhamxaura/hivemind:{version}"
    assert deployment["spec"]["replicas"] == 2
    assert deployment["spec"]["template"]["spec"]["automountServiceAccountToken"] is False
    assert deployment["spec"]["template"]["spec"]["securityContext"]["runAsNonRoot"] is True
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["securityContext"]["allowPrivilegeEscalation"] is False
    assert container["readinessProbe"]["httpGet"]["path"] == "/readyz"
    assert container["livenessProbe"]["httpGet"]["path"] == "/healthz"
    assert service["spec"]["type"] == "ClusterIP"


def test_optional_network_policy_restricts_ingress_and_denies_egress() -> None:
    policy = _yaml_documents("deploy/kubernetes/networkpolicy.yaml")[0]
    assert policy["spec"]["policyTypes"] == ["Ingress", "Egress"]
    assert policy["spec"]["egress"] == []
    assert policy["spec"]["ingress"][0]["ports"][0]["port"] == 8000


def test_prometheus_and_grafana_configs_reference_shipped_metrics() -> None:
    prometheus = _yaml_documents("deploy/prometheus/prometheus.yml")[0]
    assert prometheus["scrape_configs"][1]["static_configs"][0]["targets"] == ["api:8000"]
    dashboard_path = REPOSITORY_ROOT / "deploy/grafana/dashboards/hivemind-overview.json"
    dashboard = json.loads(dashboard_path.read_text(encoding="utf-8"))
    assert dashboard["uid"] == "hivemind-ops"
    assert dashboard["panels"]
    assert all(panel["datasource"]["uid"] == "PROMETHEUS" for panel in dashboard["panels"])
    assert any("hivemind_proposal_generation_total" in panel["targets"][0]["expr"] for panel in dashboard["panels"])
