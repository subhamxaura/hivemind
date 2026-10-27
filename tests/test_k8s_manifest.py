"""Unit tests for k8s_manifest module functions and edge cases."""

import pytest
import yaml
from yaml.constructor import ConstructorError

from hivemind.k8s_manifest import (
    _find_container,
    _get_memory_limit,
    _manifest_identity,
    _parse_manifest,
    _parse_memory_to_bytes,
    _resource_reference,
    _revision,
    _set_memory_limit,
    _valid_dns_name,
    _validate_deployment_structure,
)


def test_parse_memory_to_bytes_edge_cases():
    # 0 values
    assert _parse_memory_to_bytes(0) == 0
    assert _parse_memory_to_bytes("0") == 0
    assert _parse_memory_to_bytes("0Mi") == 0
    assert _parse_memory_to_bytes("0Gi") == 0

    # Booleans fail closed
    with pytest.raises(ValueError, match="Boolean values are not valid"):
        _parse_memory_to_bytes(True)
    with pytest.raises(ValueError, match="Boolean values are not valid"):
        _parse_memory_to_bytes(False)

    # Fractional strings fail closed
    with pytest.raises(ValueError, match="Invalid or unsupported"):
        _parse_memory_to_bytes("1.5Gi")
    with pytest.raises(ValueError, match="Invalid or unsupported"):
        _parse_memory_to_bytes("0.5Mi")
    with pytest.raises(ValueError, match="Invalid or unsupported"):
        _parse_memory_to_bytes("1e6")

    # Negative values fail closed
    with pytest.raises(ValueError, match="Invalid or unsupported"):
        _parse_memory_to_bytes("-128Mi")

    # All suffix types
    assert _parse_memory_to_bytes("1024") == 1024
    assert _parse_memory_to_bytes("100B") == 100
    assert _parse_memory_to_bytes("100b") == 100
    assert _parse_memory_to_bytes("2k") == 2_000
    assert _parse_memory_to_bytes("2K") == 2_000
    assert _parse_memory_to_bytes("3M") == 3_000_000
    assert _parse_memory_to_bytes("4G") == 4_000_000_000
    assert _parse_memory_to_bytes("5T") == 5_000_000_000_000
    assert _parse_memory_to_bytes("6P") == 6_000_000_000_000_000
    assert _parse_memory_to_bytes("7E") == 7_000_000_000_000_000_000
    assert _parse_memory_to_bytes("1Ki") == 1024
    assert _parse_memory_to_bytes("2Mi") == 2 * 1024**2
    assert _parse_memory_to_bytes("3Gi") == 3 * 1024**3
    assert _parse_memory_to_bytes("4Ti") == 4 * 1024**4
    assert _parse_memory_to_bytes("5Pi") == 5 * 1024**5
    assert _parse_memory_to_bytes("6Ei") == 6 * 1024**6


def test_valid_dns_name_edge_cases():
    # Empty string
    assert not _valid_dns_name("", allow_dots=True, max_length=253)
    assert not _valid_dns_name("", allow_dots=False, max_length=63)

    # 64-char label fails (max label length is 63)
    label_63 = "a" * 63
    label_64 = "a" * 64
    assert _valid_dns_name(label_63, allow_dots=False, max_length=63)
    assert not _valid_dns_name(label_64, allow_dots=False, max_length=63)
    assert not _valid_dns_name(label_64, allow_dots=True, max_length=253)

    # Max length boundary
    subdomain_253 = ".".join(["a" * 60, "b" * 60, "c" * 60, "d" * 70])  # d*70 fails label limit
    assert not _valid_dns_name(subdomain_253, allow_dots=True, max_length=253)
    valid_subdomain = ".".join(["a" * 60, "b" * 60, "c" * 60, "d" * 60])  # len = 243 <= 253
    assert _valid_dns_name(valid_subdomain, allow_dots=True, max_length=253)
    assert not _valid_dns_name(valid_subdomain, allow_dots=True, max_length=200)

    # Dots allowed vs disallowed
    dotted = "app.subdomain.internal"
    assert _valid_dns_name(dotted, allow_dots=True, max_length=253)
    assert not _valid_dns_name(dotted, allow_dots=False, max_length=63)

    # Hyphen edge cases and characters
    assert not _valid_dns_name("-invalid", allow_dots=False, max_length=63)
    assert not _valid_dns_name("invalid-", allow_dots=False, max_length=63)
    assert not _valid_dns_name("in_valid", allow_dots=False, max_length=63)
    assert not _valid_dns_name("UpperCase", allow_dots=False, max_length=63)
    assert _valid_dns_name("valid-name-123", allow_dots=False, max_length=63)


def test_manifest_identity_with_non_deployment_kinds():
    # Non-Deployment kinds
    daemonset = {
        "apiVersion": "apps/v1",
        "kind": "DaemonSet",
        "metadata": {"name": "agent", "namespace": "monitoring"},
    }
    assert _manifest_identity(daemonset) is None

    statefulset = {
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": {"name": "db", "namespace": "data"},
    }
    assert _manifest_identity(statefulset) is None

    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "standalone", "namespace": "default"},
    }
    assert _manifest_identity(pod) is None

    # Invalid metadata
    assert _manifest_identity({"apiVersion": "apps/v1", "kind": "Deployment"}) is None
    assert _manifest_identity({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": "bad"}) is None
    assert (
        _manifest_identity(
            {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "BAD_NAME", "namespace": "prod"}}
        )
        is None
    )

    # Valid deployment
    valid_deployment = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "web-service", "namespace": "production"},
    }
    assert _manifest_identity(valid_deployment) == ("production", "web-service")
    assert _resource_reference(valid_deployment) == "apps/v1:Deployment/production/web-service"


def test_validate_deployment_structure_with_missing_and_malformed_fields():
    # Non-dict manifest
    assert "Test must be a YAML mapping" in _validate_deployment_structure("not-a-dict", "Test")

    # Missing/wrong apiVersion & kind
    errors = _validate_deployment_structure({"apiVersion": "v1", "kind": "Service"}, "ServiceTest")
    assert any("must be an apps/v1 Deployment" in e for e in errors)

    # Metadata missing/malformed
    errors = _validate_deployment_structure(
        {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": ""}},
        "MetaTest",
    )
    assert any("name must be a non-empty string" in e for e in errors)
    assert any("namespace must be a non-empty string" in e for e in errors)

    # Spec missing
    errors = _validate_deployment_structure(
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "valid", "namespace": "valid"},
        },
        "SpecTest",
    )
    assert any("spec must be a mapping" in e for e in errors)

    # Selector matchLabels mismatch with template labels
    errors = _validate_deployment_structure(
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "app", "namespace": "default"},
            "spec": {
                "selector": {"matchLabels": {"app": "web"}},
                "template": {
                    "metadata": {"labels": {"app": "worker"}},
                    "spec": {"containers": [{"name": "c", "image": "img:v1"}]},
                },
            },
        },
        "MismatchTest",
    )
    assert any("labels must satisfy spec.selector.matchLabels" in e for e in errors)

    # Containers list empty or malformed
    errors = _validate_deployment_structure(
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "app", "namespace": "default"},
            "spec": {
                "selector": {"matchLabels": {"app": "web"}},
                "template": {
                    "metadata": {"labels": {"app": "web"}},
                    "spec": {"containers": []},
                },
            },
        },
        "EmptyContainers",
    )
    assert any("containers must be a non-empty list" in e for e in errors)


def test_find_container_with_duplicate_names():
    # Duplicate container names
    manifest = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "app", "namespace": "default"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {"name": "worker", "image": "worker:v1"},
                        {"name": "worker", "image": "worker:v2"},
                    ]
                }
            }
        },
    }
    # Duplicate container should fail closed (return None)
    assert _find_container(manifest, "worker") is None

    # Single match returns the container
    manifest["spec"]["template"]["spec"]["containers"][1]["name"] = "sidecar"
    found = _find_container(manifest, "worker")
    assert found is not None
    assert found["image"] == "worker:v1"

    # Non-existent container returns None
    assert _find_container(manifest, "non-existent") is None


def test_manifest_duplicate_keys_and_revision():
    # Duplicate keys in YAML rejected by _parse_manifest
    duplicate_yaml = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
  name: duplicate-app
  namespace: default
"""
    with pytest.raises((ConstructorError, yaml.YAMLError)):
        _parse_manifest(duplicate_yaml)

    # Revision extraction
    manifest_with_rev = {
        "metadata": {
            "annotations": {"hivemind.io/revision": "rev-42"}
        }
    }
    assert _revision(manifest_with_rev) == "rev-42"
    assert _revision({"metadata": {}}) is None

    # Memory limit getter and setter
    container = {"name": "c", "resources": {"limits": {"memory": "256Mi"}}}
    assert _get_memory_limit(container) == "256Mi"
    doc = {
        "spec": {
            "template": {
                "spec": {
                    "containers": [container]
                }
            }
        }
    }
    assert _set_memory_limit(doc, "c", "512Mi") is True
    assert _get_memory_limit(container) == "512Mi"
    assert _set_memory_limit(doc, "missing", "512Mi") is False
