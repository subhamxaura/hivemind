"""Kubernetes manifest parsing, structure validation, and resource helpers."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode

REVISION_ANNOTATION = "hivemind.io/revision"


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys instead of hiding data."""


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader,
    node: MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _parse_memory_to_bytes(memory: Any) -> int:
    """Parse a conservative subset of Kubernetes memory quantities into exact bytes.

    Accepted suffixes are binary Ki/Mi/Gi/Ti/Pi/Ei, decimal k/K/M/G/T/P/E,
    and B/b. A suffix-free integer is interpreted as bytes. Unsupported,
    fractional, negative, boolean, or non-integral forms fail closed.
    """
    if isinstance(memory, bool):
        raise ValueError("Boolean values are not valid memory quantities")
    raw = str(memory).strip()
    match = re.fullmatch(r"(\d+)(Ki|Mi|Gi|Ti|Pi|Ei|k|K|M|G|T|P|E|B|b)?", raw)
    if not match:
        raise ValueError(f"Invalid or unsupported Kubernetes memory quantity: {memory!r}")

    value = int(match.group(1))
    suffix = match.group(2) or ""
    multipliers = {
        "": 1,
        "B": 1,
        "b": 1,
        "k": 1000,
        "K": 1000,
        "M": 1000**2,
        "G": 1000**3,
        "T": 1000**4,
        "P": 1000**5,
        "E": 1000**6,
        "Ki": 1024,
        "Mi": 1024**2,
        "Gi": 1024**3,
        "Ti": 1024**4,
        "Pi": 1024**5,
        "Ei": 1024**6,
    }
    return value * multipliers[suffix]


def _valid_dns_name(value: str, *, allow_dots: bool, max_length: int) -> bool:
    if not value or len(value) > max_length:
        return False
    labels = value.split(".") if allow_dots else [value]
    return all(
        0 < len(label) <= 63
        and re.fullmatch(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", label) is not None
        for label in labels
    )


def _manifest_identity(manifest: Mapping[str, Any]) -> tuple[str, str] | None:
    if manifest.get("apiVersion") != "apps/v1" or manifest.get("kind") != "Deployment":
        return None
    metadata = manifest.get("metadata")
    if not isinstance(metadata, Mapping):
        return None
    name = metadata.get("name")
    namespace = metadata.get("namespace")
    if not isinstance(name, str) or not _valid_dns_name(name, allow_dots=True, max_length=253):
        return None
    if not isinstance(namespace, str) or not _valid_dns_name(namespace, allow_dots=False, max_length=63):
        return None
    return namespace, name


def _resource_reference(manifest: Mapping[str, Any]) -> str | None:
    identity = _manifest_identity(manifest)
    if identity is None:
        return None
    namespace, name = identity
    return f"apps/v1:Deployment/{namespace}/{name}"


def _validate_deployment_structure(manifest: Any, label: str) -> list[str]:
    """Validate the Kubernetes Deployment fields this tool relies on."""
    problems: list[str] = []
    if not isinstance(manifest, dict):
        return [f"{label} must be a YAML mapping"]
    if manifest.get("apiVersion") != "apps/v1" or manifest.get("kind") != "Deployment":
        problems.append(f"{label} must be an apps/v1 Deployment")

    metadata = manifest.get("metadata")
    if not isinstance(metadata, dict):
        problems.append(f"{label}.metadata must be a mapping")
    else:
        for field in ("name", "namespace"):
            value = metadata.get(field)
            if not isinstance(value, str) or not value.strip():
                problems.append(f"{label}.metadata.{field} must be a non-empty string")
            elif field == "name" and not _valid_dns_name(value, allow_dots=True, max_length=253):
                problems.append(f"{label}.metadata.name must be a valid Kubernetes DNS subdomain")
            elif field == "namespace" and not _valid_dns_name(value, allow_dots=False, max_length=63):
                problems.append(f"{label}.metadata.namespace must be a valid Kubernetes DNS label")

    spec = manifest.get("spec")
    if not isinstance(spec, dict):
        problems.append(f"{label}.spec must be a mapping")
        return problems

    selector = spec.get("selector")
    match_labels = selector.get("matchLabels") if isinstance(selector, dict) else None
    if not isinstance(match_labels, dict) or not match_labels:
        problems.append(f"{label}.spec.selector.matchLabels must be a non-empty mapping")

    template = spec.get("template")
    if not isinstance(template, dict):
        problems.append(f"{label}.spec.template must be a mapping")
        return problems
    template_metadata = template.get("metadata")
    labels = template_metadata.get("labels") if isinstance(template_metadata, dict) else None
    if not isinstance(labels, dict):
        problems.append(f"{label}.spec.template.metadata.labels must be a mapping")
    elif isinstance(match_labels, dict) and any(labels.get(k) != v for k, v in match_labels.items()):
        problems.append(f"{label}.spec.template labels must satisfy spec.selector.matchLabels")

    pod_spec = template.get("spec")
    if not isinstance(pod_spec, dict):
        problems.append(f"{label}.spec.template.spec must be a mapping")
        return problems
    containers = pod_spec.get("containers")
    if not isinstance(containers, list) or not containers:
        problems.append(f"{label}.spec.template.spec.containers must be a non-empty list")
        return problems

    names: list[str] = []
    for index, container in enumerate(containers):
        if not isinstance(container, dict):
            problems.append(f"{label} container at index {index} must be a mapping")
            continue
        name = container.get("name")
        if not isinstance(name, str) or not name.strip():
            problems.append(f"{label} container at index {index} must have a non-empty name")
        else:
            names.append(name)
        image = container.get("image")
        if not isinstance(image, str) or not image.strip():
            problems.append(f"{label} container at index {index} must have a non-empty image")
    if len(names) != len(set(names)):
        problems.append(f"{label} container names must be unique")
    return problems


def _find_container(manifest: Mapping[str, Any], container_name: str) -> dict[str, Any] | None:
    spec = manifest.get("spec")
    template = spec.get("template") if isinstance(spec, dict) else None
    pod_spec = template.get("spec") if isinstance(template, dict) else None
    containers = pod_spec.get("containers") if isinstance(pod_spec, dict) else None
    if not isinstance(containers, list):
        return None
    matches = [
        container
        for container in containers
        if isinstance(container, dict) and container.get("name") == container_name
    ]
    return matches[0] if len(matches) == 1 else None


def _get_memory_limit(container: Mapping[str, Any]) -> Any:
    resources = container.get("resources")
    limits = resources.get("limits") if isinstance(resources, dict) else None
    return limits.get("memory") if isinstance(limits, dict) else None


def _set_memory_limit(manifest: dict[str, Any], container_name: str, value: Any) -> bool:
    container = _find_container(manifest, container_name)
    if container is None:
        return False
    resources = container.get("resources")
    if resources is None:
        resources = {}
        container["resources"] = resources
    if not isinstance(resources, dict):
        return False
    limits = resources.get("limits")
    if limits is None:
        limits = {}
        resources["limits"] = limits
    if not isinstance(limits, dict):
        return False
    limits["memory"] = value
    return True


def _parse_manifest(text: str) -> dict[str, Any]:
    loaded = yaml.load(text, Loader=_UniqueKeySafeLoader)
    if not isinstance(loaded, dict):
        raise ValueError("manifest must be a YAML mapping")
    return loaded


def _revision(manifest: Mapping[str, Any]) -> str | None:
    metadata = manifest.get("metadata")
    annotations = metadata.get("annotations") if isinstance(metadata, dict) else None
    value = annotations.get(REVISION_ANNOTATION) if isinstance(annotations, dict) else None
    return value.strip() if isinstance(value, str) and value.strip() else None
