"""Kubernetes pod specification security inspection and guardrails."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def _security_violations(manifest: Mapping[str, Any]) -> list[str]:
    violations: list[str] = []
    spec = manifest.get("spec")
    template = spec.get("template") if isinstance(spec, dict) else None
    pod_spec = template.get("spec") if isinstance(template, dict) else None
    if not isinstance(pod_spec, dict):
        return ["Deployment pod spec is not a mapping"]

    for field in ("hostNetwork", "hostPID", "hostIPC"):
        if pod_spec.get(field) is True:
            violations.append(f"pod spec {field}: true")

    volumes = pod_spec.get("volumes", [])
    if not isinstance(volumes, list):
        violations.append("pod spec volumes must be a list")
    else:
        for index, volume in enumerate(volumes):
            if isinstance(volume, dict) and "hostPath" in volume:
                violations.append(f"pod volume at index {index} uses hostPath")

    for collection_name in ("containers", "initContainers", "ephemeralContainers"):
        containers = pod_spec.get(collection_name, [])
        if not isinstance(containers, list):
            violations.append(f"pod spec {collection_name} must be a list")
            continue
        for index, container in enumerate(containers):
            if not isinstance(container, dict):
                continue
            security_context = container.get("securityContext", {})
            if not isinstance(security_context, dict):
                violations.append(f"{collection_name}[{index}].securityContext must be a mapping")
                continue
            if security_context.get("privileged") is True:
                violations.append(f"{collection_name}[{index}] sets privileged: true")
            if security_context.get("allowPrivilegeEscalation") is True:
                violations.append(f"{collection_name}[{index}] sets allowPrivilegeEscalation: true")
            capabilities = security_context.get("capabilities", {})
            if isinstance(capabilities, dict):
                added = capabilities.get("add", [])
                if not isinstance(added, list):
                    violations.append(f"{collection_name}[{index}] capabilities.add must be a list")
                elif any(str(cap).upper() in {"SYS_ADMIN", "ALL"} for cap in added):
                    violations.append(f"{collection_name}[{index}] adds SYS_ADMIN or ALL capabilities")
    return violations
