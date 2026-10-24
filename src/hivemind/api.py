"""Local REST API for HiveMind incident investigation.

Provides read-only inspection endpoints:
- GET /healthz
- POST /analyze

Strictly read-only: No mutation endpoints, cluster connections, or credentials.
"""

from typing import Any

import yaml
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from hivemind import __version__
from hivemind.engine import DeterministicCorrelationEngine
from hivemind.models import CURRENT_SCHEMA_VERSION, IncidentAnalysisReport, IncidentEvent

app = FastAPI(
    title="HiveMind Incident Investigation API",
    description=(
        "Safety-first, read-only incident investigation and remediation proposal tool. "
        "Strictly operates offline without cluster mutation capabilities."
    ),
    version=__version__,
)


@app.get("/healthz", summary="Liveness & Readiness Health Probe")
def healthz() -> dict[str, Any]:
    """Health check endpoint confirming service status and read-only operation."""
    return {
        "status": "ok",
        "read_only": True,
        "mutation_enabled": False,
        "version": __version__,
        "supported_schema_version": CURRENT_SCHEMA_VERSION,
    }


@app.post(
    "/analyze",
    response_model=IncidentAnalysisReport,
    summary="Analyze Incident Telemetry",
    responses={
        400: {"description": "Malformed JSON or YAML input"},
        422: {"description": "Validation failure against strict IncidentEvent schema"},
    },
)
async def analyze_incident(request: Request) -> IncidentAnalysisReport:
    """Accepts an incident payload (JSON or YAML) and returns deterministic correlation findings."""
    body_bytes = await request.body()
    if not body_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request body is empty. Expected JSON or YAML incident payload.",
        )

    # Attempt parsing as JSON first, then YAML
    try:
        raw_text = body_bytes.decode("utf-8")
        parsed_data = yaml.safe_load(raw_text)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unable to parse request body as valid JSON/YAML: {e}",
        )

    if not isinstance(parsed_data, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Incident document must be a top-level mapping, received {type(parsed_data).__name__}.",
        )

    try:
        incident = IncidentEvent.model_validate(parsed_data)
    except ValidationError as ve:
        # Non-sensitive error formatting
        error_details = [
            {"field": " -> ".join(str(p) for p in err["loc"]), "message": err["msg"]}
            for err in ve.errors()
        ]
        return JSONResponse(
            status_code=422,
            content={
                "error": "Incident schema validation failed",
                "details": error_details,
            },
        )  # type: ignore[return-value]

    engine = DeterministicCorrelationEngine(incident)
    report = engine.analyze()
    return report
