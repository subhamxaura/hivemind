"""Local REST API for HiveMind incident investigation.

Provides read-only inspection endpoints:
- GET /healthz (liveness)
- GET /readyz (readiness)
- GET /metrics (trusted internal networks only)
- POST /analyze

Strictly read-only: No mutation endpoints, cluster connections, or credentials.
"""

from time import perf_counter
from typing import Any

import yaml
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from pydantic import ValidationError
from starlette.middleware.base import RequestResponseEndpoint

from hivemind import __version__
from hivemind.engine import DeterministicCorrelationEngine
from hivemind.models import CURRENT_SCHEMA_VERSION, IncidentAnalysisReport, IncidentEvent
from hivemind.redaction import redact_secrets

HTTP_REQUESTS = Counter(
    "hivemind_http_requests",
    "HTTP requests handled by HiveMind, excluding metric scrapes.",
    ("method", "path", "status_code"),
)
HTTP_REQUEST_DURATION = Histogram(
    "hivemind_http_request_duration_seconds",
    "HTTP request duration in seconds, excluding metric scrapes.",
    ("method", "path"),
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)
PROPOSAL_GENERATION = Counter(
    "hivemind_proposal_generation",
    "Proposal generation outcomes by bounded status and reason code.",
    ("status", "reason_code"),
)
_KNOWN_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"})
_KNOWN_PATHS = frozenset({"/healthz", "/readyz", "/analyze"})

app = FastAPI(
    title="HiveMind Incident Investigation API",
    description=(
        "Safety-first, read-only incident investigation and remediation proposal tool. "
        "Strictly operates offline without cluster mutation capabilities."
    ),
    version=__version__,
)


@app.middleware("http")
async def observe_http_request(
    request: Request,
    call_next: RequestResponseEndpoint,
) -> Response:
    """Record bounded request metrics without labels derived from incident input."""
    if request.url.path == "/metrics":
        return await call_next(request)

    method = request.method if request.method in _KNOWN_METHODS else "OTHER"
    path = request.url.path if request.url.path in _KNOWN_PATHS else "unmatched"
    started_at = perf_counter()
    response_status = 500
    try:
        response = await call_next(request)
        response_status = response.status_code
        return response
    finally:
        labels = {"method": method, "path": path}
        HTTP_REQUESTS.labels(**labels, status_code=str(response_status)).inc()
        HTTP_REQUEST_DURATION.labels(**labels).observe(perf_counter() - started_at)


@app.get("/healthz", summary="Liveness Health Probe")
def healthz() -> dict[str, Any]:
    """Health check endpoint confirming service status and read-only operation."""
    return {
        "status": "ok",
        "read_only": True,
        "mutation_enabled": False,
        "version": __version__,
        "supported_schema_version": CURRENT_SCHEMA_VERSION,
    }


@app.get("/readyz", summary="Readiness Probe")
def readyz() -> dict[str, bool | str]:
    """Report readiness; the API is stateless and has no external dependency checks."""
    return {"status": "ready", "ready": True, "read_only": True}


@app.get("/metrics", include_in_schema=False)
def metrics() -> Response:
    """Expose Prometheus metrics; keep this endpoint on a trusted internal network."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


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
        safe_msg = redact_secrets(str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unable to parse request body as valid JSON/YAML: {safe_msg}",
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
            {"field": " -> ".join(str(p) for p in err["loc"]), "message": redact_secrets(err["msg"])}
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
    PROPOSAL_GENERATION.labels(
        status=report.proposal_generation.status.value,
        reason_code=report.proposal_generation.reason_code.value,
    ).inc()
    return report
