"""Local REST API for HiveMind incident investigation.

Provides read-only inspection endpoints:
- GET /healthz (liveness)
- GET /readyz (readiness)
- GET /metrics (trusted internal networks only)
- POST /analyze

Strictly read-only: No mutation endpoints, cluster connections, or credentials.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from time import perf_counter
from typing import Any

import yaml
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from pydantic import ValidationError
from starlette.middleware.base import RequestResponseEndpoint

from hivemind import __version__
from hivemind.config import HiveMindConfig
from hivemind.engine import DeterministicCorrelationEngine
from hivemind.logging_config import setup_logging
from hivemind.models import CURRENT_SCHEMA_VERSION, IncidentAnalysisReport, IncidentEvent
from hivemind.redaction import redact_secrets

api_config = HiveMindConfig()
MAX_REQUEST_BODY_BYTES = api_config.max_request_body_bytes
MAX_YAML_DEPTH = api_config.max_yaml_depth
MAX_YAML_KEYS = api_config.max_yaml_keys
ANALYSIS_CONCURRENCY = api_config.analysis_concurrency

analysis_semaphore = asyncio.Semaphore(ANALYSIS_CONCURRENCY)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Configure structured JSON logging and load configuration on API startup."""
    global api_config, analysis_semaphore, MAX_REQUEST_BODY_BYTES, MAX_YAML_DEPTH, MAX_YAML_KEYS, ANALYSIS_CONCURRENCY
    api_config = HiveMindConfig()
    MAX_REQUEST_BODY_BYTES = api_config.max_request_body_bytes
    MAX_YAML_DEPTH = api_config.max_yaml_depth
    MAX_YAML_KEYS = api_config.max_yaml_keys
    ANALYSIS_CONCURRENCY = api_config.analysis_concurrency
    analysis_semaphore = asyncio.Semaphore(ANALYSIS_CONCURRENCY)
    setup_logging(log_format="json")
    yield


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
    lifespan=lifespan,
)


def _check_yaml_depth_and_keys(
    data: Any,
    max_depth: int = MAX_YAML_DEPTH,
    max_keys: int = MAX_YAML_KEYS,
) -> None:
    """Recursively validate that YAML data does not exceed nesting depth or key limits."""
    total_keys = 0

    def _traverse(node: Any, depth: int) -> None:
        nonlocal total_keys
        if depth > max_depth:
            raise ValueError(f"YAML nesting depth exceeds maximum allowed depth of {max_depth}.")

        if isinstance(node, dict):
            total_keys += len(node)
            if total_keys > max_keys:
                raise ValueError(f"YAML total key count across mappings exceeds maximum allowed keys of {max_keys}.")
            for key, val in node.items():
                if isinstance(key, (dict, list)):
                    _traverse(key, depth + 1)
                if isinstance(val, (dict, list)):
                    _traverse(val, depth + 1)
        elif isinstance(node, list):
            for item in node:
                if isinstance(item, (dict, list)):
                    _traverse(item, depth + 1)

    if isinstance(data, (dict, list)):
        _traverse(data, 1)


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
        400: {"description": "Malformed JSON or YAML input, excessive depth, or key count"},
        413: {"description": "Payload exceeds maximum allowed size"},
        422: {"description": "Validation failure against strict IncidentEvent schema"},
        503: {"description": "Concurrency limit reached; service temporarily unavailable"},
    },
)
async def analyze_incident(request: Request) -> IncidentAnalysisReport:
    """Accepts an incident payload (JSON or YAML) and returns deterministic correlation findings."""
    body_bytes = await request.body()
    if len(body_bytes) > api_config.max_request_body_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"Request body exceeds maximum size of {api_config.max_request_body_bytes} bytes.",
        )
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

    try:
        _check_yaml_depth_and_keys(
            parsed_data,
            max_depth=api_config.max_yaml_depth,
            max_keys=api_config.max_yaml_keys,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
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

    engine = DeterministicCorrelationEngine(incident, config=api_config)
    try:
        await asyncio.wait_for(analysis_semaphore.acquire(), timeout=0.1)
    except (asyncio.TimeoutError, TimeoutError):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Analysis service busy. Concurrency limit reached.",
            headers={"Retry-After": "1"},
        )
    try:
        report = engine.analyze()
    finally:
        analysis_semaphore.release()

    PROPOSAL_GENERATION.labels(
        status=report.proposal_generation.status.value,
        reason_code=report.proposal_generation.reason_code.value,
    ).inc()
    return report
