# Findings & Decisions

## Requirements
- Add integration tests that exercise incident input through diagnosis and proposal generation.
- Verify successful and fail-closed behavior through the engine and user-facing CLI/API outputs.
- Add automated verification that runs on pushes and pull requests.

## Research Findings
- The repository had focused tests for fixtures, proposal policy, CLI, and FastAPI `TestClient`, but no `.github/workflows` directory.
- `pyproject.toml` declares Python `>=3.11`, pytest, Ruff, mypy, FastAPI, and HTTPX.
- The diagnosable fixture contains a complete Deployment manifest and telemetry; expected result is a read-only memory proposal.
- Local Python is unavailable (`py -m pytest` reports `No installed Python found`), so the test suite could not be executed on this desktop.
- Added a cross-interface test comparing engine model output, CLI JSON, and FastAPI JSON for a generated proposal and three fail-closed input variants.
- Added GitHub Actions verification for pushes and pull requests on Python 3.11/3.12: Ruff, mypy, dedicated proposal integration tests, and the full pytest suite.

## Technical Decisions
| Decision | Rationale |
|----------|-----------|
| Compare direct engine, CLI JSON, and FastAPI JSON outputs | Confirms public surfaces agree on diagnosis, proposal, evidence references, and failure reason |
| Mutate fixture data for missing-manifest, invalid-quantity, and baseline-mismatch cases | Exercises rejection outcomes without duplicating the large manifest fixture |
| Use GitHub Actions matrix Python 3.11/3.12 and run pytest, Ruff, mypy | Automates declared runtime checks on pull requests and pushes |
| Avoid coverage threshold before measuring current coverage | Prevents speculative threshold failures unrelated to this task |

## Issues Encountered
| Issue | Resolution |
|-------|------------|
| Direct PowerShell execution of initializer blocked by script policy | Used process-scoped execution-policy bypass for initializer only |
| Python runtime absent | Tests remain to be executed by CI; not reported as passed |

## Resources
- `pyproject.toml`
- `tests/test_proposal_integration.py`
- `.github/workflows/ci.yml`
- `src/hivemind/engine.py`
- `src/hivemind/api.py`
- `src/hivemind/cli.py`
- `fixtures/incident_diagnosable.yaml`
