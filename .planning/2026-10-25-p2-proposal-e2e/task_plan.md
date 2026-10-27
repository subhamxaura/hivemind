# Task Plan: P2 Proposal End-to-End Verification

## Goal
Add end-to-end proposal-engine tests and a repeatable CI workflow that verifies supported Python versions.

## Next Step
Complete final static review and deliver the integration-test and CI changes with the local test limitation disclosed.

## Current Phase
Phase 4: Delivery

## Phases

### Phase 1: Requirements & Discovery
- [x] Confirm proposal output contract and API/CLI entry points
- [x] Confirm package Python support and development dependencies
- [x] Confirm no existing CI workflow
- **Status:** complete

### Phase 2: Integration tests and CI
- [x] Add engine-to-CLI/API success-path integration test
- [x] Add fail-closed integration cases and compare cross-interface results
- [x] Add GitHub Actions matrix workflow for test, lint, and type checks
- **Status:** complete

### Phase 3: Verification
- [x] Attempt tests, Ruff, and mypy; record local runtime limitation
- [x] Run diff and changed-file checks
- [x] Record verification limitations accurately
- **Status:** complete

### Phase 4: Delivery
- [x] Review integration test and workflow files
- [x] Document workflow and test coverage
- [x] Deliver linked file paths and verification status
- **Status:** complete

## Decisions Made
| Decision | Rationale |
|----------|-----------|
| Use a new `tests/test_proposal_integration.py` to compare the engine, CLI JSON, and FastAPI response | Exercises actual public surfaces while keeping focused policy unit tests separate |
| Add GitHub Actions matrix Python 3.11/3.12 | Covers declared minimum and a newer supported runtime |
| Run full pytest, Ruff, and mypy in CI; avoid speculative coverage threshold | Verifies the workflow without introducing an unmeasured threshold |

## Errors Encountered
| Error | Resolution |
|-------|------------|
| PowerShell blocked planning initializer by execution policy | Retried in isolated directory with process-scoped `-ExecutionPolicy Bypass`; machine policy unchanged |
| Attempted to overwrite initialized planning files before reading them | Read existing files, then updated them |
| Python runner unavailable on this desktop | Recorded tests as not run locally; GitHub Actions installs Python 3.11/3.12 |
