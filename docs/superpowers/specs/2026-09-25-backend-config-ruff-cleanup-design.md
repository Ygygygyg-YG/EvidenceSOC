# Backend configuration and Ruff cleanup design

## Goal

Make backend settings load the repository-root `.env` independently of the process working directory, then remove the existing backend Ruff baseline without changing Task 6 behavior.

## Scope

- Change the default `Settings` dotenv path from the relative `.env` name to the repository-root `.env` resolved from the backend source location.
- Preserve Pydantic settings precedence: explicit initializer values and process environment variables continue to override dotenv values.
- Preserve `Settings(_env_file=None)` so isolated tests and callers can disable dotenv loading.
- Add regression tests proving the default dotenv path is absolute and working-directory independent, explicit environment variables win, and `_env_file=None` remains isolated.
- Apply Ruff's import-order fix only to the files currently reporting `I001`.
- Replace the redundant `datetime.fromisoformat(value.strip().replace("Z", "+00:00"))` call with native Python 3.12 `datetime.fromisoformat(value.strip())` and add a regression test for a timestamp ending in `Z`.

## Design

`services/backend/src/evidencesoc/config.py` will define the backend and repository roots from `Path(__file__).resolve()`. `Settings.model_config.env_file` will use the resulting absolute repository-root `.env` path. No directory search, duplicate backend `.env`, or test-only current-directory mutation will be introduced.

The configuration tests will inspect and exercise the public `Settings` behavior rather than relying on the developer's ignored `.env` contents. Temporary dotenv files and monkeypatched environment variables will keep tests deterministic.

The Ruff cleanup is mechanical except for the ISO timestamp change. Import edits will only reorder or separate existing imports. Native trailing-`Z` parsing is supported by the project's required Python version (`>=3.12.14`); existing validation will continue to reject timestamps without timezone information.

## Alternatives considered

1. Require every command to run from the repository root. This avoids code changes but leaves a fragile, undocumented working-directory dependency.
2. Fix only the Task 5 integration test by passing `_env_file`. This makes that test pass but leaves backend processes launched from `services/backend` misconfigured.
3. Copy `.env` into `services/backend`. This creates two configuration sources that can drift.

The absolute repository-root dotenv path is preferred because it fixes the source of the inconsistency while retaining explicit environment overrides for CI and deployment.

## Verification

- Observe the new configuration regression test fail before changing production code.
- Run the focused configuration tests after the fix.
- Use the existing Ruff `FURB162` failure as the red check, add a trailing-`Z` behavior regression test, then make the minimal cleanup and rerun Ruff plus the normalization tests.
- Run full backend Ruff, mypy, and the complete backend test suite with PostgreSQL/OpenSearch available.
- Run `git diff --check` and review the final diff for changes outside this scope.

## Delivery

Use two commits after this design commit:

1. `fix(backend): make settings loading cwd-independent`
2. `chore(backend): clean Ruff baseline`
