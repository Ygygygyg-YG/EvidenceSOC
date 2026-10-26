# Task13 Portable Analysis Package Implementation Plan

> **For agentic workers:** Execute this already approved Task A inline, using TDD and verification before completion. Do not commit.

**Goal:** Export immutable original analysis artifacts into a new self-contained POSIX-relative package and independently replay them after relocation.

**Architecture:** Keep the public v1 verifier strict. Extract only its already existing byte-reader and semantic replay helpers, then use those from a separate v2 reader which validates exact inventory, original byte lineage, safe paths, current replay code and actual original reply.

**Tech Stack:** Python, Pydantic, pathlib, hashlib, pytest.

## Global Constraints

- Work only in `D:\传智杯\.backups\task13-stage-e`; original remediation tree remains read-only.
- No database, container, model, approval or paid action. Never execute copied artifact source.
- Preserve original anchor/manifest/artifact bytes; refresh replay-code identity only in a new v2 manifest.
- Reject absolute/empty/backslash/drive/dot/parent/duplicate paths, links/reparse points/multiple hard links, missing and extra inventory.

### Task A: Portable source package

**Files:** Create `evals/adapters/analysis_package.py`, `scripts/task13_export_analysis_package.py`, `evals/tests/test_analysis_package.py`; minimally refactor `evals/adapters/analysis_import.py` after its other owner finishes.

**Interfaces:** `export_portable_analysis_package(anchor: SourceAnchor, destination: Path) -> dict`; `verify_portable_analysis_package(root: Path, manifest_sha256: str) -> ImportedAnalysis`.

- [ ] Write and run failing tests for export, relocation, original bytes, current replay pin and provenance identity.
- [ ] Add the exact v2 schema, restricted path resolver, inventory check, original lineage binding and shared semantic replay.
- [ ] Run the first tests and confirm green.
- [ ] Write/run negative tests for tampering, refreshed hashes with invalid semantics, bad paths, extras/missing files and links.
- [ ] Add only necessary defenses, then run package + existing import tests with unique temporary roots and `SSLKEYLOGFILE` removed.
- [ ] Export into a unique new slot9 audit directory, verify read-only, and write the requested audit report. Do not overwrite the original audit package.
