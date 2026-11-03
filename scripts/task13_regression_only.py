"""Independent 176-row regression admission; no E timing or F8 credit.

Importing and offline validation dispatch nothing. Execution still requires the
actual, separately approved packet and all non-timing admission evidence.
"""

from __future__ import annotations

import argparse
import json
from copy import deepcopy
from hashlib import sha256
from pathlib import Path

from evals.contracts import AdapterResult, canonical_hash
from evals.remediation import _summary
from scripts.task13_e_trial import _decode, _path
from scripts.task13_regression import FreeDependencies, RegressionHost, _time

__all__ = ["FreeDependencies", "RegressionOnlyHost"]

SCOPE = "Task13supplement176regression-only"
INPUTS = RegressionHost.INPUTS - {"e_timing_receipt"}
FROZEN_INPUTS = INPUTS - {"final_freeze", "scope_packet", "scope_decision"}
HOST_ENTRYPOINT = "scripts/task13_regression_only.py"
HOST_ENTRIES = RegressionHost.HOST_ENTRIES | {HOST_ENTRYPOINT}


class RegressionOnlyHost(RegressionHost):
    HOST_SCHEMA = "task13-regression-only-host-v1"
    SCOPE_SCHEMA = "task13-regression-only-scope-v1"
    DECISION_SCHEMA = "task13-regression-only-user-scope-decision-v1"
    FREEZE_SCHEMA = "task13-regression-only-final-freeze-v1"
    SCOPE = SCOPE
    INPUTS = INPUTS
    FROZEN_INPUTS = FROZEN_INPUTS
    HOST_ENTRYPOINT = HOST_ENTRYPOINT
    HOST_ENTRIES = HOST_ENTRIES

    def _validate_deadline(self):
        if (
            self._manifest.get("mode") != "regression_only"
            or "deadline_at" not in self._manifest
            or self._manifest["deadline_at"] is not None
        ):
            raise ValueError("explicit regression_only mode and null deadline required")

    def _check_deadline(self):
        self._validate_deadline()

    def _scope(self, data):
        packet = data["scope_packet"]
        if (
            packet.get("mode") != "regression_only"
            or "deadline_at" not in packet
            or packet["deadline_at"] is not None
        ):
            raise PermissionError(
                "independent packet needs explicit mode/null deadline"
            )
        super()._scope(data)

    def _fixed(self, data):
        super()._fixed(data)
        if any(
            "timing" in key.lower() or "f8" in key.lower()
            for key in data["core_config"]
        ):
            raise PermissionError(
                "regression-only core cannot claim timing or F8 credit"
            )
        # The shared implementation is executable authority too, including for
        # synthetic fixtures: freezing only this thin wrapper is insufficient.
        helper = Path(__file__).resolve().with_name("task13_regression.py")
        if (
            data["final_freeze"]["source_files"].get(str(helper))
            != sha256(helper.read_bytes()).hexdigest()
        ):
            raise PermissionError("shared actual host helper is outside freeze")

    def _preflight(self):
        data = self._load()
        if (self._root / "model-runtime-halt.json").exists():
            raise PermissionError("formal model runtime halted; no automatic recovery")
        self._scope(data)
        self._fixed(data)
        self._rag(data)
        self._engineering(data)
        self._price(data)
        self._prior_results(data)
        self._runtime(data)
        return data

    def validate_frozen_scope(self):
        """Read-only detached authority for offline scoring; raises on invalid pins.

        No freshness/dispatch admission, runtime validation, DB access, locks,
        recovery or worker creation. Unknown/in-flight attempts are refused.
        Returned attempts contain raw artifact pins and decoded sealed contents.
        """
        data = self._load()
        self._scope(data)
        self._fixed(data)
        self._rag(data, fresh=False)
        self._engineering(data)
        self._price(data, fresh=False)
        self._runtime_binding(data)
        scope = (
            "offline_contract_test" if self._manifest["synthetic"] else "real_execution"
        )
        summary = _summary(data["bundle"], self._root, scope)
        if summary["counts"]["unknown"]:
            raise PermissionError("unsealed or unknown dispatch needs reconciliation")
        binding = self._root / "host-binding.json"
        if any(summary["counts"][key] for key in ("completed", "failed")) and (
            not binding.exists() or binding.read_bytes() != self._raw
        ):
            raise PermissionError("sealed attempts belong to another frozen host")
        attempts = []
        for row, progress in zip(data["bundle"]["rows"], summary["rows"], strict=True):
            directory = self._root / row["slot_id"]
            if progress["status"] == "not_started":
                if (directory / "result.json").exists():
                    raise PermissionError("orphan result has no sealed attempt")
                continue
            if progress["status"] not in {"completed", "failed"}:
                raise PermissionError("only sealed determinate attempts can be scored")
            artifacts = {}
            for name in ("started", "attempt", "result", "admission"):
                path = _path(directory / (name + ".json"), file=True)
                raw = path.read_bytes()
                artifacts[name] = {
                    "pin": {"path": str(path), "sha256": sha256(raw).hexdigest()},
                    "value": _decode(raw),
                }
            start, attempt, result, admission = (
                artifacts[name]["value"]
                for name in ("started", "attempt", "result", "admission")
            )
            AdapterResult.model_validate(result)
            self._sealed_model_identity(data, result)
            identity = {
                key: data["bundle"][key]
                for key in (
                    "bundle_sha256",
                    "campaign_id",
                    "purpose",
                    "source_commit",
                    "source_sha256",
                    "config_sha256",
                    "budget_identity_sha256",
                    "epoch_id",
                    "epoch_manifest_sha256",
                )
            }
            if (
                any(
                    start.get(key) != value or admission.get(key) != value
                    for key, value in identity.items()
                )
                or start.get("slot_id") != row["slot_id"]
                or attempt.get("slot_id") != row["slot_id"]
                or attempt.get("status") != progress["status"]
                or any(
                    value.get("scope") != scope for value in (start, attempt, admission)
                )
                or start.get("input_hashes") != row["input_hashes"]
                or start.get("admission_sha256") != canonical_hash(admission)
                or admission.get("status") != "verified"
                or admission.get("schema_version") != "task13-v3-execution-gate-v1"
                or attempt.get("started_at") != start.get("started_at")
                or attempt.get("result_sha256") != artifacts["result"]["pin"]["sha256"]
                or attempt.get("bundle_sha256") != data["bundle"]["bundle_sha256"]
                or start.get("request_sha256") != canonical_hash(row["request"])
                or _time(attempt["finished_at"]) < _time(start["started_at"])
                or attempt.get("reason")
                != (
                    None
                    if progress["status"] == "completed"
                    else result.get("execution_status")
                )
                or (progress["status"] == "completed")
                != (result.get("execution_status") == "completed")
            ):
                raise PermissionError("sealed attempt identity/status differs")
            attempts.append(
                {
                    "slot_id": row["slot_id"],
                    "case_id": row["case_id"],
                    "status": progress["status"],
                    "artifacts": artifacts,
                }
            )
        return deepcopy(
            {
                "schema_version": "task13-regression-only-frozen-authority-v1",
                "status": "verified",
                "scope": self.SCOPE,
                "mode": "regression_only",
                "synthetic": self._manifest["synthetic"],
                "manifest_pin": self._pin,
                "input_pins": self._manifest["inputs"],
                **data,
                "summary": summary,
                "attempts": attempts,
            }
        )

    def _sealed_model_identity(self, data, result):
        # Validate the raw received identity offline; source-epoch/model
        # registration and live accounting remain execution-only checks.
        core = data["core_config"]
        expected = (
            core["model_identity"]
            if data["bundle"].get("model_identity_binding") is not None
            else core["original_observed_model_binding"]
        )
        for call in result["model_ledger"]:
            raw = call.get("raw_response")
            if call.get("http_status") != 200 and not isinstance(raw, dict):
                continue
            if (
                call.get("response_model") != expected["response_model"]
                or call.get("system_fingerprint") != expected["fingerprint"]
                or not isinstance(raw, dict)
                or raw.get("model") != expected["response_model"]
                or raw.get("system_fingerprint") != expected["fingerprint"]
            ):
                raise PermissionError("sealed received model identity differs")

    def audit(self):
        """Read-only frozen authority, or PENDING; never admits execution."""
        try:
            return self.validate_frozen_scope()
        except (
            OSError,
            ValueError,
            PermissionError,
            RuntimeError,
            KeyError,
            TypeError,
        ) as error:
            return {
                "status": "PENDING",
                "reason": type(error).__name__,
                "scope": self.SCOPE,
            }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument(
        "operation", choices=("readiness", "status", "execute", "audit")
    )
    parser.add_argument("--row-limit", type=int)
    args = parser.parse_args(argv)
    try:
        host = RegressionOnlyHost(args.manifest, args.manifest_sha256)
        result = (
            host.execute(row_limit=args.row_limit)
            if args.operation == "execute"
            else getattr(host, args.operation)()
        )
    except (
        OSError,
        ValueError,
        PermissionError,
        RuntimeError,
        KeyError,
        TypeError,
    ) as error:
        result = {"status": "PENDING", "reason": type(error).__name__, "scope": SCOPE}
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 2 if result.get("status") == "PENDING" else 0


if __name__ == "__main__":
    raise SystemExit(main())
