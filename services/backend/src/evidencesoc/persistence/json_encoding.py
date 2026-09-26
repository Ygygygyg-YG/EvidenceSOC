"""Reversible JSON envelopes for values PostgreSQL cannot represent directly."""
import base64
import json
import re
from typing import Any


def safe_json(value: dict[str, Any]) -> dict[str, Any]:
    serialized = json.dumps(value, ensure_ascii=True, allow_nan=False)
    reserved = set(value) == {"_audit_encoding", "value"} and value["_audit_encoding"] == "base64-json"
    if not reserved and not re.search(r"\\u(?:0000|d[89a-f][0-9a-f]{2})", serialized):
        return value
    return {
        "_audit_encoding": "base64-json",
        "value": base64.b64encode(serialized.encode("utf-8")).decode("ascii"),
    }


def restore_json(value: dict[str, Any]) -> dict[str, Any]:
    if set(value) == {"_audit_encoding", "value"} and value["_audit_encoding"] == "base64-json":
        decoded: dict[str, Any] = json.loads(base64.b64decode(value["value"]))
        return decoded
    return value
