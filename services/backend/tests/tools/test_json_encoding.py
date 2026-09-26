from evidencesoc.persistence.json_encoding import restore_json, safe_json


def test_reserved_envelope_roundtrips_without_collision() -> None:
    value = {"_audit_encoding": "base64-json", "value": "e30="}
    assert restore_json(safe_json(value)) == value
