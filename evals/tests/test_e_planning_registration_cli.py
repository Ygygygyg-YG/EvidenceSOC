"""CLI pins external synthetic authority before it creates a temporary journal."""

import json

import pytest

from evals.contracts import canonical_hash
from evals.tests.test_e_planning_contracts import registration_fixture
from evals.tests.test_e_planning_journal import authority_fixture
from scripts.task13_register_e_planning import main


@pytest.mark.parametrize("valid", [True, False])
def test_cli_requires_exact_external_authority_before_any_registration(
    tmp_path, capsys, valid
):
    registration = registration_fixture()
    dispatch = tmp_path / "dispatch"
    dispatch.mkdir()
    journal = dispatch / "e-planning.sqlite"
    authority = authority_fixture(journal, registration)
    for name, value in (("registration", registration), ("authority", authority)):
        (tmp_path / (name + ".json")).write_text(json.dumps(value), encoding="utf-8")
    arguments = [
        "--journal",
        str(journal),
        "--registration",
        str(tmp_path / "registration.json"),
        "--expected-registration-sha256",
        canonical_hash(registration),
        "--authority",
        str(tmp_path / "authority.json"),
        "--expected-authority-sha256",
        canonical_hash(authority) if valid else "0" * 64,
    ]
    if valid:
        assert main(arguments) == 0
        receipt = json.loads(capsys.readouterr().out)
        assert receipt["synthetic"] is True
        assert receipt["registration_sha256"] == canonical_hash(registration)
        assert len(receipt["planning_slot_ids"]) == 3
    else:
        with pytest.raises((ValueError, PermissionError)):
            main(arguments)
        assert not journal.exists()
