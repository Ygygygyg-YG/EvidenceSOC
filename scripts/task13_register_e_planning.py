"""Register exactly three host-authorized E planning slots; never create consent."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from evals.adapters.e_planning_journal import register_planning_slots
from scripts.task13_register_source_epoch import _read_json


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--registration", type=Path, required=True)
    parser.add_argument("--expected-registration-sha256", required=True)
    parser.add_argument("--authority", type=Path, required=True)
    parser.add_argument("--expected-authority-sha256", required=True)
    args = parser.parse_args(argv)
    receipt = register_planning_slots(
        args.journal,
        _read_json(args.registration),
        expected_registration_sha256=args.expected_registration_sha256,
        authority=_read_json(args.authority),
        expected_authority_sha256=args.expected_authority_sha256,
    )
    print(json.dumps(receipt, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
