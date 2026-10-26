"""Explicit host registration; every authority JSON is supplied, never generated."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from evals.adapters.source_epochs import register_source_epoch


def _read_json(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ValueError("an existing unlinked host input JSON is required")
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--budget", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--budget-identity", type=Path, required=True)
    parser.add_argument("--authority", type=Path, required=True)
    parser.add_argument("--expected-authority-sha256", required=True)
    args = parser.parse_args(argv)
    receipt = register_source_epoch(
        args.budget,
        _read_json(args.manifest),
        expected_manifest_sha256=args.expected_manifest_sha256,
        budget_identity=_read_json(args.budget_identity),
        authority=_read_json(args.authority),
        expected_authority_sha256=args.expected_authority_sha256,
    )
    print(json.dumps(receipt, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
