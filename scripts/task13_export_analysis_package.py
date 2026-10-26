"""Export or independently verify a readonly Task13 portable source package."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from evals.adapters.analysis_import import SourceAnchor
from evals.adapters.analysis_package import (
    export_portable_analysis_package,
    verify_portable_analysis_package,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    export = commands.add_parser("export")
    export.add_argument("--anchor", type=Path, required=True)
    export.add_argument("--destination", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--root", type=Path, required=True)
    verify.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args()
    if args.operation == "export":
        anchor = SourceAnchor.model_validate_json(args.anchor.read_bytes())
        result = export_portable_analysis_package(anchor, args.destination)
    else:
        source = verify_portable_analysis_package(args.root, args.manifest_sha256)
        source.revalidate()
        result = {
            "source_identity": source.source_identity,
            "provenance": source.provenance,
        }
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
