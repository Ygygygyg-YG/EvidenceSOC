"""Rebuild path-independent neutral DEDALE cases from each root's preparation."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evals.datasets.dedale.common import canonical
from evals.datasets.dedale.neutralize import finalize_dataset


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("sources", "scan-splits", "splits", "label-policy", "data-root",
                 "prepared-root", "preparation-checkpoints", "output-root"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--work-root", type=Path)
    args = parser.parse_args(argv)
    result = finalize_dataset(**vars(args))
    print(canonical({"protocol": result["protocol"], "status": result["status"],
                     "N_D": result["N_D"], "M_D": result["M_D"], "counts": result["counts"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
