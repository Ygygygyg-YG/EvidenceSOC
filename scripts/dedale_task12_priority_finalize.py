"""Rebuild public-priority v4 cases from each root's own verified v2/v3 lineage."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evals.datasets.dedale.common import canonical
from evals.datasets.dedale.public_priority import finalize_dataset


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("sources", "scan-splits", "splits", "neutral-policy", "label-policy", "data-root",
                 "prepared-root", "preparation-checkpoints", "neutral-root", "output-root"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--work-root", type=Path)
    result = finalize_dataset(**vars(parser.parse_args(argv)))
    print(canonical({key: result[key] for key in ("protocol", "status", "N_D", "M_D", "counts")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
