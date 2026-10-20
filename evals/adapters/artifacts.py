"""Answer-free immutable JSON artifacts shared by controllers and workers."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def write_immutable_json(path: Path, value: Any) -> None:
    """Create a canonical UTF-8 artifact once, refusing to overwrite a file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    )
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
