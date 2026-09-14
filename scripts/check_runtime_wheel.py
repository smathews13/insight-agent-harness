#!/usr/bin/env python3
"""Build the local Python runtime wheel twice and verify byte-for-byte reproducibility."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def wheel_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build(source: Path, destination: Path) -> Path:
    environment = {
        **os.environ,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INDEX": "1",
        "SOURCE_DATE_EPOCH": "315532800",
    }
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(destination),
            str(source),
        ],
        check=True,
        env=environment,
    )
    wheels = sorted(destination.glob("*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected one wheel, found {len(wheels)}")
    return wheels[0]


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    source = root / "packages/agent-runtime-py"
    with tempfile.TemporaryDirectory(prefix="insight-runtime-wheel-") as temporary:
        work = Path(temporary)
        first = build(source, work / "first")
        second = build(source, work / "second")
        first_digest = wheel_digest(first)
        second_digest = wheel_digest(second)
        if first.name != second.name or first_digest != second_digest:
            print("ERROR: Python runtime wheel build is not deterministic", file=sys.stderr)
            return 1
        print(f"deterministic Python runtime wheel: {first.name} sha256:{first_digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
