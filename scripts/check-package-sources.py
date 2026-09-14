#!/usr/bin/env python3
"""Require package inputs to use local paths or public registries."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRIVATE_MARKERS = (
    "registry.example.com",
    "-proxy.dev.databricks.com",
    "registry.example.com",
)
PUBLIC_REGISTRIES = (
    "https://registry.npmjs.org/",
    "https://pypi.org/simple",
)


def main() -> int:
    files = (
        ROOT / "package-lock.json",
        ROOT / "platform/app/package-lock.json",
        ROOT / "platform/agent/uv.lock",
    )
    for path in (candidate for candidate in files if candidate.is_file()):
        text = path.read_text(encoding="utf-8")
        marker = next((value for value in PRIVATE_MARKERS if value in text), None)
        if marker:
            raise SystemExit(f"{path.relative_to(ROOT)} contains private registry marker: {marker}")

    root_lock = json.loads(files[0].read_text(encoding="utf-8"))
    encoded_root = json.dumps(root_lock, sort_keys=True)
    if "http://" in encoded_root or "https://" in encoded_root:
        raise SystemExit("root package-lock.json must contain only local workspace packages")

    if files[1].is_file():
        app_lock = files[1].read_text(encoding="utf-8")
        app_urls = {
            token.split('"')[0]
            for token in app_lock.split('"resolved": "')[1:]
            if token.startswith(("http://", "https://"))
        }
        unexpected = sorted(
            url for url in app_urls if not any(url.startswith(prefix) for prefix in PUBLIC_REGISTRIES)
        )
        if unexpected:
            raise SystemExit(
                "platform/app/package-lock.json contains non-public sources: "
                + ", ".join(unexpected)
            )

    if files[2].is_file():
        agent_lock = files[2].read_text(encoding="utf-8")
        unexpected_agent = sorted(
            line.strip()
            for line in agent_lock.splitlines()
            if "registry = " in line and 'registry = "https://pypi.org/simple"' not in line
        )
        if unexpected_agent:
            raise SystemExit(
                "platform/agent/uv.lock contains an unexpected package registry: "
                + ", ".join(unexpected_agent)
            )

    print("package source check passed: local workspaces plus public registries only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
