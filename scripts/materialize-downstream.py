#!/usr/bin/env python3
"""Materialize one downstream distribution from an immutable Harness pin."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

PIN_KEYS = ("upstream_tag", "upstream_sha", "upstream_artifact_sha256")
TAG_PATTERN = re.compile(r"^v?(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$")
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
ALLOWED_SLOTS = (
    "assets",
    "navigation",
    "loading",
    "prompts",
    "knowledge",
    "tools",
    "genie",
    "resources",
    "migrations",
    "settings",
    "export",
)
SLOT_MANIFEST_KEYS = {
    "assets": "branding",
    "navigation": "navigation",
    "loading": "loading",
    "prompts": "prompts",
    "knowledge": "knowledge",
    "tools": "tool_registry",
    "genie": "genie_mode",
    "resources": "resources",
    "migrations": "migrations",
    "settings": "settings",
    "export": "export_chrome",
}
IGNORED_UPSTREAM = {".git", "build", "node_modules", "node_modules.partial-harness", "overlays"}
CONTRACT_SOURCE = Path(__file__).resolve().parents[1] / "packages" / "contracts" / "src"
COMPATIBILITY_REGISTRY = (
    Path(__file__).resolve().parents[1]
    / "profiles"
    / "sample-neutral"
    / "compatibility-aliases.json"
)
sys.path.insert(0, str(CONTRACT_SOURCE))
from insight_agent_harness_contracts import validate_contract  # noqa: E402


class MaterializationError(ValueError):
    """Raised when a distribution cannot be reproduced safely."""


def validate_compatibility_aliases(manifest: dict[str, Any]) -> None:
    registry = json.loads(COMPATIBILITY_REGISTRY.read_text(encoding="utf-8"))
    policy = registry["policy"]
    mapping = registry["mapping"]
    registered = set(registry["aliases"])
    seen: set[str] = set()
    for alias in manifest["compatibility"]["aliases"]:
        name = alias["alias"]
        if not name.startswith(mapping["legacy_prefix"]):
            raise MaterializationError(
                f"compatibility alias must use {mapping['legacy_prefix']}: {name}"
            )
        suffix = name.removeprefix(mapping["legacy_prefix"])
        if suffix not in registered:
            raise MaterializationError(f"compatibility alias is not registered for 1.1: {name}")
        if name in seen:
            raise MaterializationError(f"compatibility alias is duplicated: {name}")
        seen.add(name)
        expected = {
            "target": f"{mapping['canonical_prefix']}{suffix}",
            "owner": mapping["owner"],
            "telemetry_key": f"{mapping['telemetry_key_prefix']}{suffix.lower()}",
            "removal_version": policy["removal_version"],
        }
        for field, value in expected.items():
            if alias.get(field) != value:
                raise MaterializationError(f"compatibility alias {name} must set {field}={value!r}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def parse_pin(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as exc:
        raise MaterializationError(f"upstream pin is missing: {path}") from exc
    for line_number, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise MaterializationError(f"{path}:{line_number}: expected key=value")
        key, value = (part.strip() for part in line.split("=", 1))
        if key not in PIN_KEYS:
            raise MaterializationError(f"{path}:{line_number}: unknown pin key {key!r}")
        if key in values:
            raise MaterializationError(f"{path}:{line_number}: duplicate pin key {key!r}")
        values[key] = value
    missing = [key for key in PIN_KEYS if not values.get(key)]
    if missing:
        raise MaterializationError(f"{path}: missing pin keys: {', '.join(missing)}")
    if not TAG_PATTERN.fullmatch(values["upstream_tag"]):
        raise MaterializationError("upstream_tag must be a semantic release tag")
    if not SHA_PATTERN.fullmatch(values["upstream_sha"]):
        raise MaterializationError("upstream_sha must be a full lowercase 40-character Git SHA")
    if not DIGEST_PATTERN.fullmatch(values["upstream_artifact_sha256"]):
        raise MaterializationError("upstream_artifact_sha256 must be sha256:<64 lowercase hex>")
    return values


def git(checkout: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(checkout), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise MaterializationError(f"git {' '.join(args)} failed: {detail}")
    return completed.stdout.strip()


def verify_checkout(checkout: Path, pin: dict[str, str], artifact: Path) -> None:
    top_level = Path(git(checkout, "rev-parse", "--show-toplevel")).resolve()
    if top_level != checkout:
        raise MaterializationError(
            f"vendor/upstream must be the Git checkout root, not a nested path: {checkout}"
        )
    if git(checkout, "status", "--porcelain", "--untracked-files=all"):
        raise MaterializationError("vendor/upstream checkout is not read-only and clean")
    head = git(checkout, "rev-parse", "HEAD")
    if head != pin["upstream_sha"]:
        raise MaterializationError(
            f"vendor/upstream HEAD {head} does not match pinned SHA {pin['upstream_sha']}"
        )
    tag_ref = f"refs/tags/{pin['upstream_tag']}"
    if git(checkout, "for-each-ref", tag_ref, "--format=%(objecttype)") != "tag":
        raise MaterializationError(f"{pin['upstream_tag']} is missing or is not an annotated tag")
    tag_commit = git(checkout, "rev-parse", f"{pin['upstream_tag']}^{{commit}}")
    if tag_commit != pin["upstream_sha"]:
        raise MaterializationError(
            f"{pin['upstream_tag']} does not resolve to pinned SHA {pin['upstream_sha']}"
        )
    try:
        artifact_relative = artifact.relative_to(checkout)
    except ValueError as exc:
        raise MaterializationError(
            "pinned upstream artifact must stay inside vendor/upstream"
        ) from exc
    resolved_artifact = artifact.resolve()
    if checkout not in resolved_artifact.parents:
        raise MaterializationError("pinned upstream artifact resolves outside vendor/upstream")
    current = artifact
    while current != checkout:
        if current.is_symlink():
            raise MaterializationError("pinned upstream artifact path may not use symlinks")
        current = current.parent
    if not artifact.is_file():
        raise MaterializationError(f"pinned upstream artifact is missing: {artifact}")
    git(checkout, "ls-files", "--error-unmatch", "--", artifact_relative.as_posix())
    actual_digest = sha256_file(artifact)
    if actual_digest != pin["upstream_artifact_sha256"]:
        raise MaterializationError(
            "upstream artifact digest mismatch: "
            f"expected {pin['upstream_artifact_sha256']}, got {actual_digest}"
        )


def load_overlay(overlay: Path) -> dict[str, Any]:
    manifest_path = overlay / "product.manifest.json"
    if manifest_path.is_symlink():
        raise MaterializationError("overlay ProductManifest may not be a symlink")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise MaterializationError(f"overlay manifest is missing: {manifest_path}") from exc
    except json.JSONDecodeError as exc:
        raise MaterializationError(f"overlay manifest is invalid JSON: {exc.msg}") from exc
    if not isinstance(manifest, dict):
        raise MaterializationError("overlay manifest root must be an object")
    validation = validate_contract("product-manifest", manifest)
    if not validation["valid"]:
        raise MaterializationError(
            "overlay ProductManifest is invalid: " + "; ".join(validation["errors"])
        )
    manifest_slots = manifest.get("extensions", {})
    if set(manifest_slots) != set(SLOT_MANIFEST_KEYS.values()):
        raise MaterializationError(
            "overlay ProductManifest extension slots do not match the materializer"
        )
    validate_compatibility_aliases(manifest)
    for child in overlay.iterdir():
        if child.name == "product.manifest.json":
            continue
        if child.name not in ALLOWED_SLOTS:
            raise MaterializationError(f"overlay contains unknown extension slot: {child.name}")
        if child.is_symlink():
            raise MaterializationError(f"overlay slot may not be a symlink: {child.name}")
        if not child.is_dir():
            raise MaterializationError(f"overlay slot must be a directory: {child.name}")
    for candidate in overlay.rglob("*"):
        if candidate.is_symlink():
            raise MaterializationError(
                f"overlay content may not use symlinks: {candidate.relative_to(overlay)}"
            )
        if not candidate.is_dir() and not candidate.is_file():
            raise MaterializationError(
                "overlay content must be a regular file or directory: "
                f"{candidate.relative_to(overlay)}"
            )
    return manifest


def _ignore(_directory: str, names: list[str]) -> set[str]:
    return set(names).intersection(IGNORED_UPSTREAM)


def file_inventory(root: Path, *, exclude_root_metadata: bool = False) -> dict[str, str]:
    inventory: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if exclude_root_metadata and relative.parts and relative.parts[0] == ".harness":
            continue
        if path.is_symlink():
            raise MaterializationError(f"materialized content may not use symlinks: {relative}")
        if path.is_dir():
            continue
        if not stat.S_ISREG(path.stat().st_mode):
            raise MaterializationError(f"materialized content must be a regular file: {relative}")
        inventory[relative.as_posix()] = sha256_file(path)
    return inventory


def materialize(
    upstream: Path,
    overlay: Path,
    pin_path: Path,
    artifact_relative: Path,
    output: Path,
) -> dict[str, Any]:
    upstream = upstream.resolve()
    overlay = overlay.resolve()
    output = output.resolve()
    if overlay == upstream or upstream in overlay.parents:
        raise MaterializationError("overlay must be outside the immutable upstream checkout")
    if (
        output == upstream
        or upstream in output.parents
        or output == overlay
        or overlay in output.parents
    ):
        raise MaterializationError("output must be outside the upstream checkout and overlay")
    if output.exists():
        raise MaterializationError(f"materialization output already exists: {output}")
    pin = parse_pin(pin_path)
    if artifact_relative.is_absolute() or ".." in artifact_relative.parts:
        raise MaterializationError("artifact must be a repository-relative path without '..'")
    artifact = upstream / artifact_relative
    verify_checkout(upstream, pin, artifact)
    manifest = load_overlay(overlay)
    shutil.copytree(upstream, output, ignore=_ignore)
    metadata_root = output / ".harness"
    extension_root = metadata_root / "extensions"
    extension_root.mkdir(parents=True)
    for slot in ALLOWED_SLOTS:
        source = overlay / slot
        if source.is_dir():
            shutil.copytree(source, extension_root / slot)
    canonical_manifest = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    (metadata_root / "product.manifest.json").write_text(
        f"{canonical_manifest}\n", encoding="utf-8"
    )
    manifest_digest = hashlib.sha256(canonical_manifest.encode()).hexdigest()
    metadata = {
        "schema_version": "1.0.0",
        **pin,
        "product_manifest_sha256": f"sha256:{manifest_digest}",
        "artifact_path": artifact_relative.as_posix(),
        "extension_slots": [slot for slot in ALLOWED_SLOTS if (overlay / slot).is_dir()],
        "extension_files": file_inventory(extension_root),
        "upstream_files": file_inventory(output, exclude_root_metadata=True),
    }
    (metadata_root / "distribution.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return metadata


def verify_materialized(output: Path) -> None:
    metadata_path = output / ".harness" / "distribution.json"
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        raise MaterializationError(
            f"materialization metadata is missing or invalid: {metadata_path}"
        ) from exc
    expected = metadata.get("upstream_files")
    if not isinstance(expected, dict):
        raise MaterializationError("materialization metadata has no upstream file inventory")
    actual = file_inventory(output, exclude_root_metadata=True)
    changed = sorted(
        path for path in set(expected) | set(actual) if expected.get(path) != actual.get(path)
    )
    if changed:
        raise MaterializationError(
            f"downstream modified upstream-owned paths: {', '.join(changed[:20])}"
        )
    metadata_root = output / ".harness"
    if metadata_root.is_symlink() or not metadata_root.is_dir():
        raise MaterializationError("materialization metadata root is missing or is a symlink")
    expected_metadata_entries = {"distribution.json", "extensions", "product.manifest.json"}
    actual_metadata_entries = {path.name for path in metadata_root.iterdir()}
    if actual_metadata_entries != expected_metadata_entries:
        changed_entries = sorted(
            expected_metadata_entries.symmetric_difference(actual_metadata_entries)
        )
        raise MaterializationError(
            "materialization metadata contains unexpected or missing paths: "
            + ", ".join(changed_entries)
        )
    manifest_path = metadata_root / "product.manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        raise MaterializationError("materialized ProductManifest is missing or invalid") from exc
    canonical_manifest = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    manifest_digest = f"sha256:{hashlib.sha256(canonical_manifest.encode()).hexdigest()}"
    if manifest_digest != metadata.get("product_manifest_sha256"):
        raise MaterializationError(
            "materialized ProductManifest digest does not match distribution metadata"
        )
    if manifest_path.read_text(encoding="utf-8") != f"{canonical_manifest}\n":
        raise MaterializationError("materialized ProductManifest is not canonical")
    expected_extensions = metadata.get("extension_files")
    if not isinstance(expected_extensions, dict):
        raise MaterializationError("materialization metadata has no extension file inventory")
    extension_root = metadata_root / "extensions"
    actual_extensions = file_inventory(extension_root)
    changed_extensions = sorted(
        path
        for path in set(expected_extensions) | set(actual_extensions)
        if expected_extensions.get(path) != actual_extensions.get(path)
    )
    if changed_extensions:
        raise MaterializationError(
            "materialized extension content changed: " + ", ".join(changed_extensions[:20])
        )
    expected_slots = metadata.get("extension_slots")
    if not isinstance(expected_slots, list) or not all(
        isinstance(slot, str) and slot in ALLOWED_SLOTS for slot in expected_slots
    ):
        raise MaterializationError(
            "materialization metadata has an invalid extension slot inventory"
        )
    if any(path.is_symlink() or not path.is_dir() for path in extension_root.iterdir()):
        raise MaterializationError("materialized extension slots must be ordinary directories")
    actual_slots = sorted(path.name for path in extension_root.iterdir())
    if actual_slots != sorted(expected_slots):
        raise MaterializationError("materialized extension slot inventory changed")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path)
    parser.add_argument("--overlay", type=Path)
    parser.add_argument("--pin", type=Path)
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true", help="verify an existing materialized tree")
    args = parser.parse_args(argv)
    try:
        if args.check:
            verify_materialized(args.output)
            print(f"Materialized downstream boundary is intact: {args.output}")
            return 0
        missing = [
            name
            for name in ("upstream", "overlay", "pin", "artifact")
            if getattr(args, name) is None
        ]
        if missing:
            parser.error(f"materialization requires: {', '.join('--' + name for name in missing)}")
        metadata = materialize(args.upstream, args.overlay, args.pin, args.artifact, args.output)
        print(
            f"Materialized {metadata['upstream_tag']}@{metadata['upstream_sha']} "
            f"with {len(metadata['extension_slots'])} extension slots."
        )
        return 0
    except MaterializationError as exc:
        print(f"downstream materialization failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
