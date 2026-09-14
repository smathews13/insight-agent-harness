#!/usr/bin/env python3
"""Audit public-safe source against the committed publication policy."""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {
    ".cjs",
    ".css",
    ".html",
    ".js",
    ".json",
    ".md",
    ".mjs",
    ".mts",
    ".py",
    ".sh",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}
SKIPPED_PARTS = {
    ".git",
    ".harness",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "node_modules.partial-harness",
}


@dataclass(frozen=True)
class AuditPaths:
    root: Path
    ownership: Path
    alias_registry: Path
    publication_policy: Path
    product_manifest: Path


@dataclass(frozen=True)
class PublicationPolicy:
    required_posture_files: tuple[str, ...]
    caveat_files: tuple[str, ...]
    unofficial_software_caveat: str
    root_license_allowed: bool
    forbidden_identity_markers: tuple[str, ...]
    identity_debt_files: frozenset[str]


DEFAULT_PATHS = AuditPaths(
    root=ROOT,
    ownership=ROOT / "OWNERSHIP.yaml",
    alias_registry=ROOT / "profiles" / "sample-neutral" / "compatibility-aliases.json",
    publication_policy=ROOT / "profiles" / "sample-neutral" / "publication-policy.json",
    product_manifest=ROOT / "profiles" / "sample-neutral" / "product.manifest.json",
)


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} root must be an object")
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], field: str) -> None:
    actual = set(value)
    if actual != expected:
        detail = ", ".join(sorted(actual.symmetric_difference(expected)))
        raise ValueError(f"{field} has unexpected or missing fields: {detail}")


def _relative_paths(value: Any, field: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or (not allow_empty and not value)
        or not all(isinstance(item, str) for item in value)
    ):
        qualifier = "" if allow_empty else "non-empty "
        raise ValueError(f"{field} must be a {qualifier}array of repository-relative paths")
    paths: list[str] = []
    for item in value:
        candidate = PurePosixPath(item)
        if candidate.is_absolute() or item in {"", "."} or ".." in candidate.parts:
            raise ValueError(f"{field} must stay inside the repository: {item!r}")
        paths.append(candidate.as_posix())
    if len(paths) != len(set(paths)):
        raise ValueError(f"{field} must contain unique paths")
    return tuple(paths)


def load_publication_policy(path: Path) -> PublicationPolicy:
    raw = load(path)
    _exact_keys(
        raw,
        {
            "schema_version",
            "required_posture_files",
            "caveat_files",
            "unofficial_software_caveat",
            "root_license_allowed",
            "forbidden_identity_marker_fragments",
            "identity_debt_files",
        },
        "publication policy",
    )
    if raw["schema_version"] != "1.0.0":
        raise ValueError("publication policy schema_version must be 1.0.0")
    required = _relative_paths(raw["required_posture_files"], "required_posture_files")
    caveat_files = _relative_paths(raw["caveat_files"], "caveat_files")
    if not set(caveat_files).issubset(required):
        raise ValueError("caveat_files must be included in required_posture_files")
    caveat = raw["unofficial_software_caveat"]
    if not isinstance(caveat, str) or not caveat.strip():
        raise ValueError("unofficial_software_caveat must be a non-empty string")
    root_license_allowed = raw["root_license_allowed"]
    if not isinstance(root_license_allowed, bool):
        raise ValueError("root_license_allowed must be true or false")
    fragment_sets = raw["forbidden_identity_marker_fragments"]
    if (
        not isinstance(fragment_sets, list)
        or not fragment_sets
        or not all(
            isinstance(parts, list)
            and len(parts) >= 2
            and all(isinstance(part, str) and part for part in parts)
            for parts in fragment_sets
        )
    ):
        raise ValueError(
            "forbidden_identity_marker_fragments must contain non-empty fragment arrays"
        )
    markers = tuple("".join(parts) for parts in fragment_sets)
    if len(markers) != len(set(markers)):
        raise ValueError("forbidden identity markers must be unique")
    debt_files = _relative_paths(
        raw["identity_debt_files"],
        "identity_debt_files",
        allow_empty=True,
    )
    return PublicationPolicy(
        required_posture_files=required,
        caveat_files=caveat_files,
        unofficial_software_caveat=caveat,
        root_license_allowed=root_license_allowed,
        forbidden_identity_markers=markers,
        identity_debt_files=frozenset(debt_files),
    )


def public_safe_roots(paths: AuditPaths) -> list[Path]:
    ownership = load(paths.ownership)
    roots = []
    for record in ownership.get("paths", []):
        if "public-safe" not in record.get("classification", []):
            continue
        path = paths.root / record["path"]
        if path.exists() and not any(
            existing == path or existing in path.parents for existing in roots
        ):
            roots.append(path)
    return roots


def source_files(audit_paths: AuditPaths) -> list[Path]:
    candidates: set[Path] = set()
    for root in public_safe_roots(audit_paths):
        paths = [root] if root.is_file() else root.rglob("*")
        for path in paths:
            if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            relative = path.relative_to(audit_paths.root)
            if any(part in SKIPPED_PARTS for part in relative.parts):
                continue
            if (
                "tests" in relative.parts
                or path.name.startswith("test_")
                or ".test." in path.name
                or ".spec." in path.name
            ):
                continue
            candidates.add(path)
    return sorted(candidates)


def _registry_mapping(registry: dict[str, Any]) -> tuple[dict[str, str], dict[str, Any]]:
    _exact_keys(
        registry,
        {"schema_version", "registry_ref", "policy", "aliases", "mapping"},
        "compatibility alias registry",
    )
    if registry["schema_version"] != "1.0.0":
        raise ValueError("compatibility alias registry schema_version must be 1.0.0")
    policy = registry["policy"]
    if not isinstance(policy, dict):
        raise ValueError("compatibility alias policy must be an object")
    _exact_keys(
        policy,
        {"retained_through", "removal_version", "new_aliases_allowed"},
        "compatibility alias policy",
    )
    mapping = registry["mapping"]
    if not isinstance(mapping, dict):
        raise ValueError("compatibility alias mapping must be an object")
    _exact_keys(
        mapping,
        {
            "canonical_prefix",
            "legacy_prefix",
            "owner",
            "telemetry_key_prefix",
            "diagnostic",
        },
        "compatibility alias mapping",
    )
    if not all(isinstance(value, str) and value for value in mapping.values()):
        raise ValueError("compatibility alias mapping values must be non-empty strings")
    for field in ("canonical_prefix", "legacy_prefix"):
        if re.fullmatch(r"[A-Z][A-Z0-9_]*_", mapping[field]) is None:
            raise ValueError(f"compatibility alias mapping {field} is invalid")
    if mapping["canonical_prefix"] == mapping["legacy_prefix"]:
        raise ValueError("canonical and legacy compatibility prefixes must differ")
    registry_ref = registry["registry_ref"]
    if not isinstance(registry_ref, str) or not registry_ref.startswith("compatibility:"):
        raise ValueError("compatibility alias registry_ref is invalid")
    return mapping, policy


def audit(paths: AuditPaths = DEFAULT_PATHS) -> list[str]:
    registry = load(paths.alias_registry)
    mapping, compatibility_policy = _registry_mapping(registry)
    if (
        compatibility_policy.get("retained_through") != "1.1.x"
        or compatibility_policy.get("removal_version") != "1.2.0"
    ):
        return ["compatibility alias lifecycle must retain 1.1.x and remove no earlier than 1.2.0"]
    if compatibility_policy.get("new_aliases_allowed") is not False:
        return ["compatibility alias registry must prohibit new aliases"]
    suffixes = registry.get("aliases", [])
    if not isinstance(suffixes, list) or not all(isinstance(item, str) for item in suffixes):
        return ["compatibility aliases must be an array of suffixes"]
    allowed_aliases = set(suffixes)
    if len(allowed_aliases) != len(suffixes):
        return ["compatibility aliases must be unique"]

    manifest = load(paths.product_manifest)
    compatibility = manifest.get("compatibility", {})
    if compatibility.get("registry_ref") != registry["registry_ref"]:
        return ["ProductManifest compatibility registry_ref must match the committed registry"]
    manifest_aliases = compatibility.get("aliases", [])
    if not isinstance(manifest_aliases, list) or not all(
        isinstance(alias, dict) for alias in manifest_aliases
    ):
        return ["ProductManifest compatibility aliases must be objects"]

    publication = load_publication_policy(paths.publication_policy)
    errors: list[str] = []
    seen_manifest_aliases: set[str] = set()
    seen_telemetry_keys: set[str] = set()
    for index, alias in enumerate(manifest_aliases):
        name = alias.get("alias")
        if not isinstance(name, str) or not name.startswith(mapping["legacy_prefix"]):
            errors.append(
                f"ProductManifest compatibility alias {index} must use the registered legacy prefix"
            )
            continue
        suffix = name.removeprefix(mapping["legacy_prefix"])
        if suffix not in allowed_aliases:
            errors.append(f"ProductManifest introduces unregistered compatibility alias: {name}")
        if name in seen_manifest_aliases:
            errors.append(f"ProductManifest repeats compatibility alias: {name}")
        seen_manifest_aliases.add(name)
        expected_target = f"{mapping['canonical_prefix']}{suffix}"
        if alias.get("target") != expected_target:
            errors.append(f"{name} must target {expected_target}")
        if alias.get("owner") != mapping["owner"]:
            errors.append(f"{name} must be owned by {mapping['owner']}")
        expected_telemetry = f"{mapping['telemetry_key_prefix']}{suffix.lower()}"
        telemetry_key = alias.get("telemetry_key")
        if telemetry_key != expected_telemetry:
            errors.append(f"{name} must emit compatibility telemetry as {expected_telemetry}")
        if isinstance(telemetry_key, str) and telemetry_key in seen_telemetry_keys:
            errors.append(f"ProductManifest repeats compatibility telemetry key: {telemetry_key}")
        if isinstance(telemetry_key, str):
            seen_telemetry_keys.add(telemetry_key)
        if alias.get("removal_version") != compatibility_policy["removal_version"]:
            errors.append(
                f"{name} removal_version must be {compatibility_policy['removal_version']}"
            )

    for required in publication.required_posture_files:
        if not (paths.root / required).is_file():
            errors.append(f"required public posture file is missing: {required}")
    for caveat_file in publication.caveat_files:
        caveat_path = paths.root / caveat_file
        if not caveat_path.is_file():
            continue
        text = caveat_path.read_text(encoding="utf-8")
        if publication.unofficial_software_caveat not in " ".join(text.split()):
            errors.append(f"{caveat_file} does not contain the exact unofficial-software caveat")
    root_licenses = sorted(path.name for path in paths.root.glob("LICENSE*") if path.is_file())
    if root_licenses and not publication.root_license_allowed:
        errors.append(
            "v1.1 public rights posture prohibits a root license file: " + ", ".join(root_licenses)
        )

    legacy_alias = re.compile(rf"\b{re.escape(mapping['legacy_prefix'])}([A-Z0-9_]+)\b")
    observed_aliases: set[str] = set()
    observed_debt: set[str] = set()
    unknown_aliases: dict[str, set[str]] = {}
    for path in source_files(paths):
        relative = path.relative_to(paths.root).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for match in legacy_alias.finditer(text):
            suffix = match.group(1)
            observed_aliases.add(suffix)
            if suffix not in allowed_aliases:
                unknown_aliases.setdefault(suffix, set()).add(relative)
        if any(marker in text for marker in publication.forbidden_identity_markers):
            observed_debt.add(relative)
            if relative not in publication.identity_debt_files:
                errors.append(f"forbidden inherited product identity location: {relative}")

    unused = sorted(publication.identity_debt_files.difference(observed_debt))
    if unknown_aliases:
        errors.append(
            "new unregistered legacy compatibility aliases are prohibited: "
            + ", ".join(sorted(unknown_aliases))
        )
    if unused:
        errors.append(
            "neutral identity debt baseline is stale; remove resolved entries: " + ", ".join(unused)
        )
    # Missing aliases are allowed: the registry is a compatibility promise for
    # downstream materializations, not a requirement to keep legacy names in new source.
    print(
        f"Neutral audit observed {len(observed_aliases)} registered legacy aliases "
        f"and {len(observed_debt)} explicitly mapped identity-debt files."
    )
    return errors


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments:
        print("usage: check-neutral-surface.py", file=sys.stderr)
        return 2
    try:
        errors = audit()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        errors = [str(exc)]
    if errors:
        print("neutral surface audit failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print("neutral surface audit passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
