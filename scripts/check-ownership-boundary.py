#!/usr/bin/env python3
"""Validate the Insight Agent Harness ownership and dependency boundary."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

REQUIRED_TARGET_PATHS = {
    "platform/app",
    "platform/agent",
    "platform/scripts",
    "platform/tests",
    "extensions/sample-neutral/agent",
    "packages/contracts",
    "packages/export-core",
    "packages/governance",
    "packages/lakebase",
    "packages/observability",
    "packages/agent-runtime-py",
    "agent/eval",
    "agent/tests",
    "bundle",
    "resources",
    "profiles",
    "mirror",
    "docs",
    "overlays",
}
OWNERSHIP_CLASSES = {"upstream-owned", "overlay-owned", "generated"}
PUBLICATION_CLASSES = {"public-safe", "excluded"}
SOURCE_SUFFIXES = {".cjs", ".js", ".mjs", ".mts", ".py", ".ts", ".tsx"}
SKIPPED_DIRECTORY_NAMES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "node_modules",
}
EMAIL_PATTERN = re.compile(
    r"\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b",
    re.IGNORECASE,
)
DATABRICKS_HOST_PATTERN = re.compile(
    r"\b(?:https?://)?(?:dbc-[a-z0-9-]+\.)?[a-z0-9-]+\.cloud\.databricks\.com\b",
    re.IGNORECASE,
)
OVERLAY_PATH_PATTERN = re.compile(
    r"(?:^|[/\\])(?:overlays|overlay[/\\]product|\.harness[/\\]extensions)(?:[/\\]|$)"
)
PYTHON_OVERLAY_IMPORT_PATTERN = re.compile(
    r"^\s*(?:from|import)\s+(?:overlays|overlay(?:\.product)?)(?:[.\s]|$)",
    re.MULTILINE,
)
PLATFORM_AGENT_PRODUCT_PATTERNS = {
    "product identity": re.compile(r"\b(?:Player Insights|legacy downstream product|ADAPT)\b", re.IGNORECASE),
    "product tool implementation": re.compile(
        r"\b(?:PlayerInsightTools|data_genie_tool|dictionary_genie_tool|"
        r"RUN_SQL_TOOL|QUERY_NAMED_TABLE_TOOL|SEARCH_TAGGED_ASSETS_TOOL)\b"
    ),
    "product runtime module": re.compile(
        r"^\s*(?:from|import)\s+(?:genie_routing|semantic_layer|tools)(?:[.\s]|$)",
        re.MULTILINE,
    ),
}


class OwnershipConfigError(ValueError):
    """Raised when OWNERSHIP.yaml is not a valid boundary declaration."""


def _normalise_relative_path(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise OwnershipConfigError(f"{field} must be a non-empty repository-relative path")
    candidate = value.replace("\\", "/").strip().rstrip("/")
    path = PurePosixPath(candidate)
    if path.is_absolute() or candidate in {"", "."} or ".." in path.parts:
        raise OwnershipConfigError(f"{field} must stay inside the repository: {value!r}")
    return path.as_posix()


def load_config(config_path: Path) -> dict[str, Any]:
    try:
        loaded = json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise OwnershipConfigError(f"ownership config is missing: {config_path}") from exc
    except json.JSONDecodeError as exc:
        raise OwnershipConfigError(
            f"{config_path} must use JSON-compatible YAML: {exc.msg} at line {exc.lineno}"
        ) from exc
    if not isinstance(loaded, dict):
        raise OwnershipConfigError("ownership config root must be an object")
    return loaded


def _validated_records(config: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    errors: list[str] = []
    raw_records = config.get("paths")
    if not isinstance(raw_records, list):
        return [], ["OWNERSHIP.yaml paths must be an array"]

    records: list[dict[str, Any]] = []
    for index, raw_record in enumerate(raw_records):
        label = f"paths[{index}]"
        if not isinstance(raw_record, dict):
            errors.append(f"{label} must be an object")
            continue
        try:
            path = _normalise_relative_path(raw_record.get("path"), f"{label}.path")
        except OwnershipConfigError as exc:
            errors.append(str(exc))
            continue

        owner = raw_record.get("owner")
        if (
            not isinstance(owner, dict)
            or not isinstance(owner.get("area"), str)
            or not owner["area"].strip()
            or not isinstance(owner.get("team"), str)
            or not owner["team"].strip()
        ):
            errors.append(f"{path}: owner must contain non-empty area and team labels")

        classification = raw_record.get("classification")
        if not isinstance(classification, list) or not all(
            isinstance(item, str) for item in classification
        ):
            errors.append(f"{path}: classification must be an array of labels")
            classification = []
        ownership = OWNERSHIP_CLASSES.intersection(classification)
        publication = PUBLICATION_CLASSES.intersection(classification)
        unknown_classes = set(classification).difference(OWNERSHIP_CLASSES | PUBLICATION_CLASSES)
        if len(ownership) != 1:
            errors.append(
                f"{path}: classification must contain exactly one of {sorted(OWNERSHIP_CLASSES)}"
            )
        if len(publication) != 1:
            errors.append(
                f"{path}: classification must contain exactly one of {sorted(PUBLICATION_CLASSES)}"
            )
        if unknown_classes:
            errors.append(f"{path}: unknown classification labels: {sorted(unknown_classes)}")

        dependencies = raw_record.get("allowed_dependency_targets")
        if not isinstance(dependencies, list) or not all(
            isinstance(item, str) for item in dependencies
        ):
            errors.append(f"{path}: allowed_dependency_targets must be an array of paths")
            dependencies = []

        if not isinstance(raw_record.get("customer_values_allowed"), bool):
            errors.append(f"{path}: customer_values_allowed must be true or false")

        record = dict(raw_record)
        record["path"] = path
        record["classification"] = classification
        record["allowed_dependency_targets"] = dependencies
        records.append(record)

    return records, errors


def _find_overlaps(records: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    ordered = sorted(records, key=lambda record: record["path"])
    for index, record in enumerate(ordered):
        path = record["path"]
        for other_record in ordered[index + 1 :]:
            other = other_record["path"]
            if other == path:
                errors.append(f"overlapping path ownership: {path!r} conflicts with {other!r}")
                continue
            if not other.startswith(f"{path}/"):
                continue
            if (
                other_record.get("generated_deploy_output") is True
                or other_record.get("generated_output") is True
            ) and "generated" in other_record["classification"]:
                continue
            errors.append(f"overlapping path ownership: {path!r} conflicts with {other!r}")
    return errors


def _find_unknown_dependencies(records: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    known_paths = {record["path"] for record in records}
    for record in records:
        source = record["path"]
        seen: set[str] = set()
        for target in record["allowed_dependency_targets"]:
            if target in seen:
                errors.append(f"{source}: duplicate dependency target {target!r}")
            seen.add(target)
            if target not in known_paths:
                errors.append(f"{source}: unknown dependency target {target!r}")
            if target == source:
                errors.append(f"{source}: self-dependency is not allowed")
    return errors


def _find_package_cycles(records: list[dict[str, Any]]) -> list[str]:
    graph = {
        record["path"]: [
            target
            for target in record["allowed_dependency_targets"]
            if target.startswith("packages/")
        ]
        for record in records
        if record["path"].startswith("packages/")
    }
    errors: list[str] = []
    visiting: list[str] = []
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            cycle_start = visiting.index(node)
            cycle = visiting[cycle_start:] + [node]
            message = f"package dependency cycle: {' -> '.join(cycle)}"
            if message not in errors:
                errors.append(message)
            return
        if node in visited:
            return
        visiting.append(node)
        for target in graph.get(node, []):
            if target in graph:
                visit(target)
        visiting.pop()
        visited.add(node)

    for package in sorted(graph):
        visit(package)
    return errors


def validate_config(config: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    records, errors = _validated_records(config)
    if config.get("schema_version") != "1.0":
        errors.append("schema_version must be '1.0'")
    if config.get("repository_role") not in {"upstream", "downstream"}:
        errors.append("repository_role must be 'upstream' or 'downstream'")

    declared_paths = {record["path"] for record in records}
    missing = sorted(REQUIRED_TARGET_PATHS.difference(declared_paths))
    if missing:
        errors.append(f"missing required target path ownership: {', '.join(missing)}")
    if not any(
        record.get("generated_deploy_output") is True and "generated" in record["classification"]
        for record in records
    ):
        errors.append("at least one generated deploy output must be declared")

    raw_profile_paths = config.get("neutral_profile_paths")
    if not isinstance(raw_profile_paths, list) or not all(
        isinstance(item, str) for item in raw_profile_paths
    ):
        errors.append("neutral_profile_paths must be an array of paths")
    else:
        for raw_path in raw_profile_paths:
            try:
                profile_path = _normalise_relative_path(raw_path, "neutral_profile_paths[]")
            except OwnershipConfigError as exc:
                errors.append(str(exc))
                continue
            if profile_path not in declared_paths:
                errors.append(f"neutral profile path has no ownership record: {profile_path}")

    errors.extend(_find_overlaps(records))
    errors.extend(_find_unknown_dependencies(records))
    errors.extend(_find_package_cycles(records))
    return records, errors


def _is_within(path: Path, boundary: Path) -> bool:
    try:
        path.relative_to(boundary)
        return True
    except ValueError:
        return False


def _overlay_errors(root: Path, config: dict[str, Any], records: list[dict[str, Any]]) -> list[str]:
    if config.get("repository_role") != "upstream":
        return []
    errors: list[str] = []
    overlay_roots = [
        root / record["path"] for record in records if "overlay-owned" in record["classification"]
    ]
    for overlay_root in overlay_roots:
        if overlay_root.exists():
            errors.append(
                f"upstream repository contains downstream-only overlay path: "
                f"{overlay_root.relative_to(root)}"
            )

    generated_roots = [
        root / record["path"] for record in records if "generated" in record["classification"]
    ]
    for source in root.rglob("*"):
        if not source.is_file() or source.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        relative = source.relative_to(root)
        if any(part in SKIPPED_DIRECTORY_NAMES for part in relative.parts):
            continue
        if any(_is_within(source, boundary) for boundary in overlay_roots + generated_roots):
            continue
        try:
            text = source.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        suspicious_lines = [
            line
            for line in text.splitlines()
            if (
                any(token in line for token in ("import", "export", "require"))
                and (
                    OVERLAY_PATH_PATTERN.search(line)
                    or re.search(r"\b(?:from|import)\s+overlays(?:[.\s]|$)", line)
                )
            )
        ]
        if PYTHON_OVERLAY_IMPORT_PATTERN.search(text) or suspicious_lines:
            errors.append(f"upstream source imports downstream overlay path: {relative}")
    return errors


def _generated_metadata_errors(root: Path, records: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for record in records:
        declaration = record.get("generated_source_hash")
        if declaration is None:
            continue
        generated_root = root / record["path"]
        if not generated_root.exists():
            continue
        if not isinstance(declaration, dict):
            errors.append(f"{record['path']}: generated_source_hash must be an object")
            continue
        try:
            metadata_rel = _normalise_relative_path(
                declaration.get("metadata_file"),
                f"{record['path']}.generated_source_hash.metadata_file",
            )
        except OwnershipConfigError as exc:
            errors.append(str(exc))
            continue
        pattern = declaration.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            errors.append(f"{record['path']}: generated source-hash pattern is missing")
            continue
        metadata_path = generated_root / metadata_rel
        if not metadata_path.is_file():
            errors.append(
                f"{record['path']}: generated source-hash metadata is missing: {metadata_rel}"
            )
            continue
        try:
            metadata = metadata_path.read_text(encoding="utf-8")
            compiled = re.compile(pattern)
        except UnicodeDecodeError:
            errors.append(f"{record['path']}: source-hash metadata is not UTF-8 text")
            continue
        except re.error as exc:
            errors.append(f"{record['path']}: invalid source-hash pattern: {exc}")
            continue
        if compiled.search(metadata) is None:
            errors.append(
                f"{record['path']}: generated source-hash metadata does not match "
                f"the declared pattern in {metadata_rel}"
            )
    return errors


def _root_agent_ownership_errors(root: Path) -> list[str]:
    """Keep the historical root as the evaluation owner, never a second runtime."""

    agent_root = root / "agent"
    if not agent_root.exists():
        return []
    allowed = {"eval", "tests"}
    errors: list[str] = []
    for child in sorted(agent_root.iterdir()):
        if child.name in SKIPPED_DIRECTORY_NAMES:
            continue
        if child.name not in allowed:
            errors.append(
                f"unowned root-agent runtime path: {child.relative_to(root)}; "
                "agent/ may contain only eval/ and tests/"
            )
    return errors


def _platform_agent_neutrality_errors(root: Path) -> list[str]:
    """Reject product identity, prompts, and domain-tool ownership in composition."""

    platform_agent = root / "platform" / "agent"
    if not platform_agent.exists():
        return []
    errors: list[str] = []
    for source in sorted(platform_agent.rglob("*")):
        if not source.is_file() or source.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        relative = source.relative_to(root)
        if "generated" in relative.parts or any(
            part in SKIPPED_DIRECTORY_NAMES for part in relative.parts
        ):
            continue
        try:
            text = source.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for label, pattern in PLATFORM_AGENT_PRODUCT_PATTERNS.items():
            if pattern.search(text):
                errors.append(
                    f"platform agent contains {label}: {relative}; "
                    "move product behavior behind ProductManifest extension refs"
                )
    return errors


def _placeholder_value(value: str) -> bool:
    candidate = value.strip().rstrip(",").strip().strip("'\"")
    lowered = candidate.lower()
    return (
        not candidate
        or lowered in {"example", "none", "null", "placeholder", "replace_me", "sample"}
        or candidate.startswith(("${", "<", "{{"))
        or candidate.endswith((">", "}}"))
        or (candidate.upper() == candidate and " " not in candidate)
        or lowered.startswith(("example-", "sample-", "neutral-"))
    )


def _neutral_profile_errors(root: Path, config: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    customer_keys = config.get("neutral_profile_customer_keys", [])
    if not isinstance(customer_keys, list) or not all(
        isinstance(item, str) and item for item in customer_keys
    ):
        return ["neutral_profile_customer_keys must be an array of non-empty strings"]
    key_pattern = re.compile(
        rf"^\s*[\"']?(?:{'|'.join(re.escape(key) for key in customer_keys)})[\"']?"
        r"\s*[:=]\s*(.*?)\s*$",
        re.IGNORECASE,
    )
    for raw_profile_root in config.get("neutral_profile_paths", []):
        profile_root = root / raw_profile_root
        if not profile_root.exists():
            continue
        candidates = [profile_root] if profile_root.is_file() else profile_root.rglob("*")
        for candidate in candidates:
            if not candidate.is_file():
                continue
            try:
                text = candidate.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            relative = candidate.relative_to(root)
            for match in EMAIL_PATTERN.finditer(text):
                domain = match.group(1).lower()
                if domain not in {"example.com", "example.net", "example.org", "invalid"}:
                    errors.append(f"neutral profile contains an email identifier: {relative}")
                    break
            if DATABRICKS_HOST_PATTERN.search(text):
                errors.append(f"neutral profile contains a Databricks workspace host: {relative}")
            for line_number, line in enumerate(text.splitlines(), start=1):
                key_match = key_pattern.match(line)
                if key_match and not _placeholder_value(key_match.group(1)):
                    errors.append(
                        f"neutral profile contains a customer identifier field: "
                        f"{relative}:{line_number}"
                    )
    return errors


def check_repository(root: Path, config_path: Path) -> list[str]:
    root = root.resolve()
    config = load_config(config_path.resolve())
    records, errors = validate_config(config)
    if errors:
        return errors
    errors.extend(_overlay_errors(root, config, records))
    errors.extend(_generated_metadata_errors(root, records))
    errors.extend(_neutral_profile_errors(root, config))
    errors.extend(_root_agent_ownership_errors(root))
    errors.extend(_platform_agent_neutrality_errors(root))
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    default_root = Path(__file__).resolve().parents[1]
    parser.add_argument("--root", type=Path, default=default_root)
    parser.add_argument("--config", type=Path)
    args = parser.parse_args(argv)
    config_path = args.config or args.root / "OWNERSHIP.yaml"
    try:
        errors = check_repository(args.root, config_path)
    except (OSError, OwnershipConfigError) as exc:
        errors = [str(exc)]
    if errors:
        print("ownership boundary check failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    config = load_config(config_path)
    print(f"ownership boundary check passed ({len(config['paths'])} path records).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
