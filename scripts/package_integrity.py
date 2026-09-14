#!/usr/bin/env python3
"""Validate local packages and generate a deterministic SPDX dependency inventory."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

DEFAULT_OUTPUT = Path("docs/compatibility/dependency-inventory.spdx.json")
DEFAULT_POLICY = Path("scripts/package-policy.json")
LOCAL_CREATED = "1970-01-01T00:00:00Z"
LOCAL_SOURCE_COMMIT = "NOASSERTION"
IGNORED_PARTS = {
    ".git",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
}
LOCAL_DEPENDENCY_FIELDS = ("dependencies", "optionalDependencies", "peerDependencies")
SPDX_TOKEN = re.compile(r"(?:LicenseRef-[A-Za-z0-9.-]+|[A-Za-z0-9][A-Za-z0-9.-]*)")


class IntegrityError(ValueError):
    """Raised for an invalid package-integration declaration."""


def canonical_json(value: Any, *, pretty: bool = False) -> str:
    if pretty:
        return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _included_files(directory: Path) -> list[Path]:
    files: list[Path] = []
    for candidate in directory.rglob("*"):
        relative = candidate.relative_to(directory)
        if any(part in IGNORED_PARTS or part.endswith(".egg-info") for part in relative.parts):
            continue
        if candidate.is_symlink():
            raise IntegrityError(f"package contains a symlink: {directory.name}/{relative}")
        if candidate.is_file():
            files.append(candidate)
    return sorted(files, key=lambda item: item.relative_to(directory).as_posix())


def directory_digest(directory: Path) -> str:
    digest = hashlib.sha256()
    for path in _included_files(directory):
        relative = path.relative_to(directory).as_posix().encode("utf-8")
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise IntegrityError(f"required file is missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise IntegrityError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise IntegrityError(f"{path} must contain a JSON object")
    return value


def load_policy(root: Path, policy_path: Path | None = None) -> dict[str, Any]:
    path = policy_path or root / DEFAULT_POLICY
    policy = load_json(path)
    expected = policy.get("workspace_packages")
    forbidden = policy.get("forbidden_license_identifiers")
    reviewed = policy.get("reviewed_license_identifiers")
    if not isinstance(expected, list) or not expected:
        raise IntegrityError("package policy workspace_packages must be a non-empty array")
    if not isinstance(forbidden, list) or not all(
        isinstance(item, str) and item for item in forbidden
    ):
        raise IntegrityError("package policy forbidden_license_identifiers must be strings")
    if not isinstance(reviewed, list) or not all(
        isinstance(item, str) and item for item in reviewed
    ):
        raise IntegrityError("package policy reviewed_license_identifiers must be strings")
    overlap = set(forbidden).intersection(reviewed)
    if overlap:
        raise IntegrityError(
            f"license identifiers cannot be both forbidden and reviewed: {sorted(overlap)}"
        )
    return policy


def _workspace_patterns(root_manifest: dict[str, Any]) -> list[str]:
    workspaces = root_manifest.get("workspaces")
    if isinstance(workspaces, dict):
        workspaces = workspaces.get("packages")
    if not isinstance(workspaces, list) or not all(isinstance(item, str) for item in workspaces):
        raise IntegrityError("root package.json workspaces must be an array of paths")
    return workspaces


def _normalise_workspace_path(value: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "*" in value:
        raise IntegrityError(f"workspace entries must be explicit repository paths: {value!r}")
    return path.as_posix().rstrip("/")


def _expected_packages(policy: dict[str, Any]) -> dict[str, str]:
    expected: dict[str, str] = {}
    for index, entry in enumerate(policy["workspace_packages"]):
        if not isinstance(entry, dict):
            raise IntegrityError(f"workspace_packages[{index}] must be an object")
        path = entry.get("path")
        name = entry.get("name")
        if not isinstance(path, str) or not isinstance(name, str) or not path or not name:
            raise IntegrityError(f"workspace_packages[{index}] requires path and name")
        normalised = _normalise_workspace_path(path)
        if normalised in expected:
            raise IntegrityError(f"duplicate workspace package path: {normalised}")
        expected[normalised] = name
    return expected


def load_workspace_packages(
    root: Path, policy: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    root_manifest = load_json(root / "package.json")
    declared = {_normalise_workspace_path(item) for item in _workspace_patterns(root_manifest)}
    expected = _expected_packages(policy)
    if declared != set(expected):
        missing = sorted(set(expected) - declared)
        extra = sorted(declared - set(expected))
        detail = []
        if missing:
            detail.append(f"missing {', '.join(missing)}")
        if extra:
            detail.append(f"unexpected {', '.join(extra)}")
        raise IntegrityError(f"root npm workspaces do not match policy ({'; '.join(detail)})")

    packages: dict[str, dict[str, Any]] = {}
    for package_path, expected_name in sorted(expected.items()):
        manifest_path = root / package_path / "package.json"
        manifest = load_json(manifest_path)
        if manifest.get("name") != expected_name:
            raise IntegrityError(
                f"{package_path} name must be {expected_name!r}, got {manifest.get('name')!r}"
            )
        if not isinstance(manifest.get("version"), str) or not manifest["version"]:
            raise IntegrityError(f"{package_path} must declare a version")
        packages[package_path] = manifest
    return root_manifest, packages


def validate_root_lock(
    root: Path,
    root_manifest: dict[str, Any],
    packages: dict[str, dict[str, Any]],
) -> None:
    lock = load_json(root / "package-lock.json")
    lock_packages = lock.get("packages")
    if not isinstance(lock_packages, dict):
        raise IntegrityError("root package-lock.json packages must be an object")
    root_entry = lock_packages.get("")
    if not isinstance(root_entry, dict):
        raise IntegrityError("root package-lock.json is missing its root package entry")
    if root_entry.get("workspaces") != _workspace_patterns(root_manifest):
        raise IntegrityError("root package-lock.json workspace list is stale")

    by_name = {manifest["name"]: path for path, manifest in packages.items()}
    expected_keys = {""}
    for package_path, manifest in packages.items():
        expected_keys.add(package_path)
        link_path = f"node_modules/{manifest['name']}"
        expected_keys.add(link_path)
        locked = lock_packages.get(package_path)
        if not isinstance(locked, dict):
            raise IntegrityError(f"root package-lock.json is missing {package_path}")
        for field in ("name", "version"):
            if locked.get(field) != manifest.get(field):
                raise IntegrityError(f"root package-lock.json has stale {field} for {package_path}")
        expected_dependencies = manifest.get("dependencies")
        if expected_dependencies:
            if locked.get("dependencies") != expected_dependencies:
                raise IntegrityError(
                    f"root package-lock.json has stale dependencies for {package_path}"
                )
        elif "dependencies" in locked:
            raise IntegrityError(
                f"root package-lock.json has unexpected dependencies for {package_path}"
            )
        link = lock_packages.get(link_path)
        if link != {"resolved": package_path, "link": True}:
            raise IntegrityError(
                f"root package-lock.json has a stale workspace link for {package_path}"
            )

    extra = sorted(set(lock_packages) - expected_keys)
    if extra:
        raise IntegrityError(
            f"root package-lock.json contains non-workspace packages: {', '.join(extra)}"
        )
    encoded = canonical_json(lock)
    if re.search(r"https?://|(?:_auth|password|token)\s*[:=]", encoded, re.IGNORECASE):
        raise IntegrityError("root package-lock.json contains registry or credential metadata")
    for package_path, manifest in packages.items():
        for field in LOCAL_DEPENDENCY_FIELDS:
            for dependency_name in manifest.get(field, {}):
                if dependency_name not in by_name:
                    raise IntegrityError(
                        f"{package_path} lock dependency is not a workspace package: "
                        f"{dependency_name}"
                    )


def _ownership_dependencies(root: Path) -> dict[str, set[str]]:
    ownership = load_json(root / "OWNERSHIP.yaml")
    records = ownership.get("paths")
    if not isinstance(records, list):
        raise IntegrityError("OWNERSHIP.yaml paths must be an array")
    result: dict[str, set[str]] = {}
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            continue
        targets = record.get("allowed_dependency_targets", [])
        if isinstance(targets, list) and all(isinstance(item, str) for item in targets):
            result[record["path"]] = set(targets)
    return result


def local_dependency_graph(root: Path, packages: dict[str, dict[str, Any]]) -> dict[str, set[str]]:
    by_name = {manifest["name"]: path for path, manifest in packages.items()}
    ownership = _ownership_dependencies(root)
    graph: dict[str, set[str]] = {path: set() for path in packages}
    for package_path, manifest in packages.items():
        for field in LOCAL_DEPENDENCY_FIELDS:
            dependencies = manifest.get(field, {})
            if not isinstance(dependencies, dict):
                raise IntegrityError(f"{package_path} {field} must be an object")
            for dependency_name, declaration in dependencies.items():
                target = by_name.get(dependency_name)
                if target is None:
                    raise IntegrityError(
                        f"{package_path} has non-workspace {field} dependency {dependency_name!r}"
                    )
                expected_declaration = f"file:../{PurePosixPath(target).name}"
                if declaration != expected_declaration:
                    raise IntegrityError(
                        f"{package_path} dependency {dependency_name!r} must use "
                        f"{expected_declaration!r}"
                    )
                if target not in ownership.get(package_path, set()):
                    raise IntegrityError(
                        f"{package_path} depends on {target}, but OWNERSHIP.yaml does not allow it"
                    )
                graph[package_path].add(target)
    return graph


def assert_acyclic(graph: dict[str, set[str]]) -> None:
    visiting: list[str] = []
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            start = visiting.index(node)
            cycle = visiting[start:] + [node]
            raise IntegrityError(f"workspace package dependency cycle: {' -> '.join(cycle)}")
        if node in visited:
            return
        visiting.append(node)
        for target in sorted(graph[node]):
            visit(target)
        visiting.pop()
        visited.add(node)

    for node in sorted(graph):
        visit(node)


def validate_repository(
    root: Path, policy_path: Path | None = None
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], dict[str, set[str]], dict[str, Any]]:
    policy = load_policy(root, policy_path)
    root_manifest, packages = load_workspace_packages(root, policy)
    validate_root_lock(root, root_manifest, packages)
    graph = local_dependency_graph(root, packages)
    assert_acyclic(graph)
    return root_manifest, packages, graph, policy


def _license_value(value: Any) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return "NOASSERTION"


def _license_tokens(expression: str) -> set[str]:
    if expression == "NOASSERTION":
        return set()
    ignored = {"AND", "OR", "WITH"}
    return {token for token in SPDX_TOKEN.findall(expression) if token not in ignored}


def license_state(expression: str, forbidden: set[str], reviewed: set[str]) -> str:
    if expression == "NOASSERTION":
        return "review-required"
    tokens = _license_tokens(expression)
    if tokens.intersection(forbidden):
        return "forbidden"
    return "allowed" if tokens and tokens.issubset(reviewed) else "review-required"


def _spdx_id(ecosystem: str, identity: str) -> str:
    return f"SPDXRef-{ecosystem}-{sha256_bytes(identity.encode('utf-8'))[:20]}"


def _integrity_checksum(integrity: Any) -> dict[str, str] | None:
    if not isinstance(integrity, str) or "-" not in integrity:
        return None
    algorithm, encoded = integrity.split("-", 1)
    if algorithm not in {"sha256", "sha512"}:
        return None
    try:
        digest = base64.b64decode(encoded, validate=True).hex()
    except (ValueError, base64.binascii.Error):
        return None
    return {"algorithm": algorithm.upper(), "checksumValue": digest}


def _npm_name_from_lock_path(lock_path: str) -> str:
    marker = "node_modules/"
    name = lock_path.rsplit(marker, 1)[-1]
    return name


def parse_uv_packages(lock_text: str) -> list[dict[str, str]]:
    """Parse the stable scalar fields needed from uv.lock without a TOML dependency."""
    packages: list[dict[str, str]] = []
    for block in re.split(r"(?m)^\[\[package\]\]\s*$", lock_text)[1:]:
        entry: dict[str, str] = {}
        for key in ("name", "version", "license"):
            match = re.search(rf'(?m)^{key}\s*=\s*"([^"\r\n]+)"\s*$', block)
            if match:
                entry[key] = match.group(1)
        hash_match = re.search(r'\bhash\s*=\s*"sha256:([0-9a-fA-F]{64})"', block)
        if hash_match:
            entry["sha256"] = hash_match.group(1).lower()
        if "name" in entry and "version" in entry:
            packages.append(entry)
    return packages


def canonical_created(value: str) -> str:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise IntegrityError("created must be a canonical UTC timestamp (YYYY-MM-DDTHH:MM:SSZ)")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise IntegrityError("created is not a valid UTC timestamp") from exc
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


def verify_release_attestation(
    root: Path,
    source_commit: str,
    created: str,
    run: Any = subprocess.run,
) -> tuple[str, str]:
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise IntegrityError("release source commit must be a full lowercase 40-character SHA")
    canonical = canonical_created(created)
    verifier = root / "scripts/source-integrity.mjs"
    try:
        run(
            ["node", str(verifier), "verify-repository", str(root), source_commit],
            cwd=root,
            check=True,
        )
        status = run(
            [
                "git",
                "-C",
                str(root),
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise IntegrityError("release source commit or cleanliness verification failed") from exc
    if status.stdout.strip():
        raise IntegrityError("release-attested generation requires a completely clean repository")
    return source_commit, canonical


def _input_digest(root: Path, package_paths: list[str]) -> str:
    inputs = [
        "package.json",
        "package-lock.json",
        "OWNERSHIP.yaml",
        DEFAULT_POLICY.as_posix(),
        "platform/app/package-lock.json",
        "platform/agent/uv.lock",
        *package_paths,
    ]
    digest = hashlib.sha256()
    for relative in sorted(inputs):
        path = root / relative
        value = directory_digest(path) if path.is_dir() else sha256_file(path)
        encoded = relative.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(value.encode("ascii"))
    return digest.hexdigest()


def _package_record(
    *,
    spdx_id: str,
    name: str,
    version: str,
    license_expression: str,
    review_state: str,
    checksum: dict[str, str] | None = None,
    comment: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "SPDXID": spdx_id,
        "name": name,
        "versionInfo": version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": license_expression,
        "copyrightText": "NOASSERTION",
        "comment": comment or f"license-review: {review_state}",
    }
    if checksum is not None:
        result["checksums"] = [checksum]
    return result


def build_sbom(
    root: Path,
    policy_path: Path | None = None,
    *,
    source_commit: str = LOCAL_SOURCE_COMMIT,
    created: str = LOCAL_CREATED,
) -> dict[str, Any]:
    root_manifest, workspace_packages, graph, policy = validate_repository(root, policy_path)
    package_paths = sorted(workspace_packages)
    input_digest = _input_digest(root, package_paths)
    if source_commit != LOCAL_SOURCE_COMMIT and not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise IntegrityError("source commit must be NOASSERTION or a full lowercase commit SHA")
    created = canonical_created(created)
    forbidden = set(policy["forbidden_license_identifiers"])
    reviewed = set(policy["reviewed_license_identifiers"])
    packages: list[dict[str, Any]] = []
    relationships: list[dict[str, str]] = []

    root_id = _spdx_id("workspace", f"{root_manifest['name']}@{root_manifest['version']}")
    root_license = _license_value(root_manifest.get("license"))
    packages.append(
        _package_record(
            spdx_id=root_id,
            name=root_manifest["name"],
            version=root_manifest["version"],
            license_expression=root_license,
            review_state=license_state(root_license, forbidden, reviewed),
            checksum={"algorithm": "SHA256", "checksumValue": sha256_file(root / "package.json")},
            comment=(
                f"license-review: {license_state(root_license, forbidden, reviewed)}; "
                "scope: root workspace"
            ),
        )
    )

    workspace_ids: dict[str, str] = {}
    for package_path, manifest in sorted(workspace_packages.items()):
        identity = f"{manifest['name']}@{manifest['version']}:{package_path}"
        package_id = _spdx_id("workspace", identity)
        workspace_ids[package_path] = package_id
        expression = _license_value(manifest.get("license"))
        packages.append(
            _package_record(
                spdx_id=package_id,
                name=manifest["name"],
                version=manifest["version"],
                license_expression=expression,
                review_state=license_state(expression, forbidden, reviewed),
                checksum={
                    "algorithm": "SHA256",
                    "checksumValue": directory_digest(root / package_path),
                },
                comment=(
                    f"license-review: {license_state(expression, forbidden, reviewed)}; "
                    f"local-path: {package_path}"
                ),
            )
        )
        relationships.append(
            {
                "spdxElementId": root_id,
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": package_id,
            }
        )
    for source, targets in sorted(graph.items()):
        for target in sorted(targets):
            relationships.append(
                {
                    "spdxElementId": workspace_ids[source],
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": workspace_ids[target],
                }
            )

    app_lock = load_json(root / "platform/app/package-lock.json")
    app_entries = app_lock.get("packages")
    if not isinstance(app_entries, dict):
        raise IntegrityError("platform/app/package-lock.json packages must be an object")
    for lock_path, entry in sorted(app_entries.items()):
        if (
            not isinstance(lock_path, str)
            or "node_modules/" not in lock_path
            or not isinstance(entry, dict)
            or not isinstance(entry.get("version"), str)
        ):
            continue
        name = _npm_name_from_lock_path(lock_path)
        version = entry["version"]
        expression = _license_value(entry.get("license"))
        packages.append(
            _package_record(
                spdx_id=_spdx_id("npm", f"{lock_path}@{version}"),
                name=name,
                version=version,
                license_expression=expression,
                review_state=license_state(expression, forbidden, reviewed),
                checksum=_integrity_checksum(entry.get("integrity")),
                comment=(
                    f"license-review: {license_state(expression, forbidden, reviewed)}; "
                    "source: platform/app/package-lock.json"
                ),
            )
        )

    try:
        uv_packages = parse_uv_packages(
            (root / "platform/agent/uv.lock").read_text(encoding="utf-8")
        )
    except FileNotFoundError as exc:
        raise IntegrityError(f"cannot parse platform/agent/uv.lock: {exc}") from exc
    if not uv_packages:
        raise IntegrityError("platform/agent/uv.lock has no parseable package entries")
    for index, entry in enumerate(uv_packages):
        name = entry["name"]
        version = entry["version"]
        checksum = None
        if "sha256" in entry:
            checksum = {"algorithm": "SHA256", "checksumValue": entry["sha256"]}
        expression = _license_value(entry.get("license"))
        packages.append(
            _package_record(
                spdx_id=_spdx_id("python", f"{index}:{name}@{version}"),
                name=name,
                version=version,
                license_expression=expression,
                review_state=license_state(expression, forbidden, reviewed),
                checksum=checksum,
                comment=(
                    f"license-review: {license_state(expression, forbidden, reviewed)}; "
                    "source: platform/agent/uv.lock"
                ),
            )
        )

    packages.sort(key=lambda item: item["SPDXID"])
    relationships.sort(
        key=lambda item: (
            item["spdxElementId"],
            item["relationshipType"],
            item["relatedSpdxElement"],
        )
    )
    states = {
        "allowed": 0,
        "forbidden": 0,
        "review-required": 0,
    }
    for package in packages:
        states[license_state(package["licenseDeclared"], forbidden, reviewed)] += 1
    annotation = canonical_json(
        {
            "inputDigest": f"sha256:{input_digest}",
            "licenseReview": states,
            "sourceCommit": source_commit,
        }
    )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "insight-agent-harness-dependency-inventory",
        "documentNamespace": f"urn:insight-agent-harness:sbom:{input_digest}",
        "creationInfo": {
            "created": created,
            "creators": ["Tool: scripts/package_integrity.py"],
        },
        "annotations": [
            {
                "annotationDate": created,
                "annotationType": "OTHER",
                "annotator": "Tool: scripts/package_integrity.py",
                "comment": annotation,
            }
        ],
        "documentDescribes": [root_id],
        "packages": packages,
        "relationships": relationships,
    }


def policy_violations(document: dict[str, Any], forbidden: set[str]) -> list[str]:
    violations = []
    for package in document.get("packages", []):
        expression = package.get("licenseDeclared", "NOASSERTION")
        matches = sorted(_license_tokens(expression).intersection(forbidden))
        if matches:
            violations.append(
                f"{package.get('name')}@{package.get('versionInfo')}: "
                f"forbidden license identifier(s) {', '.join(matches)}"
            )
    return violations


def publication_violations(document: dict[str, Any], forbidden: set[str]) -> list[str]:
    violations = policy_violations(document, forbidden)
    for package in document.get("packages", []):
        if "license-review: review-required" in package.get("comment", ""):
            violations.append(
                f"{package.get('name')}@{package.get('versionInfo')}: license is review-required"
            )
    return violations


def _review_count(document: dict[str, Any]) -> int:
    return sum(
        "license-review: review-required" in package.get("comment", "")
        for package in document.get("packages", [])
    )


def check(root: Path, output: Path, policy_path: Path | None = None) -> list[str]:
    policy = load_policy(root, policy_path)
    document = build_sbom(root, policy_path)
    errors = policy_violations(document, set(policy["forbidden_license_identifiers"]))
    expected = canonical_json(document, pretty=True)
    try:
        actual = output.read_text(encoding="utf-8")
    except FileNotFoundError:
        errors.append(f"generated SBOM is missing: {output}")
    else:
        if actual != expected:
            errors.append(f"generated SBOM is stale or a package digest was tampered: {output}")
    return errors


def _resolved_output(root: Path, value: Path | None, default: Path | None) -> Path:
    selected = value or default
    if selected is None:
        raise IntegrityError("an explicit --output path is required")
    return selected.resolve() if selected.is_absolute() else (root / selected).resolve()


def _within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def validate_release_output(root: Path, output: Path, package_paths: list[str]) -> None:
    root = root.resolve()
    output = output.resolve()
    checked_output = (root / DEFAULT_OUTPUT).resolve()
    if output == checked_output:
        raise IntegrityError("release-attested output must not replace the checked-in inventory")
    input_paths = [
        root / "package.json",
        root / "package-lock.json",
        root / "OWNERSHIP.yaml",
        root / DEFAULT_POLICY,
        root / "platform/app/package-lock.json",
        root / "platform/agent/uv.lock",
        *(root / package_path for package_path in package_paths),
    ]
    if any(output == path.resolve() or _within(output, path.resolve()) for path in input_paths):
        raise IntegrityError("release-attested output must be outside SBOM source inputs")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=("generate", "check", "release-generate", "license-final-check"),
    )
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--source-commit")
    parser.add_argument("--created")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    policy_path = args.policy.resolve() if args.policy else None
    try:
        output = _resolved_output(
            root,
            args.output,
            DEFAULT_OUTPUT
            if args.command in {"generate", "check", "license-final-check"}
            else None,
        )
        if args.command == "release-generate":
            if args.source_commit is None or args.created is None:
                raise IntegrityError("release-generate requires --source-commit and --created")
            source_commit, created = verify_release_attestation(
                root, args.source_commit, args.created
            )
            policy = load_policy(root, policy_path)
            _, workspace_packages = load_workspace_packages(root, policy)
            validate_release_output(root, output, sorted(workspace_packages))
            document = build_sbom(
                root,
                policy_path,
                source_commit=source_commit,
                created=created,
            )
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(canonical_json(document, pretty=True), encoding="utf-8")
            print(f"wrote release-attested SBOM: {output}")
            return 0
        if args.command == "generate":
            policy = load_policy(root, policy_path)
            document = build_sbom(root, policy_path)
            violations = policy_violations(document, set(policy["forbidden_license_identifiers"]))
            if violations:
                for violation in violations:
                    print(f"ERROR: {violation}", file=sys.stderr)
                return 1
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(canonical_json(document, pretty=True), encoding="utf-8")
            print(
                f"wrote deterministic SBOM with {len(document['packages'])} packages; "
                f"{_review_count(document)} license entries require review"
            )
            return 0
        if args.command == "license-final-check":
            errors = check(root, output, policy_path)
            document = build_sbom(root, policy_path)
            policy = load_policy(root, policy_path)
            errors = sorted(
                set(errors).union(
                    publication_violations(document, set(policy["forbidden_license_identifiers"]))
                )
            )
            if errors:
                print(
                    f"ERROR: final publication license gate blocked {len(errors)} issue(s)",
                    file=sys.stderr,
                )
                for error in errors:
                    print(f"  - {error}", file=sys.stderr)
                return 1
            print("final publication license gate passed")
            return 0
        errors = check(root, output, policy_path)
        if errors:
            for error in errors:
                print(f"ERROR: {error}", file=sys.stderr)
            return 1
        document = build_sbom(root, policy_path)
        print(
            f"package integrity and SBOM check passed; "
            f"{_review_count(document)} license entries require review"
        )
        return 0
    except (IntegrityError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
