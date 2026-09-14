#!/usr/bin/env python3
"""Deterministic local security checks and strict external-evidence adapters.

The local SAST rules are intentionally narrow heuristics, not a claim of complete
static analysis. Final release additionally requires fresh dependency evidence and
an independently verified upstream attestation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA_VERSION = "1.0"
DEFAULT_POLICY = Path("security/security-gate-policy.json")
DEFAULT_ALLOWLIST = Path("security/sast-allowlist.json")
DEFAULT_ADVISORY = Path("security/advisory-snapshot.json")
SOURCE_SUFFIXES = {".cjs", ".js", ".mjs", ".py", ".sh", ".ts", ".tsx"}
REQUIRED_DEPENDENCY_INPUTS = (
    "package.json",
    "package-lock.json",
    "platform/app/package.json",
    "platform/app/package-lock.json",
    "platform/agent/pyproject.toml",
    "platform/agent/uv.lock",
)
SEVERITY_ORDER = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
VULNERABILITY_STATUSES = {"open", "fixed", "not_affected"}
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


class GateError(ValueError):
    """A malformed or unavailable security input."""


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    title: str
    pattern: re.Pattern[str]


RULES = (
    Rule(
        "SAST-SECRET-LOG",
        "high",
        "Possible secret or authorization material written to logs",
        re.compile(
            r"(?:console\.(?:debug|error|info|log|warn)|print|logging\.\w+)\s*\(\s*"
            r"(?:(?=[A-Za-z_$][\w$]*\b)(?=[\w$]*(?:authorization|cookie|password|secret|token))"
            r"[A-Za-z_$][\w$]*|"
            r"`[^`]*\$\{[^}]*(?:authorization|cookie|password|secret|token)[^}]*\})",
            re.IGNORECASE,
        ),
    ),
    Rule(
        "SAST-SHELL-INTERPOLATION",
        "high",
        "Possible dynamic command execution or shell interpolation",
        re.compile(
            r"(?:\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|[A-Za-z_$])|"
            r"\b(?:os\.system|subprocess\.(?:call|check_output|Popen|run))\s*\("
            r"[^;\n]*(?:shell\s*=\s*True|f[\"']|\.format\s*\())"
        ),
    ),
    Rule(
        "SAST-DYNAMIC-CODE",
        "high",
        "Dynamic code evaluation requires explicit review",
        re.compile(
            r"(?:(?<![.\w])eval\s*\(|\bnew\s+Function\s*\(|"
            r"(?<![.\w])Function\s*\(\s*[A-Za-z_$]|"
            r"(?<![.\w])(?:exec|compile)\s*\(\s*[A-Za-z_])"
        ),
    ),
    Rule(
        "SAST-UNBOUNDED-NETWORK",
        "high",
        "Possible user-controlled or unbounded network destination",
        re.compile(
            r"(?:\bfetch\s*\(\s*(?:req(?:uest)?\.|input\b|user\w*|url\b)|"
            r"\b(?:axios|httpx|requests)\.(?:delete|get|head|patch|post|put)\s*\("
            r"\s*(?:req(?:uest)?\.|input\b|user\w*|url\b))",
            re.IGNORECASE,
        ),
    ),
    Rule(
        "SAST-SQL-IDENTIFIER-INTERPOLATION",
        "high",
        "SQL interpolation outside an approved identifier helper",
        re.compile(
            r"(?:\b(?:execute|query)\s*\(\s*`[^`]*\$\{|"
            r"\b(?:execute|query)\s*\(\s*f[\"'][^\"']*\{)"
        ),
    ),
    Rule(
        "SAST-TOKEN-PERSISTENCE",
        "critical",
        "Possible token or authorization-header persistence",
        re.compile(
            r"(?:\b(?:localStorage|sessionStorage)\.setItem\s*\([^;]{0,1000}"
            r"(?:authorization|cookie|secret|token)|"
            r"\b(?:writeFile|write_text|write_bytes)\s*\([^;]{0,1000}"
            r"(?:authorization|cookie|secret|token))",
            re.IGNORECASE,
        ),
    ),
    Rule(
        "SAST-UNSAFE-DESERIALIZATION",
        "critical",
        "Unsafe deserialization primitive",
        re.compile(
            r"(?:\b(?:dill|marshal|pickle)\.loads?\s*\(|"
            r"\byaml\.(?:full_load|load|unsafe_load)\s*\(|"
            r"\bv8\.deserialize\s*\(|\bunserialize\s*\()"
        ),
    ),
)
SUPPRESSION_PATTERN = re.compile(r"security-gate\s*:\s*(?:ignore|suppress)", re.IGNORECASE)
EXACT_NPM_VERSION = re.compile(r"^(?:v)?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")
JS_SHELL_PATTERN = re.compile(r"(?<![.\w])(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|[A-Za-z_$])")
PYTHON_SHELL_PATTERN = re.compile(
    r"\b(?:os\.system|subprocess\.(?:call|check_output|Popen|run))\s*\("
    r"[^;\n]*(?:shell\s*=\s*True|f[\"']|\.format\s*\()"
)
PYTHON_MULTILINE_SHELL_PATTERN = re.compile(
    r"\b(?:os\.system|subprocess\.(?:call|check_output|Popen|run))\s*\("
    r"[^;]{0,1000}?shell\s*=\s*True"
)
SHELL_SHELL_PATTERN = re.compile(r"\b(?:bash|sh|zsh)\s+-c\s+[\"']?\$|\beval\s+[\"']?\$")
SAST_WINDOW_LINES = 8


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_regular_file(path: Path, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise GateError(f"{label} is missing: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise GateError(f"{label} must not be a symbolic link: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise GateError(f"{label} must be a regular file: {path}")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise GateError(f"{label} could not be read: {path}: {exc}") from exc


def load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(read_regular_file(path, label).decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise GateError(f"{label} is not valid UTF-8: {path}") from exc
    except json.JSONDecodeError as exc:
        raise GateError(f"{label} is invalid JSON: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise GateError(f"{label} must be a JSON object: {path}")
    return value


def resolve(root: Path, value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else root / path


def parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise GateError(f"{label} must be a non-empty ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GateError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise GateError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def now_from_arg(value: str | None) -> datetime:
    return parse_time(value, "--now") if value else datetime.now(timezone.utc)


def verified_document(value: dict[str, Any], label: str) -> None:
    if value.get("schema_version") != SCHEMA_VERSION:
        raise GateError(f"{label} schema_version is unsupported")
    expected = value.get("document_sha256")
    if not isinstance(expected, str) or not SHA256_PATTERN.fullmatch(expected):
        raise GateError(f"{label} document_sha256 is missing or invalid")
    unsigned = dict(value)
    del unsigned["document_sha256"]
    actual = sha256_bytes(canonical_json(unsigned).encode("utf-8"))
    if actual != expected:
        raise GateError(f"{label} document_sha256 does not match its content")


def nonnegative_int(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise GateError(f"{label} must be a non-negative integer")
    return value


def load_policy(root: Path, path: Path) -> dict[str, Any]:
    policy = load_object(resolve(root, path), "security gate policy")
    if policy.get("schema_version") != SCHEMA_VERSION:
        raise GateError("security gate policy schema_version is unsupported")
    scanners = policy.get("approved_external_scanners")
    if not isinstance(scanners, list) or not all(
        isinstance(item, str) and item for item in scanners
    ):
        raise GateError("approved_external_scanners must be a non-empty string array")
    excluded = policy.get("excluded_paths")
    if not isinstance(excluded, list) or not all(isinstance(item, str) for item in excluded):
        raise GateError("excluded_paths must be a string array")
    for item in excluded:
        normalized = PurePosixPath(item)
        if (
            not item
            or "\\" in item
            or normalized.is_absolute()
            or normalized.as_posix() != item.rstrip("/")
            or ".." in normalized.parts
            or "." in normalized.parts
        ):
            raise GateError(f"excluded path is not a canonical repository path: {item!r}")
    freshness = policy.get("advisory_max_age_days")
    if not isinstance(freshness, int) or freshness < 1:
        raise GateError("advisory_max_age_days must be a positive integer")
    attestation_freshness = policy.get("attestation_max_age_days")
    if not isinstance(attestation_freshness, int) or attestation_freshness < 1:
        raise GateError("attestation_max_age_days must be a positive integer")
    suppression_lifetime = policy.get("suppression_max_days")
    if not isinstance(suppression_lifetime, int) or suppression_lifetime < 1:
        raise GateError("suppression_max_days must be a positive integer")
    helpers = policy.get("approved_sql_identifier_helpers")
    if not isinstance(helpers, list) or not all(
        isinstance(item, str) and re.fullmatch(r"[A-Za-z_$][\w$]*", item) for item in helpers
    ):
        raise GateError("approved_sql_identifier_helpers must be an identifier array")
    return policy


def tracked_files(root: Path) -> list[str]:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise GateError("could not enumerate tracked files with git") from exc
    try:
        return sorted(raw.decode("utf-8") for raw in result.stdout.split(b"\0") if raw)
    except UnicodeDecodeError as exc:
        raise GateError("tracked repository path is not valid UTF-8") from exc


def tracked_sources(root: Path, policy: dict[str, Any]) -> list[Path]:
    excluded = tuple(value.rstrip("/") for value in policy["excluded_paths"])
    files: list[Path] = []
    for relative in tracked_files(root):
        if Path(relative).suffix not in SOURCE_SUFFIXES:
            continue
        if any(relative == prefix or relative.startswith(f"{prefix}/") for prefix in excluded):
            continue
        candidate = root / relative
        try:
            metadata = candidate.lstat()
        except FileNotFoundError as exc:
            raise GateError(f"tracked source is missing from the working tree: {relative}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise GateError(f"tracked source must not be a symbolic link: {relative}")
        if not stat.S_ISREG(metadata.st_mode):
            raise GateError(f"tracked source must be a regular file: {relative}")
        files.append(candidate)
    return sorted(files, key=lambda item: item.relative_to(root).as_posix())


def finding_fingerprint(rule_id: str, path: str, line_text: str) -> str:
    normalized = " ".join(line_text.strip().split())
    material = f"{rule_id}\0{path}\0{normalized}".encode()
    return sha256_bytes(material)


def approved_sql_interpolation(evidence: str, helpers: tuple[str, ...]) -> bool:
    expressions = re.findall(r"\$\{([^{}]*)\}", evidence)
    if not expressions:
        expressions = re.findall(r"\{([^{}]*)\}", evidence)
    if not expressions or not helpers:
        return False
    helper_pattern = "|".join(re.escape(helper) for helper in helpers)
    return all(
        re.fullmatch(rf"\s*(?:{helper_pattern})\s*\([^()]*\)\s*", expression)
        for expression in expressions
    )


def local_sast_findings(root: Path, policy: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    approved_sql_helpers = tuple(policy.get("approved_sql_identifier_helpers", []))
    for path in tracked_sources(root, policy):
        relative = path.relative_to(root).as_posix()
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError as exc:
            raise GateError(f"source is not valid UTF-8: {relative}") from exc
        source_text = "\n".join(lines)
        for index, line in enumerate(lines):
            line_number = index + 1
            stripped = line.lstrip()
            if stripped.startswith(("#", "/*", "*", "//")):
                continue
            evidence = "\n".join(lines[index : index + SAST_WINDOW_LINES])
            for rule in RULES:
                if rule.rule_id == "SAST-SHELL-INTERPOLATION":
                    if path.suffix in {".cjs", ".js", ".mjs", ".ts", ".tsx"}:
                        if (
                            "child_process" not in source_text
                            and "node:child_process" not in source_text
                        ):
                            continue
                        match = JS_SHELL_PATTERN.search(evidence)
                    elif path.suffix == ".py":
                        match = PYTHON_SHELL_PATTERN.search(
                            line
                        ) or PYTHON_MULTILINE_SHELL_PATTERN.search(evidence)
                    elif path.suffix == ".sh":
                        match = SHELL_SHELL_PATTERN.search(evidence)
                    else:
                        match = None
                else:
                    rule_evidence = (
                        line if rule.rule_id == "SAST-SQL-IDENTIFIER-INTERPOLATION" else evidence
                    )
                    match = rule.pattern.search(rule_evidence)
                if not match or match.start() > len(line):
                    continue
                if (
                    rule.rule_id == "SAST-SQL-IDENTIFIER-INTERPOLATION"
                    and approved_sql_interpolation(line, approved_sql_helpers)
                ):
                    continue
                matched_evidence = line if "\n" not in match.group(0) else match.group(0)
                findings.append(
                    {
                        "column": match.start() + 1,
                        "confidence": "heuristic",
                        "evidence_sha256": sha256_bytes(matched_evidence.encode("utf-8")),
                        "fingerprint": finding_fingerprint(
                            rule.rule_id, relative, matched_evidence
                        ),
                        "line": line_number,
                        "message": rule.title,
                        "path": relative,
                        "rule_id": rule.rule_id,
                        "scanner": "local-deterministic-sast",
                        "severity": rule.severity,
                    }
                )
            if SUPPRESSION_PATTERN.search(line):
                findings.append(
                    {
                        "column": SUPPRESSION_PATTERN.search(line).start() + 1,
                        "confidence": "high",
                        "evidence_sha256": sha256_bytes(line.encode("utf-8")),
                        "fingerprint": finding_fingerprint(
                            "SAST-UNREVIEWED-SUPPRESSION", relative, line
                        ),
                        "line": line_number,
                        "message": "Inline suppression is not a reviewed allowlist entry",
                        "path": relative,
                        "rule_id": "SAST-UNREVIEWED-SUPPRESSION",
                        "scanner": "local-deterministic-sast",
                        "severity": "high",
                    }
                )
    return findings


def load_allowlist(
    root: Path, path: Path, now: datetime, policy: dict[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    allowlist = load_object(resolve(root, path), "SAST allowlist")
    if allowlist.get("schema_version") != SCHEMA_VERSION:
        raise GateError("SAST allowlist schema_version is unsupported")
    entries = allowlist.get("entries")
    if not isinstance(entries, list):
        raise GateError("SAST allowlist entries must be an array")
    expected = allowlist.get("entries_sha256")
    actual = sha256_bytes(canonical_json(entries).encode("utf-8"))
    if not isinstance(expected, str) or not SHA256_PATTERN.fullmatch(expected):
        raise GateError("SAST allowlist entries_sha256 is missing or invalid")
    if expected != actual:
        raise GateError("SAST allowlist entries_sha256 does not match its entries")
    expired: list[str] = []
    fingerprints: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise GateError(f"SAST allowlist entry {index} must be an object")
        required_strings = (
            "expires_on",
            "fingerprint",
            "owner",
            "path",
            "reason",
            "review_reference",
            "reviewed_by",
            "rule_id",
        )
        if any(
            not isinstance(entry.get(field), str) or not entry[field] for field in required_strings
        ):
            raise GateError(f"SAST allowlist entry {index} is missing review metadata")
        if any(entry[field] != entry[field].strip() for field in required_strings):
            raise GateError(f"SAST allowlist entry {index} metadata must not have outer whitespace")
        if entry.get("approved") is not True:
            raise GateError(f"SAST allowlist entry {index} is not approved")
        fingerprint = entry["fingerprint"]
        if not SHA256_PATTERN.fullmatch(fingerprint):
            raise GateError(f"SAST allowlist entry {index} fingerprint is invalid")
        if fingerprint in fingerprints:
            raise GateError(f"SAST allowlist fingerprint is duplicated: {fingerprint}")
        fingerprints.add(fingerprint)
        relative = PurePosixPath(entry["path"])
        if (
            "\\" in entry["path"]
            or relative.is_absolute()
            or relative.as_posix() != entry["path"]
            or ".." in relative.parts
            or any(character in entry["path"] for character in "*?[")
        ):
            raise GateError(f"SAST allowlist entry {index} path must be exact and canonical")
        if len(entry["reason"]) < 20:
            raise GateError(f"SAST allowlist entry {index} reason is too short")
        if entry["owner"] == entry["reviewed_by"]:
            raise GateError(f"SAST allowlist entry {index} owner and reviewer must differ")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", entry["expires_on"]):
            raise GateError(f"SAST allowlist entry {index} expires_on must be YYYY-MM-DD")
        expiry = parse_time(f"{entry['expires_on']}T23:59:59Z", f"entry {index} expires_on")
        if (expiry - now).total_seconds() > policy["suppression_max_days"] * 86400:
            raise GateError(
                f"SAST allowlist entry {index} exceeds the maximum suppression lifetime"
            )
        if expiry < now:
            expired.append(fingerprint)
    return allowlist, expired


def apply_allowlist(
    findings: list[dict[str, Any]], allowlist: dict[str, Any], expired: list[str]
) -> list[dict[str, Any]]:
    entries = {entry["fingerprint"]: entry for entry in allowlist["entries"]}
    output: list[dict[str, Any]] = []
    for finding in findings:
        entry = entries.get(finding["fingerprint"])
        disposition = "active"
        if entry:
            exact = entry["rule_id"] == finding["rule_id"] and entry["path"] == finding["path"]
            if finding["severity"] == "critical":
                disposition = "invalid-suppression"
            elif exact and finding["fingerprint"] not in expired:
                disposition = "suppressed"
            elif finding["fingerprint"] in expired:
                disposition = "expired-suppression"
            else:
                disposition = "invalid-suppression"
        output.append({**finding, "disposition": disposition})
    for fingerprint in expired:
        entry = entries[fingerprint]
        if not any(item["fingerprint"] == fingerprint for item in output):
            output.append(
                {
                    "column": 0,
                    "confidence": "high",
                    "disposition": "expired-suppression",
                    "evidence_sha256": "",
                    "fingerprint": fingerprint,
                    "line": 0,
                    "message": "Reviewed suppression expired and must be removed or re-reviewed",
                    "path": entry["path"],
                    "rule_id": entry["rule_id"],
                    "scanner": "allowlist-validator",
                    "severity": "high",
                }
            )
    used = {item["fingerprint"] for item in output}
    for fingerprint, entry in entries.items():
        if fingerprint in used:
            continue
        output.append(
            {
                "column": 0,
                "confidence": "high",
                "disposition": "invalid-suppression",
                "evidence_sha256": "",
                "fingerprint": fingerprint,
                "line": 0,
                "message": "Reviewed suppression no longer matches a current finding",
                "path": entry["path"],
                "rule_id": entry["rule_id"],
                "scanner": "allowlist-validator",
                "severity": "high",
            }
        )
    return sorted(
        output,
        key=lambda item: (item["path"], item["line"], item["rule_id"], item["fingerprint"]),
    )


def external_sast_findings(
    root: Path, paths: list[str], policy: dict[str, Any]
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    approved = set(policy["approved_external_scanners"])
    for raw_path in paths:
        path = resolve(root, raw_path)
        document = load_object(path, "external SAST result")
        verified_document(document, f"external SAST result {path}")
        scanner = document.get("scanner")
        if scanner not in approved:
            raise GateError(f"external SAST scanner is not approved: {scanner!r}")
        if document.get("status") != "verified":
            raise GateError(f"external SAST result is not verified: {path}")
        findings = document.get("findings")
        if not isinstance(findings, list):
            raise GateError(f"external SAST findings must be an array: {path}")
        for index, finding in enumerate(findings):
            if not isinstance(finding, dict):
                raise GateError(f"external SAST finding {index} must be an object")
            required = ("fingerprint", "message", "path", "rule_id", "severity")
            if any(
                not isinstance(finding.get(field), str) or not finding[field] for field in required
            ):
                raise GateError(f"external SAST finding {index} is incomplete")
            severity = finding["severity"].lower()
            if severity not in SEVERITY_ORDER:
                raise GateError(f"external SAST finding {index} has an invalid severity")
            fingerprint = finding["fingerprint"]
            if not SHA256_PATTERN.fullmatch(fingerprint):
                raise GateError(f"external SAST finding {index} fingerprint is invalid")
            finding_path = PurePosixPath(finding["path"])
            if (
                "\\" in finding["path"]
                or finding_path.is_absolute()
                or finding_path.as_posix() != finding["path"]
                or ".." in finding_path.parts
            ):
                raise GateError(f"external SAST finding {index} path is not canonical")
            output.append(
                {
                    "column": nonnegative_int(
                        finding.get("column", 0), f"external SAST finding {index} column"
                    ),
                    "confidence": str(finding.get("confidence", "external")),
                    "evidence_sha256": str(finding.get("evidence_sha256", "")),
                    "fingerprint": fingerprint,
                    "line": nonnegative_int(
                        finding.get("line", 0), f"external SAST finding {index} line"
                    ),
                    "message": finding["message"],
                    "path": finding_path.as_posix(),
                    "rule_id": finding["rule_id"],
                    "scanner": scanner,
                    "severity": severity,
                }
            )
    return output


def sast_report(
    args: argparse.Namespace, policy: dict[str, Any], now: datetime
) -> tuple[dict[str, Any], int]:
    findings = local_sast_findings(args.root, policy)
    findings.extend(external_sast_findings(args.root, args.external_results, policy))
    allowlist, expired = load_allowlist(args.root, args.allowlist, now, policy)
    findings = apply_allowlist(findings, allowlist, expired)
    active = [item for item in findings if item["disposition"] != "suppressed"]
    report = {
        "engine": {
            "kind": "deterministic-heuristic",
            "limitations": (
                "Pattern checks are high-signal local guardrails, not comprehensive SAST. "
                "Final assurance may merge approved external scanner output."
            ),
            "name": "insight-agent-harness-local-sast",
        },
        "findings": findings,
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "schema_version": SCHEMA_VERSION,
        "status": "blocked" if active else "passed",
        "summary": {
            "active": len(active),
            "active_by_rule": {
                rule_id: sum(1 for item in active if item["rule_id"] == rule_id)
                for rule_id in sorted({item["rule_id"] for item in active})
            },
            "scanned_files": len(tracked_sources(args.root, policy)),
            "suppressed": len(findings) - len(active),
        },
    }
    return report, 1 if active else 0


def dependency_inventory_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    dependency_inputs = set(REQUIRED_DEPENDENCY_INPUTS)
    dependency_inputs.update(
        path
        for path in tracked_files(root)
        if path.endswith(("package.json", "package-lock.json"))
        and "node_modules" not in PurePosixPath(path).parts
        and "node_modules.partial-harness" not in PurePosixPath(path).parts
        and not path.startswith(("platform/app/build/", "platform/app/dist/"))
    )
    for relative in sorted(dependency_inputs):
        path = root / relative
        content = read_regular_file(path, f"dependency input {relative}")
        encoded = relative.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def local_npm_dependency_is_pinned(
    root: Path, manifest_path: Path, requirement: str, tracked: set[str]
) -> bool:
    if not requirement.startswith("file:"):
        return False
    raw_target = requirement.removeprefix("file:")
    if not raw_target or Path(raw_target).is_absolute():
        return False
    target = (manifest_path.parent / raw_target).resolve()
    if not target.is_relative_to(root):
        return False
    relative_target = target.relative_to(root)
    current = root
    for part in relative_target.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            return False
        if stat.S_ISLNK(metadata.st_mode):
            return False
    package_manifest = target / "package.json" if target.is_dir() else target
    return package_manifest.relative_to(root).as_posix() in tracked


def npm_requirement_is_pinned(
    root: Path,
    manifest_path: Path,
    requirement: str,
    tracked: set[str],
) -> bool:
    alias = requirement.startswith("npm:") and bool(
        re.fullmatch(
            r"npm:(?:@[^/@]+/)?[^/@]+@\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?",
            requirement,
        )
    )
    return bool(
        EXACT_NPM_VERSION.fullmatch(requirement)
        or alias
        or local_npm_dependency_is_pinned(root, manifest_path, requirement, tracked)
    )


def npm_pin_findings(root: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    tracked = set(tracked_files(root))
    for relative_text in sorted(path for path in tracked if path.endswith("package.json")):
        relative = PurePosixPath(relative_text)
        if (
            "node_modules" in relative.parts
            or "node_modules.partial-harness" in relative.parts
            or relative_text.startswith("platform/app/build/")
            or relative_text.startswith("platform/app/dist/")
        ):
            continue
        manifest_path = root / relative_text
        manifest = load_object(manifest_path, "npm manifest")
        for field in ("dependencies", "devDependencies", "optionalDependencies"):
            dependencies = manifest.get(field, {})
            if not isinstance(dependencies, dict):
                raise GateError(f"{relative} {field} must be an object")
            for name, version in sorted(dependencies.items()):
                if not isinstance(version, str):
                    raise GateError(f"{relative} dependency {name} has a non-string version")
                if not npm_requirement_is_pinned(root, manifest_path, version, tracked):
                    findings.append(
                        {
                            "dependency": name,
                            "field": field,
                            "manifest": relative.as_posix(),
                            "requirement": version,
                        }
                    )
        overrides = manifest.get("overrides", {})
        if not isinstance(overrides, dict):
            raise GateError(f"{relative} overrides must be an object")
        pending = [(f"overrides.{name}", value) for name, value in overrides.items()]
        while pending:
            name, value = pending.pop()
            if isinstance(value, dict):
                pending.extend(
                    (f"{name}.{child_name}", child_value)
                    for child_name, child_value in value.items()
                )
                continue
            if not isinstance(value, str):
                raise GateError(f"{relative} {name} must be a string or object")
            if not npm_requirement_is_pinned(root, manifest_path, value, tracked):
                findings.append(
                    {
                        "dependency": name,
                        "field": "overrides",
                        "manifest": relative.as_posix(),
                        "requirement": value,
                    }
                )
    return findings


def git_head(root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise GateError("could not resolve repository HEAD") from exc
    return result.stdout.strip()


def verifier_argv(
    raw: str,
    *,
    replacements: dict[str, str],
    required_placeholders: set[str],
    label: str,
) -> list[str]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise GateError(f"{label} verifier must be a JSON argv array") from exc
    if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
        raise GateError(f"{label} verifier must be a non-empty JSON string array")
    configured_placeholders = {item for item in value if item in replacements}
    missing = required_placeholders - configured_placeholders
    if missing:
        raise GateError(
            f"{label} verifier is missing required placeholders: {', '.join(sorted(missing))}"
        )
    output: list[str] = []
    for item in value:
        unknown = re.findall(r"\{[^{}]+\}", item)
        if any(token not in replacements for token in unknown):
            raise GateError(f"{label} verifier contains an unknown placeholder: {item}")
        for token, replacement in replacements.items():
            item = item.replace(token, replacement)
        output.append(item)
    return output


def run_verifier(argv: list[str], root: Path, label: str) -> int:
    try:
        result = subprocess.run(
            argv,
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GateError(f"{label} verifier could not run: {exc}") from exc
    return result.returncode


def dependency_report(
    args: argparse.Namespace, policy: dict[str, Any], now: datetime
) -> tuple[dict[str, Any], int]:
    inventory = dependency_inventory_sha256(args.root)
    pins = npm_pin_findings(args.root)
    advisory_path = resolve(args.root, args.advisory)
    advisory = load_object(advisory_path, "dependency advisory input")
    verified_document(advisory, "dependency advisory input")
    scanner = advisory.get("scanner")
    if scanner not in set(policy["approved_external_scanners"]):
        raise GateError(f"dependency advisory scanner is not approved: {scanner!r}")
    if advisory.get("inventory_sha256") != inventory:
        raise GateError("dependency advisory inventory_sha256 does not match current lock inputs")
    generated_at = parse_time(advisory.get("generated_at"), "advisory generated_at")
    age_seconds = (now - generated_at).total_seconds()
    fresh = 0 <= age_seconds <= policy["advisory_max_age_days"] * 86400
    status_claim_verified = advisory.get("status") == "verified"
    vulnerabilities = advisory.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise GateError("dependency advisory vulnerabilities must be an array")
    blocking: list[dict[str, Any]] = []
    for index, vulnerability in enumerate(vulnerabilities):
        if not isinstance(vulnerability, dict):
            raise GateError(f"dependency vulnerability {index} must be an object")
        severity_value = vulnerability.get("severity")
        status_value = vulnerability.get("status")
        if not isinstance(severity_value, str) or not severity_value:
            raise GateError(f"dependency vulnerability {index} severity is missing")
        if not isinstance(status_value, str) or not status_value:
            raise GateError(f"dependency vulnerability {index} status is missing")
        severity = severity_value.lower()
        status = status_value.lower()
        if severity not in SEVERITY_ORDER or severity == "unknown":
            raise GateError(f"dependency vulnerability {index} has an invalid severity")
        if status not in VULNERABILITY_STATUSES:
            raise GateError(f"dependency vulnerability {index} has an invalid status")
        if severity in {"critical", "high"} and status == "open":
            blocking.append(vulnerability)

    raw_verifier = args.advisory_verifier_json or os.environ.get(
        "SECURITY_DEPENDENCY_ADVISORY_VERIFIER_JSON", ""
    )
    raw_trust_root = args.advisory_trust_root or os.environ.get(
        "SECURITY_DEPENDENCY_ADVISORY_TRUST_ROOT", ""
    )
    verifier_exit_code: int | None = None
    if args.mode == "strict" and raw_verifier and raw_trust_root:
        trust_root = resolve(args.root, raw_trust_root)
        read_regular_file(trust_root, "dependency advisory trust root")
        argv = verifier_argv(
            raw_verifier,
            replacements={
                "{advisory}": str(advisory_path),
                "{inventory}": inventory,
                "{repository}": str(args.root),
                "{trust_root}": str(trust_root),
            },
            required_placeholders={"{advisory}", "{inventory}", "{trust_root}"},
            label="dependency advisory",
        )
        verifier_exit_code = run_verifier(argv, args.root, "dependency advisory")

    state = "unverified"
    exit_code = 0
    reason = "external verification is final-only"
    if pins or blocking:
        state = "blocked"
        exit_code = 1
        reason = "mutable npm dependencies or open high/critical vulnerabilities"
    elif args.mode == "strict":
        if not raw_verifier:
            exit_code = 2
            reason = "dependency advisory verifier is not configured"
        elif not raw_trust_root:
            exit_code = 2
            reason = "dependency advisory trust root is not configured"
        elif not (fresh and status_claim_verified and verifier_exit_code == 0):
            exit_code = 1
            state = "blocked"
            reason = "advisory claim, freshness, and trusted verifier must all pass"
        else:
            state = "passed"
            reason = ""
    report = {
        "advisory": {
            "fresh": fresh,
            "generated_at": advisory.get("generated_at"),
            "path": advisory_path.relative_to(args.root).as_posix()
            if advisory_path.is_relative_to(args.root)
            else str(advisory_path),
            "scanner": scanner,
            "status_claim_verified": status_claim_verified,
            "trust_root_configured": bool(raw_trust_root),
            "verifier_configured": bool(raw_verifier),
            "verifier_exit_code": verifier_exit_code,
        },
        "blocking_vulnerabilities": blocking,
        "inventory_sha256": inventory,
        "mode": args.mode,
        "mutable_npm_dependencies": pins,
        "python_resolution": {
            "authoritative_lock": "platform/agent/uv.lock",
            "present": (args.root / "platform/agent/uv.lock").is_file(),
        },
        "reason": reason,
        "schema_version": SCHEMA_VERSION,
        "status": state,
    }
    return report, exit_code


def attestation_report(
    args: argparse.Namespace, policy: dict[str, Any], now: datetime
) -> tuple[dict[str, Any], int]:
    raw_path = args.attestation or os.environ.get("SECURITY_UPSTREAM_ATTESTATION_FILE", "")
    raw_verifier = args.verifier_json or os.environ.get("SECURITY_ATTESTATION_VERIFIER_JSON", "")
    raw_trust_root = args.attestation_trust_root or os.environ.get(
        "SECURITY_ATTESTATION_TRUST_ROOT", ""
    )
    base = {
        "mode": args.mode,
        "schema_version": SCHEMA_VERSION,
        "status": "unverified",
        "trust_root_configured": bool(raw_trust_root),
        "verifier_configured": bool(raw_verifier),
    }
    if not raw_path:
        return {**base, "reason": "upstream attestation file is not configured"}, (
            2 if args.mode == "strict" else 0
        )
    path = resolve(args.root, raw_path)
    attestation = load_object(path, "upstream attestation")
    verified_document(attestation, "upstream attestation")
    commit = git_head(args.root)
    subject = attestation.get("subject")
    if not isinstance(subject, dict):
        raise GateError("upstream attestation subject must be an object")
    binding_ok = subject.get("commit") == commit and subject.get(
        "dependency_inventory_sha256"
    ) == dependency_inventory_sha256(args.root)
    generated = parse_time(attestation.get("generated_at"), "attestation generated_at")
    expires = parse_time(attestation.get("expires_at"), "attestation expires_at")
    age_seconds = (now - generated).total_seconds()
    fresh = (
        generated <= now <= expires
        and 0 <= age_seconds <= policy["attestation_max_age_days"] * 86400
    )
    status_verified = attestation.get("status") == "verified"
    if args.mode == "fast":
        return {
            **base,
            "binding_valid": binding_ok,
            "fresh": fresh,
            "reason": "attestation structure checked; external verification is final-only",
            "status_claim_verified": status_verified,
        }, 0
    if not raw_verifier:
        return {
            **base,
            "binding_valid": binding_ok,
            "fresh": fresh,
            "reason": "external attestation verifier is not configured",
            "status_claim_verified": status_verified,
        }, 2
    if not raw_trust_root:
        return {
            **base,
            "binding_valid": binding_ok,
            "fresh": fresh,
            "reason": "external attestation trust root is not configured",
            "status_claim_verified": status_verified,
        }, 2
    trust_root = resolve(args.root, raw_trust_root)
    read_regular_file(trust_root, "attestation trust root")
    argv = verifier_argv(
        raw_verifier,
        replacements={
            "{attestation}": str(path),
            "{commit}": commit,
            "{repository}": str(args.root),
            "{trust_root}": str(trust_root),
        },
        required_placeholders={"{attestation}", "{commit}", "{trust_root}"},
        label="attestation",
    )
    verifier_exit_code = run_verifier(argv, args.root, "attestation")
    verifier_ok = verifier_exit_code == 0
    passed = status_verified and binding_ok and fresh and verifier_ok
    return {
        **base,
        "binding_valid": binding_ok,
        "fresh": fresh,
        "reason": ""
        if passed
        else "attestation claim, binding, freshness, and verifier must all pass",
        "status": "passed" if passed else "blocked",
        "status_claim_verified": status_verified,
        "verifier_exit_code": verifier_exit_code,
    }, 0 if passed else 1


def emit(report: dict[str, Any], output: str) -> None:
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if output:
        Path(output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


def parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    common.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    common.add_argument("--now")
    common.add_argument("--output", default="")
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="command", required=True)
    sast = subparsers.add_parser("sast", parents=[common])
    sast.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    sast.add_argument("--external-results", action="append", default=[])
    dependency = subparsers.add_parser("dependency", parents=[common])
    dependency.add_argument("--mode", choices=("fast", "strict"), default="fast")
    dependency.add_argument(
        "--advisory",
        type=Path,
        default=Path(os.environ.get("SECURITY_DEPENDENCY_ADVISORY_FILE", DEFAULT_ADVISORY)),
    )
    dependency.add_argument("--advisory-verifier-json", default="")
    dependency.add_argument("--advisory-trust-root", default="")
    attestation = subparsers.add_parser("attestation", parents=[common])
    attestation.add_argument("--mode", choices=("fast", "strict"), default="fast")
    attestation.add_argument("--attestation", default="")
    attestation.add_argument("--verifier-json", default="")
    attestation.add_argument("--attestation-trust-root", default="")
    final = subparsers.add_parser("final", parents=[common])
    final.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    final.add_argument("--external-results", action="append", default=[])
    final.add_argument(
        "--advisory",
        type=Path,
        default=Path(os.environ.get("SECURITY_DEPENDENCY_ADVISORY_FILE", DEFAULT_ADVISORY)),
    )
    final.add_argument("--advisory-verifier-json", default="")
    final.add_argument("--advisory-trust-root", default="")
    final.add_argument("--attestation", default="")
    final.add_argument("--verifier-json", default="")
    final.add_argument("--attestation-trust-root", default="")
    return result


def main() -> int:
    args = parser().parse_args()
    args.root = args.root.resolve()
    try:
        policy = load_policy(args.root, args.policy)
        now = now_from_arg(args.now)
        if args.command == "sast":
            report, status = sast_report(args, policy, now)
        elif args.command == "dependency":
            report, status = dependency_report(args, policy, now)
        elif args.command == "attestation":
            report, status = attestation_report(args, policy, now)
        else:
            sast, sast_status = sast_report(args, policy, now)
            args.mode = "strict"
            dependency, dependency_status = dependency_report(args, policy, now)
            attestation, attestation_status = attestation_report(args, policy, now)
            statuses = (sast_status, dependency_status, attestation_status)
            report = {
                "checks": {
                    "attestation": attestation,
                    "dependency": dependency,
                    "sast": sast,
                },
                "schema_version": SCHEMA_VERSION,
                "status": "passed" if not any(statuses) else "blocked",
            }
            status = 2 if 2 in statuses else (1 if any(statuses) else 0)
        emit(report, args.output)
        return status
    except GateError as exc:
        emit(
            {
                "error": str(exc),
                "schema_version": SCHEMA_VERSION,
                "status": "unverified",
            },
            args.output,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
