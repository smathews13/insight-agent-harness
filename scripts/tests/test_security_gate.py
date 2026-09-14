from __future__ import annotations

import hashlib
import hmac
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "security_gate.py"
FIXTURE = Path(__file__).parent / "fixtures/security/vulnerable.ts"
NOW = "2026-09-13T12:00:00Z"


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def signed_document(value: dict[str, object]) -> dict[str, object]:
    result = dict(value)
    result["document_sha256"] = hashlib.sha256(canonical(value).encode()).hexdigest()
    return result


def run(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args, "--root", str(root), "--now", NOW],
        check=False,
        capture_output=True,
        text=True,
    )


class SecurityGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        write_json(
            self.root / "security/security-gate-policy.json",
            {
                "advisory_max_age_days": 7,
                "attestation_max_age_days": 7,
                "approved_external_scanners": [
                    "committed-advisory-snapshot",
                    "test-scanner",
                ],
                "approved_sql_identifier_helpers": ["quoteIdentifier"],
                "excluded_paths": [],
                "schema_version": "1.0",
                "suppression_max_days": 180,
            },
        )
        self.write_allowlist([])

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_allowlist(self, entries: list[dict[str, object]]) -> None:
        write_json(
            self.root / "security/sast-allowlist.json",
            {
                "entries": entries,
                "entries_sha256": hashlib.sha256(canonical(entries).encode()).hexdigest(),
                "schema_version": "1.0",
            },
        )

    def track(self) -> None:
        subprocess.run(["git", "-C", str(self.root), "add", "-A"], check=True)

    def write_dependency_inputs(self) -> str:
        for relative in (
            "package.json",
            "package-lock.json",
            "platform/app/package.json",
            "platform/app/package-lock.json",
        ):
            write_json(self.root / relative, {"name": relative, "dependencies": {}})
        (self.root / "platform/agent").mkdir(parents=True, exist_ok=True)
        (self.root / "platform/agent/pyproject.toml").write_text(
            '[project]\nname = "fixture"\nversion = "1.0.0"\n', encoding="utf-8"
        )
        (self.root / "platform/agent/uv.lock").write_text(
            'version = 1\n[[package]]\nname = "fixture"\nversion = "1.0.0"\n',
            encoding="utf-8",
        )
        sys.path.insert(0, str(SCRIPT.parent))
        try:
            import security_gate

            return security_gate.dependency_inventory_sha256(self.root)
        finally:
            sys.path.pop(0)

    def write_advisory(
        self,
        inventory: str,
        *,
        generated_at: str = NOW,
        status: str = "verified",
        vulnerabilities: list[dict[str, object]] | None = None,
    ) -> Path:
        path = self.root / "advisory.json"
        write_json(
            path,
            signed_document(
                {
                    "generated_at": generated_at,
                    "inventory_sha256": inventory,
                    "scanner": "test-scanner",
                    "schema_version": "1.0",
                    "status": status,
                    "vulnerabilities": vulnerabilities or [],
                }
            ),
        )
        return path

    def write_trust_and_verifier(self) -> tuple[Path, Path]:
        trust = self.root / "trust-root.txt"
        trust.write_text("fixture-trust-root\n", encoding="utf-8")
        verifier = self.root / "verifier.py"
        verifier.write_text(
            "import pathlib, sys\n"
            "evidence, subject, trust = sys.argv[1:4]\n"
            "assert pathlib.Path(evidence).is_file()\n"
            "assert subject\n"
            "assert pathlib.Path(trust).read_text() == 'fixture-trust-root\\n'\n",
            encoding="utf-8",
        )
        return trust, verifier

    def commit(self) -> str:
        self.track()
        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "-c",
                "user.name=Security Test",
                "-c",
                "user.email=security-test@example.invalid",
                "commit",
                "-qm",
                "fixture",
            ],
            check=True,
        )
        return subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def test_vulnerable_fixture_emits_each_local_rule_as_json(self) -> None:
        destination = self.root / "src/vulnerable.ts"
        destination.parent.mkdir(parents=True)
        shutil.copyfile(FIXTURE, destination)
        self.track()

        result = run(self.root, "sast")

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        rules = {finding["rule_id"] for finding in report["findings"]}
        self.assertEqual(
            rules,
            {
                "SAST-DYNAMIC-CODE",
                "SAST-SECRET-LOG",
                "SAST-SHELL-INTERPOLATION",
                "SAST-SQL-IDENTIFIER-INTERPOLATION",
                "SAST-TOKEN-PERSISTENCE",
                "SAST-UNBOUNDED-NETWORK",
                "SAST-UNSAFE-DESERIALIZATION",
            },
        )
        self.assertNotIn("console.log(token)", result.stdout)
        self.assertEqual(report["engine"]["kind"], "deterministic-heuristic")

    def test_suppression_requires_review_metadata_and_cannot_expire(self) -> None:
        source = self.root / "src/log.ts"
        source.parent.mkdir(parents=True)
        source.write_text("console.log(token);\n", encoding="utf-8")
        self.track()
        initial = json.loads(run(self.root, "sast").stdout)
        finding = initial["findings"][0]
        self.write_allowlist(
            [
                {
                    "approved": True,
                    "expires_on": "2026-09-12",
                    "fingerprint": finding["fingerprint"],
                    "owner": "security@example.invalid",
                    "path": finding["path"],
                    "reason": "Time-bounded fixture review",
                    "review_reference": "SEC-123",
                    "reviewed_by": "reviewer@example.invalid",
                    "rule_id": finding["rule_id"],
                }
            ]
        )
        self.track()

        expired = run(self.root, "sast")

        self.assertEqual(expired.returncode, 1)
        report = json.loads(expired.stdout)
        self.assertEqual(report["findings"][0]["disposition"], "expired-suppression")

    def test_allowlist_tampering_is_unverified(self) -> None:
        path = self.root / "security/sast-allowlist.json"
        value = json.loads(path.read_text())
        value["entries"].append({"approved": True})
        write_json(path, value)
        self.track()

        result = run(self.root, "sast")

        self.assertEqual(result.returncode, 2)
        self.assertIn("entries_sha256 does not match", result.stdout)

    def test_critical_findings_cannot_be_suppressed(self) -> None:
        source = self.root / "src/storage.ts"
        source.parent.mkdir(parents=True)
        source.write_text("localStorage.setItem('token', token);\n", encoding="utf-8")
        self.track()
        finding = json.loads(run(self.root, "sast").stdout)["findings"][0]
        self.write_allowlist(
            [
                {
                    "approved": True,
                    "expires_on": "2026-10-01",
                    "fingerprint": finding["fingerprint"],
                    "owner": "security-owner",
                    "path": finding["path"],
                    "reason": "Fixture attempts to suppress a critical finding.",
                    "review_reference": "SEC-124",
                    "reviewed_by": "independent-reviewer",
                    "rule_id": finding["rule_id"],
                }
            ]
        )
        self.track()

        result = run(self.root, "sast")

        self.assertEqual(result.returncode, 1)
        self.assertEqual(
            json.loads(result.stdout)["findings"][0]["disposition"],
            "invalid-suppression",
        )

    def test_multiline_sast_evasion_and_helper_name_comment_are_detected(self) -> None:
        source = self.root / "src/evasive.ts"
        source.parent.mkdir(parents=True)
        source.write_text(
            'import { execSync } from "node:child_process";\n'
            "console.log(\n  token\n);\n"
            "execSync(\n  command\n);\n"
            "eval(\n  userInput\n);\n"
            "fetch(\n  url\n);\n"
            "query(`SELECT * FROM ${table} /* quoteIdentifier */`);\n"
            "localStorage.setItem(\n  'token', token\n);\n"
            "pickle.loads(\n  payload\n);\n",
            encoding="utf-8",
        )
        self.track()

        result = run(self.root, "sast")

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        rules = {finding["rule_id"] for finding in json.loads(result.stdout)["findings"]}
        self.assertEqual(
            rules,
            {
                "SAST-DYNAMIC-CODE",
                "SAST-SECRET-LOG",
                "SAST-SHELL-INTERPOLATION",
                "SAST-SQL-IDENTIFIER-INTERPOLATION",
                "SAST-TOKEN-PERSISTENCE",
                "SAST-UNBOUNDED-NETWORK",
                "SAST-UNSAFE-DESERIALIZATION",
            },
        )

    def test_tracked_source_symlink_escape_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as outside_dir:
            outside = Path(outside_dir) / "outside.ts"
            outside.write_text("console.log(token);\n", encoding="utf-8")
            source = self.root / "src/linked.ts"
            source.parent.mkdir(parents=True)
            source.symlink_to(outside)
            self.track()

            result = run(self.root, "sast")

        self.assertEqual(result.returncode, 2)
        self.assertIn("must not be a symbolic link", result.stdout)

    def test_orphan_and_wildcard_suppressions_are_refused(self) -> None:
        entry = {
            "approved": True,
            "expires_on": "2026-10-01",
            "fingerprint": "0" * 64,
            "owner": "security-owner",
            "path": "src/*.ts",
            "reason": "Reviewed fixture suppression with exact evidence.",
            "review_reference": "SEC-123",
            "reviewed_by": "independent-reviewer",
            "rule_id": "SAST-DYNAMIC-CODE",
        }
        self.write_allowlist([entry])
        self.track()
        wildcard = run(self.root, "sast")
        self.assertEqual(wildcard.returncode, 2)
        self.assertIn("path must be exact and canonical", wildcard.stdout)

        entry["path"] = "src/removed.ts"
        self.write_allowlist([entry])
        self.track()
        orphan = run(self.root, "sast")
        self.assertEqual(orphan.returncode, 1)
        self.assertEqual(
            json.loads(orphan.stdout)["findings"][0]["disposition"],
            "invalid-suppression",
        )

    def test_dependency_gate_blocks_high_vulnerability_and_tampering(self) -> None:
        inventory = self.write_dependency_inputs()
        advisory = self.write_advisory(
            inventory,
            vulnerabilities=[
                {
                    "id": "TEST-CRITICAL-1",
                    "package": "fixture",
                    "severity": "critical",
                    "status": "open",
                }
            ],
        )

        informational = run(
            self.root, "dependency", "--mode", "fast", "--advisory", str(advisory)
        )
        vulnerable = run(self.root, "dependency", "--mode", "strict", "--advisory", str(advisory))
        self.assertEqual(informational.returncode, 0)
        informational_report = json.loads(informational.stdout)
        self.assertEqual(informational_report["status"], "unverified")
        self.assertEqual(len(informational_report["blocking_vulnerabilities"]), 1)
        self.assertIn("UNVERIFIED", informational_report["warning"])
        self.assertEqual(vulnerable.returncode, 1)
        self.assertEqual(json.loads(vulnerable.stdout)["status"], "blocked")

        value = json.loads(advisory.read_text())
        value["vulnerabilities"] = []
        write_json(advisory, value)
        tampered = run(self.root, "dependency", "--mode", "strict", "--advisory", str(advisory))
        self.assertEqual(tampered.returncode, 2)
        self.assertIn("document_sha256 does not match", tampered.stdout)

    def test_stale_advisory_allows_fast_but_blocks_final(self) -> None:
        inventory = self.write_dependency_inputs()
        advisory = self.write_advisory(inventory, generated_at="2026-08-01T00:00:00Z")

        fast = run(self.root, "dependency", "--mode", "fast", "--advisory", str(advisory))
        strict = run(self.root, "dependency", "--mode", "strict", "--advisory", str(advisory))

        self.assertEqual(fast.returncode, 0)
        self.assertEqual(json.loads(fast.stdout)["status"], "unverified")
        self.assertIn("UNVERIFIED", json.loads(fast.stdout)["warning"])
        self.assertEqual(strict.returncode, 2)
        self.assertEqual(json.loads(strict.stdout)["status"], "unverified")

    def test_missing_or_mismatched_advisory_is_informational_unless_strict(self) -> None:
        inventory = self.write_dependency_inputs()
        missing = self.root / "missing-advisory.json"

        missing_fast = run(
            self.root, "dependency", "--mode", "fast", "--advisory", str(missing)
        )
        missing_strict = run(self.root, "dependency", "--strict", "--advisory", str(missing))

        self.assertEqual(missing_fast.returncode, 0, missing_fast.stdout + missing_fast.stderr)
        missing_report = json.loads(missing_fast.stdout)
        self.assertEqual(missing_report["status"], "unverified")
        self.assertIn("UNVERIFIED", missing_report["warning"])
        self.assertIn("is missing", missing_report["advisory"]["validation_error"])
        self.assertEqual(missing_strict.returncode, 2)

        advisory = self.write_advisory("0" * 64)
        mismatched_fast = run(
            self.root, "dependency", "--mode", "fast", "--advisory", str(advisory)
        )
        mismatched_strict = run(
            self.root, "dependency", "--strict", "--advisory", str(advisory)
        )

        self.assertEqual(mismatched_fast.returncode, 0)
        mismatched_report = json.loads(mismatched_fast.stdout)
        self.assertIn("does not match", mismatched_report["advisory"]["validation_error"])
        self.assertIn("UNVERIFIED", mismatched_report["warning"])
        self.assertEqual(mismatched_strict.returncode, 2)
        self.assertNotEqual(inventory, "0" * 64)

    def test_dependency_evidence_requires_trusted_verifier_and_rejects_self_rehashed_tamper(
        self,
    ) -> None:
        inventory = self.write_dependency_inputs()
        trust = self.root / "advisory-trust.key"
        trust.write_bytes(b"fixture-advisory-key")
        base: dict[str, object] = {
            "generated_at": NOW,
            "inventory_sha256": inventory,
            "scanner": "test-scanner",
            "schema_version": "1.0",
            "status": "verified",
            "vulnerabilities": [],
        }
        base["signature"] = hmac.new(
            trust.read_bytes(), canonical(base).encode(), hashlib.sha256
        ).hexdigest()
        advisory = self.root / "advisory-signed.json"
        write_json(advisory, signed_document(base))
        verifier = self.root / "advisory-verifier.py"
        verifier.write_text(
            "import hashlib, hmac, json, pathlib, sys\n"
            "path, inventory, trust = sys.argv[1:4]\n"
            "value = json.loads(pathlib.Path(path).read_text())\n"
            "value.pop('document_sha256')\n"
            "signature = value.pop('signature')\n"
            "payload = json.dumps(value, ensure_ascii=True, "
            "separators=(',', ':'), sort_keys=True).encode()\n"
            "expected = hmac.new(pathlib.Path(trust).read_bytes(), payload, "
            "hashlib.sha256).hexdigest()\n"
            "raise SystemExit(0 if hmac.compare_digest(signature, expected) "
            "and value['inventory_sha256'] == inventory else 1)\n",
            encoding="utf-8",
        )
        verifier_json = json.dumps(
            [
                sys.executable,
                str(verifier),
                "{advisory}",
                "{inventory}",
                "{trust_root}",
            ]
        )

        untrusted = run(self.root, "dependency", "--mode", "strict", "--advisory", str(advisory))
        self.assertEqual(untrusted.returncode, 2)
        self.assertIn("verifier is not configured", untrusted.stdout)

        trusted = run(
            self.root,
            "dependency",
            "--mode",
            "strict",
            "--advisory",
            str(advisory),
            "--advisory-verifier-json",
            verifier_json,
            "--advisory-trust-root",
            str(trust),
        )
        self.assertEqual(trusted.returncode, 0, trusted.stdout + trusted.stderr)
        self.assertEqual(json.loads(trusted.stdout)["status"], "passed")

        tampered = json.loads(advisory.read_text())
        tampered["vulnerabilities"] = [
            {"id": "LOW-1", "package": "fixture", "severity": "low", "status": "open"}
        ]
        tampered.pop("document_sha256")
        write_json(advisory, signed_document(tampered))
        rejected = run(
            self.root,
            "dependency",
            "--mode",
            "strict",
            "--advisory",
            str(advisory),
            "--advisory-verifier-json",
            verifier_json,
            "--advisory-trust-root",
            str(trust),
        )
        self.assertEqual(rejected.returncode, 1)
        self.assertEqual(json.loads(rejected.stdout)["advisory"]["verifier_exit_code"], 1)

    def test_malformed_dependency_evidence_is_visible_and_strict_only(self) -> None:
        inventory = self.write_dependency_inputs()
        advisory = self.write_advisory(
            inventory,
            vulnerabilities=[{"id": "UNKNOWN-1", "package": "fixture", "status": "open"}],
        )

        missing_severity = run(
            self.root, "dependency", "--mode", "fast", "--advisory", str(advisory)
        )

        self.assertEqual(missing_severity.returncode, 0)
        missing_report = json.loads(missing_severity.stdout)
        self.assertEqual(missing_report["status"], "unverified")
        self.assertIn("severity is missing", missing_report["advisory"]["validation_error"])
        self.assertIn("UNVERIFIED", missing_report["warning"])

        advisory = self.write_advisory(
            inventory,
            vulnerabilities=[
                {
                    "id": "UNKNOWN-2",
                    "package": "fixture",
                    "severity": "unknown",
                    "status": "open",
                }
            ],
        )
        unknown_severity = run(
            self.root, "dependency", "--mode", "fast", "--advisory", str(advisory)
        )
        strict = run(self.root, "dependency", "--strict", "--advisory", str(advisory))
        self.assertEqual(unknown_severity.returncode, 0)
        self.assertIn(
            "invalid severity",
            json.loads(unknown_severity.stdout)["advisory"]["validation_error"],
        )
        self.assertEqual(strict.returncode, 2)

    def test_dependency_inventory_binds_workspace_manifests(self) -> None:
        self.write_dependency_inputs()
        workspace_manifest = self.root / "packages/example/package.json"
        write_json(
            workspace_manifest,
            {"name": "example", "dependencies": {"fixture": "1.0.0"}},
        )
        self.track()
        sys.path.insert(0, str(SCRIPT.parent))
        try:
            import security_gate

            before = security_gate.dependency_inventory_sha256(self.root)
            write_json(
                workspace_manifest,
                {"name": "example", "dependencies": {"fixture": "1.0.1"}},
            )
            after = security_gate.dependency_inventory_sha256(self.root)
        finally:
            sys.path.pop(0)

        self.assertNotEqual(before, after)

    def test_npm_ranges_escaping_file_targets_and_mutable_overrides_block(self) -> None:
        self.write_dependency_inputs()
        write_json(
            self.root / "platform/app/package.json",
            {
                "dependencies": {
                    "exact": "1.2.3",
                    "range": "^1.2.3",
                    "escape": "file:../../../outside",
                },
                "overrides": {"nested": {"child": "~2.0.0"}},
            },
        )
        self.track()
        sys.path.insert(0, str(SCRIPT.parent))
        try:
            import security_gate

            inventory = security_gate.dependency_inventory_sha256(self.root)
        finally:
            sys.path.pop(0)
        advisory = self.write_advisory(inventory)

        result = run(self.root, "dependency", "--mode", "fast", "--advisory", str(advisory))

        self.assertEqual(result.returncode, 1)
        dependencies = {
            finding["dependency"]
            for finding in json.loads(result.stdout)["mutable_npm_dependencies"]
        }
        self.assertEqual(dependencies, {"range", "escape", "overrides.nested.child"})

    def test_attestation_status_and_verifier_cannot_be_bypassed(self) -> None:
        inventory = self.write_dependency_inputs()
        commit = self.commit()
        trust, verifier = self.write_trust_and_verifier()
        attestation = self.root / "attestation.json"
        base = {
            "expires_at": "2026-09-20T00:00:00Z",
            "generated_at": NOW,
            "schema_version": "1.0",
            "status": "unverified",
            "subject": {
                "commit": commit,
                "dependency_inventory_sha256": inventory,
            },
        }
        write_json(attestation, signed_document(base))
        verifier_json = json.dumps(
            [
                sys.executable,
                str(verifier),
                "{attestation}",
                "{commit}",
                "{trust_root}",
            ]
        )

        claimed = run(
            self.root,
            "attestation",
            "--mode",
            "strict",
            "--attestation",
            str(attestation),
            "--verifier-json",
            verifier_json,
            "--attestation-trust-root",
            str(trust),
        )
        self.assertEqual(claimed.returncode, 1)
        self.assertFalse(json.loads(claimed.stdout)["status_claim_verified"])

        base["status"] = "verified"
        base["subject"]["commit"] = "0" * 40
        write_json(attestation, signed_document(base))
        wrong_subject = run(
            self.root,
            "attestation",
            "--mode",
            "strict",
            "--attestation",
            str(attestation),
            "--verifier-json",
            verifier_json,
            "--attestation-trust-root",
            str(trust),
        )
        self.assertEqual(wrong_subject.returncode, 1)
        self.assertFalse(json.loads(wrong_subject.stdout)["binding_valid"])

        base["subject"]["commit"] = commit
        write_json(attestation, signed_document(base))
        missing_verifier = run(
            self.root,
            "attestation",
            "--mode",
            "strict",
            "--attestation",
            str(attestation),
        )
        self.assertEqual(missing_verifier.returncode, 2)
        self.assertIn("not configured", missing_verifier.stdout)

    def test_attestation_requires_trust_and_rejects_shell_like_verifier_arguments(
        self,
    ) -> None:
        inventory = self.write_dependency_inputs()
        commit = self.commit()
        trust, verifier = self.write_trust_and_verifier()
        attestation = self.root / "attestation.json"
        write_json(
            attestation,
            signed_document(
                {
                    "expires_at": "2026-09-20T00:00:00Z",
                    "generated_at": NOW,
                    "schema_version": "1.0",
                    "status": "verified",
                    "subject": {
                        "commit": commit,
                        "dependency_inventory_sha256": inventory,
                    },
                }
            ),
        )
        marker = self.root / "shell-injected"
        malformed = json.dumps(
            [
                sys.executable,
                str(verifier),
                f"{{attestation}};touch {marker}",
                "{commit}",
                "{trust_root}",
            ]
        )

        result = run(
            self.root,
            "attestation",
            "--mode",
            "strict",
            "--attestation",
            str(attestation),
            "--verifier-json",
            malformed,
            "--attestation-trust-root",
            str(trust),
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("missing required placeholders", result.stdout)
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
