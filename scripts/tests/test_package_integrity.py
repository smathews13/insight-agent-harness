from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "package_integrity.py"
SPEC = importlib.util.spec_from_file_location("package_integrity", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
integrity = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(integrity)


class PackageIntegrityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.paths = ["packages/contracts", "packages/governance"]
        self._write_json(
            "package.json",
            {
                "name": "test-workspace",
                "version": "1.0.0",
                "private": True,
                "workspaces": self.paths,
            },
        )
        self._write_json(
            "package-lock.json",
            {
                "name": "test-workspace",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "packages": {
                    "": {
                        "name": "test-workspace",
                        "version": "1.0.0",
                        "workspaces": self.paths,
                    },
                    "node_modules/@test/contracts": {
                        "resolved": "packages/contracts",
                        "link": True,
                    },
                    "node_modules/@test/governance": {
                        "resolved": "packages/governance",
                        "link": True,
                    },
                    "packages/contracts": {
                        "name": "@test/contracts",
                        "version": "1.0.0",
                    },
                    "packages/governance": {
                        "name": "@test/governance",
                        "version": "1.0.0",
                        "dependencies": {"@test/contracts": "file:../contracts"},
                    },
                },
            },
        )
        self._write_json(
            "scripts/package-policy.json",
            {
                "forbidden_license_identifiers": ["AGPL-3.0-only", "SSPL-1.0"],
                "reviewed_license_identifiers": ["Apache-2.0", "MIT"],
                "workspace_packages": [
                    {"path": "packages/contracts", "name": "@test/contracts"},
                    {"path": "packages/governance", "name": "@test/governance"},
                ],
            },
        )
        self._write_json(
            "OWNERSHIP.yaml",
            {
                "paths": [
                    {
                        "path": "packages/contracts",
                        "allowed_dependency_targets": [],
                    },
                    {
                        "path": "packages/governance",
                        "allowed_dependency_targets": ["packages/contracts"],
                    },
                ]
            },
        )
        self._write_json(
            "packages/contracts/package.json",
            {"name": "@test/contracts", "version": "1.0.0", "license": "MIT"},
        )
        self._write_text("packages/contracts/src/index.js", "export const value = 1;\n")
        self._write_json(
            "packages/governance/package.json",
            {
                "name": "@test/governance",
                "version": "1.0.0",
                "dependencies": {"@test/contracts": "file:../contracts"},
            },
        )
        self._write_text("packages/governance/src/index.js", "export const allowed = true;\n")
        self._write_json(
            "platform/app/package-lock.json",
            {
                "name": "app",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "app", "version": "1.0.0"},
                    "node_modules/example": {
                        "version": "2.0.0",
                        "license": "Apache-2.0",
                        "resolved": "https://user:password@example.invalid/example.tgz",
                    },
                },
            },
        )
        self._write_text(
            "platform/agent/uv.lock",
            'version = 1\n\n[[package]]\nname = "python-example"\nversion = "3.0.0"\n'
            'source = { registry = "https://token@example.invalid/simple" }\n',
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _write_text(self, relative: str, value: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")

    def _write_json(self, relative: str, value: object) -> None:
        self._write_text(relative, json.dumps(value, indent=2, sort_keys=True) + "\n")

    def test_tampered_package_digest_fails_generated_sbom_check(self) -> None:
        output = self.root / integrity.DEFAULT_OUTPUT
        output.parent.mkdir(parents=True)
        document = integrity.build_sbom(self.root)
        output.write_text(integrity.canonical_json(document, pretty=True), encoding="utf-8")
        self._write_text("packages/contracts/src/index.js", "export const value = 2;\n")

        errors = integrity.check(self.root, output)

        self.assertTrue(any("digest was tampered" in error for error in errors), errors)

    def test_workspace_package_missing_is_rejected(self) -> None:
        (self.root / "packages/governance/package.json").unlink()
        with self.assertRaisesRegex(integrity.IntegrityError, "required file is missing"):
            integrity.validate_repository(self.root)

    def test_dependency_cycle_is_rejected(self) -> None:
        self._write_json(
            "packages/contracts/package.json",
            {
                "name": "@test/contracts",
                "version": "1.0.0",
                "license": "MIT",
                "dependencies": {"@test/governance": "file:../governance"},
            },
        )
        ownership = json.loads((self.root / "OWNERSHIP.yaml").read_text(encoding="utf-8"))
        ownership["paths"][0]["allowed_dependency_targets"] = ["packages/governance"]
        self._write_json("OWNERSHIP.yaml", ownership)
        root_lock = json.loads((self.root / "package-lock.json").read_text(encoding="utf-8"))
        root_lock["packages"]["packages/contracts"]["dependencies"] = {
            "@test/governance": "file:../governance"
        }
        self._write_json("package-lock.json", root_lock)

        with self.assertRaisesRegex(integrity.IntegrityError, "dependency cycle"):
            integrity.validate_repository(self.root)

    def test_forbidden_known_license_fails_policy(self) -> None:
        app_lock = json.loads(
            (self.root / "platform/app/package-lock.json").read_text(encoding="utf-8")
        )
        app_lock["packages"]["node_modules/example"]["license"] = "AGPL-3.0-only"
        self._write_json("platform/app/package-lock.json", app_lock)
        document = integrity.build_sbom(self.root)
        violations = integrity.policy_violations(document, {"AGPL-3.0-only", "SSPL-1.0"})

        self.assertEqual(
            violations,
            ["example@2.0.0: forbidden license identifier(s) AGPL-3.0-only"],
        )

    def test_unknown_license_is_review_required_not_allowed(self) -> None:
        app_lock = json.loads(
            (self.root / "platform/app/package-lock.json").read_text(encoding="utf-8")
        )
        app_lock["packages"]["node_modules/example"]["license"] = "Custom-Unknown"
        self._write_json("platform/app/package-lock.json", app_lock)
        document = integrity.build_sbom(self.root)
        governance = next(
            package for package in document["packages"] if package["name"] == "@test/governance"
        )
        python_package = next(
            package for package in document["packages"] if package["name"] == "python-example"
        )
        npm_package = next(
            package for package in document["packages"] if package["name"] == "example"
        )

        self.assertEqual(governance["licenseDeclared"], "NOASSERTION")
        self.assertIn("license-review: review-required", governance["comment"])
        self.assertEqual(python_package["licenseDeclared"], "NOASSERTION")
        self.assertIn("license-review: review-required", python_package["comment"])
        self.assertEqual(npm_package["licenseDeclared"], "Custom-Unknown")
        self.assertIn("license-review: review-required", npm_package["comment"])

    def test_sbom_is_deterministic_and_redacts_source_urls(self) -> None:
        first = integrity.canonical_json(integrity.build_sbom(self.root), pretty=True)
        second = integrity.canonical_json(integrity.build_sbom(self.root), pretty=True)

        self.assertEqual(first, second)
        self.assertNotIn("user:password", first)
        self.assertNotIn("token@", first)
        self.assertNotIn("https://", first)
        self.assertIn("sha256:", first)

    def test_checked_inventory_is_stable_across_head_changes(self) -> None:
        head = self.root / ".git/HEAD"
        head.parent.mkdir()
        head.write_text("a" * 40 + "\n", encoding="utf-8")
        first = integrity.canonical_json(integrity.build_sbom(self.root), pretty=True)
        head.write_text("b" * 40 + "\n", encoding="utf-8")
        second = integrity.canonical_json(integrity.build_sbom(self.root), pretty=True)

        self.assertEqual(first, second)
        document = json.loads(first)
        self.assertEqual(document["creationInfo"]["created"], integrity.LOCAL_CREATED)
        annotation = json.loads(document["annotations"][0]["comment"])
        self.assertEqual(annotation["sourceCommit"], "NOASSERTION")
        self.assertEqual(document["dataLicense"], "CC0-1.0")

    def test_release_attestation_requires_full_sha_and_canonical_time(self) -> None:
        calls: list[list[str]] = []

        def accepted(command, **_kwargs):
            calls.append(command)
            return type("Result", (), {"stdout": ""})()

        commit = "a" * 40
        result = integrity.verify_release_attestation(
            self.root,
            commit,
            "2026-09-13T23:45:00Z",
            run=accepted,
        )
        self.assertEqual(result, (commit, "2026-09-13T23:45:00Z"))
        self.assertEqual(calls[0][-2:], [str(self.root), commit])
        self.assertEqual(calls[1][0:3], ["git", "-C", str(self.root)])
        with self.assertRaisesRegex(integrity.IntegrityError, "full lowercase"):
            integrity.verify_release_attestation(
                self.root, "a" * 12, "2026-09-13T23:45:00Z", run=accepted
            )
        with self.assertRaisesRegex(integrity.IntegrityError, "canonical UTC"):
            integrity.verify_release_attestation(
                self.root, commit, "2026-09-13T23:45:00+00:00", run=accepted
            )

        def dirty(command, **_kwargs):
            output = " M docs/note.md\n" if command[0] == "git" else ""
            return type("Result", (), {"stdout": output})()

        with self.assertRaisesRegex(integrity.IntegrityError, "completely clean"):
            integrity.verify_release_attestation(
                self.root, commit, "2026-09-13T23:45:00Z", run=dirty
            )

    def test_release_output_cannot_overlap_inventory_inputs(self) -> None:
        with self.assertRaisesRegex(integrity.IntegrityError, "checked-in inventory"):
            integrity.validate_release_output(
                self.root,
                self.root / integrity.DEFAULT_OUTPUT,
                self.paths,
            )
        with self.assertRaisesRegex(integrity.IntegrityError, "outside SBOM source inputs"):
            integrity.validate_release_output(
                self.root,
                self.root / "packages/contracts/release.spdx.json",
                self.paths,
            )

    def test_final_publication_gate_blocks_review_required_license(self) -> None:
        document = integrity.build_sbom(self.root)
        violations = integrity.publication_violations(document, {"AGPL-3.0-only", "SSPL-1.0"})
        self.assertTrue(
            any("@test/governance@1.0.0: license is review-required" in item for item in violations)
        )


if __name__ == "__main__":
    unittest.main()
