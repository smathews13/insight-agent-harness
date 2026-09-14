from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check-neutral-surface.py"
SPEC = importlib.util.spec_from_file_location("check_neutral_surface", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = checker
SPEC.loader.exec_module(checker)

PROFILE = ROOT / "profiles" / "sample-neutral"


class NeutralSurfaceAuditTest(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = json.loads((PROFILE / "compatibility-aliases.json").read_text())
        self.manifest = json.loads((PROFILE / "product.manifest.json").read_text())
        self.publication = json.loads((PROFILE / "publication-policy.json").read_text())

    def fixture(
        self,
        source_text: str,
        *,
        change_manifest: Callable[[dict[str, Any]], None] | None = None,
        change_publication: Callable[[dict[str, Any]], None] | None = None,
    ) -> checker.AuditPaths:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        source = root / "platform" / "app" / "server.ts"
        source.parent.mkdir(parents=True)
        source.write_text(source_text, encoding="utf-8")
        ownership = {
            "paths": [
                {
                    "path": "platform/app",
                    "classification": ["upstream-owned", "public-safe"],
                }
            ]
        }
        (root / "OWNERSHIP.yaml").write_text(json.dumps(ownership), encoding="utf-8")

        profile = root / "profiles" / "sample-neutral"
        profile.mkdir(parents=True)
        manifest = copy.deepcopy(self.manifest)
        publication = copy.deepcopy(self.publication)
        publication["identity_debt_files"] = []
        if change_manifest is not None:
            change_manifest(manifest)
        if change_publication is not None:
            change_publication(publication)
        (profile / "compatibility-aliases.json").write_text(
            json.dumps(self.registry),
            encoding="utf-8",
        )
        (profile / "product.manifest.json").write_text(
            json.dumps(manifest),
            encoding="utf-8",
        )
        (profile / "publication-policy.json").write_text(
            json.dumps(publication),
            encoding="utf-8",
        )

        caveat = publication["unofficial_software_caveat"]
        for relative in publication["required_posture_files"]:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            text = caveat if relative in publication["caveat_files"] else "public posture\n"
            path.write_text(text, encoding="utf-8")
        return checker.AuditPaths(
            root=root,
            ownership=root / "OWNERSHIP.yaml",
            alias_registry=profile / "compatibility-aliases.json",
            publication_policy=profile / "publication-policy.json",
            product_manifest=profile / "product.manifest.json",
        )

    def test_repository_surface_matches_committed_publication_policy(self) -> None:
        self.assertEqual(checker.audit(), [])

    def test_new_legacy_alias_is_rejected_from_registry_configuration(self) -> None:
        mapping = self.registry["mapping"]
        suffix = "".join(("UNREGISTERED", "_", "SENTINEL"))
        paths = self.fixture(f"process.env.{mapping['legacy_prefix']}{suffix}\n")

        errors = checker.audit(paths)

        self.assertTrue(
            any("new unregistered legacy compatibility aliases" in error for error in errors),
            errors,
        )

    def test_forbidden_identity_is_assembled_from_publication_policy(self) -> None:
        marker = "".join(self.publication["forbidden_identity_marker_fragments"][0])
        paths = self.fixture(f"export const label = {marker!r};\n")

        errors = checker.audit(paths)

        self.assertTrue(
            any("forbidden inherited product identity location" in error for error in errors),
            errors,
        )

    def test_checker_source_does_not_contain_the_patterns_it_enforces(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        policy = checker.load_publication_policy(PROFILE / "publication-policy.json")
        for marker in policy.forbidden_identity_markers:
            self.assertNotIn(marker, source)
        self.assertNotIn(self.registry["mapping"]["legacy_prefix"], source)

    def test_manifest_alias_must_use_registry_metadata(self) -> None:
        mapping = self.registry["mapping"]
        suffix = "".join(("UNREGISTERED", "_", "MANIFEST"))

        def change_manifest(manifest: dict[str, Any]) -> None:
            alias = manifest["compatibility"]["aliases"][0]
            alias["alias"] = f"{mapping['legacy_prefix']}{suffix}"
            alias["target"] = f"{mapping['canonical_prefix']}{suffix}"
            alias["owner"] = "somebody-else"
            alias["telemetry_key"] = "compat.wrong"
            alias["removal_version"] = "1.3.0"

        errors = checker.audit(self.fixture("", change_manifest=change_manifest))

        self.assertTrue(
            any("unregistered compatibility alias" in error for error in errors), errors
        )
        self.assertTrue(any("must be owned" in error for error in errors), errors)
        self.assertTrue(any("compatibility telemetry" in error for error in errors), errors)
        self.assertTrue(any("removal_version must be 1.2.0" in error for error in errors), errors)

    def test_publication_policy_is_closed_and_fragmented(self) -> None:
        def change_publication(publication: dict[str, Any]) -> None:
            publication["runtime_override"] = True

        with self.assertRaisesRegex(ValueError, "unexpected or missing fields"):
            checker.audit(self.fixture("", change_publication=change_publication))

        def collapse_marker(publication: dict[str, Any]) -> None:
            publication["forbidden_identity_marker_fragments"][0] = [
                "".join(publication["forbidden_identity_marker_fragments"][0])
            ]

        with self.assertRaisesRegex(ValueError, "fragment arrays"):
            checker.audit(self.fixture("", change_publication=collapse_marker))

    def test_command_line_cannot_select_a_weaker_policy(self) -> None:
        self.assertEqual(checker.main(["--publication-policy", "/tmp/permissive.json"]), 2)


if __name__ == "__main__":
    unittest.main()
