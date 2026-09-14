from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

CHECKER_PATH = Path(__file__).resolve().parents[1] / "check-ownership-boundary.py"
SPEC = importlib.util.spec_from_file_location("check_ownership_boundary", CHECKER_PATH)
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


class OwnershipBoundaryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.config_path = self.root / "OWNERSHIP.yaml"
        self.config = self._base_config()
        generated = self.root / "generated" / "deploy"
        generated.mkdir(parents=True)
        (generated / "source.json").write_text(
            '{"source_hash": "sha256:' + "a" * 64 + '"}\n',
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _base_config(self) -> dict[str, object]:
        records = []
        for path in sorted(checker.REQUIRED_TARGET_PATHS):
            ownership = "overlay-owned" if path == "overlays" else "upstream-owned"
            publication = "excluded" if path in {"docs", "overlays"} else "public-safe"
            records.append(
                {
                    "path": path,
                    "owner": {"area": f"{path} area", "team": f"{path} team"},
                    "classification": [ownership, publication],
                    "allowed_dependency_targets": [],
                    "customer_values_allowed": path == "overlays",
                }
            )
        records.append(
            {
                "path": "generated/deploy",
                "owner": {"area": "generated deploy output", "team": "release"},
                "classification": ["generated", "excluded"],
                "allowed_dependency_targets": [],
                "customer_values_allowed": False,
                "generated_deploy_output": True,
                "generated_source_hash": {
                    "metadata_file": "source.json",
                    "pattern": r'"source_hash":\s*"sha256:[0-9a-f]{64}"',
                },
            }
        )
        return {
            "schema_version": "1.0",
            "repository_role": "upstream",
            "neutral_profile_paths": ["profiles"],
            "neutral_profile_customer_keys": [
                "account_id",
                "customer_name",
                "workspace_id",
            ],
            "paths": records,
        }

    def _record(self, path: str) -> dict[str, object]:
        records = self.config["paths"]
        assert isinstance(records, list)
        return next(record for record in records if record["path"] == path)

    def _check(self) -> list[str]:
        self.config_path.write_text(json.dumps(self.config), encoding="utf-8")
        return checker.check_repository(self.root, self.config_path)

    def assert_failure_contains(self, expected: str) -> None:
        errors = self._check()
        self.assertTrue(
            any(expected in error for error in errors),
            f"expected {expected!r} in errors: {errors}",
        )

    def test_valid_future_topology_passes_when_target_paths_are_absent(self) -> None:
        self.assertEqual(self._check(), [])

    def test_rejects_overlapping_path_ownership(self) -> None:
        records = self.config["paths"]
        assert isinstance(records, list)
        records.append(
            {
                "path": "platform/app/client",
                "owner": {"area": "conflict", "team": "conflict"},
                "classification": ["upstream-owned", "public-safe"],
                "allowed_dependency_targets": [],
                "customer_values_allowed": False,
            }
        )
        self.assert_failure_contains("overlapping path ownership")

    def test_allows_generated_deploy_output_inside_owned_app(self) -> None:
        generated = self._record("generated/deploy")
        generated["path"] = "platform/app/build/deploy"
        metadata = self.root / "platform" / "app" / "build" / "deploy" / "source.json"
        metadata.parent.mkdir(parents=True)
        metadata.write_text(
            '{"source_hash": "sha256:' + "a" * 64 + '"}\n',
            encoding="utf-8",
        )
        self.assertEqual(self._check(), [])

    def test_allows_hashed_generated_binding_inside_owned_app(self) -> None:
        records = self.config["paths"]
        assert isinstance(records, list)
        records.append(
            {
                "path": "platform/app/server/generated",
                "owner": {"area": "generated manifest binding", "team": "platform-contracts"},
                "classification": ["generated", "public-safe"],
                "allowed_dependency_targets": ["packages/contracts"],
                "customer_values_allowed": False,
                "generated_output": True,
                "generated_source_hash": {
                    "metadata_file": "product-manifest.ts",
                    "pattern": r"PRODUCT_MANIFEST_SOURCE_SHA256 = \"[0-9a-f]{64}\"",
                },
            }
        )
        generated = self.root / "platform" / "app" / "server" / "generated"
        generated.mkdir(parents=True)
        (generated / "product-manifest.ts").write_text(
            'PRODUCT_MANIFEST_SOURCE_SHA256 = "' + "a" * 64 + '"\n'
        )
        self.assertEqual(self._check(), [])

    def test_rejects_unknown_dependency_target(self) -> None:
        self._record("platform/app")["allowed_dependency_targets"] = ["packages/missing"]
        self.assert_failure_contains("unknown dependency target")

    def test_rejects_package_dependency_cycle(self) -> None:
        self._record("packages/contracts")["allowed_dependency_targets"] = ["packages/governance"]
        self._record("packages/governance")["allowed_dependency_targets"] = ["packages/contracts"]
        self.assert_failure_contains("package dependency cycle")

    def test_rejects_agent_runtime_contract_cycle(self) -> None:
        self._record("packages/agent-runtime-py")["allowed_dependency_targets"] = [
            "packages/contracts"
        ]
        self._record("packages/contracts")["allowed_dependency_targets"] = [
            "packages/agent-runtime-py"
        ]
        self.assert_failure_contains("package dependency cycle")

    def test_rejects_unowned_root_agent_runtime_file(self) -> None:
        runtime = self.root / "agent" / "runtime.py"
        runtime.parent.mkdir(parents=True)
        runtime.write_text("RUNTIME = True\n", encoding="utf-8")
        self.assert_failure_contains("unowned root-agent runtime path")

    def test_rejects_product_identity_in_platform_agent(self) -> None:
        source = self.root / "platform" / "agent" / "agent.py"
        source.parent.mkdir(parents=True)
        source.write_text("SYSTEM_PROMPT = 'You are legacy downstream product'\n", encoding="utf-8")
        self.assert_failure_contains("platform agent contains product identity")

    def test_rejects_domain_tools_in_platform_agent(self) -> None:
        source = self.root / "platform" / "agent" / "agent.py"
        source.parent.mkdir(parents=True)
        source.write_text("from tools import RUN_SQL_TOOL\n", encoding="utf-8")
        self.assert_failure_contains("platform agent contains product tool implementation")

    def test_rejects_overlay_directory_in_upstream(self) -> None:
        (self.root / "overlays").mkdir()
        self.assert_failure_contains("contains downstream-only overlay path")

    def test_rejects_upstream_import_from_overlay(self) -> None:
        source = self.root / "platform" / "app" / "main.py"
        source.parent.mkdir(parents=True)
        overlay_import = "from " + "overlays.product import prompt\n"
        source.write_text(overlay_import, encoding="utf-8")
        self.assert_failure_contains("imports downstream overlay path")

    def test_rejects_upstream_import_from_singular_overlay_template_path(self) -> None:
        source = self.root / "platform" / "app" / "main.ts"
        source.parent.mkdir(parents=True)
        source.write_text(
            "import config from '../../" + "overlay/product/config';\n", encoding="utf-8"
        )
        self.assert_failure_contains("imports downstream overlay path")

    def test_rejects_upstream_import_from_materialized_extension_path(self) -> None:
        source = self.root / "platform" / "app" / "main.ts"
        source.parent.mkdir(parents=True)
        source.write_text(
            "import config from '../../.harness/" + "extensions/config';\n", encoding="utf-8"
        )
        self.assert_failure_contains("imports downstream overlay path")

    def test_rejects_generated_output_without_source_hash_metadata(self) -> None:
        (self.root / "generated" / "deploy" / "source.json").unlink()
        self.assert_failure_contains("generated source-hash metadata is missing")

    def test_rejects_customer_identifier_in_neutral_profile(self) -> None:
        profile = self.root / "profiles" / "default.yaml"
        profile.parent.mkdir(parents=True)
        profile.write_text("customer_name: Acme Games\n", encoding="utf-8")
        self.assert_failure_contains("neutral profile contains a customer identifier field")


if __name__ == "__main__":
    unittest.main()
