from __future__ import annotations

import importlib.util
import json
import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "materialize-product-manifest.py"
SPEC = importlib.util.spec_from_file_location("materialize_product_manifest", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
materializer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(materializer)


class ProductManifestMaterializationTest(unittest.TestCase):
    def test_neutral_profile_is_the_validated_contract_fixture(self) -> None:
        profile, _ = materializer.load_and_validate(ROOT, "sample-neutral")
        fixtures = json.loads(
            (ROOT / "packages" / "contracts" / "fixtures" / "contracts.json").read_text()
        )
        self.assertEqual(profile, fixtures["valid_neutral_manifest"])

    def test_generated_app_agent_and_client_bindings_have_the_same_hash(self) -> None:
        app = (ROOT / materializer.APP_OUTPUT).read_text()
        client = (ROOT / materializer.CLIENT_OUTPUT).read_text()
        agent = (ROOT / materializer.AGENT_OUTPUT).read_text()
        manifest_hash = materializer.hashes(
            *materializer.load_and_validate(ROOT, "sample-neutral")
        )[0]
        self.assertIn(f'PRODUCT_MANIFEST_SHA256 = "{manifest_hash}"', app)
        self.assertIn(f'"manifestSha256":"{manifest_hash}"', client)
        self.assertIn(f"PRODUCT_MANIFEST_SHA256 = {json.dumps(manifest_hash)}", agent)

    def test_manifest_hash_binds_privileged_extension_references(self) -> None:
        profile, source = materializer.load_and_validate(ROOT, "sample-neutral")
        original_hash, original_source_hash = materializer.hashes(profile, source)
        changed = json.loads(json.dumps(profile))
        changed["extensions"]["prompts"] = "extension:prompts/other-neutral"
        changed_hash, changed_source_hash = materializer.hashes(changed, source)

        self.assertNotEqual(original_hash, changed_hash)
        self.assertEqual(original_source_hash, changed_source_hash)

    def test_client_binding_contains_only_browser_safe_extension_slots(self) -> None:
        client = (ROOT / materializer.CLIENT_OUTPUT).read_text()
        for slot in ("branding", "navigation", "loading", "settings", "export_chrome"):
            self.assertIn(f'"{slot}"', client)
        for private_section in (
            "authorization",
            "data_boundary",
            "knowledge",
            "migrations",
            "prompts",
            "resources",
            "tool_registry",
        ):
            self.assertNotIn(f'"{private_section}"', client)

    def test_aliases_keep_owner_telemetry_and_removal_metadata(self) -> None:
        profile, _ = materializer.load_and_validate(ROOT, "sample-neutral")
        alias = profile["compatibility"]["aliases"][0]
        self.assertEqual(
            set(alias),
            {"alias", "target", "owner", "telemetry_key", "removal_version"},
        )
        self.assertEqual(alias["owner"], "platform-contracts")
        self.assertEqual(alias["telemetry_key"], "compat.player_insights.catalog")
        self.assertEqual(alias["removal_version"], "1.2.0")

    def test_downstream_migrations_begin_after_immutable_core_45(self) -> None:
        slots = json.loads(
            (ROOT / "profiles" / "sample-neutral" / materializer.EXTENSION_SLOT_FILE).read_text()
        )
        self.assertEqual(slots["migrations"]["first_migration_version"], 46)
        migration_source = (
            ROOT / "platform" / "app" / "server" / "lib" / "migrations.ts"
        ).read_text()
        versions = [int(value) for value in re.findall(r"\bversion:\s*(\d+)", migration_source)]
        self.assertEqual(versions[-2:], [44, 45])
        self.assertEqual(max(versions), slots["migrations"]["first_migration_version"] - 1)

    def test_unknown_privileged_fields_stop_materialization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = ROOT / "packages" / "contracts"
            destination = root / "packages" / "contracts"
            destination.parent.mkdir(parents=True)
            destination.symlink_to(source, target_is_directory=True)
            manifest = json.loads(
                (ROOT / "profiles" / "sample-neutral" / "product.manifest.json").read_text()
            )
            manifest["authorization"]["request_selectable"] = True
            path = root / "profiles" / "bad" / "product.manifest.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(manifest))
            (path.parent / materializer.EXTENSION_SLOT_FILE).write_text(
                (
                    ROOT / "profiles" / "sample-neutral" / materializer.EXTENSION_SLOT_FILE
                ).read_text()
            )
            with self.assertRaisesRegex(ValueError, "unknown field"):
                materializer.load_and_validate(root, "bad")

    def test_profile_selection_never_reads_environment_names(self) -> None:
        with self.assertRaisesRegex(ValueError, "explicit profile"):
            materializer.load_and_validate(ROOT, "production")
        self.assertEqual(materializer.DEFAULT_PROFILE, "sample-neutral")

    def test_checked_bindings_are_current(self) -> None:
        materializer.materialize(ROOT, "sample-neutral", check=True)


if __name__ == "__main__":
    unittest.main()
