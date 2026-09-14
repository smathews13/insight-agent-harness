from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "materialize-downstream.py"
SPEC = importlib.util.spec_from_file_location("materialize_downstream", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
materializer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(materializer)


class DownstreamMaterializationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.upstream = self.root / "vendor" / "upstream"
        self.overlay = self.root / "overlay" / "product"
        self.output = self.root / "build" / "materialized"
        self.pin = self.root / "upstream-pin.txt"
        self.upstream.mkdir(parents=True)
        self.overlay.mkdir(parents=True)
        self._git("init", "-b", "main")
        (self.upstream / "platform").mkdir()
        (self.upstream / "platform" / "owned.txt").write_text("owned\n", encoding="utf-8")
        (self.upstream / "platform" / ".harness").mkdir()
        (self.upstream / "platform" / ".harness" / "owned.txt").write_text(
            "nested upstream metadata\n",
            encoding="utf-8",
        )
        (self.upstream / "release.tar").write_bytes(b"immutable artifact\n")
        self._git("add", "platform/owned.txt", "platform/.harness/owned.txt", "release.tar")
        self._git(
            "-c",
            "user.name=Harness Test",
            "-c",
            "user.email=harness@example.invalid",
            "commit",
            "-m",
            "fixture",
        )
        self.sha = self._git("rev-parse", "HEAD")
        self._git(
            "-c",
            "user.name=Harness Test",
            "-c",
            "user.email=harness@example.invalid",
            "tag",
            "-a",
            "v1.1.0",
            "-m",
            "fixture release",
        )
        digest = hashlib.sha256((self.upstream / "release.tar").read_bytes()).hexdigest()
        self.pin.write_text(
            "\n".join(
                [
                    "upstream_tag=v1.1.0",
                    f"upstream_sha={self.sha}",
                    f"upstream_artifact_sha256=sha256:{digest}",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        manifest = json.loads(
            (ROOT / "profiles" / "sample-neutral" / "product.manifest.json").read_text()
        )
        (self.overlay / "product.manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        (self.overlay / "prompts").mkdir()
        (self.overlay / "prompts" / "system.md").write_text(
            "Use governed evidence.\n", encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _git(self, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.upstream), *args],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def test_materializes_annotated_tag_sha_and_artifact_digest(self) -> None:
        metadata = materializer.materialize(
            self.upstream,
            self.overlay,
            self.pin,
            Path("release.tar"),
            self.output,
        )
        self.assertEqual(metadata["upstream_tag"], "v1.1.0")
        self.assertEqual(metadata["upstream_sha"], self.sha)
        self.assertEqual(metadata["extension_slots"], ["prompts"])
        self.assertEqual((self.output / "platform" / "owned.txt").read_text(), "owned\n")
        self.assertEqual(
            (self.output / ".harness" / "extensions" / "prompts" / "system.md").read_text(),
            "Use governed evidence.\n",
        )
        self.assertIn("prompts/system.md", metadata["extension_files"])
        materializer.verify_materialized(self.output)

    def test_boundary_check_rejects_downstream_change_to_upstream_file(self) -> None:
        materializer.materialize(
            self.upstream, self.overlay, self.pin, Path("release.tar"), self.output
        )
        (self.output / "platform" / "owned.txt").write_text("downstream edit\n", encoding="utf-8")
        with self.assertRaisesRegex(materializer.MaterializationError, "upstream-owned paths"):
            materializer.verify_materialized(self.output)

    def test_boundary_check_rejects_nested_harness_and_extension_changes(self) -> None:
        materializer.materialize(
            self.upstream, self.overlay, self.pin, Path("release.tar"), self.output
        )
        nested = self.output / "platform" / ".harness" / "owned.txt"
        nested.write_text("downstream edit\n", encoding="utf-8")
        with self.assertRaisesRegex(materializer.MaterializationError, "upstream-owned paths"):
            materializer.verify_materialized(self.output)

        nested.write_text("nested upstream metadata\n", encoding="utf-8")
        extension = self.output / ".harness" / "extensions" / "prompts" / "system.md"
        extension.write_text("changed prompt\n", encoding="utf-8")
        with self.assertRaisesRegex(materializer.MaterializationError, "extension content changed"):
            materializer.verify_materialized(self.output)

    def test_boundary_check_rejects_manifest_and_metadata_changes(self) -> None:
        metadata = materializer.materialize(
            self.upstream,
            self.overlay,
            self.pin,
            Path("release.tar"),
            self.output,
        )
        manifest = self.output / ".harness" / "product.manifest.json"
        manifest.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(materializer.MaterializationError, "ProductManifest digest"):
            materializer.verify_materialized(self.output)

        manifest.write_text(
            json.dumps(
                json.loads((self.overlay / "product.manifest.json").read_text()),
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        (self.output / ".harness" / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")
        with self.assertRaisesRegex(
            materializer.MaterializationError, "unexpected or missing paths"
        ):
            materializer.verify_materialized(self.output)
        self.assertTrue(metadata["product_manifest_sha256"].startswith("sha256:"))

    def test_rejects_short_sha_and_wrong_artifact_digest(self) -> None:
        self.pin.write_text(
            "upstream_tag=v1.1.0\nupstream_sha=abc\nupstream_artifact_sha256=sha256:"
            + "0" * 64
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(materializer.MaterializationError, "full lowercase"):
            materializer.parse_pin(self.pin)

        self.pin.write_text(
            f"upstream_tag=v1.1.0\nupstream_sha={self.sha}\nupstream_artifact_sha256=sha256:"
            + "0" * 64
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(materializer.MaterializationError, "digest mismatch"):
            materializer.materialize(
                self.upstream, self.overlay, self.pin, Path("release.tar"), self.output
            )

    def test_rejects_artifact_escape_and_untracked_artifact(self) -> None:
        outside = self.root / "outside.tar"
        outside.write_bytes(b"outside\n")
        with self.assertRaisesRegex(materializer.MaterializationError, "repository-relative"):
            materializer.materialize(
                self.upstream,
                self.overlay,
                self.pin,
                Path("../outside.tar"),
                self.output,
            )

        ignored = self.upstream / "ignored.tar"
        ignored.write_bytes(b"ignored\n")
        (self.upstream / ".git" / "info" / "exclude").write_text("ignored.tar\n", encoding="utf-8")
        digest = hashlib.sha256(ignored.read_bytes()).hexdigest()
        self.pin.write_text(
            f"upstream_tag=v1.1.0\nupstream_sha={self.sha}\n"
            f"upstream_artifact_sha256=sha256:{digest}\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(materializer.MaterializationError, "ls-files"):
            materializer.materialize(
                self.upstream,
                self.overlay,
                self.pin,
                Path("ignored.tar"),
                self.output,
            )

    def test_rejects_unknown_overlay_slot(self) -> None:
        (self.overlay / "platform").mkdir()
        with self.assertRaisesRegex(materializer.MaterializationError, "unknown extension slot"):
            materializer.load_overlay(self.overlay)

    def test_rejects_unregistered_compatibility_alias(self) -> None:
        manifest_path = self.overlay / "product.manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["compatibility"]["aliases"][0] = {
            "alias": "LEGACY_PRODUCT_NEW_ALIAS",
            "target": "INSIGHT_AGENT_NEW_ALIAS",
            "owner": "platform-contracts",
            "telemetry_key": "compat.player_insights.new_alias",
            "removal_version": "1.2.0",
        }
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(materializer.MaterializationError, "not registered"):
            materializer.load_overlay(self.overlay)


if __name__ == "__main__":
    unittest.main()
