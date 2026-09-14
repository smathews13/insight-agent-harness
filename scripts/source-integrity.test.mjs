import assert from "node:assert/strict";
import {
  mkdtempSync,
  mkdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  appSourceSha256,
  modelSourceSha256,
  releaseSourceInputFiles,
  releaseSourceSha256,
  verifyRepositorySourceIdentity,
} from "./source-integrity.mjs";

const REPOSITORY_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const TEST_TEMP_ROOT = path.join(REPOSITORY_ROOT, ".tmp");

function fixture() {
  mkdirSync(TEST_TEMP_ROOT, { recursive: true });
  const root = mkdtempSync(path.join(TEST_TEMP_ROOT, "release-integrity-"));
  const files = [
    "platform/app/server/main.ts",
    "platform/agent/agent.py",
    "extensions/sample-neutral/agent/runtime_extension.py",
    "packages/contracts/schema.json",
    "bundle/app-release.sh",
    "resources/release-signing-keys.json",
    "profiles/sample-neutral/product.manifest.json",
    "scripts/release-manifest.mjs",
    "genie/space.json",
    "infra/databricks.yml",
    "mirror/publish-exclude.txt",
    ".github/workflows/publish-public-mirror.yml",
    "OWNERSHIP.yaml",
    "sync-mirror.sh",
    "databricks.yml",
    "package.json",
    "package-lock.json",
  ];
  for (const file of files) {
    const target = path.join(root, file);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, `${file}\n`);
  }
  return root;
}

test("every release behavior source class changes the release digest", () => {
  const root = fixture();
  try {
    const baseline = releaseSourceSha256(root);
    for (const file of [
      "platform/app/server/main.ts",
      "platform/agent/agent.py",
      "extensions/sample-neutral/agent/runtime_extension.py",
      "packages/contracts/schema.json",
      "bundle/app-release.sh",
      "resources/release-signing-keys.json",
      "profiles/sample-neutral/product.manifest.json",
      "mirror/publish-exclude.txt",
      ".github/workflows/publish-public-mirror.yml",
      "OWNERSHIP.yaml",
      "sync-mirror.sh",
    ]) {
      writeFileSync(path.join(root, file), "changed\n");
      assert.notEqual(releaseSourceSha256(root), baseline, file);
      writeFileSync(path.join(root, file), `${file}\n`);
      assert.equal(releaseSourceSha256(root), baseline, `${file} restored`);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("app and model digests cover their own source and shared packages", () => {
  const root = fixture();
  try {
    const app = appSourceSha256(root);
    const model = modelSourceSha256(root);
    writeFileSync(
      path.join(root, "platform/app/server/main.ts"),
      "app changed\n",
    );
    assert.notEqual(appSourceSha256(root), app);
    assert.equal(modelSourceSha256(root), model);
    writeFileSync(
      path.join(root, "platform/app/server/main.ts"),
      "platform/app/server/main.ts\n",
    );
    writeFileSync(
      path.join(root, "extensions/sample-neutral/agent/runtime_extension.py"),
      "agent changed\n",
    );
    assert.equal(appSourceSha256(root), app);
    assert.notEqual(modelSourceSha256(root), model);
    writeFileSync(
      path.join(root, "packages/contracts/schema.json"),
      "shared changed\n",
    );
    assert.notEqual(appSourceSha256(root), app);
    assert.notEqual(modelSourceSha256(root), model);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("generated outputs, reports, caches, secrets, and private keys are excluded", () => {
  const root = fixture();
  try {
    const baseline = releaseSourceSha256(root);
    for (const file of [
      ".git/HEAD",
      "platform/agent/__pycache__/agent.pyc",
      "bundle/test-results/result.json",
      "platform/app/build/server.mjs",
      "platform/app/dist/server.mjs",
      "platform/app/.env.production",
      "resources/release-private-key.pem",
    ]) {
      const target = path.join(root, file);
      mkdirSync(path.dirname(target), { recursive: true });
      writeFileSync(target, "must not be hashed\n");
      assert.equal(releaseSourceSha256(root), baseline, file);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("paths and text line endings are canonical and symlinks are rejected", () => {
  const root = fixture();
  try {
    const files = releaseSourceInputFiles(root);
    assert.ok(files.every((file) => !file.includes("\\")));
    const baseline = releaseSourceSha256(root);
    writeFileSync(
      path.join(root, "platform/agent/agent.py"),
      "platform/agent/agent.py\r\n",
    );
    assert.equal(releaseSourceSha256(root), baseline);
    symlinkSync(
      path.join(root, "platform/agent/agent.py"),
      path.join(root, "platform/agent/linked.py"),
    );
    assert.throws(
      () => releaseSourceSha256(root),
      /integrity input cannot be a symbolic link/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("release source identity requires the exact clean Git commit", () => {
  const head = "a".repeat(40);
  const responses = (statusOutput = "") => (args) => {
    if (args.includes("rev-parse")) {
      return { status: 0, stdout: `${head}\n`, stderr: "" };
    }
    if (args.includes("status")) {
      return { status: 0, stdout: statusOutput, stderr: "" };
    }
    return { status: 1, stdout: "", stderr: "unexpected git command" };
  };

  verifyRepositorySourceIdentity("/release/source", head, responses());
  assert.throws(
    () =>
      verifyRepositorySourceIdentity(
        "/release/source",
        head.slice(0, 12),
        responses(),
      ),
    /requires a full commit SHA/,
  );
  assert.throws(
    () => verifyRepositorySourceIdentity("/release/source", "main", responses()),
    /requires a full commit SHA/,
  );
  assert.throws(
    () =>
      verifyRepositorySourceIdentity(
        "/release/source",
        "f".repeat(40),
        responses(),
      ),
    /does not match repository HEAD/,
  );
  assert.throws(
    () =>
      verifyRepositorySourceIdentity(
        "/release/source",
        head,
        responses(" M platform/agent/agent.py\n"),
      ),
    /uncommitted changes/,
  );
  assert.throws(
    () =>
      verifyRepositorySourceIdentity("/release/source", head, () => ({
        status: 1,
        stdout: "",
        stderr: "repository unavailable",
      })),
    /not a readable Git checkout/,
  );
});
