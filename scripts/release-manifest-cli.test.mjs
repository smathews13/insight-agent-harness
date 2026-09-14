import assert from "node:assert/strict";
import {
  chmodSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const CLI = new URL("./release-manifest.mjs", import.meta.url);

function run(args) {
  return spawnSync(process.execPath, [CLI.pathname, ...args], {
    encoding: "utf8",
  });
}

test("raw approval-record command-line content is unsupported", () => {
  const secret = "approval body must never be printed";
  const result = run(["sign", "--approval-record", secret]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /--approval-record is unsupported/);
  assert.doesNotMatch(
    result.stdout + result.stderr,
    /approval body must never/,
  );
});

test("approval records must be regular files and symlinks are rejected", () => {
  const root = mkdtempSync(path.join(tmpdir(), "approval-record-"));
  try {
    const candidate = path.join(root, "candidate.json");
    const target = path.join(root, "approval.txt");
    const linked = path.join(root, "approval-link.txt");
    writeFileSync(candidate, "{}\n");
    writeFileSync(target, "private approval content\n");
    symlinkSync(target, linked);
    const result = run([
      "sign",
      "--candidate",
      candidate,
      "--private-key-file",
      path.join(root, "missing-private-key.pem"),
      "--approval-record-file",
      linked,
      "--repository-root",
      root,
    ]);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /approval record could not be read safely/);
    assert.doesNotMatch(
      result.stdout + result.stderr,
      /private approval content/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("private key inputs cannot be group- or world-readable", () => {
  if (process.platform === "win32") return;
  const root = mkdtempSync(path.join(tmpdir(), "release-private-key-"));
  try {
    const candidate = path.join(root, "candidate.json");
    const approval = path.join(root, "approval.txt");
    const privateKey = path.join(root, "release.pem");
    writeFileSync(candidate, "{}\n");
    writeFileSync(approval, "approval\n");
    writeFileSync(privateKey, "key material must never be printed\n");
    chmodSync(privateKey, 0o644);
    const result = run([
      "sign",
      "--candidate",
      candidate,
      "--private-key-file",
      privateKey,
      "--approval-record-file",
      approval,
      "--repository-root",
      root,
    ]);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /permissions allow group or other access/);
    assert.doesNotMatch(
      result.stdout + result.stderr,
      /key material must never/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
