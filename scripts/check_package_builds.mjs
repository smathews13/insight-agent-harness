#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const policy = JSON.parse(
  readFileSync(resolve(root, "scripts/package-policy.json"), "utf8"),
);

function pack(packageName) {
  const result = spawnSync(
    "npm",
    [
      "pack",
      "--dry-run",
      "--json",
      "--ignore-scripts",
      "--workspace",
      packageName,
    ],
    {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        npm_config_audit: "false",
        npm_config_fund: "false",
        npm_config_offline: "true",
        npm_config_update_notifier: "false",
      },
    },
  );
  if (result.status !== 0) {
    throw new Error(
      `npm pack failed for ${packageName}: ${result.stderr || result.stdout}`,
    );
  }
  const parsed = JSON.parse(result.stdout);
  if (!Array.isArray(parsed) || parsed.length !== 1) {
    throw new Error(`npm pack returned an unexpected result for ${packageName}`);
  }
  return parsed[0];
}

for (const { name } of policy.workspace_packages) {
  const first = pack(name);
  const second = pack(name);
  if (JSON.stringify(first) !== JSON.stringify(second)) {
    throw new Error(`npm pack metadata is not deterministic for ${name}`);
  }
  const paths = new Set(first.files.map((file) => file.path));
  for (const required of ["package.json", "README.md"]) {
    if (!paths.has(required)) {
      throw new Error(`${name} package is missing ${required}`);
    }
  }
  if (![...paths].some((path) => path.startsWith("src/"))) {
    throw new Error(`${name} package contains no runtime source`);
  }
  if ([...paths].some((path) => path.endsWith("package-lock.json"))) {
    throw new Error(`${name} package must not contain a component lockfile`);
  }
  console.log(`package build check passed: ${name} (${first.entryCount} files)`);
}
