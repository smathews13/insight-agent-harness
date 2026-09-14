import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const EXCLUDED_SEGMENTS = new Set([
  ".git",
  ".mypy_cache",
  ".pytest_cache",
  ".ruff_cache",
  ".tmp",
  ".venv",
  "__pycache__",
  "build",
  "coverage",
  "dist",
  "generated",
  "htmlcov",
  "node_modules",
  "node_modules.partial-harness",
  "playwright-report",
  "test-results",
]);
const EXCLUDED_FILES = [
  /^\.env(?:\.|$)/,
  /^generated\.py$/,
  /\.(?:key|p12|pem|pfx)$/i,
  /(?:^|[-_.])credentials?(?:[-_.]|$)/i,
  /(?:^|[-_.])private[-_.]?key(?:[-_.]|$)/i,
  /(?:^|[-_.])secrets?(?:[-_.]|$)/i,
];
const RELEASE_ROOTS = [
  ".github",
  "OWNERSHIP.yaml",
  "agent",
  "bundle",
  "extensions",
  "genie",
  "infra",
  "mirror",
  "packages",
  "platform/agent",
  "platform/app",
  "profiles",
  "resources",
  "scripts",
  "sync-mirror.sh",
  "databricks.yml",
  "package.json",
  "package-lock.json",
];
const APP_ROOTS = [
  "packages/contracts",
  "platform/app",
  "profiles",
  "resources",
  "package.json",
  "package-lock.json",
];
const MODEL_ROOTS = [
  "extensions",
  "packages",
  "platform/agent",
  "profiles",
  "resources",
  "package.json",
  "package-lock.json",
];

function portable(relative) {
  return relative.split(path.sep).join("/");
}

function excluded(relative) {
  const parts = portable(relative).split("/");
  return (
    parts.some((part) => EXCLUDED_SEGMENTS.has(part)) ||
    EXCLUDED_FILES.some((pattern) => pattern.test(parts[parts.length - 1]))
  );
}

export function integrityFilesBelow(root, relative) {
  if (excluded(relative)) return [];
  const absolute = path.join(root, relative);
  if (!existsSync(absolute)) return [];
  const stat = lstatSync(absolute);
  if (stat.isSymbolicLink()) {
    throw new Error(
      `integrity input cannot be a symbolic link: ${portable(relative)}`,
    );
  }
  if (!stat.isDirectory()) return [portable(relative)];
  return readdirSync(absolute, { withFileTypes: true })
    .sort((left, right) => left.name.localeCompare(right.name, "en"))
    .flatMap((entry) =>
      integrityFilesBelow(root, path.join(relative, entry.name)),
    );
}

function normalizedBytes(file) {
  const bytes = readFileSync(file);
  if (bytes.includes(0)) return bytes;
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return Buffer.from(text.replace(/\r\n?/g, "\n"), "utf8");
  } catch {
    return bytes;
  }
}

export function integrityTreeSha256(root, files) {
  const hash = createHash("sha256");
  for (const relative of [...new Set(files)].sort()) {
    hash.update(portable(relative), "utf8");
    hash.update("\0");
    hash.update(normalizedBytes(path.join(root, relative)));
    hash.update("\0");
  }
  return hash.digest("hex");
}

function filesFor(repositoryRoot, roots) {
  return roots
    .flatMap((relative) => integrityFilesBelow(repositoryRoot, relative))
    .sort();
}

export function releaseSourceInputFiles(repositoryRoot) {
  return filesFor(repositoryRoot, RELEASE_ROOTS);
}

export function appSourceInputFiles(repositoryRoot) {
  return filesFor(repositoryRoot, APP_ROOTS);
}

export function modelSourceInputFiles(repositoryRoot) {
  return filesFor(repositoryRoot, MODEL_ROOTS);
}

export function releaseSourceSha256(repositoryRoot) {
  return integrityTreeSha256(
    repositoryRoot,
    releaseSourceInputFiles(repositoryRoot),
  );
}

export function appSourceSha256(repositoryRoot) {
  return integrityTreeSha256(
    repositoryRoot,
    appSourceInputFiles(repositoryRoot),
  );
}

export function modelSourceSha256(repositoryRoot) {
  return integrityTreeSha256(
    repositoryRoot,
    modelSourceInputFiles(repositoryRoot),
  );
}

function isolatedGitEnvironment() {
  const env = { ...process.env };
  for (const name of [
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_WORK_TREE",
  ]) {
    delete env[name];
  }
  return env;
}

export function verifyRepositorySourceIdentity(
  repositoryRoot,
  expectedCommit,
  runGit = (args) =>
    spawnSync("git", args, {
      encoding: "utf8",
      env: isolatedGitEnvironment(),
    }),
) {
  if (!/^[0-9a-f]{40}$/.test(expectedCommit ?? "")) {
    throw new Error("release source identity requires a full commit SHA");
  }
  const head = runGit([
    "-C",
    repositoryRoot,
    "rev-parse",
    "--verify",
    "HEAD",
  ]);
  if (head.status !== 0 || !/^[0-9a-f]{40}$/.test(head.stdout.trim())) {
    throw new Error("release source root is not a readable Git checkout");
  }
  if (head.stdout.trim() !== expectedCommit) {
    throw new Error("release source commit does not match repository HEAD");
  }
  const status = runGit([
    "-C",
    repositoryRoot,
    "status",
    "--porcelain=v1",
    "--untracked-files=all",
    "--",
    ...RELEASE_ROOTS,
  ]);
  if (status.status !== 0) {
    throw new Error("release source cleanliness could not be verified");
  }
  if (status.stdout.trim()) {
    throw new Error("release source inputs contain uncommitted changes");
  }
}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))
) {
  const [command, repositoryRoot, expectedCommit] = process.argv.slice(2);
  if (command !== "verify-repository" || !repositoryRoot || !expectedCommit) {
    console.error(
      "usage: node scripts/source-integrity.mjs verify-repository <root> <full-commit-sha>",
    );
    process.exitCode = 2;
  } else {
    try {
      verifyRepositorySourceIdentity(repositoryRoot, expectedCommit);
      console.log(`release source identity verified: ${expectedCommit}`);
    } catch (error) {
      console.error(`ERROR: ${error.message}`);
      process.exitCode = 1;
    }
  }
}
