#!/usr/bin/env node
import {
  closeSync,
  constants,
  fstatSync,
  openSync,
  readFileSync,
  writeFileSync,
} from "node:fs";

import {
  compareReleaseObservations,
  sha256,
  signReleaseManifest,
  validateRollbackCompatibility,
  verifyReleaseManifest,
} from "../packages/contracts/src/index.js";
import {
  appSourceSha256,
  modelSourceSha256,
  releaseSourceSha256,
  verifyRepositorySourceIdentity,
} from "./source-integrity.mjs";

function die(message) {
  console.error(`ERROR: ${message}`);
  process.exit(2);
}

function option(name, required = true) {
  const index = process.argv.indexOf(name);
  const value = index >= 0 ? process.argv[index + 1] : "";
  if (required && !value) die(`${name} is required`);
  return value;
}

function rejectOption(name) {
  if (process.argv.includes(name)) die(`${name} is unsupported`);
}

function integrityFile(file, label, maxBytes, privateOnly = false) {
  let descriptor;
  try {
    descriptor = openSync(
      file,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
    );
    const stat = fstatSync(descriptor);
    if (!stat.isFile()) throw new Error("input is not a regular file");
    if (
      privateOnly &&
      process.platform !== "win32" &&
      (stat.mode & 0o077) !== 0
    ) {
      throw new Error("input permissions allow group or other access");
    }
    if (stat.size === 0) throw new Error("input is empty");
    if (stat.size > maxBytes)
      throw new Error(`input exceeds ${maxBytes} bytes`);
    return readFileSync(descriptor);
  } catch (error) {
    die(
      `${label} could not be read safely: ${error instanceof Error ? error.message : String(error)}`,
    );
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function json(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    die(
      `could not read ${path}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

function write(path, value) {
  const text = `${JSON.stringify(value, null, 2)}\n`;
  if (path) writeFileSync(path, text, { encoding: "utf8", mode: 0o600 });
  else process.stdout.write(text);
}

function verifySourceIdentity(repositoryRoot, sourceCommit) {
  try {
    verifyRepositorySourceIdentity(repositoryRoot, sourceCommit);
  } catch (error) {
    die(
      `source identity verification failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

const command = process.argv[2];
if (command === "observe") {
  const candidate = json(option("--candidate"));
  const measured = json(option("--measured"));
  const repositoryRoot = option("--repository-root", false);
  if (repositoryRoot) {
    measured.release_source = releaseSourceSha256(repositoryRoot);
    measured.app_source = appSourceSha256(repositoryRoot);
    measured.model_source = modelSourceSha256(repositoryRoot);
  }
  write(option("--output", false), {
    ...candidate,
    observations: compareReleaseObservations(candidate, measured),
  });
} else if (command === "sign") {
  rejectOption("--approval-record");
  const candidate = json(option("--candidate"));
  const privateKeyPath = option("--private-key-file");
  const approvalRecordPath = option("--approval-record-file");
  const repositoryRoot = option("--repository-root");
  const approvalRecord = integrityFile(
    approvalRecordPath,
    "approval record",
    10 * 1024 * 1024,
  );
  const privateKey = integrityFile(
    privateKeyPath,
    "private key",
    64 * 1024,
    true,
  ).toString("utf8");
  const sourceDigests = {
    release_source_sha256: releaseSourceSha256(repositoryRoot),
    app_source_sha256: appSourceSha256(repositoryRoot),
    model_source_sha256: modelSourceSha256(repositoryRoot),
  };
  for (const [field, observed] of Object.entries(sourceDigests)) {
    if (candidate[field] !== observed) {
      die(`${field} does not match the deterministic repository source digest`);
    }
  }
  verifySourceIdentity(repositoryRoot, candidate.source_commit);
  if (
    candidate.signature ||
    candidate.manifest_id ||
    candidate.manifest_content_sha256
  ) {
    die(
      "sign input must be an unsigned candidate without derived identity or signature fields",
    );
  }
  const manifest = signReleaseManifest(
    {
      ...candidate,
      approval_record_id: `approval:sha256:${sha256(approvalRecord)}`,
    },
    privateKey,
  );
  write(option("--output", false), manifest);
} else if (command === "source-digest") {
  const repositoryRoot = option("--repository-root");
  write(option("--output", false), {
    schema_version: "1.0.0",
    release_source_sha256: releaseSourceSha256(repositoryRoot),
    app_source_sha256: appSourceSha256(repositoryRoot),
    model_source_sha256: modelSourceSha256(repositoryRoot),
  });
} else if (command === "verify") {
  const manifest = json(option("--manifest"));
  const registry = json(option("--key-registry"));
  const production = process.argv.includes("--production");
  const allowUnsigned = process.argv.includes("--allow-unsigned-local-fixture");
  const repositoryRoot = option("--repository-root", false);
  if (production && allowUnsigned)
    die(
      "unsigned fixture mode can never be combined with production verification",
    );
  if (production && !repositoryRoot) {
    die("--repository-root is required for production source verification");
  }
  if (repositoryRoot) {
    const expected = {
      release_source_sha256: releaseSourceSha256(repositoryRoot),
      app_source_sha256: appSourceSha256(repositoryRoot),
      model_source_sha256: modelSourceSha256(repositoryRoot),
    };
    for (const [field, observed] of Object.entries(expected)) {
      if (manifest[field] !== observed) {
        die(
          `${field} does not match the deterministic repository source digest`,
        );
      }
    }
    verifySourceIdentity(repositoryRoot, manifest.source_commit);
  }
  const result = verifyReleaseManifest(manifest, registry, {
    mode: production ? "production" : "local",
    allowUnsignedLocalFixture: allowUnsigned,
  });
  if (!result.valid) {
    result.errors.forEach((error) => console.error(`  - ${error}`));
    process.exit(1);
  }
  console.log(
    `${production ? "Production" : allowUnsigned ? "Explicit unsigned local fixture" : "Local"} release manifest verification passed: ${manifest.manifest_id}`,
  );
} else if (command === "rollback") {
  const result = validateRollbackCompatibility(
    json(option("--current")),
    json(option("--candidate")),
    json(option("--transaction")),
  );
  if (!result.valid) {
    result.errors.forEach((error) => console.error(`  - ${error}`));
    process.exit(1);
  }
  console.log("Rollback compatibility rehearsal passed.");
} else {
  die(
    "usage: release-manifest.mjs observe|sign|source-digest|verify|rollback (signing requires --private-key-file, --approval-record-file, and --repository-root)",
  );
}
