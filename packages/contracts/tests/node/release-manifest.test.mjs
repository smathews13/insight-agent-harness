import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  canonicalJson,
  compareReleaseObservations,
  releaseManifestContentHash,
  sha256,
  signReleaseManifest,
  validateImmutableUpstreamPin,
  validateReleaseManifest,
  validateRollbackCompatibility,
  verifyReleaseManifest,
} from "../../src/index.js";

const H = (value) => sha256(value);

function candidate(overrides = {}) {
  return {
    schema_version: "1.0.0",
    release_id: {
      product: "insight-agent-harness:1.0.0",
      upstream: "upstream:v1.2.3",
      overlay: "neutral:1.0.0",
      app_artifact: "app:1.0.0",
      model_artifact: "model:7",
    },
    source_commit: "a".repeat(40),
    release_source_sha256: H("release sources"),
    app_source_sha256: H("app sources"),
    model_source_sha256: H("model sources"),
    upstream_tag: "v1.2.3",
    upstream_sha: "b".repeat(40),
    upstream_artifact_sha256: H("upstream artifact"),
    upstream_attestation: { status: "unverified", verifier: "none-configured" },
    app_artifact_sha256: H("app artifact"),
    model_artifact_sha256: H("model artifact"),
    registered_model: { version: "7", ref_sha256: H("catalog.schema.model") },
    prompt_pack_sha256: H("prompt pack"),
    policy_version: "1.0.0",
    product_manifest_sha256: H("product manifest"),
    shared_packages: [
      {
        name: "@insight-agent-harness/contracts",
        version: "0.1.0",
        artifact_sha256: H("contracts"),
      },
    ],
    artifact_contract: {
      canonical_schema_version: "1.1.0",
      export_adapter_version: "1.2.0",
      supported_formats: ["csv", "html", "json", "markdown", "pdf", "png", "tsv", "xlsx"],
      binary_adapters: {
        pdf: "available",
        png: "available",
        pptx: "unavailable",
        xlsx: "available",
      },
    },
    lakebase: { migration_version: 44, rollback_floor: 40 },
    authorization: {
      auth_mode: "user_authorization",
      oauth_scopes: ["dashboards.genie", "sql"],
    },
    data_boundary_fingerprint: H("data boundary"),
    genie_curation_fingerprints: [{ role: "data", sha256: H("genie") }],
    enabled_capability_mcp_fingerprint: H("capabilities"),
    evaluation: {
      suite_version: "suite-3",
      dataset_version: "dataset-4",
      scorer_versions: [
        { name: "groundedness", version: "2", sha256: H("scorer") },
      ],
      gate_result_digests: [{ name: "required", sha256: H("gate") }],
    },
    controls: {
      audit_schema_version: "1.1.0",
      audit_policy_ref: "policy:audit-safe-metadata-v2",
      retention_policy_ref: "policy:retention-v1",
      budget_policy_ref: "policy:budget-reporting",
      budget_mode: "reporting_only",
      reservation_mode: "none",
    },
    deploy_artifact_sha256: H("deploy tree"),
    resource_bindings_fingerprint: H("bindings"),
    observations: [],
    signer_key_id: "release-test-1",
    approval_record_id: `approval:sha256:${H("approval")}`,
    ...overrides,
  };
}

function fixture() {
  const keys = generateKeyPairSync("ed25519");
  const draft = candidate();
  draft.observations = compareReleaseObservations(draft, {
    source_commit: H(draft.source_commit),
    release_source: draft.release_source_sha256,
    app_source: draft.app_source_sha256,
    model_source: draft.model_source_sha256,
    upstream_pin: H(
      canonicalJson({
        tag: draft.upstream_tag,
        sha: draft.upstream_sha,
        artifact_sha256: draft.upstream_artifact_sha256,
      }),
    ),
    app_artifact: draft.app_artifact_sha256,
    model_artifact: draft.model_artifact_sha256,
    registered_model: H(canonicalJson(draft.registered_model)),
    product_manifest: draft.product_manifest_sha256,
    authorization: H(canonicalJson(draft.authorization)),
    lakebase_migration: H(canonicalJson(draft.lakebase)),
    data_boundary: draft.data_boundary_fingerprint,
    genie_curation: H(canonicalJson(draft.genie_curation_fingerprints)),
    shared_packages: H(canonicalJson(draft.shared_packages)),
    artifact_schema: H(
      canonicalJson({
        canonical_schema_version:
          draft.artifact_contract.canonical_schema_version,
      }),
    ),
    export_adapters: H(
      canonicalJson({
        export_adapter_version: draft.artifact_contract.export_adapter_version,
        supported_formats: draft.artifact_contract.supported_formats,
        binary_adapters: draft.artifact_contract.binary_adapters,
      }),
    ),
    capabilities: draft.enabled_capability_mcp_fingerprint,
    evaluation_gate: H(canonicalJson(draft.evaluation)),
    audit_schema: H(
      canonicalJson({
        audit_schema_version: draft.controls.audit_schema_version,
        audit_policy_ref: draft.controls.audit_policy_ref,
      }),
    ),
    retention_policy: H(
      canonicalJson({
        retention_policy_ref: draft.controls.retention_policy_ref,
      }),
    ),
    budget_policy: H(
      canonicalJson({
        budget_policy_ref: draft.controls.budget_policy_ref,
        budget_mode: draft.controls.budget_mode,
        reservation_mode: draft.controls.reservation_mode,
      }),
    ),
    deploy_artifact: draft.deploy_artifact_sha256,
  });
  const manifest = signReleaseManifest(
    draft,
    keys.privateKey.export({ type: "pkcs8", format: "pem" }),
    "2026-09-13T20:00:00.000Z",
  );
  const registry = {
    schema_version: "1.0.0",
    keys: [
      {
        key_id: "release-test-1",
        algorithm: "Ed25519",
        public_key_pem: keys.publicKey.export({ type: "spki", format: "pem" }),
        status: "active",
      },
    ],
  };
  return { keys, manifest, registry };
}

test("canonical content is stable and avoids a self-referential manifest id", () => {
  const { manifest } = fixture();
  const later = { ...manifest, signed_at: "2026-09-14T20:00:00.000Z" };
  assert.equal(
    releaseManifestContentHash(later),
    manifest.manifest_content_sha256,
  );
  assert.match(manifest.manifest_id, /^[0-9a-f-]{36}$/);
  assert.equal(validateReleaseManifest(manifest).valid, true);
});

test("production verification requires a trusted signature and all observations", () => {
  const { manifest, registry } = fixture();
  assert.equal(
    verifyReleaseManifest(manifest, registry, { mode: "production" }).valid,
    true,
  );
  const tampered = { ...manifest, policy_version: "2.0.0" };
  assert.match(
    verifyReleaseManifest(tampered, registry, {
      mode: "production",
    }).errors.join("\n"),
    /canonical unsigned content|verification failed/,
  );
  const incomplete = signReleaseManifest(
    {
      ...candidate(),
      observations: compareReleaseObservations(candidate(), {}),
    },
    generateKeyPairSync("ed25519").privateKey.export({
      type: "pkcs8",
      format: "pem",
    }),
  );
  assert.equal(
    verifyReleaseManifest(incomplete, registry, { mode: "production" }).valid,
    false,
  );
});

test("closed schema rejects unknown privileged fields and unsorted scopes", () => {
  const { manifest } = fixture();
  assert.match(
    validateReleaseManifest({ ...manifest, private_key: "never" }).errors.join(
      "\n",
    ),
    /unknown field/,
  );
  assert.match(
    validateReleaseManifest({
      ...manifest,
      authorization: {
        ...manifest.authorization,
        oauth_scopes: ["sql", "dashboards.genie"],
      },
    }).errors.join("\n"),
    /normalized/,
  );
});

test("immutable upstream pins reject mutable and mismatched references", () => {
  assert.equal(
    validateImmutableUpstreamPin({
      tag: "v1.2.3",
      sha: "a".repeat(40),
      artifact_sha256: H("artifact"),
    }).valid,
    true,
  );
  assert.equal(
    validateImmutableUpstreamPin(
      { tag: "latest", sha: "abc1234", artifact_sha256: H("artifact") },
      H("different"),
    ).valid,
    false,
  );
});

test("upstream attestation verification is pluggable and never assumed", () => {
  const { keys, manifest, registry } = fixture();
  const {
    manifest_id: _manifestId,
    manifest_content_sha256: _contentHash,
    signed_at: _signedAt,
    signature: _signature,
    ...candidateManifest
  } = manifest;
  const attested = signReleaseManifest(
    {
      ...candidateManifest,
      upstream_attestation: { status: "verified", verifier: "fixture-plugin" },
    },
    keys.privateKey.export({ type: "pkcs8", format: "pem" }),
  );
  assert.match(
    verifyReleaseManifest(attested, registry, {
      mode: "production",
    }).errors.join("\n"),
    /requires a configured attestation verifier/,
  );
  assert.equal(
    verifyReleaseManifest(attested, registry, {
      mode: "production",
      upstreamAttestationVerifier: () => true,
    }).valid,
    true,
  );
});

test("fixture rollback rehearsal treats app, model, policy, schema, scopes, and Genie as one transaction", () => {
  const rehearsal = JSON.parse(
    readFileSync(
      new URL("../../fixtures/rollback-rehearsal.json", import.meta.url),
      "utf8",
    ),
  );
  assert.equal(
    validateRollbackCompatibility(
      rehearsal.current,
      rehearsal.candidate,
      rehearsal.transaction,
    ).valid,
    true,
  );
  assert.match(
    validateRollbackCompatibility(rehearsal.current, rehearsal.candidate, {
      ...rehearsal.transaction,
      lakebase_migration_version: 39,
    }).errors.join("\n"),
    /Lakebase schema/,
  );
  assert.match(
    validateRollbackCompatibility(
      { ...rehearsal.current, policy_version: "2.0.0" },
      rehearsal.candidate,
      rehearsal.transaction,
    ).errors.join("\n"),
    /data policy/,
  );
});
