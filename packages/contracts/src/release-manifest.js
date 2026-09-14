import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import { validateContract } from "./validation.js";

const HASH = /^[0-9a-f]{64}$/;
const REQUIRED_OBSERVATIONS = [
  "source_commit",
  "release_source",
  "app_source",
  "model_source",
  "upstream_pin",
  "app_artifact",
  "model_artifact",
  "registered_model",
  "product_manifest",
  "authorization",
  "lakebase_migration",
  "data_boundary",
  "genie_curation",
  "shared_packages",
  "artifact_schema",
  "export_adapters",
  "capabilities",
  "evaluation_gate",
  "audit_schema",
  "retention_policy",
  "budget_policy",
  "deploy_artifact",
];
const CONTENT_EXCLUDED_FIELDS = new Set([
  "manifest_id",
  "manifest_content_sha256",
  "signature",
  "signed_at",
]);

function normalize(value) {
  if (Array.isArray(value)) return value.map(normalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, normalize(value[key])]),
    );
  }
  return typeof value === "string" ? value.replace(/\r\n?/g, "\n") : value;
}

/** RFC 8785-style deterministic JSON for this integer/string/boolean contract. */
export function canonicalJson(value) {
  return `${JSON.stringify(normalize(value))}\n`;
}

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function releaseManifestUnsignedContent(manifest) {
  return Object.fromEntries(
    Object.entries(manifest).filter(
      ([key]) => !CONTENT_EXCLUDED_FIELDS.has(key),
    ),
  );
}

export function releaseManifestContentHash(manifest) {
  return sha256(canonicalJson(releaseManifestUnsignedContent(manifest)));
}

/** Deterministic RFC 9562 UUIDv8 whose 122 payload bits come from the content hash. */
export function manifestIdFromContentHash(contentHash) {
  if (!HASH.test(contentHash))
    throw new Error("manifest content hash must be lowercase sha256");
  const bytes = Buffer.from(contentHash.slice(0, 32), "hex");
  bytes[6] = (bytes[6] & 0x0f) | 0x80;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function signaturePayload(manifest) {
  const { signature: _signature, ...signed } = manifest;
  return canonicalJson(signed);
}

function sorted(values, key = (value) => value) {
  return [...values].sort((left, right) => key(left).localeCompare(key(right)));
}

function normalizationErrors(manifest) {
  const errors = [];
  const checks = [
    [
      "$.authorization.oauth_scopes",
      manifest.authorization?.oauth_scopes ?? [],
      (value) => value,
    ],
    [
      "$.shared_packages",
      manifest.shared_packages ?? [],
      (value) => `${value.name}\0${value.version}`,
    ],
    [
      "$.genie_curation_fingerprints",
      manifest.genie_curation_fingerprints ?? [],
      (value) => value.role,
    ],
    [
      "$.evaluation.scorer_versions",
      manifest.evaluation?.scorer_versions ?? [],
      (value) => value.name,
    ],
    [
      "$.evaluation.gate_result_digests",
      manifest.evaluation?.gate_result_digests ?? [],
      (value) => value.name,
    ],
    ["$.observations", manifest.observations ?? [], (value) => value.name],
  ];
  for (const [path, values, key] of checks) {
    if (JSON.stringify(values) !== JSON.stringify(sorted(values, key))) {
      errors.push(`${path}: must be normalized in ascending order`);
    }
  }
  if (
    (manifest.lakebase?.rollback_floor ?? 0) >
    (manifest.lakebase?.migration_version ?? 0)
  ) {
    errors.push("$.lakebase.rollback_floor: cannot exceed migration_version");
  }
  return errors;
}

export function validateReleaseManifest(manifest) {
  const validation = validateContract("release-manifest", manifest);
  if (!validation.valid) return validation;
  const errors = normalizationErrors(manifest);
  const contentHash = releaseManifestContentHash(manifest);
  if (manifest.manifest_content_sha256 !== contentHash) {
    errors.push(
      "$.manifest_content_sha256: does not match canonical unsigned content",
    );
  }
  if (manifest.manifest_id !== manifestIdFromContentHash(contentHash)) {
    errors.push("$.manifest_id: does not match canonical unsigned content");
  }
  return { valid: errors.length === 0, errors };
}

/**
 * Sign a complete release candidate. The private key is accepted only as an
 * explicit caller-provided PEM value; this library never generates or writes it.
 */
export function signReleaseManifest(
  candidate,
  privateKeyPem,
  signedAt = new Date().toISOString(),
) {
  if (!privateKeyPem || typeof privateKeyPem !== "string") {
    throw new Error("an explicit Ed25519 private key input is required");
  }
  const contentHash = releaseManifestContentHash(candidate);
  const unsigned = {
    ...candidate,
    manifest_id: manifestIdFromContentHash(contentHash),
    manifest_content_sha256: contentHash,
    signed_at: signedAt,
  };
  const privateKey = createPrivateKey(privateKeyPem);
  if (privateKey.asymmetricKeyType !== "ed25519")
    throw new Error("release signing key must be Ed25519");
  const signature = sign(
    null,
    Buffer.from(signaturePayload(unsigned)),
    privateKey,
  ).toString("base64");
  const manifest = {
    ...unsigned,
    signature: { algorithm: "Ed25519", value: signature },
  };
  const validation = validateReleaseManifest(manifest);
  if (!validation.valid)
    throw new Error(
      `release manifest is invalid: ${validation.errors.join("; ")}`,
    );
  return manifest;
}

export function verifyReleaseManifest(manifest, registry, options = {}) {
  const unsignedLocalFixture =
    options.mode !== "production" &&
    options.allowUnsignedLocalFixture === true &&
    (!manifest?.signature || manifest.signature.value === "");
  const validationTarget = unsignedLocalFixture
    ? {
        ...manifest,
        signature: { algorithm: "Ed25519", value: `${"A".repeat(86)}==` },
      }
    : manifest;
  const errors = [...validateReleaseManifest(validationTarget).errors];
  if (unsignedLocalFixture) return { valid: errors.length === 0, errors };
  const registryValidation = validateContract("release-key-registry", registry);
  errors.push(
    ...registryValidation.errors.map((error) => `key registry ${error}`),
  );
  const keys = (registry?.keys ?? []).filter(
    (key) => key.key_id === manifest?.signer_key_id,
  );
  if (keys.length !== 1) {
    errors.push(
      "$.signer_key_id: must resolve to exactly one trusted public key",
    );
  } else if (keys[0].status !== "active") {
    errors.push(
      `$.signer_key_id: trusted key is ${keys[0].status}, not active`,
    );
  } else {
    try {
      const publicKey = createPublicKey(keys[0].public_key_pem);
      if (
        publicKey.asymmetricKeyType !== "ed25519" ||
        !verify(
          null,
          Buffer.from(signaturePayload(manifest)),
          publicKey,
          Buffer.from(manifest.signature?.value ?? "", "base64"),
        )
      ) {
        errors.push("$.signature: Ed25519 verification failed");
      }
    } catch {
      errors.push("$.signature: trusted public key or signature is invalid");
    }
  }
  if (options.mode === "production") {
    if (
      !/^approval:sha256:[0-9a-f]{64}$/.test(manifest?.approval_record_id ?? "")
    ) {
      errors.push(
        "$.approval_record_id: production verification requires a hashed approval record",
      );
    }
    const observations = new Map(
      (manifest?.observations ?? []).map((item) => [item.name, item.status]),
    );
    for (const required of REQUIRED_OBSERVATIONS) {
      if (observations.get(required) !== "verified") {
        errors.push(
          `$.observations.${required}: production promotion requires a verified observation`,
        );
      }
    }
  }
  if (manifest?.upstream_attestation?.status === "verified") {
    if (typeof options.upstreamAttestationVerifier !== "function") {
      errors.push(
        "$.upstream_attestation: verified status requires a configured attestation verifier",
      );
    } else if (options.upstreamAttestationVerifier(manifest) !== true) {
      errors.push(
        "$.upstream_attestation: configured attestation verifier rejected the pin",
      );
    }
  }
  return { valid: errors.length === 0, errors };
}

function expectedObservationDigests(manifest) {
  const controls = manifest.controls ?? {};
  return {
    source_commit: sha256(manifest.source_commit),
    release_source: manifest.release_source_sha256,
    app_source: manifest.app_source_sha256,
    model_source: manifest.model_source_sha256,
    upstream_pin: sha256(
      canonicalJson({
        tag: manifest.upstream_tag,
        sha: manifest.upstream_sha,
        artifact_sha256: manifest.upstream_artifact_sha256,
      }),
    ),
    app_artifact: manifest.app_artifact_sha256,
    model_artifact: manifest.model_artifact_sha256,
    registered_model: sha256(canonicalJson(manifest.registered_model)),
    product_manifest: manifest.product_manifest_sha256,
    authorization: sha256(canonicalJson(manifest.authorization)),
    lakebase_migration: sha256(canonicalJson(manifest.lakebase)),
    data_boundary: manifest.data_boundary_fingerprint,
    genie_curation: sha256(canonicalJson(manifest.genie_curation_fingerprints)),
    shared_packages: sha256(canonicalJson(manifest.shared_packages)),
    artifact_schema: sha256(
      canonicalJson({
        canonical_schema_version:
          manifest.artifact_contract?.canonical_schema_version,
      }),
    ),
    export_adapters: sha256(
      canonicalJson({
        export_adapter_version:
          manifest.artifact_contract?.export_adapter_version,
        supported_formats: manifest.artifact_contract?.supported_formats,
        binary_adapters: manifest.artifact_contract?.binary_adapters,
      }),
    ),
    capabilities: manifest.enabled_capability_mcp_fingerprint,
    evaluation_gate: sha256(canonicalJson(manifest.evaluation)),
    audit_schema: sha256(
      canonicalJson({
        audit_schema_version: controls.audit_schema_version,
        audit_policy_ref: controls.audit_policy_ref,
      }),
    ),
    retention_policy: sha256(
      canonicalJson({ retention_policy_ref: controls.retention_policy_ref }),
    ),
    budget_policy: sha256(
      canonicalJson({
        budget_policy_ref: controls.budget_policy_ref,
        budget_mode: controls.budget_mode,
        reservation_mode: controls.reservation_mode,
      }),
    ),
    deploy_artifact: manifest.deploy_artifact_sha256,
  };
}

/** Compare only measured facts. Missing facts remain unverified and block production. */
export function compareReleaseObservations(manifest, measured = {}) {
  const expected = expectedObservationDigests(manifest);
  return REQUIRED_OBSERVATIONS.map((name) => {
    const observed = measured[name];
    return {
      name,
      status: !observed
        ? "unverified"
        : observed === expected[name]
          ? "verified"
          : "failed",
      ...(observed ? { observed_sha256: observed } : {}),
    };
  }).sort((left, right) => left.name.localeCompare(right.name));
}

export function validateImmutableUpstreamPin(pin, observedArtifactSha256) {
  const errors = [];
  if (!pin || !/^[0-9a-f]{40}$/.test(pin.sha ?? "")) {
    errors.push("upstream pin requires a full immutable commit SHA");
  }
  if (
    !pin?.tag ||
    pin.tag === "latest" ||
    /^(?:refs\/heads\/|heads\/)/.test(pin.tag) ||
    /^[0-9a-f]{7,39}$/.test(pin.tag)
  ) {
    errors.push(
      "upstream pin requires an immutable tag, not a branch, latest, or abbreviated SHA",
    );
  }
  if (!HASH.test(pin?.artifact_sha256 ?? "")) {
    errors.push("upstream pin requires a lowercase artifact sha256");
  }
  if (
    observedArtifactSha256 &&
    observedArtifactSha256 !== pin?.artifact_sha256
  ) {
    errors.push("upstream artifact digest does not match the immutable pin");
  }
  return { valid: errors.length === 0, errors };
}

/**
 * Rehearse the atomic rollback tuple without touching a live deployment.
 * Every mutable binding is compared to the candidate manifest; Lakebase remains
 * data, never release authority.
 */
export function validateRollbackCompatibility(current, candidate, transaction) {
  const errors = [];
  if (transaction.app_artifact_sha256 !== candidate.app_artifact_sha256)
    errors.push("rollback app artifact does not match candidate manifest");
  if (transaction.model_artifact_sha256 !== candidate.model_artifact_sha256)
    errors.push("rollback model artifact does not match candidate manifest");
  if (transaction.model_version !== candidate.registered_model.version)
    errors.push("rollback model version does not match candidate manifest");
  if (transaction.product_manifest_sha256 !== candidate.product_manifest_sha256)
    errors.push("rollback ProductManifest does not match candidate manifest");
  if (transaction.policy_version !== candidate.policy_version)
    errors.push("rollback policy does not match candidate manifest");
  if (current.policy_version !== candidate.policy_version)
    errors.push(
      "current data policy is not rollback-compatible with candidate",
    );
  if (
    transaction.lakebase_migration_version <
      candidate.lakebase.rollback_floor ||
    transaction.lakebase_migration_version >
      candidate.lakebase.migration_version
  ) {
    errors.push(
      "Lakebase schema is outside the candidate rollback compatibility range",
    );
  }
  if (
    transaction.authorization_sha256 !==
    sha256(canonicalJson(candidate.authorization))
  )
    errors.push("rollback auth mode/scopes do not match candidate manifest");
  if (
    transaction.resource_bindings_fingerprint !==
    candidate.resource_bindings_fingerprint
  )
    errors.push("rollback resource bindings do not match candidate manifest");
  if (
    transaction.genie_curation_sha256 !==
    sha256(canonicalJson(candidate.genie_curation_fingerprints))
  ) {
    errors.push("rollback Genie curation does not match candidate manifest");
  }
  return { valid: errors.length === 0, errors };
}

export { REQUIRED_OBSERVATIONS };
