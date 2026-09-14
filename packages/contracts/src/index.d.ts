export * from "./generated/types";

export interface ContractValidation {
  valid: boolean;
  errors: string[];
}

export function validateContract(
  schemaName: string,
  value: unknown,
): ContractValidation;
export function validateRuntimeManifestChange(
  before: unknown,
  after: unknown,
): ContractValidation;
export function validateRequestAgainstManifest(
  request: unknown,
  manifest: unknown,
): ContractValidation;
export function manifestRiskMetadata(): Record<
  string,
  { risk_class: string; runtime_editable: boolean }
>;

export const REQUIRED_OBSERVATIONS: readonly string[];
export function canonicalJson(value: unknown): string;
export function sha256(value: string | Uint8Array): string;
export function releaseManifestUnsignedContent(
  manifest: ReleaseManifest,
): Record<string, unknown>;
export function releaseManifestContentHash(
  manifest: Partial<ReleaseManifest>,
): string;
export function manifestIdFromContentHash(contentHash: string): string;
export function validateReleaseManifest(manifest: unknown): ContractValidation;
export function signReleaseManifest(
  candidate: Omit<
    ReleaseManifest,
    "manifest_id" | "manifest_content_sha256" | "signed_at" | "signature"
  >,
  privateKeyPem: string,
  signedAt?: string,
): ReleaseManifest;
export function verifyReleaseManifest(
  manifest: unknown,
  registry: ReleaseKeyRegistry,
  options?: {
    mode?: "local" | "production";
    allowUnsignedLocalFixture?: boolean;
    upstreamAttestationVerifier?: (manifest: ReleaseManifest) => boolean;
  },
): ContractValidation;
export function compareReleaseObservations(
  manifest: ReleaseManifest,
  measured?: Record<string, string | undefined>,
): ReleaseManifest["observations"];
export function validateImmutableUpstreamPin(
  pin: { tag?: string; sha?: string; artifact_sha256?: string },
  observedArtifactSha256?: string,
): ContractValidation;
export function validateRollbackCompatibility(
  current: ReleaseManifest,
  candidate: ReleaseManifest,
  transaction: {
    app_artifact_sha256: string;
    model_artifact_sha256: string;
    model_version: string;
    product_manifest_sha256: string;
    policy_version: string;
    lakebase_migration_version: number;
    authorization_sha256: string;
    resource_bindings_fingerprint: string;
    genie_curation_sha256: string;
  },
): ContractValidation;
