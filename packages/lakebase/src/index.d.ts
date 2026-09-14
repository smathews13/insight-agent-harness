export class LakebaseInvariantError extends Error {
  readonly code: string;
  constructor(message: string, code?: string);
}

export class RevisionConflictError extends LakebaseInvariantError {
  readonly expected: number;
  readonly actual: number;
  constructor(expected: number, actual: number);
}

export interface Migration<Context = unknown> {
  version: number;
  id: string;
  checksum: string;
  apply(context: Context): void | Promise<void>;
  revert?(context: Context): void | Promise<void>;
}

export interface AppliedMigration {
  version: number;
  id: string;
  checksum: string;
}

export interface MigrationRegistry<Context = unknown> {
  readonly migrations: readonly Readonly<Migration<Context>>[];
  readonly latestVersion: number;
  pendingAfter(appliedVersion: number): readonly Readonly<Migration<Context>>[];
}

export function createMigrationRegistry<Context = unknown>(
  migrations: readonly Migration<Context>[],
): Readonly<MigrationRegistry<Context>>;
export function validateAppliedMigrations(
  registry: MigrationRegistry,
  appliedMigrations: readonly AppliedMigration[],
): true;

export interface SchemaOwnershipMetadata {
  owner: string;
  version: number;
}

export interface SchemaOwnershipDecision {
  action: "create" | "use" | "migrate" | "reject";
  owner: string;
  fromVersion: number;
  toVersion: number;
  reason?: string;
}

export function decideSchemaOwnership(input: {
  expectedOwner: string;
  targetVersion: number;
  existing?: SchemaOwnershipMetadata | null;
}): Readonly<SchemaOwnershipDecision>;

export function assertExpectedRevision(
  currentRevision: number,
  expectedRevision: number,
): true;

export function applyOptimisticUpdate<T extends { revision: number }>(
  current: T,
  expectedRevision: number,
  update: (draft: T) => T | void,
): Readonly<T>;

export interface Revision<T = unknown> {
  revision_id: string;
  revision: number;
  parent_revision_id: string | null;
  created_at: string;
  actor_ref: string;
  value: T;
}

export interface RevisionCandidate<T = unknown> {
  revision_id: string;
  created_at: string;
  actor_ref: string;
  value: T;
}

export function validateRevisionChain(history: readonly Revision[]): true;
export function appendRevision<T>(
  history: readonly Revision<T>[],
  candidate: RevisionCandidate<T>,
  expectedRevision: number,
): readonly Readonly<Revision<T>>[];

export interface RetentionPolicy {
  policyId: string;
  retainForMs: number;
  batchSize?: number;
}

export interface NormalizedRetentionPolicy {
  readonly policyId: string;
  readonly retainForMs: number;
  readonly batchSize: number;
}

export interface RetentionRecord {
  record_id: string;
  retained_at: string;
  legal_hold?: boolean;
}

export interface RetentionCandidate {
  record_id: string;
  retained_at: string;
}

export interface RetentionJobStore {
  listCandidates(
    policy: NormalizedRetentionPolicy,
    cutoffAt: string,
    limit: number,
  ): Promise<readonly RetentionRecord[]>;
  deleteCandidates(
    candidates: readonly RetentionCandidate[],
    expectedJobRevision: number,
  ): Promise<{ deleted: number; revision: number }>;
}

export interface RetentionJobExecutor {
  run(input: {
    policy: NormalizedRetentionPolicy;
    now: string;
    store: RetentionJobStore;
    signal?: AbortSignal;
  }): Promise<{ selected: number; deleted: number }>;
}

export function defineRetentionPolicy(policy: RetentionPolicy): NormalizedRetentionPolicy;
export function selectRetentionCandidates(
  records: readonly RetentionRecord[],
  policy: RetentionPolicy,
  now: string,
): readonly Readonly<RetentionCandidate>[];
