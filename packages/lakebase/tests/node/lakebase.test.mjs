import assert from "node:assert/strict";
import test from "node:test";

import {
  RevisionConflictError,
  appendRevision,
  applyOptimisticUpdate,
  createMigrationRegistry,
  decideSchemaOwnership,
  defineRetentionPolicy,
  selectRetentionCandidates,
  validateAppliedMigrations,
  validateRevisionChain,
} from "../../src/index.js";

const migration = (version, id = `migration-${version}`) => ({
  version,
  id,
  checksum: `sha256:${version}`,
  apply() {},
});

test("migration registry preserves a contiguous declared order", () => {
  const registry = createMigrationRegistry([migration(1), migration(2)]);
  assert.equal(registry.latestVersion, 2);
  assert.deepEqual(
    registry.pendingAfter(1).map(({ id }) => id),
    ["migration-2"],
  );
  assert.equal(
    validateAppliedMigrations(registry, [
      { version: 1, id: "migration-1", checksum: "sha256:1" },
    ]),
    true,
  );
});

test("migration registry rejects gaps, reordering, and applied drift", () => {
  assert.throws(
    () => createMigrationRegistry([migration(1), migration(3)]),
    /order must be contiguous/,
  );
  const registry = createMigrationRegistry([migration(1), migration(2)]);
  assert.throws(
    () =>
      validateAppliedMigrations(registry, [
        { version: 1, id: "migration-1", checksum: "changed" },
      ]),
    /does not match/,
  );
});

test("schema ownership never adopts or downgrades ambiguous state", () => {
  assert.equal(
    decideSchemaOwnership({ expectedOwner: "harness", targetVersion: 2 }).action,
    "create",
  );
  assert.equal(
    decideSchemaOwnership({
      expectedOwner: "harness",
      targetVersion: 2,
      existing: { owner: "harness", version: 1 },
    }).action,
    "migrate",
  );
  assert.equal(
    decideSchemaOwnership({
      expectedOwner: "harness",
      targetVersion: 2,
      existing: { owner: "other", version: 1 },
    }).action,
    "reject",
  );
  assert.equal(
    decideSchemaOwnership({
      expectedOwner: "harness",
      targetVersion: 1,
      existing: { owner: "harness", version: 2 },
    }).action,
    "reject",
  );
});

test("optimistic updates increment revisions without mutating input", () => {
  const current = { revision: 4, status: "draft" };
  const next = applyOptimisticUpdate(current, 4, (draft) => {
    draft.status = "published";
  });
  assert.deepEqual(current, { revision: 4, status: "draft" });
  assert.deepEqual(next, { revision: 5, status: "published" });
  assert.throws(
    () => applyOptimisticUpdate(current, 3, () => {}),
    RevisionConflictError,
  );
});

test("append-only revisions enforce expected revision and parent identity", () => {
  const first = appendRevision(
    [],
    {
      revision_id: "rev_1",
      created_at: "2026-09-13T20:00:00.000Z",
      actor_ref: "user:test",
      value: { title: "one" },
    },
    0,
  );
  const second = appendRevision(
    first,
    {
      revision_id: "rev_2",
      created_at: "2026-09-13T20:01:00.000Z",
      actor_ref: "user:test",
      value: { title: "two" },
    },
    1,
  );
  assert.equal(validateRevisionChain(second), true);
  assert.equal(second[1].parent_revision_id, "rev_1");
  assert.throws(() => appendRevision(first, second[1], 0), RevisionConflictError);

  const tampered = structuredClone(second);
  tampered[1].parent_revision_id = null;
  assert.throws(() => validateRevisionChain(tampered), /invalid parent/);
});

test("retention selection is deterministic and honors legal holds", () => {
  const policy = defineRetentionPolicy({
    policyId: "default",
    retainForMs: 1_000,
    batchSize: 2,
  });
  const selected = selectRetentionCandidates(
    [
      { record_id: "later", retained_at: "2026-09-13T20:00:00.000Z" },
      {
        record_id: "held",
        retained_at: "2026-09-13T19:00:00.000Z",
        legal_hold: true,
      },
      { record_id: "earlier", retained_at: "2026-09-13T19:59:59.000Z" },
      { record_id: "fresh", retained_at: "2026-09-13T20:00:01.000Z" },
    ],
    policy,
    "2026-09-13T20:00:01.000Z",
  );
  assert.deepEqual(selected, [
    { record_id: "earlier", retained_at: "2026-09-13T19:59:59.000Z" },
    { record_id: "later", retained_at: "2026-09-13T20:00:00.000Z" },
  ]);
});
