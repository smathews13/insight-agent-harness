export class LakebaseInvariantError extends Error {
  constructor(message, code = "LAKEBASE_INVARIANT") {
    super(message);
    this.name = "LakebaseInvariantError";
    this.code = code;
  }
}

export class RevisionConflictError extends LakebaseInvariantError {
  constructor(expected, actual) {
    super(
      `revision conflict: expected ${expected}, current revision is ${actual}`,
      "REVISION_CONFLICT",
    );
    this.name = "RevisionConflictError";
    this.expected = expected;
    this.actual = actual;
  }
}

const fail = (message, code) => {
  throw new LakebaseInvariantError(message, code);
};

const nonEmpty = (value, name) => {
  if (typeof value !== "string" || value.trim() !== value || value.length === 0) {
    fail(`${name} must be a non-empty, trimmed string`);
  }
  return value;
};

const revisionNumber = (value, name = "revision") => {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(`${name} must be a non-negative safe integer`);
  }
  return value;
};

const positiveVersion = (value, name = "version") => {
  if (!Number.isSafeInteger(value) || value < 1) {
    fail(`${name} must be a positive safe integer`);
  }
  return value;
};

const isoTimestamp = (value, name) => {
  nonEmpty(value, name);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    fail(`${name} must be a canonical ISO-8601 timestamp`);
  }
  return value;
};

const clone = (value) => structuredClone(value);

const deepFreeze = (value) => {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) {
      deepFreeze(child);
    }
  }
  return value;
};

export function createMigrationRegistry(migrations) {
  if (!Array.isArray(migrations)) {
    fail("migrations must be an array");
  }

  const ids = new Set();
  const normalized = migrations.map((migration, index) => {
    if (!migration || typeof migration !== "object") {
      fail(`migration at index ${index} must be an object`);
    }
    const version = positiveVersion(migration.version, `migration[${index}].version`);
    const expectedVersion = index + 1;
    if (version !== expectedVersion) {
      fail(
        `migration order must be contiguous from version 1; expected ${expectedVersion}, received ${version}`,
        "MIGRATION_ORDER",
      );
    }
    const id = nonEmpty(migration.id, `migration[${index}].id`);
    if (ids.has(id)) {
      fail(`migration id ${id} is duplicated`, "MIGRATION_DUPLICATE");
    }
    ids.add(id);
    const checksum = nonEmpty(migration.checksum, `migration[${index}].checksum`);
    if (typeof migration.apply !== "function") {
      fail(`migration ${id} must provide an apply function`);
    }
    if (migration.revert !== undefined && typeof migration.revert !== "function") {
      fail(`migration ${id} revert must be a function when provided`);
    }
    return deepFreeze({
      version,
      id,
      checksum,
      apply: migration.apply,
      ...(migration.revert ? { revert: migration.revert } : {}),
    });
  });

  return deepFreeze({
    migrations: normalized,
    latestVersion: normalized.length,
    pendingAfter(appliedVersion) {
      revisionNumber(appliedVersion, "appliedVersion");
      if (appliedVersion > normalized.length) {
        fail(
          `applied version ${appliedVersion} is newer than registry version ${normalized.length}`,
          "MIGRATION_AHEAD",
        );
      }
      return normalized.slice(appliedVersion);
    },
  });
}

export function validateAppliedMigrations(registry, appliedMigrations) {
  if (!registry || !Array.isArray(registry.migrations)) {
    fail("registry must be created by createMigrationRegistry");
  }
  if (!Array.isArray(appliedMigrations)) {
    fail("appliedMigrations must be an array");
  }
  if (appliedMigrations.length > registry.migrations.length) {
    fail("applied migrations are ahead of the registry", "MIGRATION_AHEAD");
  }

  appliedMigrations.forEach((applied, index) => {
    const registered = registry.migrations[index];
    if (
      !applied ||
      applied.version !== registered.version ||
      applied.id !== registered.id ||
      applied.checksum !== registered.checksum
    ) {
      fail(
        `applied migration at index ${index} does not match the registered migration prefix`,
        "MIGRATION_DRIFT",
      );
    }
  });
  return true;
}

export function decideSchemaOwnership({ expectedOwner, targetVersion, existing = null }) {
  nonEmpty(expectedOwner, "expectedOwner");
  positiveVersion(targetVersion, "targetVersion");

  if (existing === null) {
    return deepFreeze({ action: "create", owner: expectedOwner, fromVersion: 0, toVersion: targetVersion });
  }
  if (!existing || typeof existing !== "object") {
    fail("existing schema metadata must be an object or null");
  }
  nonEmpty(existing.owner, "existing.owner");
  positiveVersion(existing.version, "existing.version");

  if (existing.owner !== expectedOwner) {
    return deepFreeze({
      action: "reject",
      owner: existing.owner,
      fromVersion: existing.version,
      toVersion: targetVersion,
      reason: "schema is owned by a different component",
    });
  }
  if (existing.version > targetVersion) {
    return deepFreeze({
      action: "reject",
      owner: existing.owner,
      fromVersion: existing.version,
      toVersion: targetVersion,
      reason: "schema downgrade is not allowed",
    });
  }
  return deepFreeze({
    action: existing.version === targetVersion ? "use" : "migrate",
    owner: existing.owner,
    fromVersion: existing.version,
    toVersion: targetVersion,
  });
}

export function assertExpectedRevision(currentRevision, expectedRevision) {
  revisionNumber(currentRevision, "currentRevision");
  revisionNumber(expectedRevision, "expectedRevision");
  if (currentRevision !== expectedRevision) {
    throw new RevisionConflictError(expectedRevision, currentRevision);
  }
  return true;
}

export function applyOptimisticUpdate(current, expectedRevision, update) {
  if (!current || typeof current !== "object" || Array.isArray(current)) {
    fail("current value must be an object");
  }
  const currentRevision = revisionNumber(current.revision, "current.revision");
  assertExpectedRevision(currentRevision, expectedRevision);
  if (typeof update !== "function") {
    fail("update must be a function");
  }

  const draft = clone(current);
  const result = update(draft);
  const next = result === undefined ? draft : result;
  if (!next || typeof next !== "object" || Array.isArray(next)) {
    fail("update must produce an object");
  }
  if (next.revision !== currentRevision) {
    fail("update cannot set revision directly", "REVISION_MUTATION");
  }
  return deepFreeze({ ...clone(next), revision: currentRevision + 1 });
}

export function validateRevisionChain(history) {
  if (!Array.isArray(history)) {
    fail("revision history must be an array");
  }
  const ids = new Set();
  history.forEach((entry, index) => {
    if (!entry || typeof entry !== "object") {
      fail(`revision at index ${index} must be an object`);
    }
    nonEmpty(entry.revision_id, `history[${index}].revision_id`);
    if (ids.has(entry.revision_id)) {
      fail(`revision id ${entry.revision_id} is duplicated`, "REVISION_DUPLICATE");
    }
    ids.add(entry.revision_id);
    revisionNumber(entry.revision, `history[${index}].revision`);
    if (entry.revision !== index + 1) {
      fail(`revision numbers must be contiguous from 1`, "REVISION_CHAIN");
    }
    const expectedParent = index === 0 ? null : history[index - 1].revision_id;
    if (entry.parent_revision_id !== expectedParent) {
      fail(`revision ${entry.revision_id} has an invalid parent`, "REVISION_CHAIN");
    }
    isoTimestamp(entry.created_at, `history[${index}].created_at`);
    nonEmpty(entry.actor_ref, `history[${index}].actor_ref`);
  });
  return true;
}

export function appendRevision(history, candidate, expectedRevision) {
  validateRevisionChain(history);
  assertExpectedRevision(history.length, expectedRevision);
  if (!candidate || typeof candidate !== "object") {
    fail("revision candidate must be an object");
  }
  const revisionId = nonEmpty(candidate.revision_id, "candidate.revision_id");
  if (history.some((entry) => entry.revision_id === revisionId)) {
    fail(`revision id ${revisionId} is duplicated`, "REVISION_DUPLICATE");
  }
  isoTimestamp(candidate.created_at, "candidate.created_at");
  nonEmpty(candidate.actor_ref, "candidate.actor_ref");
  if (!Object.hasOwn(candidate, "value")) {
    fail("candidate.value is required");
  }

  const entry = deepFreeze({
    revision_id: revisionId,
    revision: history.length + 1,
    parent_revision_id: history.at(-1)?.revision_id ?? null,
    created_at: candidate.created_at,
    actor_ref: candidate.actor_ref,
    value: clone(candidate.value),
  });
  return deepFreeze([...history.map(clone), entry]);
}

export function defineRetentionPolicy({ policyId, retainForMs, batchSize = 100 }) {
  nonEmpty(policyId, "policyId");
  if (!Number.isSafeInteger(retainForMs) || retainForMs < 1) {
    fail("retainForMs must be a positive safe integer");
  }
  if (!Number.isSafeInteger(batchSize) || batchSize < 1) {
    fail("batchSize must be a positive safe integer");
  }
  return deepFreeze({ policyId, retainForMs, batchSize });
}

export function selectRetentionCandidates(records, policy, now) {
  if (!Array.isArray(records)) {
    fail("records must be an array");
  }
  const normalizedPolicy = defineRetentionPolicy(policy);
  isoTimestamp(now, "now");
  const cutoff = Date.parse(now) - normalizedPolicy.retainForMs;

  return deepFreeze(
    records
      .map((record, index) => {
        if (!record || typeof record !== "object") {
          fail(`record at index ${index} must be an object`);
        }
        nonEmpty(record.record_id, `records[${index}].record_id`);
        isoTimestamp(record.retained_at, `records[${index}].retained_at`);
        return record;
      })
      .filter((record) => record.legal_hold !== true && Date.parse(record.retained_at) <= cutoff)
      .sort(
        (left, right) =>
          left.retained_at.localeCompare(right.retained_at) ||
          left.record_id.localeCompare(right.record_id),
      )
      .slice(0, normalizedPolicy.batchSize)
      .map((record) => ({
        record_id: record.record_id,
        retained_at: record.retained_at,
      })),
  );
}
