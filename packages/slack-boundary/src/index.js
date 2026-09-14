import { createHash } from "node:crypto";
import { URL } from "node:url";

import { prepareAuthorizedDocument } from "../../export-core/src/index.js";
import { normalizeCorrelationId } from "../../observability/src/index.js";

export class SlackBoundaryInvariantError extends Error {
  constructor(message, code = "SLACK_BOUNDARY_INVARIANT") {
    super(message);
    this.name = "SlackBoundaryInvariantError";
    this.code = code;
  }
}

const fail = (message, code) => {
  throw new SlackBoundaryInvariantError(message, code);
};

const deepFreeze = (value) => {
  if (!value || typeof value !== "object" || Object.isFrozen(value))
    return value;
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child);
  return value;
};

const clone = (value) => globalThis.structuredClone(value);
const SAFE_REF = /^[a-z][a-z0-9_.-]{1,63}:[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const SAFE_IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,255}$/;
const SLACK_ID = /^[A-Z][A-Z0-9]{1,31}$/;
const SLACK_EVENT_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/;
const SLACK_TIMESTAMP = /^\d{10,}\.\d{6}$/;
const SLACK_WORKSPACE_REF = /^slack_workspace:([A-Z][A-Z0-9]{1,31})$/;
const SLACK_CHANNEL_REF =
  /^slack_channel:([A-Z][A-Z0-9]{1,31}):([A-Z][A-Z0-9]{1,31})$/;
const SLACK_USER_REF =
  /^slack_user:([A-Z][A-Z0-9]{1,31}):([A-Z][A-Z0-9]{1,31})$/;
const SLACK_MESSAGE_REF =
  /^slack_message:([A-Z][A-Z0-9]{1,31}):([A-Z][A-Z0-9]{1,31}):(\d{10,}\.\d{6})$/;
const SLACK_THREAD_REF =
  /^slack_thread:([A-Z][A-Z0-9]{1,31}):([A-Z][A-Z0-9]{1,31}):(\d{10,}\.\d{6})$/;
const SLACK_EVENT_REF =
  /^slack_event:([A-Z][A-Z0-9]{1,31}):([A-Za-z0-9][A-Za-z0-9._:-]{2,127})$/;
const LINK_STATE_REF = /^link_state:v1:[A-Za-z0-9_-]{43}$/;
const SHA256_REF = /^sha256:[a-f0-9]{64}$/;
const CORRELATION_ID =
  /^(?:corr_[a-z0-9][a-z0-9_-]{2,95}|req-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/;
const SENSITIVE_KEYS = new Set([
  "accesstoken",
  "authorization",
  "clientsecret",
  "cookie",
  "idtoken",
  "password",
  "refreshtoken",
  "setcookie",
  "token",
]);
const TOKEN_VALUE = [
  /\bBearer\s+[A-Za-z0-9._~+/=-]+/i,
  /\b(?:dapi|dapiclient|dkea)[A-Za-z0-9_-]{12,}\b/i,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/,
];
const RAW_CONTENT_KEYS =
  /^(?:blocks|files|message|messages|prompt|raw_event|response|text|thread_messages)$/i;

const nonEmpty = (value, name, maximum = 512) => {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximum ||
    value.trim() !== value
  ) {
    fail(
      `${name} must be a non-empty, trimmed string of at most ${maximum} characters`,
    );
  }
  return value;
};

const oneOf = (value, allowed, name) => {
  if (!allowed.includes(value)) {
    fail(`${name} must be one of: ${allowed.join(", ")}`);
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

const slackId = (value, name) => {
  if (typeof value !== "string" || !SLACK_ID.test(value)) {
    fail(`${name} must be an opaque Slack identifier`);
  }
  return value;
};

const slackTimestamp = (value, name) => {
  if (typeof value !== "string" || !SLACK_TIMESTAMP.test(value)) {
    fail(`${name} must be a canonical Slack timestamp`);
  }
  return value;
};

const compareSlackTimestamps = (left, right) => {
  const [leftSeconds, leftFraction] = left.split(".");
  const [rightSeconds, rightFraction] = right.split(".");
  const secondsDelta = BigInt(leftSeconds) - BigInt(rightSeconds);
  if (secondsDelta !== 0n) return secondsDelta < 0n ? -1 : 1;
  if (leftFraction === rightFraction) return 0;
  return leftFraction < rightFraction ? -1 : 1;
};

const safeRef = (value, name, prefix) => {
  if (
    typeof value !== "string" ||
    !SAFE_REF.test(value) ||
    (prefix && !value.startsWith(prefix))
  ) {
    fail(`${name} must be an opaque ${prefix ?? ""}reference`);
  }
  return value;
};

const strictSlackRef = (value, name, pattern) => {
  if (typeof value !== "string" || !pattern.test(value)) {
    fail(`${name} must be a canonical opaque Slack reference`);
  }
  return value;
};

const exactKeys = (value, allowed, name) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(`${name} must be an object`);
  }
  for (const key of Object.keys(value)) {
    if (!allowed.has(key))
      fail(`${name}.${key} is not allowed`, "UNDECLARED_FIELD");
  }
  return value;
};

function findRawToken(value, path = "$", seen = new WeakSet()) {
  if (typeof value === "string") {
    return TOKEN_VALUE.some((pattern) => pattern.test(value)) ? path : null;
  }
  if (!value || typeof value !== "object") return null;
  if (seen.has(value)) return null;
  seen.add(value);
  for (const [key, child] of Object.entries(value)) {
    const normalizedKey = key.replace(/[^a-z0-9]/gi, "").toLowerCase();
    if (SENSITIVE_KEYS.has(normalizedKey) && !key.endsWith("_ref")) {
      return `${path}.${key}`;
    }
    const nested = findRawToken(child, `${path}.${key}`, seen);
    if (nested) return nested;
  }
  return null;
}

export function assertNoRawDatabricksToken(value) {
  const path = findRawToken(value);
  if (path) {
    fail(
      `raw Databricks token material is forbidden at ${path}`,
      "RAW_TOKEN_FORBIDDEN",
    );
  }
  return value;
}

function assertNoRawSlackContent(value, path = "$", seen = new WeakSet()) {
  if (!value || typeof value !== "object") return value;
  if (seen.has(value)) return value;
  seen.add(value);
  for (const [key, child] of Object.entries(value)) {
    if (RAW_CONTENT_KEYS.test(key)) {
      fail(
        `raw Slack content is forbidden at ${path}.${key}`,
        "RAW_SLACK_CONTENT_FORBIDDEN",
      );
    }
    assertNoRawSlackContent(child, `${path}.${key}`, seen);
  }
  return value;
}

const digest = (value, length = 20) =>
  createHash("sha256")
    .update(String(value), "utf8")
    .digest("hex")
    .slice(0, length);

const slackRef = (kind, ...parts) => `slack_${kind}:${parts.join(":")}`;

export const SLACK_PRODUCT_BOUNDARY = deepFreeze({
  schema_version: "1.0.0",
  verdict: "NO_GO",
  mode: "authenticated_web_app_link_out_only",
  reason_code: "delegated_databricks_authorization_unproven",
  allowed_actions: [
    "acknowledge_event",
    "persist_safe_metadata",
    "render_authentication_link_out",
    "render_authenticated_link_out",
  ],
  prohibited_actions: [
    "enable_production_slack_bot",
    "accept_unverified_slack_event",
    "execute_databricks_request_from_slack",
    "send_governed_result_to_slack",
    "substitute_service_principal",
    "store_raw_databricks_token",
  ],
});

/**
 * This spike cannot be flipped by configuration or self-attestation. A later
 * reviewed code change, backed by real supported-verifier tests, is required.
 */
export function getSlackProductBoundary() {
  return SLACK_PRODUCT_BOUNDARY;
}

const EVENT_INPUT_KEYS = new Set([
  "team_id",
  "event_id",
  "event_type",
  "user_id",
  "channel_id",
  "event_ts",
  "message_ts",
  "thread_ts",
  "mutation",
  "revision_ts",
  "retry_number",
  "retry_reason",
  "received_at",
]);
const NORMALIZED_EVENT_KEYS = new Set([
  "schema_version",
  "event_ref",
  "workspace_ref",
  "channel_ref",
  "actor_ref",
  "message_ref",
  "thread_ref",
  "event_id",
  "event_type",
  "event_ts",
  "message_ts",
  "thread_ts",
  "revision_ts",
  "mutation",
  "idempotency_key",
  "retry",
  "received_at",
]);

export function createSlackEventContract(input) {
  exactKeys(input, EVENT_INPUT_KEYS, "event");
  assertNoRawSlackContent(input);
  assertNoRawDatabricksToken(input);

  const teamId = slackId(input.team_id, "event.team_id");
  if (
    typeof input.event_id !== "string" ||
    !SLACK_EVENT_ID.test(input.event_id)
  ) {
    fail("event.event_id must be an opaque Slack event identifier");
  }
  const eventType = nonEmpty(input.event_type, "event.event_type", 80);
  const userId = slackId(input.user_id, "event.user_id");
  const channelId = slackId(input.channel_id, "event.channel_id");
  const eventTs = slackTimestamp(input.event_ts, "event.event_ts");
  const messageTs = slackTimestamp(
    input.message_ts ?? eventTs,
    "event.message_ts",
  );
  const threadTs = slackTimestamp(
    input.thread_ts ?? messageTs,
    "event.thread_ts",
  );
  const mutation = oneOf(
    input.mutation ?? "created",
    ["created", "edited", "deleted"],
    "event.mutation",
  );
  const revisionTs = slackTimestamp(
    input.revision_ts ?? (mutation === "created" ? messageTs : eventTs),
    "event.revision_ts",
  );
  const retryNumber = input.retry_number ?? 0;
  if (!Number.isSafeInteger(retryNumber) || retryNumber < 0) {
    fail("event.retry_number must be a non-negative safe integer");
  }
  if (input.retry_reason !== undefined) {
    nonEmpty(input.retry_reason, "event.retry_reason", 80);
  }
  isoTimestamp(input.received_at, "event.received_at");

  const workspaceRef = slackRef("workspace", teamId);
  const channelRef = slackRef("channel", teamId, channelId);
  const actorRef = slackRef("user", teamId, userId);
  const messageRef = slackRef("message", teamId, channelId, messageTs);
  const threadRef = slackRef("thread", teamId, channelId, threadTs);
  const eventRef = slackRef("event", teamId, input.event_id);
  const idempotencyKey = `slack:${teamId}:${input.event_id}:${revisionTs}`;
  if (!SAFE_IDEMPOTENCY_KEY.test(idempotencyKey)) {
    fail("the derived Slack idempotency key is invalid");
  }

  return deepFreeze({
    schema_version: "1.0.0",
    event_ref: eventRef,
    workspace_ref: workspaceRef,
    channel_ref: channelRef,
    actor_ref: actorRef,
    message_ref: messageRef,
    thread_ref: threadRef,
    event_id: input.event_id,
    event_type: eventType,
    event_ts: eventTs,
    message_ts: messageTs,
    thread_ts: threadTs,
    revision_ts: revisionTs,
    mutation,
    idempotency_key: idempotencyKey,
    retry: {
      number: retryNumber,
      ...(input.retry_reason ? { reason: input.retry_reason } : {}),
    },
    received_at: input.received_at,
  });
}

function validateSlackEventContract(event) {
  exactKeys(event, NORMALIZED_EVENT_KEYS, "eventContract");
  if (event.schema_version !== "1.0.0") {
    fail("eventContract.schema_version must be 1.0.0");
  }
  const workspaceMatch = strictSlackRef(
    event.workspace_ref,
    "eventContract.workspace_ref",
    SLACK_WORKSPACE_REF,
  ).match(SLACK_WORKSPACE_REF);
  const channelMatch = strictSlackRef(
    event.channel_ref,
    "eventContract.channel_ref",
    SLACK_CHANNEL_REF,
  ).match(SLACK_CHANNEL_REF);
  const actorMatch = strictSlackRef(
    event.actor_ref,
    "eventContract.actor_ref",
    SLACK_USER_REF,
  ).match(SLACK_USER_REF);
  strictSlackRef(
    event.message_ref,
    "eventContract.message_ref",
    SLACK_MESSAGE_REF,
  );
  strictSlackRef(
    event.thread_ref,
    "eventContract.thread_ref",
    SLACK_THREAD_REF,
  );
  const eventMatch = strictSlackRef(
    event.event_ref,
    "eventContract.event_ref",
    SLACK_EVENT_REF,
  ).match(SLACK_EVENT_REF);
  exactKeys(event.retry, new Set(["number", "reason"]), "eventContract.retry");

  const normalized = createSlackEventContract({
    team_id: workspaceMatch[1],
    event_id: event.event_id,
    event_type: event.event_type,
    user_id: actorMatch[2],
    channel_id: channelMatch[2],
    event_ts: event.event_ts,
    message_ts: event.message_ts,
    thread_ts: event.thread_ts,
    mutation: event.mutation,
    revision_ts: event.revision_ts,
    retry_number: event.retry.number,
    ...(event.retry.reason ? { retry_reason: event.retry.reason } : {}),
    received_at: event.received_at,
  });
  if (
    channelMatch[1] !== workspaceMatch[1] ||
    actorMatch[1] !== workspaceMatch[1] ||
    eventMatch[1] !== workspaceMatch[1] ||
    eventMatch[2] !== event.event_id ||
    ![...NORMALIZED_EVENT_KEYS].every((key) => {
      if (key !== "retry") return normalized[key] === event[key];
      return (
        normalized.retry.number === event.retry.number &&
        normalized.retry.reason === event.retry.reason
      );
    })
  ) {
    fail(
      "normalized Slack event references do not describe one canonical event",
      "FORGED_SLACK_EVENT",
    );
  }
  return event;
}

const DELIVERY_ACTIONS = Object.freeze({
  CREATED: "render_link_out",
  EDITED: "replace_link_out",
  DELETED: "remove_link_out",
  DUPLICATE: "acknowledge_duplicate",
  STALE: "acknowledge_stale_revision",
});

export function planSlackEventDelivery(event, receipt = null) {
  validateSlackEventContract(event);
  assertNoRawDatabricksToken(event);
  if (receipt === null) {
    return deepFreeze({
      acknowledge: true,
      action:
        event.mutation === "edited"
          ? DELIVERY_ACTIONS.EDITED
          : event.mutation === "deleted"
            ? DELIVERY_ACTIONS.DELETED
            : DELIVERY_ACTIONS.CREATED,
      idempotency_key: event.idempotency_key,
    });
  }

  exactKeys(
    receipt,
    new Set(["message_ref", "idempotency_key", "latest_revision_ts"]),
    "receipt",
  );
  strictSlackRef(receipt.message_ref, "receipt.message_ref", SLACK_MESSAGE_REF);
  if (
    typeof receipt.idempotency_key !== "string" ||
    !SAFE_IDEMPOTENCY_KEY.test(receipt.idempotency_key)
  ) {
    fail("receipt.idempotency_key is invalid");
  }
  slackTimestamp(receipt.latest_revision_ts, "receipt.latest_revision_ts");
  if (receipt.message_ref !== event.message_ref) {
    fail(
      "receipt and event must describe the same Slack message",
      "CROSS_MESSAGE_RECEIPT",
    );
  }

  if (receipt.idempotency_key === event.idempotency_key) {
    return deepFreeze({
      acknowledge: true,
      action: DELIVERY_ACTIONS.DUPLICATE,
      idempotency_key: event.idempotency_key,
    });
  }
  if (
    compareSlackTimestamps(event.revision_ts, receipt.latest_revision_ts) <= 0
  ) {
    return deepFreeze({
      acknowledge: true,
      action: DELIVERY_ACTIONS.STALE,
      idempotency_key: event.idempotency_key,
    });
  }
  return deepFreeze({
    acknowledge: true,
    action:
      event.mutation === "edited"
        ? DELIVERY_ACTIONS.EDITED
        : event.mutation === "deleted"
          ? DELIVERY_ACTIONS.DELETED
          : DELIVERY_ACTIONS.CREATED,
    idempotency_key: event.idempotency_key,
  });
}

const THREAD_MAPPING_KEYS = new Set([
  "schema_version",
  "workspace_ref",
  "channel_ref",
  "thread_ref",
  "project_ref",
  "conversation_ref",
  "created_at",
]);

export function createSlackThreadMapping(input) {
  exactKeys(input, THREAD_MAPPING_KEYS, "threadMapping");
  const workspaceRef = strictSlackRef(
    input.workspace_ref,
    "threadMapping.workspace_ref",
    SLACK_WORKSPACE_REF,
  );
  const channelRef = strictSlackRef(
    input.channel_ref,
    "threadMapping.channel_ref",
    SLACK_CHANNEL_REF,
  );
  const threadRef = strictSlackRef(
    input.thread_ref,
    "threadMapping.thread_ref",
    SLACK_THREAD_REF,
  );
  const teamId = workspaceRef.match(SLACK_WORKSPACE_REF)[1];
  const channelMatch = channelRef.match(SLACK_CHANNEL_REF);
  const threadMatch = threadRef.match(SLACK_THREAD_REF);
  if (
    channelMatch[1] !== teamId ||
    threadMatch[1] !== teamId ||
    threadMatch[2] !== channelMatch[2]
  ) {
    fail(
      "thread mapping Slack references must belong to one workspace and channel",
      "CROSS_WORKSPACE_MAPPING",
    );
  }
  const mapping = {
    schema_version: "1.0.0",
    workspace_ref: workspaceRef,
    channel_ref: channelRef,
    thread_ref: threadRef,
    project_ref: safeRef(
      input.project_ref,
      "threadMapping.project_ref",
      "project:",
    ),
    ...(input.conversation_ref
      ? {
          conversation_ref: safeRef(
            input.conversation_ref,
            "threadMapping.conversation_ref",
            "conversation:",
          ),
        }
      : {}),
    created_at: isoTimestamp(input.created_at, "threadMapping.created_at"),
  };
  assertNoRawDatabricksToken(mapping);
  return deepFreeze(mapping);
}

export function decideSlackThreadMappingWrite(existing, candidate) {
  const next = createSlackThreadMapping(candidate);
  if (existing === null || existing === undefined) {
    return deepFreeze({ allowed: true, action: "insert", mapping: next });
  }
  const current = createSlackThreadMapping(existing);
  if (current.thread_ref !== next.thread_ref) {
    return deepFreeze({ allowed: false, reason: "thread_identity_mismatch" });
  }
  if (
    current.project_ref === next.project_ref &&
    current.conversation_ref === next.conversation_ref
  ) {
    return deepFreeze({ allowed: true, action: "noop", mapping: current });
  }
  return deepFreeze({
    allowed: false,
    reason: "thread_rebind_requires_review",
  });
}

const SUBJECT_LINK_KEYS = new Set([
  "schema_version",
  "workspace_ref",
  "slack_user_ref",
  "databricks_workspace_ref",
  "databricks_subject_ref",
  "auth_mode",
  "status",
  "linked_at",
  "verified_by_ref",
]);

export function createSlackSubjectLink(input) {
  exactKeys(input, SUBJECT_LINK_KEYS, "subjectLink");
  const authMode = input.auth_mode ?? "user_authorization";
  if (authMode !== "user_authorization") {
    fail(
      "Slack subject links cannot use a service principal",
      "SERVICE_PRINCIPAL_FORBIDDEN",
    );
  }
  const workspaceRef = strictSlackRef(
    input.workspace_ref,
    "subjectLink.workspace_ref",
    SLACK_WORKSPACE_REF,
  );
  const slackUserRef = strictSlackRef(
    input.slack_user_ref,
    "subjectLink.slack_user_ref",
    SLACK_USER_REF,
  );
  if (
    slackUserRef.match(SLACK_USER_REF)[1] !==
    workspaceRef.match(SLACK_WORKSPACE_REF)[1]
  ) {
    fail(
      "the Slack user and workspace references do not match",
      "CROSS_WORKSPACE_SUBJECT_LINK",
    );
  }
  const link = {
    schema_version: "1.0.0",
    workspace_ref: workspaceRef,
    slack_user_ref: slackUserRef,
    databricks_workspace_ref: safeRef(
      input.databricks_workspace_ref,
      "subjectLink.databricks_workspace_ref",
      "databricks_workspace:",
    ),
    databricks_subject_ref: safeRef(
      input.databricks_subject_ref,
      "subjectLink.databricks_subject_ref",
      "databricks_user:",
    ),
    auth_mode: authMode,
    status: oneOf(
      input.status ?? "active",
      ["active", "revoked"],
      "subjectLink.status",
    ),
    linked_at: isoTimestamp(input.linked_at, "subjectLink.linked_at"),
    verified_by_ref: safeRef(
      input.verified_by_ref,
      "subjectLink.verified_by_ref",
      "delegated_verifier:",
    ),
  };
  assertNoRawDatabricksToken(link);
  return deepFreeze(link);
}

export const DELEGATED_AUTH_STATES = deepFreeze({
  UNLINKED: "unlinked",
  CONSENT_PENDING: "consent_pending",
  ACTIVE: "active",
  REFRESH_REQUIRED: "refresh_required",
  REVOKED: "revoked",
  WORKSPACE_CHANGED: "workspace_changed",
});

const AUTH_STATE_KEYS = new Set([
  "schema_version",
  "state",
  "workspace_ref",
  "slack_user_ref",
  "databricks_workspace_ref",
  "databricks_subject_ref",
  "managed_credential_ref",
  "consent_request_ref",
  "verified_by_ref",
  "revision",
  "updated_at",
  "reason",
]);

export function createDelegatedAuthState(input) {
  exactKeys(input, AUTH_STATE_KEYS, "authState");
  assertNoRawDatabricksToken(input);
  const state = oneOf(
    input.state ?? DELEGATED_AUTH_STATES.UNLINKED,
    Object.values(DELEGATED_AUTH_STATES),
    "authState.state",
  );
  const revision = input.revision ?? 0;
  if (!Number.isSafeInteger(revision) || revision < 0) {
    fail("authState.revision must be a non-negative safe integer");
  }
  const normalized = {
    schema_version: "1.0.0",
    state,
    workspace_ref: strictSlackRef(
      input.workspace_ref,
      "authState.workspace_ref",
      SLACK_WORKSPACE_REF,
    ),
    slack_user_ref: strictSlackRef(
      input.slack_user_ref,
      "authState.slack_user_ref",
      SLACK_USER_REF,
    ),
    revision,
    updated_at: isoTimestamp(input.updated_at, "authState.updated_at"),
    ...(input.databricks_workspace_ref
      ? {
          databricks_workspace_ref: safeRef(
            input.databricks_workspace_ref,
            "authState.databricks_workspace_ref",
            "databricks_workspace:",
          ),
        }
      : {}),
    ...(input.databricks_subject_ref
      ? {
          databricks_subject_ref: safeRef(
            input.databricks_subject_ref,
            "authState.databricks_subject_ref",
            "databricks_user:",
          ),
        }
      : {}),
    ...(input.managed_credential_ref
      ? {
          managed_credential_ref: safeRef(
            input.managed_credential_ref,
            "authState.managed_credential_ref",
            "managed_credential:",
          ),
        }
      : {}),
    ...(input.consent_request_ref
      ? {
          consent_request_ref: safeRef(
            input.consent_request_ref,
            "authState.consent_request_ref",
            "consent_request:",
          ),
        }
      : {}),
    ...(input.verified_by_ref
      ? {
          verified_by_ref: safeRef(
            input.verified_by_ref,
            "authState.verified_by_ref",
            "delegated_verifier:",
          ),
        }
      : {}),
    ...(input.reason
      ? { reason: nonEmpty(input.reason, "authState.reason", 160) }
      : {}),
  };

  if (
    normalized.slack_user_ref.match(SLACK_USER_REF)[1] !==
    normalized.workspace_ref.match(SLACK_WORKSPACE_REF)[1]
  ) {
    fail("authState Slack user and workspace references do not match");
  }
  if (
    [
      DELEGATED_AUTH_STATES.ACTIVE,
      DELEGATED_AUTH_STATES.REFRESH_REQUIRED,
    ].includes(state) &&
    (!normalized.databricks_workspace_ref ||
      !normalized.databricks_subject_ref ||
      !normalized.managed_credential_ref ||
      !normalized.verified_by_ref)
  ) {
    fail(
      "active delegated auth state requires verified subject and managed credential references",
    );
  }
  if (
    state === DELEGATED_AUTH_STATES.CONSENT_PENDING &&
    (!normalized.consent_request_ref || !normalized.databricks_workspace_ref)
  ) {
    fail(
      "consent_pending state requires Databricks workspace and consent request references",
    );
  }
  if (
    [
      DELEGATED_AUTH_STATES.UNLINKED,
      DELEGATED_AUTH_STATES.REVOKED,
      DELEGATED_AUTH_STATES.WORKSPACE_CHANGED,
    ].includes(state) &&
    (normalized.databricks_workspace_ref ||
      normalized.databricks_subject_ref ||
      normalized.managed_credential_ref ||
      normalized.consent_request_ref ||
      normalized.verified_by_ref)
  ) {
    fail(
      `${state} auth state must not retain delegated identity or credentials`,
    );
  }
  if (
    state === DELEGATED_AUTH_STATES.CONSENT_PENDING &&
    (normalized.databricks_subject_ref ||
      normalized.managed_credential_ref ||
      normalized.verified_by_ref)
  ) {
    fail(
      "consent_pending state must not contain a verified delegated identity",
    );
  }
  return deepFreeze(normalized);
}

export function createInitialDelegatedAuthState({
  workspace_ref,
  slack_user_ref,
  updated_at,
}) {
  return createDelegatedAuthState({
    state: DELEGATED_AUTH_STATES.UNLINKED,
    workspace_ref,
    slack_user_ref,
    revision: 0,
    updated_at,
  });
}

const AUTH_EVENT_KEYS = new Set([
  "type",
  "expected_revision",
  "occurred_at",
  "reason",
  "databricks_workspace_ref",
  "databricks_subject_ref",
  "managed_credential_ref",
  "consent_request_ref",
  "verified_by_ref",
  "new_workspace_ref",
  "new_slack_user_ref",
]);

const requireState = (current, allowed, eventType) => {
  if (!allowed.includes(current.state)) {
    fail(
      `${eventType} is not allowed from ${current.state}`,
      "INVALID_AUTH_TRANSITION",
    );
  }
};

export function transitionDelegatedAuthState(currentInput, event) {
  const current = createDelegatedAuthState(currentInput);
  exactKeys(event, AUTH_EVENT_KEYS, "authEvent");
  assertNoRawDatabricksToken(event);
  nonEmpty(event.type, "authEvent.type", 80);
  if (
    !Number.isSafeInteger(event.expected_revision) ||
    event.expected_revision !== current.revision
  ) {
    fail(
      "authEvent.expected_revision must match the current state revision",
      "AUTH_EVENT_REPLAY_OR_CONFLICT",
    );
  }
  const occurredAt = isoTimestamp(event.occurred_at, "authEvent.occurred_at");
  if (Date.parse(occurredAt) <= Date.parse(current.updated_at)) {
    fail(
      "authEvent.occurred_at must be newer than the current state",
      "STALE_AUTH_EVENT",
    );
  }
  const base = {
    workspace_ref: current.workspace_ref,
    slack_user_ref: current.slack_user_ref,
    revision: current.revision + 1,
    updated_at: occurredAt,
  };

  if (event.type === "consent_started") {
    requireState(
      current,
      [
        DELEGATED_AUTH_STATES.UNLINKED,
        DELEGATED_AUTH_STATES.REVOKED,
        DELEGATED_AUTH_STATES.WORKSPACE_CHANGED,
      ],
      event.type,
    );
    return createDelegatedAuthState({
      ...base,
      state: DELEGATED_AUTH_STATES.CONSENT_PENDING,
      databricks_workspace_ref: event.databricks_workspace_ref,
      consent_request_ref: event.consent_request_ref,
    });
  }
  if (event.type === "consent_verified") {
    requireState(current, [DELEGATED_AUTH_STATES.CONSENT_PENDING], event.type);
    return createDelegatedAuthState({
      ...base,
      state: DELEGATED_AUTH_STATES.ACTIVE,
      databricks_workspace_ref: current.databricks_workspace_ref,
      databricks_subject_ref: event.databricks_subject_ref,
      managed_credential_ref: event.managed_credential_ref,
      verified_by_ref: event.verified_by_ref,
    });
  }
  if (event.type === "refresh_due") {
    requireState(current, [DELEGATED_AUTH_STATES.ACTIVE], event.type);
    return createDelegatedAuthState({
      ...base,
      state: DELEGATED_AUTH_STATES.REFRESH_REQUIRED,
      databricks_workspace_ref: current.databricks_workspace_ref,
      databricks_subject_ref: current.databricks_subject_ref,
      managed_credential_ref: current.managed_credential_ref,
      verified_by_ref: current.verified_by_ref,
      ...(event.reason ? { reason: event.reason } : {}),
    });
  }
  if (event.type === "refresh_verified") {
    requireState(current, [DELEGATED_AUTH_STATES.REFRESH_REQUIRED], event.type);
    return createDelegatedAuthState({
      ...base,
      state: DELEGATED_AUTH_STATES.ACTIVE,
      databricks_workspace_ref: current.databricks_workspace_ref,
      databricks_subject_ref: current.databricks_subject_ref,
      managed_credential_ref: event.managed_credential_ref,
      verified_by_ref: event.verified_by_ref,
    });
  }
  if (event.type === "revoked") {
    return createDelegatedAuthState({
      ...base,
      state: DELEGATED_AUTH_STATES.REVOKED,
      ...(event.reason ? { reason: event.reason } : {}),
    });
  }
  if (event.type === "slack_workspace_changed") {
    strictSlackRef(
      event.new_workspace_ref,
      "authEvent.new_workspace_ref",
      SLACK_WORKSPACE_REF,
    );
    strictSlackRef(
      event.new_slack_user_ref,
      "authEvent.new_slack_user_ref",
      SLACK_USER_REF,
    );
    return createDelegatedAuthState({
      state: DELEGATED_AUTH_STATES.WORKSPACE_CHANGED,
      workspace_ref: event.new_workspace_ref,
      slack_user_ref: event.new_slack_user_ref,
      revision: current.revision + 1,
      updated_at: occurredAt,
      reason: event.reason ?? "slack_workspace_changed",
    });
  }
  if (event.type === "databricks_workspace_changed") {
    return createDelegatedAuthState({
      ...base,
      state: DELEGATED_AUTH_STATES.WORKSPACE_CHANGED,
      reason: event.reason ?? "databricks_workspace_changed",
    });
  }
  fail(
    `unsupported delegated auth event ${event.type}`,
    "UNSUPPORTED_AUTH_EVENT",
  );
}

export const SLACK_RETENTION_POLICY = deepFreeze({
  policy_id: "slack-boundary-v1",
  records: {
    slack_event_metadata: {
      classification: "internal",
      persistence: "allowed",
      retain_for_days: 30,
    },
    slack_idempotency_receipt: {
      classification: "internal",
      persistence: "allowed",
      retain_for_days: 7,
    },
    slack_thread_mapping: {
      classification: "confidential",
      persistence: "allowed",
      retention_trigger: "project_closed_plus_30_days",
    },
    slack_subject_link: {
      classification: "confidential",
      persistence: "allowed",
      retention_trigger: "revoked_plus_30_days",
    },
    delegated_auth_state: {
      classification: "confidential",
      persistence: "allowed",
      retention_trigger: "terminal_state_plus_30_days",
    },
    slack_correlation: {
      classification: "confidential",
      persistence: "allowed",
      retain_for_days: 365,
    },
    slack_link_state: {
      classification: "confidential",
      persistence: "allowed",
      retention_trigger: "delete_at_expiry_or_consumption",
    },
    slack_message_content: {
      classification: "restricted",
      persistence: "forbidden",
      retain_for_days: 0,
    },
    databricks_token_material: {
      classification: "restricted",
      persistence: "forbidden",
      retain_for_days: 0,
    },
  },
});

export function getSlackRetentionRule(recordKind) {
  const rule = SLACK_RETENTION_POLICY.records[recordKind];
  if (!rule) fail(`unknown Slack retention record kind ${String(recordKind)}`);
  return rule;
}

const PERSISTED_RECEIPT_KEYS = new Set([
  "message_ref",
  "idempotency_key",
  "latest_revision_ts",
]);
const PERSISTED_CORRELATION_KEYS = new Set([
  "schema_version",
  "correlation_id",
  "slack_event_ref",
  "slack_user_ref",
  "slack_thread_ref",
  "databricks_workspace_ref",
  "databricks_subject_ref",
  "project_ref",
  "run_ref",
  "evidence_refs",
]);

function normalizePersistenceRecord(recordKind, record) {
  if (recordKind === "slack_event_metadata") {
    return clone(validateSlackEventContract(record));
  }
  if (recordKind === "slack_idempotency_receipt") {
    exactKeys(record, PERSISTED_RECEIPT_KEYS, "persistenceRecord");
    strictSlackRef(
      record.message_ref,
      "persistenceRecord.message_ref",
      SLACK_MESSAGE_REF,
    );
    if (
      typeof record.idempotency_key !== "string" ||
      !SAFE_IDEMPOTENCY_KEY.test(record.idempotency_key)
    ) {
      fail("persistenceRecord.idempotency_key is invalid");
    }
    slackTimestamp(
      record.latest_revision_ts,
      "persistenceRecord.latest_revision_ts",
    );
    return clone(record);
  }
  if (recordKind === "slack_thread_mapping") {
    return clone(createSlackThreadMapping(record));
  }
  if (recordKind === "slack_subject_link") {
    return clone(createSlackSubjectLink(record));
  }
  if (recordKind === "delegated_auth_state") {
    return clone(createDelegatedAuthState(record));
  }
  if (recordKind === "slack_link_state") {
    return clone(validateAuthenticatedLinkStateRecord(record));
  }
  if (recordKind === "slack_correlation") {
    exactKeys(record, PERSISTED_CORRELATION_KEYS, "persistenceRecord");
    if (record.schema_version !== "1.0.0") {
      fail("persistenceRecord.schema_version must be 1.0.0");
    }
    if (
      typeof record.correlation_id !== "string" ||
      !CORRELATION_ID.test(record.correlation_id)
    ) {
      fail("persistenceRecord.correlation_id is invalid");
    }
    const eventRef = strictSlackRef(
      record.slack_event_ref,
      "persistenceRecord.slack_event_ref",
      SLACK_EVENT_REF,
    );
    const userRef = strictSlackRef(
      record.slack_user_ref,
      "persistenceRecord.slack_user_ref",
      SLACK_USER_REF,
    );
    const threadRef = strictSlackRef(
      record.slack_thread_ref,
      "persistenceRecord.slack_thread_ref",
      SLACK_THREAD_REF,
    );
    const teamId = eventRef.match(SLACK_EVENT_REF)[1];
    if (
      userRef.match(SLACK_USER_REF)[1] !== teamId ||
      threadRef.match(SLACK_THREAD_REF)[1] !== teamId
    ) {
      fail("persisted correlation Slack references cross workspaces");
    }
    safeRef(
      record.databricks_workspace_ref,
      "persistenceRecord.databricks_workspace_ref",
      "databricks_workspace:",
    );
    safeRef(
      record.databricks_subject_ref,
      "persistenceRecord.databricks_subject_ref",
      "databricks_user:",
    );
    safeRef(record.project_ref, "persistenceRecord.project_ref", "project:");
    if (record.run_ref !== undefined) {
      safeRef(record.run_ref, "persistenceRecord.run_ref", "run:");
    }
    if (
      !Array.isArray(record.evidence_refs) ||
      record.evidence_refs.length > 100
    ) {
      fail("persistenceRecord.evidence_refs is invalid");
    }
    const evidenceRefs = record.evidence_refs.map((ref, index) =>
      safeRef(ref, `persistenceRecord.evidence_refs[${index}]`, "evidence:"),
    );
    if (evidenceRefs.length > 0 && !record.run_ref) {
      fail("persisted evidence references require a run reference");
    }
    if (new Set(evidenceRefs).size !== evidenceRefs.length) {
      fail("persistenceRecord.evidence_refs must not contain duplicates");
    }
    return clone(record);
  }
  fail(`unsupported persisted Slack record kind ${recordKind}`);
}

export function prepareSlackPersistenceRecord(recordKind, record) {
  const rule = getSlackRetentionRule(recordKind);
  if (rule.persistence !== "allowed") {
    fail(`${recordKind} must not be persisted`, "PERSISTENCE_FORBIDDEN");
  }
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    fail("persistence record must be an object");
  }
  assertNoRawSlackContent(record);
  assertNoRawDatabricksToken(record);
  const normalized = normalizePersistenceRecord(recordKind, record);
  return deepFreeze({
    policy_id: SLACK_RETENTION_POLICY.policy_id,
    record_kind: recordKind,
    classification: rule.classification,
    retention: clone(rule),
    payload: normalized,
  });
}

const CORRELATION_KEYS = new Set([
  "correlation_id",
  "event",
  "subject_link",
  "thread_mapping",
  "project_ref",
  "run_ref",
  "evidence_refs",
]);

export function buildSlackCorrelation(input, uuid) {
  exactKeys(input, CORRELATION_KEYS, "correlation");
  const event = validateSlackEventContract(input.event);
  const subjectLink = createSlackSubjectLink(input.subject_link);
  const threadMapping = createSlackThreadMapping(input.thread_mapping);
  if (
    subjectLink.status !== "active" ||
    subjectLink.workspace_ref !== event.workspace_ref ||
    subjectLink.slack_user_ref !== event.actor_ref
  ) {
    fail(
      "correlation requires an active subject link for the Slack event actor",
      "CROSS_USER_CORRELATION",
    );
  }
  if (
    threadMapping.workspace_ref !== event.workspace_ref ||
    threadMapping.thread_ref !== event.thread_ref ||
    threadMapping.project_ref !== input.project_ref
  ) {
    fail(
      "correlation project must come from the event thread mapping",
      "CROSS_THREAD_CORRELATION",
    );
  }
  const evidenceRefs = input.evidence_refs ?? [];
  if (!Array.isArray(evidenceRefs))
    fail("correlation.evidence_refs must be an array");
  if (evidenceRefs.length > 100) {
    fail("correlation.evidence_refs must contain at most 100 references");
  }
  if (evidenceRefs.length > 0 && !input.run_ref) {
    fail("evidence references require a run reference");
  }
  const normalizedEvidenceRefs = evidenceRefs.map((ref, index) =>
    safeRef(ref, `correlation.evidence_refs[${index}]`, "evidence:"),
  );
  if (new Set(normalizedEvidenceRefs).size !== normalizedEvidenceRefs.length) {
    fail("correlation.evidence_refs must not contain duplicates");
  }
  const result = {
    schema_version: "1.0.0",
    correlation_id: normalizeCorrelationId(input.correlation_id, uuid),
    slack_event_ref: event.event_ref,
    slack_user_ref: event.actor_ref,
    slack_thread_ref: event.thread_ref,
    databricks_workspace_ref: subjectLink.databricks_workspace_ref,
    databricks_subject_ref: subjectLink.databricks_subject_ref,
    project_ref: safeRef(
      input.project_ref,
      "correlation.project_ref",
      "project:",
    ),
    ...(input.run_ref
      ? { run_ref: safeRef(input.run_ref, "correlation.run_ref", "run:") }
      : {}),
    evidence_refs: normalizedEvidenceRefs,
  };
  assertNoRawDatabricksToken(result);
  return deepFreeze(result);
}

const SIGNATURE_RECEIPT_KEYS = new Set([
  "schema_version",
  "workspace_ref",
  "event_ref",
  "request_timestamp",
  "body_sha256",
  "verified_at",
  "expires_at",
  "verifier_ref",
]);

export function createSlackSignatureVerificationReceipt(input) {
  exactKeys(input, SIGNATURE_RECEIPT_KEYS, "signatureReceipt");
  const workspaceRef = strictSlackRef(
    input.workspace_ref,
    "signatureReceipt.workspace_ref",
    SLACK_WORKSPACE_REF,
  );
  const eventRef = strictSlackRef(
    input.event_ref,
    "signatureReceipt.event_ref",
    SLACK_EVENT_REF,
  );
  if (
    workspaceRef.match(SLACK_WORKSPACE_REF)[1] !==
    eventRef.match(SLACK_EVENT_REF)[1]
  ) {
    fail("signature receipt references must belong to one Slack workspace");
  }
  if (
    typeof input.request_timestamp !== "string" ||
    !/^\d{10}$/.test(input.request_timestamp)
  ) {
    fail("signatureReceipt.request_timestamp must be a Unix timestamp");
  }
  if (
    typeof input.body_sha256 !== "string" ||
    !SHA256_REF.test(input.body_sha256)
  ) {
    fail("signatureReceipt.body_sha256 must be a SHA-256 reference");
  }
  const verifiedAt = isoTimestamp(
    input.verified_at,
    "signatureReceipt.verified_at",
  );
  const expiresAt = isoTimestamp(
    input.expires_at,
    "signatureReceipt.expires_at",
  );
  const requestTime = Number(input.request_timestamp) * 1000;
  if (
    Date.parse(verifiedAt) < requestTime ||
    Date.parse(expiresAt) <= Date.parse(verifiedAt) ||
    Date.parse(expiresAt) - requestTime > 5 * 60 * 1000
  ) {
    fail(
      "signature receipt must be verified and expire within Slack's five-minute replay window",
      "INVALID_SIGNATURE_RECEIPT_WINDOW",
    );
  }
  const receipt = {
    schema_version: "1.0.0",
    workspace_ref: workspaceRef,
    event_ref: eventRef,
    request_timestamp: input.request_timestamp,
    body_sha256: input.body_sha256,
    verified_at: verifiedAt,
    expires_at: expiresAt,
    verifier_ref: safeRef(
      input.verifier_ref,
      "signatureReceipt.verifier_ref",
      "slack_signature_verifier:",
    ),
  };
  assertNoRawDatabricksToken(receipt);
  return deepFreeze(receipt);
}

export function decideSlackIngress({
  kill_switch,
  signature_receipt,
  event,
  subject_link = null,
  now,
} = {}) {
  if (!kill_switch || typeof kill_switch !== "object") {
    return deepFreeze({ allowed: false, reason: "kill_switch_state_missing" });
  }
  let nowMs;
  try {
    exactKeys(
      kill_switch,
      new Set(["ref", "active", "checked_at", "expires_at", "source_ref"]),
      "killSwitch",
    );
    safeRef(kill_switch.ref, "kill_switch.ref", "kill_switch:");
    isoTimestamp(kill_switch.checked_at, "kill_switch.checked_at");
    isoTimestamp(kill_switch.expires_at, "kill_switch.expires_at");
    safeRef(kill_switch.source_ref, "kill_switch.source_ref", "control_plane:");
    assertNoRawDatabricksToken(kill_switch);
    nowMs = Date.parse(isoTimestamp(now, "now"));
  } catch {
    return deepFreeze({ allowed: false, reason: "kill_switch_state_invalid" });
  }
  if (typeof kill_switch.active !== "boolean") {
    return deepFreeze({ allowed: false, reason: "kill_switch_state_invalid" });
  }
  const checkedAtMs = Date.parse(kill_switch.checked_at);
  const expiresAtMs = Date.parse(kill_switch.expires_at);
  if (
    checkedAtMs > nowMs ||
    expiresAtMs < nowMs ||
    expiresAtMs <= checkedAtMs ||
    expiresAtMs - checkedAtMs > 5 * 60 * 1000
  ) {
    return deepFreeze({ allowed: false, reason: "kill_switch_state_stale" });
  }
  if (kill_switch.active) {
    return deepFreeze({ allowed: false, reason: "kill_switch_active" });
  }
  try {
    validateSlackEventContract(event);
  } catch {
    return deepFreeze({ allowed: false, reason: "event_invalid" });
  }
  let signatureReceipt;
  try {
    signatureReceipt =
      createSlackSignatureVerificationReceipt(signature_receipt);
  } catch {
    return deepFreeze({ allowed: false, reason: "signature_receipt_invalid" });
  }
  if (
    signatureReceipt.workspace_ref !== event.workspace_ref ||
    signatureReceipt.event_ref !== event.event_ref ||
    Date.parse(signatureReceipt.verified_at) > nowMs ||
    Date.parse(event.received_at) <
      Number(signatureReceipt.request_timestamp) * 1000 ||
    Date.parse(event.received_at) > Date.parse(signatureReceipt.expires_at) ||
    Date.parse(event.received_at) > nowMs ||
    Date.parse(signatureReceipt.expires_at) < nowMs
  ) {
    return deepFreeze({ allowed: false, reason: "signature_receipt_invalid" });
  }
  if (subject_link !== null) {
    try {
      const link = createSlackSubjectLink(subject_link);
      if (
        link.status === "active" &&
        link.workspace_ref === event.workspace_ref &&
        link.slack_user_ref === event.actor_ref
      ) {
        return deepFreeze({
          allowed: true,
          action: "render_authenticated_web_app_link_out",
          product_mode: SLACK_PRODUCT_BOUNDARY.mode,
        });
      }
    } catch {
      return deepFreeze({ allowed: false, reason: "subject_link_invalid" });
    }
  }
  return deepFreeze({
    allowed: true,
    action: "render_authentication_link_out",
    product_mode: SLACK_PRODUCT_BOUNDARY.mode,
  });
}

const LINK_STATE_RECORD_KEYS = new Set([
  "schema_version",
  "state_ref",
  "slack_event_ref",
  "slack_user_ref",
  "slack_thread_ref",
  "databricks_workspace_ref",
  "databricks_subject_ref",
  "project_ref",
  "correlation_id",
  "issued_at",
  "expires_at",
]);
const LINK_STATE_INPUT_KEYS = new Set([
  "state_ref",
  "correlation",
  "issued_at",
  "expires_at",
]);

function validateAuthenticatedLinkStateRecord(input) {
  exactKeys(input, LINK_STATE_RECORD_KEYS, "linkState");
  if (input.schema_version !== "1.0.0") {
    fail("linkState.schema_version must be 1.0.0");
  }
  const issuedAt = isoTimestamp(input.issued_at, "linkState.issued_at");
  const expiresAt = isoTimestamp(input.expires_at, "linkState.expires_at");
  if (
    Date.parse(expiresAt) <= Date.parse(issuedAt) ||
    Date.parse(expiresAt) - Date.parse(issuedAt) > 10 * 60 * 1000
  ) {
    fail(
      "link state must expire no more than ten minutes after issue",
      "INVALID_LINK_STATE_WINDOW",
    );
  }
  if (
    typeof input.state_ref !== "string" ||
    !LINK_STATE_REF.test(input.state_ref)
  ) {
    fail(
      "linkState.state_ref must contain a versioned 256-bit opaque handle",
      "WEAK_LINK_STATE",
    );
  }
  const slackEventRef = strictSlackRef(
    input.slack_event_ref,
    "linkState.slack_event_ref",
    SLACK_EVENT_REF,
  );
  const slackUserRef = strictSlackRef(
    input.slack_user_ref,
    "linkState.slack_user_ref",
    SLACK_USER_REF,
  );
  const slackThreadRef = strictSlackRef(
    input.slack_thread_ref,
    "linkState.slack_thread_ref",
    SLACK_THREAD_REF,
  );
  const teamId = slackEventRef.match(SLACK_EVENT_REF)[1];
  if (
    slackUserRef.match(SLACK_USER_REF)[1] !== teamId ||
    slackThreadRef.match(SLACK_THREAD_REF)[1] !== teamId
  ) {
    fail("link state Slack references must belong to one workspace");
  }
  const state = {
    schema_version: "1.0.0",
    state_ref: input.state_ref,
    slack_event_ref: slackEventRef,
    slack_user_ref: slackUserRef,
    slack_thread_ref: slackThreadRef,
    databricks_workspace_ref: safeRef(
      input.databricks_workspace_ref,
      "linkState.databricks_workspace_ref",
      "databricks_workspace:",
    ),
    databricks_subject_ref: safeRef(
      input.databricks_subject_ref,
      "linkState.databricks_subject_ref",
      "databricks_user:",
    ),
    project_ref: safeRef(
      input.project_ref,
      "linkState.project_ref",
      "project:",
    ),
    correlation_id:
      typeof input.correlation_id === "string" &&
      CORRELATION_ID.test(input.correlation_id)
        ? input.correlation_id
        : fail("linkState.correlation_id is invalid"),
    issued_at: issuedAt,
    expires_at: expiresAt,
  };
  assertNoRawDatabricksToken(state);
  return deepFreeze(state);
}

export function createAuthenticatedLinkState(input) {
  exactKeys(input, LINK_STATE_INPUT_KEYS, "linkStateInput");
  const correlation = normalizePersistenceRecord(
    "slack_correlation",
    input.correlation,
  );
  return validateAuthenticatedLinkStateRecord({
    schema_version: "1.0.0",
    state_ref: input.state_ref,
    slack_event_ref: correlation.slack_event_ref,
    slack_user_ref: correlation.slack_user_ref,
    slack_thread_ref: correlation.slack_thread_ref,
    databricks_workspace_ref: correlation.databricks_workspace_ref,
    databricks_subject_ref: correlation.databricks_subject_ref,
    project_ref: correlation.project_ref,
    correlation_id: correlation.correlation_id,
    issued_at: input.issued_at,
    expires_at: input.expires_at,
  });
}

const LINK_CONTEXT_KEYS = new Set([
  "base_url",
  "continue_path",
  "link_state",
  "now",
]);

export function buildAuthenticatedWebAppLink(input) {
  exactKeys(input, LINK_CONTEXT_KEYS, "link");
  let base;
  try {
    base = new URL(input.base_url);
  } catch {
    fail("link.base_url must be a valid URL");
  }
  if (base.protocol !== "https:" || base.username || base.password) {
    fail("link.base_url must be credential-free HTTPS", "UNSAFE_LINK_OUT_URL");
  }
  if (base.search || base.hash) {
    fail(
      "link.base_url must not contain query or fragment state",
      "UNSAFE_LINK_OUT_URL",
    );
  }
  const continuePath = input.continue_path ?? "/slack/continue";
  if (
    typeof continuePath !== "string" ||
    !continuePath.startsWith("/") ||
    continuePath.startsWith("//") ||
    continuePath.includes("\\") ||
    continuePath.includes("..") ||
    continuePath.includes("?") ||
    continuePath.includes("#")
  ) {
    fail("link.continue_path must be an absolute application path");
  }
  const url = new URL(continuePath, base);
  if (url.origin !== base.origin) {
    fail("link.continue_path must stay on the configured application origin");
  }
  const state = validateAuthenticatedLinkStateRecord(input.link_state);
  const nowMs = Date.parse(isoTimestamp(input.now, "link.now"));
  if (
    nowMs < Date.parse(state.issued_at) ||
    nowMs > Date.parse(state.expires_at)
  ) {
    fail("link state is not currently valid", "EXPIRED_LINK_STATE");
  }
  url.searchParams.set("state", state.state_ref);
  if (url.toString().length > 3000) {
    fail("link-out URL exceeds Slack's 3000-character limit");
  }
  return url.toString();
}

function assertSafeLinkOutText(value, name, maximum) {
  nonEmpty(value, name, maximum);
  assertNoRawDatabricksToken(value);
  return value;
}

export function validateSlackLinkOutMessage(message, { expected_origin } = {}) {
  exactKeys(message, new Set(["text", "blocks"]), "message");
  assertSafeLinkOutText(message.text, "message.text", 4000);
  if (
    !Array.isArray(message.blocks) ||
    message.blocks.length !== 2 ||
    message.blocks.length > 50
  ) {
    fail("link-out message must contain exactly two Block Kit blocks");
  }
  const [section, actions] = message.blocks;
  exactKeys(
    section,
    new Set(["type", "block_id", "text"]),
    "message.blocks[0]",
  );
  if (section.type !== "section")
    fail("the first link-out block must be a section");
  nonEmpty(section.block_id, "message.blocks[0].block_id", 255);
  exactKeys(section.text, new Set(["type", "text"]), "message.blocks[0].text");
  if (section.text.type !== "plain_text")
    fail("link-out section text must be plain_text");
  assertSafeLinkOutText(section.text.text, "message.blocks[0].text.text", 3000);

  exactKeys(
    actions,
    new Set(["type", "block_id", "elements"]),
    "message.blocks[1]",
  );
  if (actions.type !== "actions")
    fail("the second link-out block must be actions");
  nonEmpty(actions.block_id, "message.blocks[1].block_id", 255);
  if (!Array.isArray(actions.elements) || actions.elements.length !== 1) {
    fail("link-out actions block must contain one button");
  }
  const button = actions.elements[0];
  exactKeys(
    button,
    new Set(["type", "text", "url", "action_id", "accessibility_label"]),
    "message.blocks[1].elements[0]",
  );
  if (button.type !== "button") fail("link-out action must be a button");
  exactKeys(
    button.text,
    new Set(["type", "text"]),
    "message.blocks[1].elements[0].text",
  );
  if (button.text.type !== "plain_text")
    fail("link-out button text must be plain_text");
  assertSafeLinkOutText(
    button.text.text,
    "message.blocks[1].elements[0].text.text",
    75,
  );
  nonEmpty(button.action_id, "message.blocks[1].elements[0].action_id", 255);
  assertSafeLinkOutText(
    button.accessibility_label,
    "message.blocks[1].elements[0].accessibility_label",
    75,
  );
  let link;
  try {
    link = new URL(button.url);
  } catch {
    fail("link-out button URL is invalid");
  }
  if (link.protocol !== "https:" || link.username || link.password) {
    fail("link-out button URL must be credential-free HTTPS");
  }
  if (button.url.length > 3000 || link.hash) {
    fail("link-out button URL exceeds Slack constraints");
  }
  let expectedOrigin;
  try {
    expectedOrigin = new URL(expected_origin);
  } catch {
    fail("an expected authenticated application origin is required");
  }
  if (
    expectedOrigin.protocol !== "https:" ||
    expectedOrigin.username ||
    expectedOrigin.password ||
    expectedOrigin.origin !== link.origin
  ) {
    fail(
      "link-out button URL must stay on the authenticated application origin",
      "OFF_ORIGIN_LINK_OUT",
    );
  }
  const queryKeys = [...link.searchParams.keys()];
  if (
    queryKeys.length !== 1 ||
    queryKeys[0] !== "state" ||
    !LINK_STATE_REF.test(link.searchParams.get("state") ?? "")
  ) {
    fail(
      "link-out button URL must contain only a strong opaque state handle",
      "UNSAFE_LINK_OUT_STATE",
    );
  }
  assertNoRawDatabricksToken(message);
  return true;
}

export function createSlackLinkOutMessage({
  url,
  document_ref,
  revision_ref,
  expected_origin,
}) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    fail("url must be valid");
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password) {
    fail("url must be credential-free HTTPS");
  }
  const documentRef = safeRef(document_ref, "document_ref", "document:");
  const revisionRef = safeRef(revision_ref, "revision_ref", "revision:");
  const identity = digest(`${documentRef}:${revisionRef}`);
  const message = {
    text: "Open the authenticated web app to view this governed result.",
    blocks: [
      {
        type: "section",
        block_id: `slack_linkout_summary_${identity}`,
        text: {
          type: "plain_text",
          text: "This result is available only in the authenticated web app, where Databricks applies your own access.",
        },
      },
      {
        type: "actions",
        block_id: `slack_linkout_actions_${identity}`,
        elements: [
          {
            type: "button",
            text: { type: "plain_text", text: "Open governed result" },
            url: parsed.toString(),
            action_id: `open_governed_result_${identity}`,
            accessibility_label:
              "Open governed result in authenticated web app",
          },
        ],
      },
    ],
  };
  validateSlackLinkOutMessage(message, { expected_origin });
  return deepFreeze(message);
}

/**
 * Run export-core authorization and redaction, then deliberately discard all
 * document content. Slack receives only a generic authenticated-app link.
 */
export async function exportSlackLinkOut(document, options = {}) {
  const authorized = await prepareAuthorizedDocument(document, {
    authorize: options.authorize,
    redact: options.redact,
    authorizationContext: options.authorizationContext,
  });
  const url = buildAuthenticatedWebAppLink({
    base_url: options.baseUrl,
    continue_path: options.continuePath,
    link_state: options.linkState,
    now: options.now,
  });
  return deepFreeze({
    schema_version: "1.0.0",
    product_mode: SLACK_PRODUCT_BOUNDARY.mode,
    document_ref: `document:${authorized.document_id}`,
    revision_ref: `revision:${authorized.revision_id}`,
    message: createSlackLinkOutMessage({
      url,
      document_ref: `document:${authorized.document_id}`,
      revision_ref: `revision:${authorized.revision_id}`,
      expected_origin: new URL(options.baseUrl).origin,
    }),
  });
}
