import { randomUUID } from "node:crypto";

import { validateContract } from "../../contracts/src/index.js";
import { redactSensitive, redactText } from "../../governance/src/index.js";

export const CORRELATION_PREFIX = "corr_";
export const CORRELATION_PATTERN =
  /^(?:corr_[a-z0-9][a-z0-9_-]{2,95}|req-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/;
export const REDACTED = "[REDACTED]";

const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SAFE_METADATA_KEYS = new Set([
  "action",
  "attempt",
  "capability",
  "correlation_id",
  "duration_ms",
  "error_code",
  "event_type",
  "gateway_request_id",
  "http_status",
  "latency_ms",
  "mlflow_trace_id",
  "model_ref",
  "outcome",
  "policy_id",
  "request_id",
  "retryable",
  "run_id",
  "status",
  "tool_name",
  "transport",
]);

const SECRET_TEXT = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\bBearer\s+[A-Za-z0-9._~+/=-]+/i,
  /\b(?:api[_ -]?key|authorization|client[_ -]?secret|cookie|password|private[_ -]?key|refresh[_ -]?token|access[_ -]?token)\s*[:=]\s*["']?[^\s,"'}]+/i,
  /\b(?:eyJ[A-Za-z0-9_-]{8,})\.(?:[A-Za-z0-9_-]{8,})\.(?:[A-Za-z0-9_-]{8,})\b/,
];

const KEY_CLASSES = [
  ["raw_prompt", /^(?:input|input_text|messages?|prompt|question|user_content)$/i],
  ["raw_response", /^(?:answer|completion|output|output_text|response|result_text)$/i],
  ["token", /(?:^|[_-])(?:access|id|refresh)?[_-]?token(?:$|[_-])/i],
  ["cookie", /(?:^|[_-])(?:cookies?|session)(?:$|[_-])/i],
  ["header", /(?:^|[_-])headers?(?:$|[_-])/i],
  [
    "secret",
    /(?:^|[_-])(?:api[_-]?key|authorization|client[_-]?secret|credential|password|private[_-]?key|secret)(?:$|[_-])/i,
  ],
  [
    "governed_data",
    /^(?:content|data|dataset|document|excerpt|governed_data|record|records|row|rows|table)$/i,
  ],
];

const FORBIDDEN_TELEMETRY_CLASSES = new Set([
  "raw_prompt",
  "raw_response",
  "token",
  "cookie",
  "header",
  "secret",
  "governed_data",
]);
const SECRET_CLASSES = new Set(["token", "cookie", "header", "secret"]);

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child);
  return value;
}

function safeIdentifier(value, name) {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string" || !SAFE_IDENTIFIER.test(value)) {
    throw new TypeError(`${name} must be a printable opaque identifier.`);
  }
  return value;
}

export function mintCorrelationId(uuid = randomUUID) {
  const value = String(uuid()).toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value)) {
    throw new TypeError("The UUID source returned an invalid value.");
  }
  return `${CORRELATION_PREFIX}${value}`;
}

export function usableCorrelationId(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return CORRELATION_PATTERN.test(trimmed) ? trimmed : null;
}

export function normalizeCorrelationId(value, uuid = randomUUID) {
  return usableCorrelationId(value) ?? mintCorrelationId(uuid);
}

/** Build one safe join key plus optional opaque identifiers from each telemetry plane. */
export function buildCorrelationContext(input = {}, uuid = randomUUID) {
  const context = {
    correlation_id: normalizeCorrelationId(input.correlation_id, uuid),
    app: {},
    gateway: {},
    mlflow: {},
  };
  const appRequestId = safeIdentifier(input.app_request_id, "app_request_id");
  const appRunId = safeIdentifier(input.app_run_id, "app_run_id");
  const gatewayRequestId = safeIdentifier(input.gateway_request_id, "gateway_request_id");
  const mlflowTraceId = safeIdentifier(input.mlflow_trace_id, "mlflow_trace_id");
  if (appRequestId) context.app.request_id = appRequestId;
  if (appRunId) context.app.run_id = appRunId;
  if (gatewayRequestId) context.gateway.request_id = gatewayRequestId;
  if (mlflowTraceId) context.mlflow.trace_id = mlflowTraceId;
  return deepFreeze(context);
}

export function classifyPayload(key, value) {
  const name = String(key ?? "");
  for (const [classification, pattern] of KEY_CLASSES) {
    if (pattern.test(name)) return classification;
  }
  if (typeof value === "string" && SECRET_TEXT.some((pattern) => pattern.test(value))) return "secret";
  if (!SAFE_METADATA_KEYS.has(name)) return "unknown";
  if (value === null || ["string", "number", "boolean"].includes(typeof value)) return "safe_metadata";
  return "unsafe_value";
}

export function redactTelemetryPayload(value) {
  if (typeof value === "string") return redactText(value);
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(redactTelemetryPayload);
  const governed = redactSensitive(value);
  const output = {};
  for (const [key, item] of Object.entries(governed)) {
    const classification = classifyPayload(key, item);
    output[key] = FORBIDDEN_TELEMETRY_CLASSES.has(classification)
      ? REDACTED
      : redactTelemetryPayload(item);
  }
  return output;
}

/**
 * Keep only a small allowlist of scalar operational metadata.
 * Unknown keys and content-bearing fields are omitted by default.
 */
export function safeMetadata(input, options = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return {};
  const allowed = new Set(options.allowedKeys ?? SAFE_METADATA_KEYS);
  const output = {};
  for (const [key, value] of Object.entries(input)) {
    if (!allowed.has(key) || classifyPayload(key, value) !== "safe_metadata") continue;
    const redacted = typeof value === "string" ? redactText(value) : value;
    output[key] = redacted;
  }
  assertNoSecrets(output);
  return deepFreeze(output);
}

function firstUnsafe(value, classes, path = "$", seen = new WeakSet()) {
  if (typeof value === "string") {
    return SECRET_TEXT.some((pattern) => pattern.test(value)) ? { path, classification: "secret" } : null;
  }
  if (value === null || typeof value !== "object") return null;
  if (seen.has(value)) return null;
  seen.add(value);
  for (const [key, item] of Object.entries(value)) {
    const classification = classifyPayload(key, item);
    if (classes.has(classification)) return { path: `${path}.${key}`, classification };
    const nested = firstUnsafe(item, classes, `${path}.${key}`, seen);
    if (nested) return nested;
  }
  return null;
}

export class UnsafeTelemetryError extends Error {
  constructor(classification, path) {
    super(`Unsafe telemetry payload contains ${classification} at ${path}.`);
    this.name = "UnsafeTelemetryError";
    this.classification = classification;
    this.path = path;
  }
}

export function containsSecrets(value) {
  return firstUnsafe(value, SECRET_CLASSES) !== null;
}

export function assertNoSecrets(value) {
  const unsafe = firstUnsafe(value, SECRET_CLASSES);
  if (unsafe) throw new UnsafeTelemetryError(unsafe.classification, unsafe.path);
  return value;
}

export function assertSafeTelemetryPayload(value) {
  const unsafe = firstUnsafe(value, FORBIDDEN_TELEMETRY_CLASSES);
  if (unsafe) throw new UnsafeTelemetryError(unsafe.classification, unsafe.path);
  return value;
}

function validAuditEvent(event) {
  const validation = validateContract("audit-event", event);
  if (!validation.valid) throw new TypeError(`Invalid AuditEvent: ${validation.errors.join("; ")}`);
  return event;
}

/**
 * Construct an immutable AuditEvent. Details are allowlisted scalar metadata,
 * never raw request/response content.
 */
export function createAuditEvent(input, options = {}) {
  const uuid = options.randomUUID ?? randomUUID;
  const now = options.now ?? (() => new Date());
  const event = {
    schema_version: "1.0.0",
    event_id: input?.event_id ?? `audit_${String(uuid()).toLowerCase()}`,
    event_type: input?.event_type,
    occurred_at: input?.occurred_at ?? now().toISOString(),
    actor: {
      mode: input?.actor?.mode,
      subject_ref: input?.actor?.subject_ref,
    },
    action: input?.action,
    target_ref: input?.target_ref,
    outcome: input?.outcome,
    correlation_id: input?.correlation_id,
    ...(input?.details ? { details: safeMetadata(input.details, input.metadataOptions) } : {}),
  };
  validAuditEvent(event);
  assertSafeTelemetryPayload(event.details ?? {});
  return deepFreeze(event);
}

/** Append a validated immutable event. No update or delete operation is exposed. */
export async function appendAuditEvent(sink, event) {
  if (!sink || typeof sink.append !== "function") {
    throw new TypeError("An append-only audit sink is required.");
  }
  validAuditEvent(event);
  assertSafeTelemetryPayload(event.details ?? {});
  await sink.append(deepFreeze(event));
}
