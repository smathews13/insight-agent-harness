const REDACTED = "[REDACTED]";

export const EXECUTION_MODES = Object.freeze({
  USER_AUTHORIZATION: "user_authorization",
  EXPLICIT_SERVICE_PRINCIPAL: "explicit_service_principal",
  SYSTEM: "system",
});

export const IDENTITY_SOURCES = Object.freeze({
  TRUSTED_GATEWAY: "trusted_gateway",
  REVIEWED_SERVICE_BINDING: "reviewed_service_binding",
  INTERNAL_SCHEDULER: "internal_scheduler",
});

const SOURCE_FOR_MODE = Object.freeze({
  [EXECUTION_MODES.USER_AUTHORIZATION]: IDENTITY_SOURCES.TRUSTED_GATEWAY,
  [EXECUTION_MODES.EXPLICIT_SERVICE_PRINCIPAL]: IDENTITY_SOURCES.REVIEWED_SERVICE_BINDING,
  [EXECUTION_MODES.SYSTEM]: IDENTITY_SOURCES.INTERNAL_SCHEDULER,
});

const SUBJECT_REF = /^[a-z][a-z0-9_.-]{1,63}:[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$/;
const POLICY_ID = /^[a-z][a-z0-9_.-]{1,95}$/;
const OPAQUE_REF = /^[a-z][a-z0-9_.-]{1,63}:[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$/;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,255}$/;
const SAFE_EFFECTS = new Set(["read", "compute", "external_send"]);
const TOOL_TRANSPORTS = new Set(["local", "mcp"]);
const RESPONSE_TRUST = new Set(["untrusted", "validated", "trusted"]);
const CONTENT_CLASSIFICATIONS = Object.freeze(["public", "internal", "confidential", "restricted"]);
const DATA_ACCESS = new Set(["non_governed", "governed_evidence", "governed_data"]);
const SIDE_EFFECTS = new Set(["none", "state_change", "external_send"]);
const IDEMPOTENCY_REQUIREMENTS = new Set(["not_applicable", "required"]);
const SENSITIVE_KEY =
  /(?:^|[_-])(authorization|cookie|credential|governed[_-]?data|header|password|private[_-]?key|prompt|response|secret|token)(?:$|[_-])/i;
const BEARER = /\bBearer\s+[A-Za-z0-9._~+/=-]+/gi;
const ASSIGNED_SECRET =
  /\b(api[_ -]?key|authorization|client[_ -]?secret|cookie|password|private[_ -]?key|refresh[_ -]?token|access[_ -]?token)\s*[:=]\s*["']?[^\s,"'}]+/gi;
const PRIVATE_KEY = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g;
const PROVIDER_TOKEN =
  /\b(?:dapi[a-f0-9]{32,}|sk-(?:proj-)?[A-Za-z0-9_-]{20,}|(?:AKIA|ASIA)[A-Z0-9]{16})\b/gi;

function frozen(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const child of Object.values(value)) frozen(child);
  return value;
}

function denied(reason, detail) {
  return frozen({ allowed: false, reason, detail });
}

/**
 * Bind request authorization to identity evidence from a trusted boundary.
 * The verification record, never the request, selects the execution mode.
 */
export function decideVerifiedIdentity({ authorization, verification } = {}) {
  if (!verification || verification.status !== "verified") {
    return denied("identity_unverified", "Verified identity evidence is required.");
  }
  if (!SUBJECT_REF.test(verification.subject_ref ?? "")) {
    return denied("identity_invalid", "The verified subject reference is invalid.");
  }
  if (!Object.hasOwn(SOURCE_FOR_MODE, verification.mode)) {
    return denied("execution_mode_invalid", "The verified execution mode is not supported.");
  }
  if (SOURCE_FOR_MODE[verification.mode] !== verification.source) {
    return denied("identity_source_invalid", "The execution mode was not established by its trusted source.");
  }
  if (!authorization || authorization.subject_ref !== verification.subject_ref) {
    return denied("identity_mismatch", "The request subject does not match the verified subject.");
  }
  if (authorization.mode !== verification.mode) {
    return denied("execution_mode_mismatch", "A request cannot select a different execution mode.");
  }
  return frozen({
    allowed: true,
    identity: {
      subject_ref: verification.subject_ref,
      mode: verification.mode,
      source: verification.source,
      verified: true,
    },
  });
}

export class GovernanceDeniedError extends Error {
  constructor(reason = "policy_denied") {
    super(`Governance denied the operation: ${reason}.`);
    this.name = "GovernanceDeniedError";
    this.reason = reason;
  }
}

/** Execute only an explicit allow decision. Missing and malformed decisions deny. */
export function requireAllowed(decision) {
  if (decision?.allowed !== true) throw new GovernanceDeniedError(decision?.reason);
  return decision;
}

export async function runIfAllowed(decision, operation) {
  requireAllowed(decision);
  if (typeof operation !== "function") throw new TypeError("An operation function is required.");
  return operation();
}

/**
 * Decide a capability from reviewed policy plus trusted grants.
 * No request-provided scope or privilege field is accepted.
 */
export function decideCapability({ identity, policy, capability, grantedScopes = [] } = {}) {
  if (identity?.allowed !== true) return denied("identity_denied", "A verified identity is required.");
  if (!policy || policy.enabled !== true || !POLICY_ID.test(policy.policy_id ?? "")) {
    return denied("policy_unavailable", "An enabled reviewed policy is required.");
  }
  if (!Array.isArray(policy.allowed_modes) || !policy.allowed_modes.includes(identity.identity.mode)) {
    return denied("execution_mode_denied", "The verified execution mode is not allowed by policy.");
  }
  if (!Array.isArray(policy.capabilities) || !policy.capabilities.includes(capability)) {
    return denied("capability_denied", "The capability is not allowed by policy.");
  }
  const trustedGrants = new Set(grantedScopes);
  const missing = (policy.required_scopes ?? []).filter((scope) => !trustedGrants.has(scope));
  if (missing.length > 0) {
    return denied("scope_denied", "Trusted authorization is missing a required scope.");
  }
  return frozen({
    allowed: true,
    policy_id: policy.policy_id,
    policy_version: String(policy.version ?? ""),
    capability,
    identity: identity.identity,
  });
}

/**
 * Validate immutable tool policy. Privilege administration is absent by design:
 * only read, compute, and explicitly-redacted external sends are representable.
 */
export function defineToolPolicy(candidate) {
  if (!candidate || !POLICY_ID.test(candidate.policy_id ?? "")) {
    throw new TypeError("A valid tool policy id is required.");
  }
  if (!POLICY_ID.test(candidate.tool_name ?? "")) throw new TypeError("A valid tool name is required.");
  if (!SAFE_EFFECTS.has(candidate.effect)) {
    throw new TypeError("Tool effects are limited to read, compute, or external_send.");
  }
  if (!TOOL_TRANSPORTS.has(candidate.transport)) throw new TypeError("Unsupported tool transport.");
  if (!Array.isArray(candidate.allowed_modes) || candidate.allowed_modes.length === 0) {
    throw new TypeError("At least one execution mode is required.");
  }
  for (const mode of candidate.allowed_modes) {
    if (!Object.hasOwn(SOURCE_FOR_MODE, mode)) throw new TypeError("Unsupported execution mode.");
  }
  if (candidate.effect === "external_send" && candidate.redaction !== "required") {
    throw new TypeError("External sends require redaction.");
  }
  if (
    !Array.isArray(candidate.destination_allowlist_refs) ||
    candidate.destination_allowlist_refs.length === 0 ||
    candidate.destination_allowlist_refs.some((ref) => !OPAQUE_REF.test(ref))
  ) {
    throw new TypeError("At least one opaque destination allowlist reference is required.");
  }
  if (!RESPONSE_TRUST.has(candidate.response_trust)) {
    throw new TypeError("A response trust classification is required.");
  }
  if (!CONTENT_CLASSIFICATIONS.includes(candidate.maximum_content_classification)) {
    throw new TypeError("A maximum content classification is required.");
  }
  if (!Number.isInteger(candidate.max_response_bytes) || candidate.max_response_bytes < 1) {
    throw new TypeError("A positive integer max_response_bytes is required.");
  }
  if (!DATA_ACCESS.has(candidate.data_access)) throw new TypeError("A data_access classification is required.");
  if (!SIDE_EFFECTS.has(candidate.side_effect)) throw new TypeError("An explicit side_effect is required.");
  if (!IDEMPOTENCY_REQUIREMENTS.has(candidate.idempotency)) {
    throw new TypeError("An explicit idempotency requirement is required.");
  }
  if (
    (candidate.side_effect === "none" && candidate.idempotency !== "not_applicable") ||
    (candidate.side_effect !== "none" && candidate.idempotency !== "required")
  ) {
    throw new TypeError("Side effects require idempotency; effect-free tools require not_applicable.");
  }
  if (
    (candidate.effect === "external_send" && candidate.side_effect !== "external_send") ||
    (candidate.effect !== "external_send" && candidate.side_effect === "external_send")
  ) {
    throw new TypeError("External-send effects and side-effect declarations must match.");
  }
  if (!OPAQUE_REF.test(candidate.kill_switch_ref ?? "")) {
    throw new TypeError("An opaque kill_switch_ref is required.");
  }
  if (typeof candidate.validate_response !== "function" || typeof candidate.filter_response !== "function") {
    throw new TypeError("Response validation and content filtering hooks are required.");
  }
  if (candidate.allowed_modes.includes(EXECUTION_MODES.SYSTEM)) {
    if (
      candidate.data_access !== "non_governed" ||
      !POLICY_ID.test(candidate.system_action_policy_ref ?? "") ||
      candidate.system_action_policy_ref === candidate.policy_id
    ) {
      throw new TypeError(
        "System mode requires a separate reviewed policy for an explicitly non-governed action.",
      );
    }
  }
  return frozen({
    policy_id: candidate.policy_id,
    tool_name: candidate.tool_name,
    transport: candidate.transport,
    effect: candidate.effect,
    allowed_modes: [...new Set(candidate.allowed_modes)],
    redaction: candidate.redaction === "required" ? "required" : "none",
    destination_allowlist_refs: [...new Set(candidate.destination_allowlist_refs)],
    response_trust: candidate.response_trust,
    maximum_content_classification: candidate.maximum_content_classification,
    max_response_bytes: candidate.max_response_bytes,
    data_access: candidate.data_access,
    side_effect: candidate.side_effect,
    idempotency: candidate.idempotency,
    kill_switch_ref: candidate.kill_switch_ref,
    validate_response: candidate.validate_response,
    filter_response: candidate.filter_response,
    ...(candidate.system_action_policy_ref
      ? { system_action_policy_ref: candidate.system_action_policy_ref }
      : {}),
  });
}

function responseBytes(value) {
  if (typeof value === "string") return Buffer.byteLength(value, "utf8");
  if (value instanceof Uint8Array) return value.byteLength;
  try {
    const encoded = JSON.stringify(value);
    return encoded === undefined ? 0 : Buffer.byteLength(encoded, "utf8");
  } catch {
    return Number.POSITIVE_INFINITY;
  }
}

export function decideToolInvocation({
  identity,
  capabilityDecision,
  toolPolicy,
  toolName,
  transport,
  destinationRef,
  activeKillSwitchRefs = [],
  response,
  responseTrust,
  contentClassification,
  sideEffect,
  attempt = 1,
  idempotencyKey,
  initialIdempotencyKey,
} = {}) {
  if (identity?.allowed !== true || capabilityDecision?.allowed !== true) {
    return denied("prerequisite_denied", "Identity and capability decisions must both allow.");
  }
  if (
    capabilityDecision.identity.subject_ref !== identity.identity.subject_ref ||
    capabilityDecision.identity.mode !== identity.identity.mode
  ) {
    return denied("decision_identity_mismatch", "The policy decisions do not bind the same identity.");
  }
  if (
    !toolPolicy ||
    toolPolicy.tool_name !== toolName ||
    toolPolicy.transport !== transport ||
    !Array.isArray(toolPolicy.allowed_modes) ||
    !toolPolicy.allowed_modes.includes(identity.identity.mode)
  ) {
    return denied("tool_denied", "The tool invocation is not covered by reviewed policy.");
  }
  if (
    !Array.isArray(toolPolicy.destination_allowlist_refs) ||
    toolPolicy.destination_allowlist_refs.length === 0 ||
    toolPolicy.destination_allowlist_refs.some((ref) => !OPAQUE_REF.test(ref)) ||
    !RESPONSE_TRUST.has(toolPolicy.response_trust) ||
    !CONTENT_CLASSIFICATIONS.includes(toolPolicy.maximum_content_classification) ||
    !Number.isInteger(toolPolicy.max_response_bytes) ||
    toolPolicy.max_response_bytes < 1 ||
    !DATA_ACCESS.has(toolPolicy.data_access) ||
    !SIDE_EFFECTS.has(toolPolicy.side_effect) ||
    !IDEMPOTENCY_REQUIREMENTS.has(toolPolicy.idempotency) ||
    (toolPolicy.side_effect === "none" && toolPolicy.idempotency !== "not_applicable") ||
    (toolPolicy.side_effect !== "none" && toolPolicy.idempotency !== "required") ||
    (toolPolicy.effect === "external_send" && toolPolicy.side_effect !== "external_send") ||
    (toolPolicy.effect !== "external_send" && toolPolicy.side_effect === "external_send") ||
    !OPAQUE_REF.test(toolPolicy.kill_switch_ref ?? "") ||
    typeof toolPolicy.validate_response !== "function" ||
    typeof toolPolicy.filter_response !== "function"
  ) {
    return denied("tool_policy_invalid", "The tool policy is missing required safeguards.");
  }
  if (
    identity.identity.mode === EXECUTION_MODES.SYSTEM &&
    (toolPolicy.data_access !== "non_governed" ||
      !toolPolicy.system_action_policy_ref ||
      capabilityDecision.policy_id !== toolPolicy.system_action_policy_ref)
  ) {
    return denied(
      "system_action_denied",
      "System mode requires a separate matching policy decision for a non-governed action.",
    );
  }
  if (
    activeKillSwitchRefs === null ||
    activeKillSwitchRefs === undefined ||
    typeof activeKillSwitchRefs === "string" ||
    typeof activeKillSwitchRefs[Symbol.iterator] !== "function"
  ) {
    return denied("kill_switch_state_invalid", "Trusted kill-switch state is required.");
  }
  if (new Set(activeKillSwitchRefs).has(toolPolicy.kill_switch_ref)) {
    return denied("kill_switch_active", "The required tool policy kill switch is active.");
  }
  if (!toolPolicy.destination_allowlist_refs.includes(destinationRef)) {
    return denied("destination_denied", "The destination is not on the reviewed allowlist.");
  }
  if (responseTrust !== toolPolicy.response_trust) {
    return denied("response_trust_mismatch", "The response trust classification does not match policy.");
  }
  const classificationIndex = CONTENT_CLASSIFICATIONS.indexOf(contentClassification);
  const maximumIndex = CONTENT_CLASSIFICATIONS.indexOf(toolPolicy.maximum_content_classification);
  if (classificationIndex < 0 || classificationIndex > maximumIndex) {
    return denied("content_classification_denied", "The response classification exceeds policy.");
  }
  if (responseBytes(response) > toolPolicy.max_response_bytes) {
    return denied("response_too_large", "The response exceeds the policy byte limit.");
  }
  if (sideEffect !== toolPolicy.side_effect) {
    return denied("side_effect_mismatch", "The invocation side effect does not match policy.");
  }
  if (!Number.isInteger(attempt) || attempt < 1) {
    return denied("attempt_invalid", "The invocation attempt must be a positive integer.");
  }
  if (toolPolicy.idempotency === "required" && !IDEMPOTENCY_KEY.test(idempotencyKey ?? "")) {
    return denied("idempotency_required", "A stable opaque idempotency key is required.");
  }
  if (
    sideEffect !== "none" &&
    attempt > 1 &&
    (!IDEMPOTENCY_KEY.test(initialIdempotencyKey ?? "") || initialIdempotencyKey !== idempotencyKey)
  ) {
    return denied("idempotency_unstable", "Retried side effects must reuse the initial idempotency key.");
  }
  let valid;
  try {
    valid = toolPolicy.validate_response(response, {
      trust: responseTrust,
      content_classification: contentClassification,
      destination_ref: destinationRef,
    });
  } catch {
    return denied("response_validation_failed", "The response validation hook failed.");
  }
  if (valid !== true) {
    return denied("response_validation_failed", "The response did not pass policy validation.");
  }
  let filteredResponse;
  try {
    filteredResponse = toolPolicy.filter_response(response, {
      trust: responseTrust,
      content_classification: contentClassification,
      destination_ref: destinationRef,
    });
  } catch {
    return denied("response_filter_failed", "The response content filter failed.");
  }
  if (filteredResponse === undefined) {
    return denied("response_filter_failed", "The response content filter returned no safe value.");
  }
  if (responseBytes(filteredResponse) > toolPolicy.max_response_bytes) {
    return denied("response_too_large", "The filtered response exceeds the policy byte limit.");
  }
  return frozen({
    allowed: true,
    policy_id: toolPolicy.policy_id,
    tool_name: toolName,
    transport,
    effect: toolPolicy.effect,
    destination_ref: destinationRef,
    response_trust: responseTrust,
    content_classification: contentClassification,
    response: filteredResponse,
    identity: identity.identity,
  });
}

export function redactText(value) {
  return String(value)
    .replace(PRIVATE_KEY, REDACTED)
    .replace(BEARER, "Bearer [REDACTED]")
    .replace(ASSIGNED_SECRET, (_match, label) => `${label}=[REDACTED]`)
    .replace(PROVIDER_TOKEN, REDACTED);
}

/** Recursively redact security-sensitive fields without mutating the input. */
export function redactSensitive(value, options = {}, seen = new WeakSet(), depth = 0) {
  const maxDepth = Number.isInteger(options.maxDepth) ? Math.max(0, options.maxDepth) : 8;
  if (typeof value === "string") return redactText(value);
  if (value === null || typeof value !== "object") return value;
  if (depth >= maxDepth) return REDACTED;
  if (seen.has(value)) return REDACTED;
  seen.add(value);
  if (Array.isArray(value)) {
    const output = value.map((item) => redactSensitive(item, options, seen, depth + 1));
    seen.delete(value);
    return output;
  }
  const output = {};
  for (const [key, item] of Object.entries(value)) {
    output[key] = SENSITIVE_KEY.test(key) ? REDACTED : redactSensitive(item, options, seen, depth + 1);
  }
  seen.delete(value);
  return output;
}
