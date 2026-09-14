import assert from "node:assert/strict";
import test from "node:test";

import {
  decideCapability,
  decideToolInvocation,
  decideVerifiedIdentity,
  defineToolPolicy,
  GovernanceDeniedError,
  redactSensitive,
  requireAllowed,
  runIfAllowed,
} from "../src/index.js";

const authorization = {
  mode: "user_authorization",
  subject_ref: "user:alice-123",
  scopes: ["sql"],
};

function verifiedIdentity() {
  return decideVerifiedIdentity({
    authorization,
    verification: {
      status: "verified",
      subject_ref: "user:alice-123",
      mode: "user_authorization",
      source: "trusted_gateway",
    },
  });
}

function systemIdentity() {
  return decideVerifiedIdentity({
    authorization: { mode: "system", subject_ref: "system:scheduler" },
    verification: {
      status: "verified",
      subject_ref: "system:scheduler",
      mode: "system",
      source: "internal_scheduler",
    },
  });
}

function validToolPolicy(overrides = {}) {
  return defineToolPolicy({
    policy_id: "policy.tools",
    tool_name: "evidence.read",
    transport: "mcp",
    effect: "read",
    allowed_modes: ["user_authorization"],
    redaction: "none",
    destination_allowlist_refs: ["destination:evidence-reader"],
    response_trust: "validated",
    maximum_content_classification: "confidential",
    max_response_bytes: 1024,
    data_access: "governed_evidence",
    side_effect: "none",
    idempotency: "not_applicable",
    kill_switch_ref: "kill-switch:evidence-reader",
    validate_response: () => true,
    filter_response: (response) => response,
    ...overrides,
  });
}

function capabilityFor(identity, policyId = "policy.answer") {
  return decideCapability({
    identity,
    policy: {
      policy_id: policyId,
      version: 1,
      enabled: true,
      allowed_modes: [identity.identity.mode],
      capabilities: ["answer"],
    },
    capability: "answer",
  });
}

function validInvocation(overrides = {}) {
  const identity = overrides.identity ?? verifiedIdentity();
  return {
    identity,
    capabilityDecision: overrides.capabilityDecision ?? capabilityFor(identity),
    toolPolicy: overrides.toolPolicy ?? validToolPolicy(),
    toolName: "evidence.read",
    transport: "mcp",
    destinationRef: "destination:evidence-reader",
    activeKillSwitchRefs: [],
    response: { safe: true },
    responseTrust: "validated",
    contentClassification: "internal",
    sideEffect: "none",
    attempt: 1,
    ...overrides,
  };
}

test("identity fails closed when proof is absent, mismatched, or mode-selected", () => {
  assert.equal(decideVerifiedIdentity({ authorization }).allowed, false);
  assert.equal(
    decideVerifiedIdentity({
      authorization,
      verification: {
        status: "verified",
        subject_ref: "user:bob-456",
        mode: "user_authorization",
        source: "trusted_gateway",
      },
    }).reason,
    "identity_mismatch",
  );
  assert.equal(
    decideVerifiedIdentity({
      authorization: { ...authorization, mode: "explicit_service_principal" },
      verification: {
        status: "verified",
        subject_ref: "user:alice-123",
        mode: "user_authorization",
        source: "trusted_gateway",
      },
    }).reason,
    "execution_mode_mismatch",
  );
  assert.equal(
    decideVerifiedIdentity({
      authorization,
      verification: {
        status: "verified",
        subject_ref: "user:alice-123",
        mode: "user_authorization",
        source: "reviewed_service_binding",
      },
    }).reason,
    "identity_source_invalid",
  );
});

test("capability grants come from trusted inputs, not request scopes", () => {
  const identity = verifiedIdentity();
  assert.equal(identity.allowed, true);
  const policy = {
    policy_id: "policy.answer",
    version: 1,
    enabled: true,
    allowed_modes: ["user_authorization"],
    capabilities: ["answer"],
    required_scopes: ["sql"],
  };

  assert.equal(decideCapability({ identity, policy, capability: "answer" }).reason, "scope_denied");
  assert.equal(
    decideCapability({ identity, policy, capability: "answer", grantedScopes: ["sql"] }).allowed,
    true,
  );
});

test("fail-closed helper never calls an operation for a denial", async () => {
  let called = false;
  const denied = { allowed: false, reason: "identity_unverified", detail: "missing" };
  assert.throws(() => requireAllowed(denied), GovernanceDeniedError);
  await assert.rejects(
    runIfAllowed(denied, () => {
      called = true;
    }),
    GovernanceDeniedError,
  );
  assert.equal(called, false);
});

test("tool policy cannot represent privilege administration", () => {
  assert.throws(
    () =>
      defineToolPolicy({
        policy_id: "policy.tools",
        tool_name: "catalog.permissions",
        transport: "mcp",
        effect: "privilege_administration",
        allowed_modes: ["user_authorization"],
      }),
    /limited to read, compute, or external_send/,
  );
  assert.throws(
    () =>
      defineToolPolicy({
        policy_id: "policy.tools",
        tool_name: "external.sender",
        transport: "mcp",
        effect: "external_send",
        allowed_modes: ["user_authorization"],
      }),
    /require redaction/,
  );
});

test("tool decisions bind the same verified identity and exact transport", () => {
  const identity = verifiedIdentity();
  const capabilityDecision = capabilityFor(identity);
  const toolPolicy = validToolPolicy({
    filter_response: () => ({ filtered: true }),
  });
  assert.equal(
    decideToolInvocation({
      ...validInvocation({ identity, capabilityDecision, toolPolicy }),
    }).response.filtered,
    true,
  );
  assert.equal(
    decideToolInvocation({
      ...validInvocation({ identity, capabilityDecision, toolPolicy }),
      transport: "local",
    }).reason,
    "tool_denied",
  );
});

test("H-13 tool policy fields are mandatory and internally consistent", () => {
  assert.throws(
    () => validToolPolicy({ destination_allowlist_refs: [] }),
    /destination allowlist reference/,
  );
  assert.throws(() => validToolPolicy({ kill_switch_ref: "" }), /kill_switch_ref/);
  assert.throws(() => validToolPolicy({ response_trust: undefined }), /response trust/);
  assert.throws(
    () => validToolPolicy({ maximum_content_classification: undefined }),
    /maximum content classification/,
  );
  assert.throws(() => validToolPolicy({ max_response_bytes: 0 }), /max_response_bytes/);
  assert.throws(() => validToolPolicy({ side_effect: undefined }), /side_effect/);
  assert.throws(() => validToolPolicy({ idempotency: undefined }), /idempotency/);
  assert.throws(() => validToolPolicy({ validate_response: undefined }), /validation and content filtering/);
  assert.throws(() => validToolPolicy({ filter_response: undefined }), /validation and content filtering/);
  assert.throws(
    () => validToolPolicy({ side_effect: "state_change", idempotency: "not_applicable" }),
    /Side effects require idempotency/,
  );
});

test("H-13 invocation checks deny unsafe destinations, responses, and kill switches", () => {
  assert.equal(
    decideToolInvocation(
      validInvocation({ activeKillSwitchRefs: ["kill-switch:evidence-reader"] }),
    ).reason,
    "kill_switch_active",
  );
  assert.equal(
    decideToolInvocation(validInvocation({ destinationRef: "destination:unreviewed" })).reason,
    "destination_denied",
  );
  assert.equal(
    decideToolInvocation(validInvocation({ responseTrust: "untrusted" })).reason,
    "response_trust_mismatch",
  );
  assert.equal(
    decideToolInvocation(validInvocation({ contentClassification: "restricted" })).reason,
    "content_classification_denied",
  );
  assert.equal(
    decideToolInvocation(
      validInvocation({
        toolPolicy: validToolPolicy({ max_response_bytes: 4 }),
        response: "12345",
      }),
    ).reason,
    "response_too_large",
  );
  assert.equal(
    decideToolInvocation(validInvocation({ sideEffect: "state_change" })).reason,
    "side_effect_mismatch",
  );
});

test("response validation and filtering hooks fail closed", () => {
  assert.equal(
    decideToolInvocation(
      validInvocation({ toolPolicy: validToolPolicy({ validate_response: () => false }) }),
    ).reason,
    "response_validation_failed",
  );
  assert.equal(
    decideToolInvocation(
      validInvocation({
        toolPolicy: validToolPolicy({
          filter_response: () => {
            throw new Error("unsafe parser detail");
          },
        }),
      }),
    ).reason,
    "response_filter_failed",
  );
  assert.equal(
    decideToolInvocation(
      validInvocation({ toolPolicy: validToolPolicy({ filter_response: () => undefined }) }),
    ).reason,
    "response_filter_failed",
  );
});

test("retried side effects require the original stable idempotency key", () => {
  const toolPolicy = validToolPolicy({
    effect: "external_send",
    redaction: "required",
    side_effect: "external_send",
    idempotency: "required",
  });
  const base = validInvocation({
    toolPolicy,
    sideEffect: "external_send",
    response: "accepted",
    idempotencyKey: "idem:stable-123",
  });
  assert.equal(decideToolInvocation(base).allowed, true);
  assert.equal(
    decideToolInvocation({ ...base, attempt: 2 }).reason,
    "idempotency_unstable",
  );
  assert.equal(
    decideToolInvocation({
      ...base,
      attempt: 2,
      initialIdempotencyKey: "idem:different-456",
    }).reason,
    "idempotency_unstable",
  );
  assert.equal(
    decideToolInvocation({
      ...base,
      attempt: 2,
      initialIdempotencyKey: "idem:stable-123",
    }).allowed,
    true,
  );
});

test("system mode is limited to separately reviewed non-governed actions", () => {
  assert.throws(
    () =>
      validToolPolicy({
        allowed_modes: ["system"],
        data_access: "governed_evidence",
        system_action_policy_ref: "policy.system-action",
      }),
    /explicitly non-governed/,
  );
  assert.throws(
    () => validToolPolicy({ allowed_modes: ["system"], data_access: "non_governed" }),
    /separate reviewed policy/,
  );

  const identity = systemIdentity();
  const toolPolicy = validToolPolicy({
    tool_name: "maintenance.check",
    allowed_modes: ["system"],
    data_access: "non_governed",
    destination_allowlist_refs: ["destination:health-endpoint"],
    system_action_policy_ref: "policy.system-action",
  });
  const invocation = {
    ...validInvocation({
      identity,
      capabilityDecision: capabilityFor(identity, "policy.answer"),
      toolPolicy,
    }),
    toolName: "maintenance.check",
    destinationRef: "destination:health-endpoint",
  };
  assert.equal(decideToolInvocation(invocation).reason, "system_action_denied");
  assert.equal(
    decideToolInvocation({
      ...invocation,
      capabilityDecision: capabilityFor(identity, "policy.system-action"),
    }).allowed,
    true,
  );
});

test("redaction removes nested secrets without mutating input", () => {
  const providerTokens = [
    ["da", "pi", "0123456789abcdef0123456789abcdef"].join(""),
    ["sk", "-proj-", "0123456789abcdefghijklmnop"].join(""),
  ];
  const input = {
    status: "failed",
    authorization: "Bearer abc.def.ghi",
    nested: {
      message: `client_secret=hunter2, Bearer live-token, ${providerTokens.join(", ")}`,
      prompt: "show governed rows",
    },
  };
  const output = redactSensitive(input);
  assert.deepEqual(output, {
    status: "failed",
    authorization: "[REDACTED]",
    nested: {
      message:
        "client_secret=[REDACTED], Bearer [REDACTED], [REDACTED], [REDACTED]",
      prompt: "[REDACTED]",
    },
  });
  assert.equal(input.authorization, "Bearer abc.def.ghi");
  assert.doesNotMatch(JSON.stringify(output), /hunter2|live-token|dapi0123|sk-proj|governed rows/);
});
