import assert from "node:assert/strict";
import test from "node:test";

import {
  appendAuditEvent,
  assertNoSecrets,
  assertSafeTelemetryPayload,
  buildCorrelationContext,
  classifyPayload,
  containsSecrets,
  createAuditEvent,
  normalizeCorrelationId,
  redactTelemetryPayload,
  safeMetadata,
  UnsafeTelemetryError,
  usableCorrelationId,
} from "../src/index.js";

const UUID = "123e4567-e89b-12d3-a456-426614174000";
const CORRELATION_ID = `corr_${UUID}`;

test("correlation accepts only printable bounded ids and mints on rejection", () => {
  assert.equal(usableCorrelationId(CORRELATION_ID), CORRELATION_ID);
  assert.equal(usableCorrelationId("corr_ok\nforged-line"), null);
  assert.equal(normalizeCorrelationId("raw prompt", () => UUID), CORRELATION_ID);
  assert.deepEqual(
    buildCorrelationContext(
      {
        correlation_id: CORRELATION_ID,
        app_request_id: "req_123",
        app_run_id: "run_456",
        gateway_request_id: "gateway:789",
        mlflow_trace_id: "trace.abcd",
      },
      () => UUID,
    ),
    {
      correlation_id: CORRELATION_ID,
      app: { request_id: "req_123", run_id: "run_456" },
      gateway: { request_id: "gateway:789" },
      mlflow: { trace_id: "trace.abcd" },
    },
  );
  assert.throws(
    () => buildCorrelationContext({ gateway_request_id: "unsafe\nvalue" }, () => UUID),
    /printable opaque identifier/,
  );
});

test("payload classification blocks content and credential fields", () => {
  assert.equal(classifyPayload("prompt", "hello"), "raw_prompt");
  assert.equal(classifyPayload("response", "world"), "raw_response");
  assert.equal(classifyPayload("access_token", "secret"), "token");
  assert.equal(classifyPayload("cookies", "secret"), "cookie");
  assert.equal(classifyPayload("request_headers", {}), "header");
  assert.equal(classifyPayload("rows", []), "governed_data");
  assert.equal(classifyPayload("latency_ms", 15), "safe_metadata");
  assert.equal(classifyPayload("arbitrary", "value"), "unknown");
});

test("safe metadata omits raw prompts, responses, headers, and governed data", () => {
  const metadata = safeMetadata({
    correlation_id: CORRELATION_ID,
    latency_ms: 15,
    retryable: false,
    prompt: "show private records",
    response: "private answer",
    authorization: "Bearer live-token",
    headers: { cookie: "session=secret" },
    rows: [{ governed: true }],
    arbitrary: "not reviewed",
  });
  assert.deepEqual(metadata, {
    correlation_id: CORRELATION_ID,
    latency_ms: 15,
    retryable: false,
  });
  assert.doesNotMatch(JSON.stringify(metadata), /private|live-token|session|governed/);
});

test("telemetry redaction removes nested credentials and content", () => {
  const redacted = redactTelemetryPayload({
    status: "failed",
    prompt: "show governed records",
    nested: {
      response: "raw answer",
      message: "client_secret=hunter2; Bearer live-token",
    },
    headers: { cookie: "session-value" },
  });
  assert.deepEqual(redacted, {
    status: "failed",
    prompt: "[REDACTED]",
    nested: {
      response: "[REDACTED]",
      message: "[REDACTED]",
    },
    headers: "[REDACTED]",
  });
  assert.doesNotMatch(JSON.stringify(redacted), /governed records|raw answer|hunter2|live-token|session-value/);
});

test("no-secret and safe-payload guards provide negative proofs", () => {
  assert.equal(containsSecrets({ authorization: "Bearer abc" }), true);
  assert.throws(
    () => assertNoSecrets({ nested: { access_token: "abc" } }),
    UnsafeTelemetryError,
  );
  assert.throws(
    () => assertSafeTelemetryPayload({ prompt: "even a non-secret prompt is not telemetry" }),
    /raw_prompt/,
  );
  assert.doesNotThrow(() =>
    assertSafeTelemetryPayload({ correlation_id: CORRELATION_ID, status: "succeeded" }),
  );
});

test("AuditEvent construction is contract-valid, immutable, and content-safe", () => {
  const event = createAuditEvent(
    {
      event_type: "tool_call",
      actor: { mode: "user_authorization", subject_ref: "user:alice-123" },
      action: "evidence.read",
      target_ref: "tool:evidence-reader",
      outcome: "succeeded",
      correlation_id: CORRELATION_ID,
      details: {
        request_id: "req_123",
        duration_ms: 42,
        prompt: "do not log me",
        response: "do not log me either",
        access_token: "token-value",
      },
    },
    {
      randomUUID: () => UUID,
      now: () => new Date("2026-09-13T12:00:00.000Z"),
    },
  );
  assert.equal(event.event_id, `audit_${UUID}`);
  assert.deepEqual(event.details, { request_id: "req_123", duration_ms: 42 });
  assert.equal(Object.isFrozen(event), true);
  assert.equal(Object.isFrozen(event.details), true);
  assert.throws(() => {
    event.outcome = "failed";
  }, TypeError);
});

test("audit sink is append-only and revalidates events", async () => {
  const appended = [];
  const event = createAuditEvent(
    {
      event_type: "authorization",
      actor: { mode: "system", subject_ref: "system:policy-engine" },
      action: "policy.evaluate",
      target_ref: "capability:answer",
      outcome: "allowed",
      correlation_id: CORRELATION_ID,
    },
    { randomUUID: () => UUID, now: () => new Date("2026-09-13T12:00:00.000Z") },
  );
  await appendAuditEvent({ append: (item) => appended.push(item) }, event);
  assert.deepEqual(appended, [event]);
  await assert.rejects(
    appendAuditEvent({ append: () => {} }, { ...event, correlation_id: "unsafe" }),
    /Invalid AuditEvent/,
  );
});
