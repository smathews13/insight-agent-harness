import assert from "node:assert/strict";
import test from "node:test";
import { URL } from "node:url";

import {
  SLACK_PRODUCT_BOUNDARY,
  assertNoRawDatabricksToken,
  buildAuthenticatedWebAppLink,
  buildSlackCorrelation,
  createAuthenticatedLinkState,
  createDelegatedAuthState,
  createInitialDelegatedAuthState,
  createSlackSignatureVerificationReceipt,
  createSlackEventContract,
  createSlackSubjectLink,
  createSlackThreadMapping,
  decideSlackIngress,
  decideSlackThreadMappingWrite,
  exportSlackLinkOut,
  getSlackProductBoundary,
  getSlackRetentionRule,
  planSlackEventDelivery,
  prepareSlackPersistenceRecord,
  transitionDelegatedAuthState,
  validateSlackLinkOutMessage,
} from "../../src/index.js";

const NOW = "2026-09-13T20:00:00.000Z";
const LATER = "2026-09-13T20:05:00.000Z";

const eventFixture = (overrides = {}) =>
  createSlackEventContract({
    team_id: "T123",
    event_id: "Ev123",
    event_type: "app_mention",
    user_id: "U123",
    channel_id: "C123",
    event_ts: "1789339200.000001",
    message_ts: "1789339200.000001",
    thread_ts: "1789339200.000001",
    mutation: "created",
    revision_ts: "1789339200.000001",
    retry_number: 0,
    received_at: NOW,
    ...overrides,
  });

const subjectLinkFixture = (overrides = {}) =>
  createSlackSubjectLink({
    workspace_ref: "slack_workspace:T123",
    slack_user_ref: "slack_user:T123:U123",
    databricks_workspace_ref: "databricks_workspace:ws-123",
    databricks_subject_ref: "databricks_user:user-123",
    linked_at: NOW,
    verified_by_ref: "delegated_verifier:test-double-not-production",
    ...overrides,
  });

const threadMappingFixture = (overrides = {}) =>
  createSlackThreadMapping({
    workspace_ref: "slack_workspace:T123",
    channel_ref: "slack_channel:T123:C123",
    thread_ref: "slack_thread:T123:C123:1789339200.000001",
    project_ref: "project:project-123",
    conversation_ref: "conversation:conversation-123",
    created_at: NOW,
    ...overrides,
  });

const signatureReceiptFixture = (overrides = {}) =>
  createSlackSignatureVerificationReceipt({
    schema_version: "1.0.0",
    workspace_ref: "slack_workspace:T123",
    event_ref: "slack_event:T123:Ev123",
    request_timestamp: "1789329600",
    body_sha256: `sha256:${"a".repeat(64)}`,
    verified_at: NOW,
    expires_at: "2026-09-13T20:04:00.000Z",
    verifier_ref: "slack_signature_verifier:test-double-not-production",
    ...overrides,
  });

const correlationFixture = (overrides = {}) =>
  buildSlackCorrelation(
    {
      event: eventFixture(),
      subject_link: subjectLinkFixture(),
      thread_mapping: threadMappingFixture(),
      project_ref: "project:project-123",
      run_ref: "run:run-123",
      evidence_refs: ["evidence:ev-1"],
      ...overrides,
    },
    () => "123e4567-e89b-12d3-a456-426614174000",
  );

const linkStateFixture = (overrides = {}) =>
  createAuthenticatedLinkState({
    state_ref: `link_state:v1:${"A".repeat(43)}`,
    correlation: correlationFixture(),
    issued_at: NOW,
    expires_at: "2026-09-13T20:10:00.000Z",
    ...overrides,
  });

const exportDocumentFixture = () => ({
  schema_version: "1.0.0",
  document_id: "doc_governed_result",
  revision_id: "rev_1",
  title: "Restricted customer result that must not appear in Slack",
  generated_at: NOW,
  freshness: { as_of: NOW, status: "current" },
  caveats: ["Restricted caveat that must not appear in Slack"],
  evidence_refs: [
    {
      schema_version: "1.0.0",
      evidence_id: "ev_governed",
      source_kind: "dataset",
      source_ref: "dataset:governed",
      retrieved_at: "2026-09-13T20:00:00Z",
      excerpt: "Restricted evidence that must not appear in Slack",
    },
  ],
  sections: [
    {
      id: "answer",
      heading: "Restricted heading",
      blocks: [
        {
          type: "paragraph",
          text: "Restricted answer that must not appear in Slack",
          evidence_ids: ["ev_governed"],
        },
      ],
    },
  ],
});

test("the architecture spike is an immutable NO-GO with link-out as its only product mode", () => {
  assert.equal(getSlackProductBoundary(), SLACK_PRODUCT_BOUNDARY);
  assert.equal(SLACK_PRODUCT_BOUNDARY.verdict, "NO_GO");
  assert.equal(
    SLACK_PRODUCT_BOUNDARY.mode,
    "authenticated_web_app_link_out_only",
  );
  assert.ok(
    SLACK_PRODUCT_BOUNDARY.prohibited_actions.includes(
      "substitute_service_principal",
    ),
  );
  assert.ok(
    SLACK_PRODUCT_BOUNDARY.prohibited_actions.includes(
      "enable_production_slack_bot",
    ),
  );
  assert.ok(
    SLACK_PRODUCT_BOUNDARY.prohibited_actions.includes(
      "accept_unverified_slack_event",
    ),
  );
  assert.ok(Object.isFrozen(SLACK_PRODUCT_BOUNDARY));
});

test("event contracts derive stable retry idempotency and thread references without raw content", () => {
  const first = eventFixture();
  const retry = eventFixture({ retry_number: 1, retry_reason: "http_timeout" });
  assert.equal(first.idempotency_key, retry.idempotency_key);
  assert.equal(first.thread_ref, "slack_thread:T123:C123:1789339200.000001");
  assert.equal(retry.retry.number, 1);
  assert.throws(() => eventFixture({ text: "secret question" }), /not allowed/);
});

test("duplicates, edits, stale edits, and deletes have deterministic acknowledgement plans", () => {
  const created = eventFixture();
  const receipt = {
    message_ref: created.message_ref,
    idempotency_key: created.idempotency_key,
    latest_revision_ts: created.revision_ts,
  };
  assert.equal(
    planSlackEventDelivery(created, receipt).action,
    "acknowledge_duplicate",
  );

  const edited = eventFixture({
    event_id: "Ev124",
    event_ts: "1789339260.000001",
    mutation: "edited",
    revision_ts: "1789339260.000001",
  });
  assert.equal(
    planSlackEventDelivery(edited, receipt).action,
    "replace_link_out",
  );

  const stale = eventFixture({
    event_id: "Ev125",
    event_ts: "1789339199.000001",
    mutation: "edited",
    revision_ts: "1789339199.000001",
  });
  assert.equal(
    planSlackEventDelivery(stale, receipt).action,
    "acknowledge_stale_revision",
  );
  const microsecondStale = eventFixture({
    event_id: "EvMicro",
    mutation: "edited",
    event_ts: "1789339200.000001",
    revision_ts: "1789339200.000001",
  });
  assert.equal(
    planSlackEventDelivery(microsecondStale, {
      ...receipt,
      idempotency_key: "slack:T123:EvOther:1789339200.000002",
      latest_revision_ts: "1789339200.000002",
    }).action,
    "acknowledge_stale_revision",
  );
  assert.throws(
    () =>
      planSlackEventDelivery(created, {
        ...receipt,
        message_ref: "slack_message:T123:C999:1789339200.000001",
      }),
    /same Slack message/,
  );

  const deleted = eventFixture({
    event_id: "Ev126",
    event_ts: "1789339320.000001",
    mutation: "deleted",
    revision_ts: "1789339320.000001",
  });
  assert.equal(
    planSlackEventDelivery(deleted, receipt).action,
    "remove_link_out",
  );
});

test("thread mapping is idempotent and refuses silent project rebinding", () => {
  const mapping = threadMappingFixture();
  assert.equal(decideSlackThreadMappingWrite(null, mapping).action, "insert");
  assert.equal(decideSlackThreadMappingWrite(mapping, mapping).action, "noop");
  assert.deepEqual(
    decideSlackThreadMappingWrite(mapping, {
      ...mapping,
      project_ref: "project:other-project",
    }),
    { allowed: false, reason: "thread_rebind_requires_review" },
  );
  assert.throws(
    () =>
      createSlackThreadMapping({
        ...mapping,
        channel_ref: "slack_channel:T999:C123",
      }),
    /one workspace/,
  );
  assert.throws(
    () =>
      createSlackThreadMapping({
        ...mapping,
        channel_ref: "slack_channel:T123:C999",
      }),
    /one workspace and channel/,
  );
});

test("Slack users can link only to delegated Databricks user subjects", () => {
  const link = subjectLinkFixture();
  assert.equal(link.auth_mode, "user_authorization");
  assert.match(link.databricks_subject_ref, /^databricks_user:/);
  assert.throws(
    () => subjectLinkFixture({ auth_mode: "explicit_service_principal" }),
    /cannot use a service principal/,
  );
  assert.throws(
    () =>
      subjectLinkFixture({
        databricks_subject_ref: "databricks_service_principal:sp-123",
      }),
    /databricks_user:/,
  );
});

test("delegated auth models consent, refresh, revocation, and workspace change using references only", () => {
  const unlinked = createInitialDelegatedAuthState({
    workspace_ref: "slack_workspace:T123",
    slack_user_ref: "slack_user:T123:U123",
    updated_at: NOW,
  });
  const pending = transitionDelegatedAuthState(unlinked, {
    type: "consent_started",
    expected_revision: 0,
    occurred_at: LATER,
    databricks_workspace_ref: "databricks_workspace:ws-123",
    consent_request_ref: "consent_request:req-123",
  });
  const active = transitionDelegatedAuthState(pending, {
    type: "consent_verified",
    expected_revision: 1,
    occurred_at: "2026-09-13T20:06:00.000Z",
    databricks_subject_ref: "databricks_user:user-123",
    managed_credential_ref: "managed_credential:platform-handle-1",
    verified_by_ref: "delegated_verifier:test-double-not-production",
  });
  const refreshRequired = transitionDelegatedAuthState(active, {
    type: "refresh_due",
    expected_revision: 2,
    occurred_at: "2026-09-13T20:07:00.000Z",
  });
  const refreshed = transitionDelegatedAuthState(refreshRequired, {
    type: "refresh_verified",
    expected_revision: 3,
    occurred_at: "2026-09-13T20:08:00.000Z",
    managed_credential_ref: "managed_credential:platform-handle-2",
    verified_by_ref: "delegated_verifier:test-double-not-production",
  });
  const revoked = transitionDelegatedAuthState(refreshed, {
    type: "revoked",
    expected_revision: 4,
    occurred_at: "2026-09-13T20:09:00.000Z",
  });
  assert.equal(revoked.state, "revoked");
  assert.equal("managed_credential_ref" in revoked, false);
  assert.equal("databricks_subject_ref" in revoked, false);

  const changed = transitionDelegatedAuthState(active, {
    type: "slack_workspace_changed",
    expected_revision: 2,
    occurred_at: "2026-09-13T20:10:00.000Z",
    new_workspace_ref: "slack_workspace:T999",
    new_slack_user_ref: "slack_user:T999:U999",
  });
  assert.equal(changed.state, "workspace_changed");
  assert.equal(changed.workspace_ref, "slack_workspace:T999");
  assert.equal("managed_credential_ref" in changed, false);
  assert.throws(
    () =>
      transitionDelegatedAuthState(active, {
        type: "revoked",
        expected_revision: 1,
        occurred_at: "2026-09-13T20:11:00.000Z",
      }),
    /expected_revision/,
  );
  assert.throws(
    () =>
      createDelegatedAuthState({
        state: "revoked",
        workspace_ref: "slack_workspace:T123",
        slack_user_ref: "slack_user:T123:U123",
        managed_credential_ref: "managed_credential:must-be-cleared",
        revision: 5,
        updated_at: "2026-09-13T20:12:00.000Z",
      }),
    /must not retain/,
  );
});

test("raw Databricks token material is unrepresentable in auth state and persistence", () => {
  assert.throws(
    () =>
      createDelegatedAuthState({
        state: "unlinked",
        workspace_ref: "slack_workspace:T123",
        slack_user_ref: "slack_user:T123:U123",
        updated_at: NOW,
        access_token: "dapi12345678901234567890",
      }),
    /raw Databricks token material|not allowed/,
  );
  assert.throws(
    () =>
      assertNoRawDatabricksToken({
        nested: { authorization: "Bearer secret-value" },
      }),
    /raw Databricks token material/,
  );
  assert.throws(
    () =>
      prepareSlackPersistenceRecord("delegated_auth_state", {
        state: "active",
        nested: { refresh_token: "secret-value" },
      }),
    /raw Databricks token material/,
  );
  assert.throws(
    () =>
      assertNoRawDatabricksToken({
        nested: { accessToken: "secret-value" },
      }),
    /raw Databricks token material/,
  );
  assert.throws(
    () =>
      assertNoRawDatabricksToken({
        nested: { cookie: "session-value" },
      }),
    /raw Databricks token material/,
  );
});

test("retention rules classify metadata and prohibit Slack content or token persistence", () => {
  assert.equal(
    getSlackRetentionRule("slack_event_metadata").retain_for_days,
    30,
  );
  assert.equal(
    getSlackRetentionRule("slack_message_content").persistence,
    "forbidden",
  );
  assert.throws(
    () =>
      prepareSlackPersistenceRecord("slack_message_content", { text: "hello" }),
    /must not be persisted/,
  );
  assert.throws(
    () =>
      prepareSlackPersistenceRecord("slack_event_metadata", {
        event_ref: "slack_event:T123:Ev123",
        nested: { text: "must not persist" },
      }),
    /raw Slack content is forbidden/,
  );
  assert.throws(
    () =>
      prepareSlackPersistenceRecord("slack_event_metadata", {
        event_ref: "slack_event:T123:Ev123",
        answer_body: "restricted answer under an alternate key",
      }),
    /not allowed/,
  );
  const safe = prepareSlackPersistenceRecord(
    "slack_event_metadata",
    eventFixture(),
  );
  assert.equal(safe.classification, "internal");
  const stateRecord = prepareSlackPersistenceRecord(
    "slack_link_state",
    linkStateFixture(),
  );
  assert.equal(stateRecord.classification, "confidential");
  assert.equal(
    stateRecord.retention.retention_trigger,
    "delete_at_expiry_or_consumption",
  );
});

test("correlation joins Slack event through subject and project to run and evidence", () => {
  const correlation = buildSlackCorrelation(
    {
      event: eventFixture(),
      subject_link: subjectLinkFixture(),
      thread_mapping: threadMappingFixture(),
      project_ref: "project:project-123",
      run_ref: "run:run-123",
      evidence_refs: ["evidence:ev-1", "evidence:ev-2"],
    },
    () => "123e4567-e89b-12d3-a456-426614174000",
  );
  assert.equal(correlation.slack_event_ref, "slack_event:T123:Ev123");
  assert.equal(correlation.slack_user_ref, "slack_user:T123:U123");
  assert.equal(
    correlation.slack_thread_ref,
    "slack_thread:T123:C123:1789339200.000001",
  );
  assert.equal(correlation.databricks_subject_ref, "databricks_user:user-123");
  assert.equal(correlation.run_ref, "run:run-123");
  assert.deepEqual(correlation.evidence_refs, [
    "evidence:ev-1",
    "evidence:ev-2",
  ]);
  assert.equal(
    correlation.correlation_id,
    "corr_123e4567-e89b-12d3-a456-426614174000",
  );
  assert.throws(
    () =>
      buildSlackCorrelation({
        event: eventFixture(),
        subject_link: subjectLinkFixture({
          slack_user_ref: "slack_user:T123:U999",
        }),
        thread_mapping: threadMappingFixture(),
        project_ref: "project:project-123",
      }),
    /event actor/,
  );
  assert.throws(
    () =>
      buildSlackCorrelation({
        event: eventFixture(),
        subject_link: subjectLinkFixture(),
        thread_mapping: threadMappingFixture({
          project_ref: "project:other-project",
        }),
        project_ref: "project:project-123",
      }),
    /event thread mapping/,
  );
});

test("the kill switch fails closed and all enabled ingress remains link-out only", () => {
  const event = eventFixture();
  assert.deepEqual(decideSlackIngress({ event }), {
    allowed: false,
    reason: "kill_switch_state_missing",
  });
  assert.deepEqual(
    decideSlackIngress({
      kill_switch: {
        ref: "kill_switch:slack-boundary",
        active: true,
        checked_at: NOW,
        expires_at: "2026-09-13T20:04:00.000Z",
        source_ref: "control_plane:slack-kill-switch",
      },
      event,
      now: NOW,
    }),
    { allowed: false, reason: "kill_switch_active" },
  );
  const enabled = decideSlackIngress({
    kill_switch: {
      ref: "kill_switch:slack-boundary",
      active: false,
      checked_at: NOW,
      expires_at: "2026-09-13T20:04:00.000Z",
      source_ref: "control_plane:slack-kill-switch",
    },
    signature_receipt: signatureReceiptFixture(),
    event,
    subject_link: subjectLinkFixture(),
    now: NOW,
  });
  assert.equal(enabled.allowed, true);
  assert.equal(enabled.action, "render_authenticated_web_app_link_out");
  assert.equal(enabled.product_mode, "authenticated_web_app_link_out_only");
  assert.equal(
    decideSlackIngress({
      kill_switch: {
        ref: "kill_switch:slack-boundary",
        active: false,
        checked_at: NOW,
        expires_at: "2026-09-13T20:04:00.000Z",
        source_ref: "control_plane:slack-kill-switch",
      },
      event,
      now: NOW,
    }).reason,
    "signature_receipt_invalid",
  );
  assert.equal(
    decideSlackIngress({
      kill_switch: {
        ref: "kill_switch:slack-boundary",
        active: false,
        checked_at: NOW,
        expires_at: "2026-09-13T20:04:00.000Z",
        source_ref: "control_plane:slack-kill-switch",
      },
      signature_receipt: signatureReceiptFixture(),
      event,
      now: "2026-09-13T20:05:00.000Z",
    }).reason,
    "kill_switch_state_stale",
  );
  assert.equal(
    decideSlackIngress({
      kill_switch: {
        ref: "kill_switch:slack-boundary",
        active: false,
        checked_at: "2026-09-13T20:01:00.000Z",
        expires_at: "2026-09-13T20:06:00.000Z",
        source_ref: "control_plane:slack-kill-switch",
      },
      signature_receipt: signatureReceiptFixture(),
      event,
      now: "2026-09-13T20:05:00.000Z",
    }).reason,
    "signature_receipt_invalid",
  );
  assert.equal(
    decideSlackIngress({
      kill_switch: {
        ref: "kill_switch:slack-boundary",
        active: false,
        checked_at: NOW,
        expires_at: "2026-09-13T20:04:00.000Z",
        source_ref: "control_plane:slack-kill-switch",
      },
      signature_receipt: signatureReceiptFixture({
        event_ref: "slack_event:T123:Ev999",
      }),
      event,
      now: NOW,
    }).reason,
    "signature_receipt_invalid",
  );
  assert.equal(
    decideSlackIngress({
      kill_switch: {
        ref: "kill_switch:slack-boundary",
        active: false,
        checked_at: NOW,
        expires_at: "2026-09-13T20:04:00.000Z",
        source_ref: "control_plane:slack-kill-switch",
      },
      signature_receipt: signatureReceiptFixture({
        verified_at: "2026-09-13T20:03:00.000Z",
      }),
      event,
      now: "2026-09-13T20:02:00.000Z",
    }).reason,
    "signature_receipt_invalid",
  );
});

test("the export-core adapter emits only locally validated Block Kit link-out content", async () => {
  const url = buildAuthenticatedWebAppLink({
    base_url: "https://player-insights.example/",
    link_state: linkStateFixture(),
    now: NOW,
  });
  assert.match(url, /^https:\/\/player-insights\.example\/slack\/continue\?/);
  assert.deepEqual([...new URL(url).searchParams.keys()], ["state"]);

  const exported = await exportSlackLinkOut(exportDocumentFixture(), {
    authorize: () => ({ allowed: true }),
    redact: (document) => document,
    baseUrl: "https://player-insights.example/",
    linkState: linkStateFixture(),
    now: NOW,
  });
  assert.equal(
    validateSlackLinkOutMessage(exported.message, {
      expected_origin: "https://player-insights.example",
    }),
    true,
  );
  const serialized = JSON.stringify(exported.message);
  assert.doesNotMatch(
    serialized,
    /Restricted|customer result|governed evidence/i,
  );
  assert.match(serialized, /authenticated web app/);
  assert.equal(exported.product_mode, "authenticated_web_app_link_out_only");
  assert.throws(
    () =>
      buildAuthenticatedWebAppLink({
        base_url: "http://player-insights.example/",
        link_state: linkStateFixture(),
        now: NOW,
      }),
    /credential-free HTTPS/,
  );
  assert.throws(
    () =>
      buildAuthenticatedWebAppLink({
        base_url: "https://player-insights.example/",
        continue_path: "//attacker.example/steal",
        link_state: linkStateFixture(),
        now: NOW,
      }),
    /absolute application path/,
  );
  assert.throws(
    () =>
      buildAuthenticatedWebAppLink({
        base_url: "https://player-insights.example/",
        link_state: linkStateFixture({
          state_ref: "link_state:v1:guessable",
        }),
        now: NOW,
      }),
    /256-bit opaque handle/,
  );
  const forgedMessage = globalThis.structuredClone(exported.message);
  forgedMessage.blocks[1].elements[0].url = `https://attacker.example/slack/continue?state=${encodeURIComponent(
    linkStateFixture().state_ref,
  )}`;
  assert.throws(
    () =>
      validateSlackLinkOutMessage(forgedMessage, {
        expected_origin: "https://player-insights.example",
      }),
    /authenticated application origin/,
  );
  const markdownMessage = globalThis.structuredClone(exported.message);
  markdownMessage.blocks[0].text.type = "mrkdwn";
  assert.throws(
    () =>
      validateSlackLinkOutMessage(markdownMessage, {
        expected_origin: "https://player-insights.example",
      }),
    /plain_text/,
  );
  const injectedQueryMessage = globalThis.structuredClone(exported.message);
  injectedQueryMessage.blocks[1].elements[0].url += "&project=project:other";
  assert.throws(
    () =>
      validateSlackLinkOutMessage(injectedQueryMessage, {
        expected_origin: "https://player-insights.example",
      }),
    /only a strong opaque state handle/,
  );
});
