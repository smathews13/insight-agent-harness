import type {
  CanonicalExportDocument,
  ExportAuthorizationHook,
  ExportRedactionHook,
} from "../../export-core/src/index.js";

export class SlackBoundaryInvariantError extends Error {
  readonly code: string;
}

export interface SlackProductBoundary {
  readonly schema_version: "1.0.0";
  readonly verdict: "NO_GO";
  readonly mode: "authenticated_web_app_link_out_only";
  readonly reason_code: "delegated_databricks_authorization_unproven";
  readonly allowed_actions: readonly string[];
  readonly prohibited_actions: readonly string[];
}

export const SLACK_PRODUCT_BOUNDARY: SlackProductBoundary;
export function getSlackProductBoundary(): SlackProductBoundary;
export function assertNoRawDatabricksToken<T>(value: T): T;

export type SlackMutation = "created" | "edited" | "deleted";
export interface SlackEventInput {
  team_id: string;
  event_id: string;
  event_type: string;
  user_id: string;
  channel_id: string;
  event_ts: string;
  message_ts?: string;
  thread_ts?: string;
  mutation?: SlackMutation;
  revision_ts?: string;
  retry_number?: number;
  retry_reason?: string;
  received_at: string;
}
export interface SlackEventContract {
  readonly schema_version: "1.0.0";
  readonly event_ref: string;
  readonly workspace_ref: string;
  readonly channel_ref: string;
  readonly actor_ref: string;
  readonly message_ref: string;
  readonly thread_ref: string;
  readonly event_id: string;
  readonly event_type: string;
  readonly event_ts: string;
  readonly message_ts: string;
  readonly thread_ts: string;
  readonly revision_ts: string;
  readonly mutation: SlackMutation;
  readonly idempotency_key: string;
  readonly retry: Readonly<{ number: number; reason?: string }>;
  readonly received_at: string;
}
export function createSlackEventContract(
  input: SlackEventInput,
): SlackEventContract;

export interface SlackEventReceipt {
  message_ref: string;
  idempotency_key: string;
  latest_revision_ts: string;
}
export type SlackDeliveryAction =
  | "render_link_out"
  | "replace_link_out"
  | "remove_link_out"
  | "acknowledge_duplicate"
  | "acknowledge_stale_revision";
export interface SlackDeliveryPlan {
  readonly acknowledge: true;
  readonly action: SlackDeliveryAction;
  readonly idempotency_key: string;
}
export function planSlackEventDelivery(
  event: SlackEventContract,
  receipt?: SlackEventReceipt | null,
): SlackDeliveryPlan;

export interface SlackThreadMappingInput {
  schema_version?: "1.0.0";
  workspace_ref: string;
  channel_ref: string;
  thread_ref: string;
  project_ref: string;
  conversation_ref?: string;
  created_at: string;
}
export interface SlackThreadMapping
  extends Readonly<
    Required<Omit<SlackThreadMappingInput, "conversation_ref">>
  > {
  readonly conversation_ref?: string;
}
export function createSlackThreadMapping(
  input: SlackThreadMappingInput,
): SlackThreadMapping;
export type SlackThreadMappingDecision =
  | Readonly<{
      allowed: true;
      action: "insert" | "noop";
      mapping: SlackThreadMapping;
    }>
  | Readonly<{ allowed: false; reason: string }>;
export function decideSlackThreadMappingWrite(
  existing: SlackThreadMappingInput | null | undefined,
  candidate: SlackThreadMappingInput,
): SlackThreadMappingDecision;

export interface SlackThreadMappingStore {
  getByThreadRef(threadRef: string): Promise<SlackThreadMapping | null>;
  putIfAbsent(mapping: SlackThreadMapping): Promise<SlackThreadMappingDecision>;
}

export type SlackSubjectLinkStatus = "active" | "revoked";
export interface SlackSubjectLinkInput {
  schema_version?: "1.0.0";
  workspace_ref: string;
  slack_user_ref: string;
  databricks_workspace_ref: string;
  databricks_subject_ref: string;
  auth_mode?: "user_authorization";
  status?: SlackSubjectLinkStatus;
  linked_at: string;
  verified_by_ref: string;
}
export interface SlackSubjectLink {
  readonly schema_version: "1.0.0";
  readonly workspace_ref: string;
  readonly slack_user_ref: string;
  readonly databricks_workspace_ref: string;
  readonly databricks_subject_ref: string;
  readonly auth_mode: "user_authorization";
  readonly status: SlackSubjectLinkStatus;
  readonly linked_at: string;
  readonly verified_by_ref: string;
}
export function createSlackSubjectLink(
  input: SlackSubjectLinkInput,
): SlackSubjectLink;

export interface SlackSubjectLinkResolver {
  resolve(input: {
    workspace_ref: string;
    slack_user_ref: string;
  }): Promise<SlackSubjectLink | null>;
}

export const DELEGATED_AUTH_STATES: Readonly<{
  UNLINKED: "unlinked";
  CONSENT_PENDING: "consent_pending";
  ACTIVE: "active";
  REFRESH_REQUIRED: "refresh_required";
  REVOKED: "revoked";
  WORKSPACE_CHANGED: "workspace_changed";
}>;
export type DelegatedAuthStateName =
  (typeof DELEGATED_AUTH_STATES)[keyof typeof DELEGATED_AUTH_STATES];
export interface DelegatedAuthStateInput {
  schema_version?: "1.0.0";
  state?: DelegatedAuthStateName;
  workspace_ref: string;
  slack_user_ref: string;
  databricks_workspace_ref?: string;
  databricks_subject_ref?: string;
  managed_credential_ref?: string;
  consent_request_ref?: string;
  verified_by_ref?: string;
  revision?: number;
  updated_at: string;
  reason?: string;
}
export interface DelegatedAuthState {
  readonly schema_version: "1.0.0";
  readonly state: DelegatedAuthStateName;
  readonly workspace_ref: string;
  readonly slack_user_ref: string;
  readonly databricks_workspace_ref?: string;
  readonly databricks_subject_ref?: string;
  readonly managed_credential_ref?: string;
  readonly consent_request_ref?: string;
  readonly verified_by_ref?: string;
  readonly revision: number;
  readonly updated_at: string;
  readonly reason?: string;
}
export type DelegatedAuthEvent =
  | {
      type: "consent_started";
      expected_revision: number;
      occurred_at: string;
      databricks_workspace_ref: string;
      consent_request_ref: string;
    }
  | {
      type: "consent_verified";
      expected_revision: number;
      occurred_at: string;
      databricks_subject_ref: string;
      managed_credential_ref: string;
      verified_by_ref: string;
    }
  | {
      type: "refresh_due";
      expected_revision: number;
      occurred_at: string;
      reason?: string;
    }
  | {
      type: "refresh_verified";
      expected_revision: number;
      occurred_at: string;
      managed_credential_ref: string;
      verified_by_ref: string;
    }
  | {
      type: "revoked";
      expected_revision: number;
      occurred_at: string;
      reason?: string;
    }
  | {
      type: "slack_workspace_changed";
      expected_revision: number;
      occurred_at: string;
      new_workspace_ref: string;
      new_slack_user_ref: string;
      reason?: string;
    }
  | {
      type: "databricks_workspace_changed";
      expected_revision: number;
      occurred_at: string;
      reason?: string;
    };
export function createInitialDelegatedAuthState(input: {
  workspace_ref: string;
  slack_user_ref: string;
  updated_at: string;
}): DelegatedAuthState;
export function createDelegatedAuthState(
  input: DelegatedAuthStateInput,
): DelegatedAuthState;
export function transitionDelegatedAuthState(
  current: DelegatedAuthStateInput,
  event: DelegatedAuthEvent,
): DelegatedAuthState;

export interface DelegatedAuthorizationVerifier {
  verifyConsent(input: {
    consent_request_ref: string;
    expected_slack_user_ref: string;
    expected_databricks_workspace_ref: string;
  }): Promise<{
    databricks_subject_ref: string;
    managed_credential_ref: string;
    verified_by_ref: string;
  }>;
  verifyRefresh(input: {
    managed_credential_ref: string;
    expected_databricks_subject_ref: string;
  }): Promise<{ managed_credential_ref: string; verified_by_ref: string }>;
  revoke(input: { managed_credential_ref: string }): Promise<void>;
}

export interface DelegatedAuthStateStore {
  get(
    workspaceRef: string,
    slackUserRef: string,
  ): Promise<DelegatedAuthState | null>;
  compareAndSet(
    expectedRevision: number,
    next: DelegatedAuthState,
  ): Promise<"updated" | "revision_conflict">;
}

export type SlackRecordKind =
  | "slack_event_metadata"
  | "slack_idempotency_receipt"
  | "slack_thread_mapping"
  | "slack_subject_link"
  | "delegated_auth_state"
  | "slack_correlation"
  | "slack_link_state"
  | "slack_message_content"
  | "databricks_token_material";
export interface SlackRetentionRule {
  readonly classification: "internal" | "confidential" | "restricted";
  readonly persistence: "allowed" | "forbidden";
  readonly retain_for_days?: number;
  readonly retention_trigger?: string;
}
export const SLACK_RETENTION_POLICY: Readonly<{
  policy_id: "slack-boundary-v1";
  records: Readonly<Record<SlackRecordKind, SlackRetentionRule>>;
}>;
export function getSlackRetentionRule(
  recordKind: SlackRecordKind,
): SlackRetentionRule;
export function prepareSlackPersistenceRecord<
  T extends Record<string, unknown>,
>(
  recordKind: SlackRecordKind,
  record: T,
): Readonly<{
  policy_id: string;
  record_kind: SlackRecordKind;
  classification: SlackRetentionRule["classification"];
  retention: SlackRetentionRule;
  payload: T;
}>;

export interface SlackCorrelation {
  readonly schema_version: "1.0.0";
  readonly correlation_id: string;
  readonly slack_event_ref: string;
  readonly slack_user_ref: string;
  readonly slack_thread_ref: string;
  readonly databricks_workspace_ref: string;
  readonly databricks_subject_ref: string;
  readonly project_ref: string;
  readonly run_ref?: string;
  readonly evidence_refs: readonly string[];
}
export function buildSlackCorrelation(
  input: {
    correlation_id?: string;
    event: SlackEventContract;
    subject_link: SlackSubjectLinkInput;
    thread_mapping: SlackThreadMappingInput;
    project_ref: string;
    run_ref?: string;
    evidence_refs?: readonly string[];
  },
  uuid?: () => string,
): SlackCorrelation;

export interface SlackSignatureVerificationReceipt {
  readonly schema_version: "1.0.0";
  readonly workspace_ref: string;
  readonly event_ref: string;
  readonly request_timestamp: string;
  readonly body_sha256: string;
  readonly verified_at: string;
  readonly expires_at: string;
  readonly verifier_ref: string;
}
export function createSlackSignatureVerificationReceipt(
  input: SlackSignatureVerificationReceipt,
): SlackSignatureVerificationReceipt;

export type SlackIngressDecision =
  | Readonly<{ allowed: false; reason: string }>
  | Readonly<{
      allowed: true;
      action:
        | "render_authenticated_web_app_link_out"
        | "render_authentication_link_out";
      product_mode: "authenticated_web_app_link_out_only";
    }>;
export function decideSlackIngress(input?: {
  kill_switch?: {
    ref: string;
    active: boolean;
    checked_at: string;
    expires_at: string;
    source_ref: string;
  };
  signature_receipt?: SlackSignatureVerificationReceipt;
  event?: SlackEventContract;
  subject_link?: SlackSubjectLinkInput | null;
  now?: string;
}): SlackIngressDecision;

export interface AuthenticatedLinkState {
  readonly schema_version: "1.0.0";
  readonly state_ref: string;
  readonly slack_event_ref: string;
  readonly slack_user_ref: string;
  readonly slack_thread_ref: string;
  readonly databricks_workspace_ref: string;
  readonly databricks_subject_ref: string;
  readonly project_ref: string;
  readonly correlation_id: string;
  readonly issued_at: string;
  readonly expires_at: string;
}
export function createAuthenticatedLinkState(input: {
  state_ref: string;
  correlation: SlackCorrelation;
  issued_at: string;
  expires_at: string;
}): AuthenticatedLinkState;

export interface AuthenticatedLinkStateStore {
  consume(input: {
    state_ref: string;
    expected_databricks_subject_ref: string;
    now: string;
  }): Promise<
    | Readonly<{ status: "consumed"; state: AuthenticatedLinkState }>
    | Readonly<{
        status: "missing" | "expired" | "already_consumed" | "subject_mismatch";
      }>
  >;
}

export function buildAuthenticatedWebAppLink(input: {
  base_url: string;
  continue_path?: string;
  link_state: AuthenticatedLinkState;
  now: string;
}): string;

export interface SlackPlainText {
  readonly type: "plain_text";
  readonly text: string;
}
export interface SlackLinkOutMessage {
  readonly text: string;
  readonly blocks: readonly [
    Readonly<{ type: "section"; block_id: string; text: SlackPlainText }>,
    Readonly<{
      type: "actions";
      block_id: string;
      elements: readonly [
        Readonly<{
          type: "button";
          text: SlackPlainText;
          url: string;
          action_id: string;
          accessibility_label: string;
        }>,
      ];
    }>,
  ];
}
export function validateSlackLinkOutMessage(
  message: SlackLinkOutMessage,
  options: { expected_origin: string },
): true;
export function createSlackLinkOutMessage(input: {
  url: string;
  document_ref: string;
  revision_ref: string;
  expected_origin: string;
}): SlackLinkOutMessage;

export interface SlackLinkOutExport {
  readonly schema_version: "1.0.0";
  readonly product_mode: "authenticated_web_app_link_out_only";
  readonly document_ref: string;
  readonly revision_ref: string;
  readonly message: SlackLinkOutMessage;
}
export function exportSlackLinkOut<Context = unknown>(
  document: CanonicalExportDocument,
  options: {
    authorize: ExportAuthorizationHook<Context>;
    redact: ExportRedactionHook<Context>;
    authorizationContext?: Context;
    baseUrl: string;
    continuePath?: string;
    linkState: AuthenticatedLinkState;
    now: string;
  },
): Promise<SlackLinkOutExport>;
