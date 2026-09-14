import type { RequestContext } from "../../contracts/src/index";

export type ExecutionMode =
  | "user_authorization"
  | "explicit_service_principal"
  | "system";
export type IdentitySource =
  | "trusted_gateway"
  | "reviewed_service_binding"
  | "internal_scheduler";

export const EXECUTION_MODES: Readonly<{
  USER_AUTHORIZATION: "user_authorization";
  EXPLICIT_SERVICE_PRINCIPAL: "explicit_service_principal";
  SYSTEM: "system";
}>;
export const IDENTITY_SOURCES: Readonly<{
  TRUSTED_GATEWAY: "trusted_gateway";
  REVIEWED_SERVICE_BINDING: "reviewed_service_binding";
  INTERNAL_SCHEDULER: "internal_scheduler";
}>;

export interface IdentityVerification {
  status: "verified" | "unverified" | "invalid" | "absent";
  subject_ref?: string;
  mode?: ExecutionMode;
  source?: IdentitySource;
}

export interface VerifiedIdentity {
  subject_ref: string;
  mode: ExecutionMode;
  source: IdentitySource;
  verified: true;
}

export type DeniedDecision = Readonly<{
  allowed: false;
  reason: string;
  detail: string;
}>;
export type IdentityDecision =
  | Readonly<{ allowed: true; identity: Readonly<VerifiedIdentity> }>
  | DeniedDecision;
export type AuthorizationClaim =
  | RequestContext["authorization"]
  | Readonly<{ mode: "system"; subject_ref: string }>;

export function decideVerifiedIdentity(input?: {
  authorization?: AuthorizationClaim;
  verification?: IdentityVerification;
}): IdentityDecision;

export class GovernanceDeniedError extends Error {
  readonly reason: string;
}
export function requireAllowed<T extends { allowed: true }>(decision: T | DeniedDecision | null | undefined): T;
export function runIfAllowed<T>(
  decision: { allowed: true } | DeniedDecision | null | undefined,
  operation: () => T | Promise<T>,
): Promise<T>;

export interface CapabilityPolicy {
  policy_id: string;
  version: string | number;
  enabled: boolean;
  allowed_modes: readonly ExecutionMode[];
  capabilities: readonly string[];
  required_scopes?: readonly string[];
}
export type CapabilityDecision =
  | Readonly<{
      allowed: true;
      policy_id: string;
      policy_version: string;
      capability: string;
      identity: Readonly<VerifiedIdentity>;
    }>
  | DeniedDecision;
export function decideCapability(input?: {
  identity?: IdentityDecision;
  policy?: CapabilityPolicy;
  capability?: string;
  grantedScopes?: readonly string[];
}): CapabilityDecision;

export type ToolTransport = "local" | "mcp";
export type ToolEffect = "read" | "compute" | "external_send";
export type ResponseTrust = "untrusted" | "validated" | "trusted";
export type ContentClassification = "public" | "internal" | "confidential" | "restricted";
export type DataAccess = "non_governed" | "governed_evidence" | "governed_data";
export type SideEffect = "none" | "state_change" | "external_send";
export type IdempotencyRequirement = "not_applicable" | "required";
export interface ResponseHookContext {
  trust: ResponseTrust;
  content_classification: ContentClassification;
  destination_ref: string;
}
export interface ToolPolicyCandidate {
  policy_id: string;
  tool_name: string;
  transport: ToolTransport;
  effect: ToolEffect;
  allowed_modes: readonly ExecutionMode[];
  redaction?: "none" | "required";
  destination_allowlist_refs: readonly string[];
  response_trust: ResponseTrust;
  maximum_content_classification: ContentClassification;
  max_response_bytes: number;
  data_access: DataAccess;
  side_effect: SideEffect;
  idempotency: IdempotencyRequirement;
  kill_switch_ref: string;
  validate_response(response: unknown, context: ResponseHookContext): boolean;
  filter_response(response: unknown, context: ResponseHookContext): unknown;
  system_action_policy_ref?: string;
}
export interface ToolPolicy {
  readonly policy_id: string;
  readonly tool_name: string;
  readonly transport: ToolTransport;
  readonly effect: ToolEffect;
  readonly allowed_modes: readonly ExecutionMode[];
  readonly redaction: "none" | "required";
  readonly destination_allowlist_refs: readonly string[];
  readonly response_trust: ResponseTrust;
  readonly maximum_content_classification: ContentClassification;
  readonly max_response_bytes: number;
  readonly data_access: DataAccess;
  readonly side_effect: SideEffect;
  readonly idempotency: IdempotencyRequirement;
  readonly kill_switch_ref: string;
  readonly validate_response: ToolPolicyCandidate["validate_response"];
  readonly filter_response: ToolPolicyCandidate["filter_response"];
  readonly system_action_policy_ref?: string;
}
export function defineToolPolicy(candidate: ToolPolicyCandidate): ToolPolicy;
export type ToolDecision =
  | Readonly<{
      allowed: true;
      policy_id: string;
      tool_name: string;
      transport: ToolTransport;
      effect: ToolEffect;
      destination_ref: string;
      response_trust: ResponseTrust;
      content_classification: ContentClassification;
      response: unknown;
      identity: Readonly<VerifiedIdentity>;
    }>
  | DeniedDecision;
export function decideToolInvocation(input?: {
  identity?: IdentityDecision;
  capabilityDecision?: CapabilityDecision;
  toolPolicy?: ToolPolicy;
  toolName?: string;
  transport?: ToolTransport;
  destinationRef?: string;
  activeKillSwitchRefs?: Iterable<string>;
  response?: unknown;
  responseTrust?: ResponseTrust;
  contentClassification?: ContentClassification;
  sideEffect?: SideEffect;
  attempt?: number;
  idempotencyKey?: string;
  initialIdempotencyKey?: string;
}): ToolDecision;

export function redactText(value: unknown): string;
export function redactSensitive<T>(value: T, options?: { maxDepth?: number }): T;
