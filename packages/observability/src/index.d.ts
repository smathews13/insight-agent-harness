import type { AuditEvent } from "../../contracts/src/index";

export const CORRELATION_PREFIX: "corr_";
export const CORRELATION_PATTERN: RegExp;
export const REDACTED: "[REDACTED]";

export interface AppCorrelation {
  readonly request_id?: string;
  readonly run_id?: string;
}
export interface GatewayCorrelation {
  readonly request_id?: string;
}
export interface MlflowCorrelation {
  readonly trace_id?: string;
}
export interface CorrelationContext {
  readonly correlation_id: string;
  readonly app: AppCorrelation;
  readonly gateway: GatewayCorrelation;
  readonly mlflow: MlflowCorrelation;
}
export interface CorrelationInput {
  correlation_id?: unknown;
  app_request_id?: string;
  app_run_id?: string;
  gateway_request_id?: string;
  mlflow_trace_id?: string;
}

export function mintCorrelationId(uuid?: () => string): string;
export function usableCorrelationId(value: unknown): string | null;
export function normalizeCorrelationId(value: unknown, uuid?: () => string): string;
export function buildCorrelationContext(
  input?: CorrelationInput,
  uuid?: () => string,
): CorrelationContext;

export type PayloadClassification =
  | "safe_metadata"
  | "raw_prompt"
  | "raw_response"
  | "token"
  | "cookie"
  | "header"
  | "secret"
  | "governed_data"
  | "unsafe_value"
  | "unknown";
export function classifyPayload(key: PropertyKey, value: unknown): PayloadClassification;
export function redactTelemetryPayload<T>(value: T): T;
export function safeMetadata(
  input: unknown,
  options?: { allowedKeys?: Iterable<string> },
): Readonly<Record<string, string | number | boolean | null>>;

export class UnsafeTelemetryError extends Error {
  readonly classification: PayloadClassification;
  readonly path: string;
}
export function containsSecrets(value: unknown): boolean;
export function assertNoSecrets<T>(value: T): T;
export function assertSafeTelemetryPayload<T>(value: T): T;

export type AuditEventInput = Omit<
  AuditEvent,
  "schema_version" | "event_id" | "occurred_at" | "details"
> & {
  event_id?: string;
  occurred_at?: string;
  details?: Record<string, unknown>;
  metadataOptions?: { allowedKeys?: Iterable<string> };
};
export interface AuditEventOptions {
  randomUUID?: () => string;
  now?: () => Date;
}
export interface AppendOnlyAuditSink {
  append(event: AuditEvent): void | Promise<void>;
}
export function createAuditEvent(input: AuditEventInput, options?: AuditEventOptions): AuditEvent;
export function appendAuditEvent(sink: AppendOnlyAuditSink, event: AuditEvent): Promise<void>;
