import type { EvidenceRef } from "../../contracts/src/generated/types";

export class ExportInvariantError extends Error {
  readonly code: string;
  constructor(message: string, code?: string);
}

export class ExportAuthorizationError extends ExportInvariantError {
  constructor(reason?: string);
}

export class ExportRedactionError extends ExportInvariantError {
  constructor(reason?: string);
}

export class ExportAdapterUnavailableError extends ExportInvariantError {
  readonly format: string;
  constructor(format: string);
}

export const EXPORT_ADAPTER_THREAT_CONTRACT: "threat:export-core-v1";

export interface CompiledExportAdapterRegistration {
  readonly ref: string;
  readonly owner: string;
  readonly formats: readonly ("pdf" | "png")[];
  readonly adapter: BinaryExportAdapter;
  readonly threatContractRef: typeof EXPORT_ADAPTER_THREAT_CONTRACT;
  readonly egressPolicyRef: string;
  readonly redactionProfileRef: string;
}

export interface CompiledExportAdapterRegistry {
  readonly refs: readonly string[];
  resolve(ref: string): Readonly<CompiledExportAdapterRegistration> | null;
}

declare const loadedExportAdapterBrand: unique symbol;
export type LoadedExportAdapters = Readonly<
  Partial<Record<"pdf" | "png", BinaryExportAdapter>>
> & {
  readonly [loadedExportAdapterBrand]: true;
};

export function createCompiledExportAdapterRegistry(
  registrations: readonly CompiledExportAdapterRegistration[],
): Readonly<CompiledExportAdapterRegistry>;

export function loadProductExportAdapters(
  productExports: {
    readonly external_enabled: boolean;
    readonly formats: readonly ExportFormat[];
    readonly adapter_refs?: readonly string[];
    readonly egress_policy_ref?: string;
    readonly redaction_profile_ref?: string;
  },
  registry: CompiledExportAdapterRegistry,
): LoadedExportAdapters;

export interface ExportFreshness {
  as_of: string;
  status?: string;
}

export interface ExportColumn {
  key: string;
  label: string;
}

export interface ExportParagraphBlock {
  type: "paragraph";
  text: string;
  evidence_ids?: readonly string[];
}

export type ExportContentValue =
  | null
  | string
  | number
  | boolean
  | readonly ExportContentValue[]
  | { readonly [key: string]: ExportContentValue };

export interface ExportListBlock {
  type: "list";
  items: readonly ExportContentValue[];
  evidence_ids?: readonly string[];
}

export interface ExportTableBlock {
  type: "table";
  artifact_id: string;
  columns: readonly ExportColumn[];
  rows: readonly Readonly<Record<string, ExportContentValue>>[];
  evidence_ids?: readonly string[];
}

export interface ExportFigureBlock {
  type: "figure";
  artifact_id: string;
  label: string;
  value: ExportContentValue;
  display: string;
  comparison?: ExportContentValue;
  evidence_ids: readonly string[];
}

export interface ExportChartBlock {
  type: "chart";
  artifact_id: string;
  title: string;
  kind: string;
  series: readonly Readonly<Record<string, ExportContentValue>>[];
  layout?: Readonly<Record<string, ExportContentValue>>;
  evidence_ids: readonly string[];
}

export type ExportBlock =
  | ExportParagraphBlock
  | ExportListBlock
  | ExportTableBlock
  | ExportFigureBlock
  | ExportChartBlock;

export interface ExportSection {
  id: string;
  heading: string;
  blocks: readonly ExportBlock[];
}

export interface CanonicalExportDocument {
  schema_version: "1.0.0" | "1.1.0";
  document_id: string;
  revision_id: string;
  title: string;
  generated_at: string;
  freshness: ExportFreshness;
  caveats: readonly string[];
  evidence_refs: readonly EvidenceRef[];
  sections: readonly ExportSection[];
  status?: "complete" | "partial";
  partial_reasons?: readonly string[];
}

export type ExportFormat =
  | "markdown"
  | "json"
  | "csv"
  | "tsv"
  | "html"
  | "xlsx"
  | "pdf"
  | "png";

export interface ExportArtifact {
  artifact_id: string;
  format: ExportFormat;
  media_type: string;
  file_extension: string;
  document_id: string;
  revision_id: string;
  freshness: ExportFreshness;
  caveats: readonly string[];
  evidence_refs: readonly EvidenceRef[];
  status?: "complete" | "partial";
  partial_reasons?: readonly string[];
  content: string | Uint8Array;
}

export interface AuthorizationDecision {
  allowed: boolean;
  reason?: string;
}

export type ExportAuthorizationHook<Context = unknown> = (input: {
  document: CanonicalExportDocument;
  context: Context;
}) =>
  | boolean
  | AuthorizationDecision
  | Promise<boolean | AuthorizationDecision>;

export type ExportRedactionHook<Context = unknown> = (
  document: CanonicalExportDocument,
  options: { context: Context },
) => CanonicalExportDocument | void | Promise<CanonicalExportDocument | void>;

export interface BinaryAdapterResult {
  content: Uint8Array;
  mediaType?: string;
  fileExtension?: string;
}

export type BinaryExportAdapter = (
  document: CanonicalExportDocument,
  options: { sourceArtifactId?: string },
) =>
  | Uint8Array
  | BinaryAdapterResult
  | Promise<Uint8Array | BinaryAdapterResult>;

export interface ExportOptions<Context = unknown> {
  format: ExportFormat;
  sourceArtifactId?: string;
  authorizationContext?: Context;
  authorize: ExportAuthorizationHook<Context>;
  redact: ExportRedactionHook<Context>;
  binaryAdapters?: LoadedExportAdapters;
}

export function createCanonicalDocument(
  input: CanonicalExportDocument,
): Readonly<CanonicalExportDocument>;

export function prepareAuthorizedDocument<Context = unknown>(
  input: CanonicalExportDocument,
  options: {
    authorize: ExportAuthorizationHook<Context>;
    redact: ExportRedactionHook<Context>;
    authorizationContext?: Context;
  },
): Promise<Readonly<CanonicalExportDocument>>;

export function adaptMarkdown(input: CanonicalExportDocument): string;
export function adaptJson(input: CanonicalExportDocument): string;
export function adaptDelimited(
  input: CanonicalExportDocument,
  artifactId: string,
  delimiter?: "," | "\t",
): string;
export function adaptHtml(input: CanonicalExportDocument): string;
export function adaptXlsx(
  input: CanonicalExportDocument,
  artifactId: string,
): Uint8Array;
export function adaptPdf(input: CanonicalExportDocument): Uint8Array;
export function adaptPng(
  input: CanonicalExportDocument,
  artifactId?: string,
): Uint8Array;
export function validateExportBinary(
  format: "pdf" | "png" | "xlsx",
  content: Uint8Array,
): true;

export function createExportArtifact(input: {
  document: CanonicalExportDocument;
  format: Exclude<ExportFormat, "pdf" | "png" | "xlsx">;
  content: string;
  sourceArtifactId?: string;
  mediaType: string;
  fileExtension: string;
}): Readonly<ExportArtifact>;

export function exportDocument<Context = unknown>(
  input: CanonicalExportDocument,
  options: ExportOptions<Context>,
): Promise<Readonly<ExportArtifact>>;

export interface PptxOutlineSlide {
  slide_id: string;
  title: string;
  section_id: string | null;
  evidence_ids: readonly string[];
}

export interface PptxOutlineDraft {
  schema_version: "1.0.0";
  workflow: "pptx_outline";
  outline_id: string;
  source_document_id: string;
  source_revision_id: string;
  state: "draft";
  slides: readonly PptxOutlineSlide[];
}

export interface ApprovedPptxOutline extends Omit<PptxOutlineDraft, "state"> {
  state: "approved";
  approved_by: string;
  approved_at: string;
}

export function createPptxOutlineDraft(
  input: CanonicalExportDocument,
): Readonly<PptxOutlineDraft>;

export function approvePptxOutline(
  draft: PptxOutlineDraft,
  approval: { approvedBy: string; approvedAt: string },
): Readonly<ApprovedPptxOutline>;

export function renderApprovedPptx(
  approved: ApprovedPptxOutline,
): Promise<never>;
