import {
  canonicalJson,
  sha256,
  validateContract,
} from "../../contracts/src/index.js";
import { deflateSync } from "node:zlib";

export class ExportInvariantError extends Error {
  constructor(message, code = "EXPORT_INVARIANT") {
    super(message);
    this.name = "ExportInvariantError";
    this.code = code;
  }
}

export class ExportAuthorizationError extends ExportInvariantError {
  constructor(reason = "export is not authorized") {
    super(reason, "EXPORT_NOT_AUTHORIZED");
    this.name = "ExportAuthorizationError";
  }
}

export class ExportRedactionError extends ExportInvariantError {
  constructor(reason = "a redaction policy hook is required") {
    super(reason, "EXPORT_REDACTION_REQUIRED");
    this.name = "ExportRedactionError";
  }
}

export class ExportAdapterUnavailableError extends ExportInvariantError {
  constructor(format) {
    super(`${String(format)} adapter is unavailable`, "ADAPTER_UNAVAILABLE");
    this.name = "ExportAdapterUnavailableError";
    this.format = String(format);
  }
}

export const EXPORT_ADAPTER_THREAT_CONTRACT = "threat:export-core-v1";
const EXPORT_ADAPTER_REF = /^export-adapter:[a-z][a-z0-9._/-]{1,255}$/;
const POLICY_REF = /^policy:[a-z0-9][a-z0-9._/-]{1,255}$/;
const COMPILED_EXPORT_REGISTRIES = new WeakSet();
const LOADED_EXPORT_ADAPTERS = new WeakSet();
const REGISTRATION_KEYS = new Set([
  "ref",
  "owner",
  "formats",
  "adapter",
  "threatContractRef",
  "egressPolicyRef",
  "redactionProfileRef",
]);

const fail = (message, code) => {
  throw new ExportInvariantError(message, code);
};

const MAX_CANONICAL_DOCUMENT_BYTES = 8 * 1024 * 1024;
const MAX_BINARY_EXPORT_BYTES = 64 * 1024 * 1024;
const MAX_ZIP_ENTRIES = 128;
const MAX_ZIP_ENTRY_BYTES = 16 * 1024 * 1024;
const MAX_ZIP_TOTAL_BYTES = 32 * 1024 * 1024;
const MAX_PNG_DIMENSION = 8_192;
const MAX_PNG_PIXELS = 8_000_000;
const MAX_PNG_CHUNKS = 256;

const nonEmpty = (value, name) => {
  if (
    typeof value !== "string" ||
    value.trim() !== value ||
    value.length === 0
  ) {
    fail(`${name} must be a non-empty, trimmed string`);
  }
  return value;
};

const unsafePath = (value) =>
  value
    .split("/")
    .some((segment) => segment === "" || segment === "." || segment === "..");

/**
 * Construct an immutable registry from adapters compiled into the application.
 * A registry has no mutation API and accepts no module/path/specifier fields.
 */
export function createCompiledExportAdapterRegistry(registrations) {
  if (!Array.isArray(registrations)) {
    fail("compiled export adapter registrations must be an array");
  }
  const byRef = new Map();
  for (const registration of registrations) {
    if (!registration || typeof registration !== "object") {
      fail("compiled export adapter registration must be an object");
    }
    const unexpected = Object.keys(registration).filter(
      (key) => !REGISTRATION_KEYS.has(key),
    );
    if (unexpected.length > 0) {
      fail(
        `compiled export adapter registration has unsupported fields: ${unexpected.join(", ")}`,
        "UNSAFE_ADAPTER_REGISTRATION",
      );
    }
    if (
      !EXPORT_ADAPTER_REF.test(registration.ref ?? "") ||
      !/^[a-z][a-z0-9_.-]{1,63}$/.test(registration.owner ?? "") ||
      unsafePath(registration.ref) ||
      !registration.ref.startsWith(`export-adapter:${registration.owner}/`) ||
      registration.threatContractRef !== EXPORT_ADAPTER_THREAT_CONTRACT ||
      !POLICY_REF.test(registration.egressPolicyRef ?? "") ||
      unsafePath(registration.egressPolicyRef) ||
      !POLICY_REF.test(registration.redactionProfileRef ?? "") ||
      unsafePath(registration.redactionProfileRef) ||
      typeof registration.adapter !== "function" ||
      !Array.isArray(registration.formats) ||
      registration.formats.length === 0 ||
      registration.formats.some(
        (format) => format !== "pdf" && format !== "png",
      )
    ) {
      fail(
        `compiled export adapter ${String(registration.ref)} is invalid`,
        "UNSAFE_ADAPTER_REGISTRATION",
      );
    }
    if (new Set(registration.formats).size !== registration.formats.length) {
      fail(`compiled export adapter ${registration.ref} repeats a format`);
    }
    if (byRef.has(registration.ref)) {
      fail(`duplicate compiled export adapter ref: ${registration.ref}`);
    }
    byRef.set(
      registration.ref,
      Object.freeze({
        ...registration,
        formats: Object.freeze([...registration.formats]),
      }),
    );
  }
  const registry = Object.freeze({
    refs: Object.freeze(Array.from(byRef.keys()).sort()),
    resolve(ref) {
      return byRef.get(ref) ?? null;
    },
  });
  COMPILED_EXPORT_REGISTRIES.add(registry);
  return registry;
}

/**
 * Select only compiled adapters referenced by the signed ProductManifest.
 * Policy refs must match export-core's threat, egress, and redaction contracts.
 */
export function loadProductExportAdapters(productExports, registry) {
  if (!productExports || typeof productExports !== "object") {
    fail("ProductManifest exports are required");
  }
  if (!registry || !COMPILED_EXPORT_REGISTRIES.has(registry)) {
    fail(
      "export adapters require a registry created from compiled registrations",
      "UNSAFE_ADAPTER_REGISTRATION",
    );
  }
  const refs = productExports.adapter_refs ?? [];
  if (
    !Array.isArray(refs) ||
    refs.some((ref) => !EXPORT_ADAPTER_REF.test(ref) || unsafePath(ref))
  ) {
    fail(
      "ProductManifest export adapter refs must be opaque allowlisted refs",
      "UNSAFE_ADAPTER_REGISTRATION",
    );
  }
  if (!productExports.external_enabled && refs.length > 0) {
    fail("disabled external exports may not activate adapters");
  }
  const selected = {};
  for (const ref of refs) {
    const registration = registry.resolve(ref);
    if (!registration) throw new ExportAdapterUnavailableError(ref);
    if (
      registration.threatContractRef !== EXPORT_ADAPTER_THREAT_CONTRACT ||
      registration.egressPolicyRef !== productExports.egress_policy_ref ||
      registration.redactionProfileRef !== productExports.redaction_profile_ref
    ) {
      fail(
        `export adapter ${ref} does not match ProductManifest policy contracts`,
        "ADAPTER_POLICY_MISMATCH",
      );
    }
    for (const format of registration.formats) {
      if (!productExports.formats?.includes(format)) {
        fail(`export adapter ${ref} enables undeclared format ${format}`);
      }
      if (selected[format]) {
        fail(`more than one ProductManifest adapter owns ${format}`);
      }
      selected[format] = registration.adapter;
    }
  }
  const loaded = Object.freeze(selected);
  LOADED_EXPORT_ADAPTERS.add(loaded);
  return loaded;
}

const timestamp = (value, name) => {
  nonEmpty(value, name);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    fail(`${name} must be a canonical ISO-8601 timestamp`);
  }
  return value;
};

const clone = (value) => structuredClone(value);

const hiddenField = (key) => {
  const normalized = key.toLowerCase().replaceAll(/[\s_-]/g, "");
  return [
    "debug",
    "debuglog",
    "diagnostic",
    "diagnostics",
    "executiontrace",
    "generatedsql",
    "hiddendiagnostic",
    "hiddendiagnostics",
    "providererror",
    "providerpayload",
    "querytext",
    "rawprovidererror",
    "rawsql",
    "rawtrace",
    "rawtraces",
    "sql",
    "sqltext",
    "stacktrace",
    "statement",
    "statementtext",
    "trace",
  ].includes(normalized);
};

const hiddenContentMarker = (value) =>
  /(?:^|[^a-z])(?:hidden[\s_-]*diagnostics?|raw[\s_-]*(?:sql|traces?)|provider[\s_-]*(?:error|payload)|stack[\s_-]*trace)(?:[^a-z]|$)/i.test(
    value,
  ) ||
  /\bselect\b[\s\S]{0,512}\bfrom\b/i.test(value) ||
  /\b(?:insert\s+into|delete\s+from|merge\s+into|update\s+[^\s]+\s+set|(?:create|alter|drop)\s+(?:table|view|schema|catalog))\b/i.test(
    value,
  );

const sanitizeContent = (value, path = "content", seen = new WeakSet()) => {
  if (Array.isArray(value)) {
    if (seen.has(value)) {
      fail(`${path} must not contain circular values`);
    }
    seen.add(value);
    const sanitized = value.map((child, index) =>
      sanitizeContent(child, `${path}[${index}]`, seen),
    );
    seen.delete(value);
    return sanitized;
  }
  if (value && typeof value === "object") {
    if (Object.getPrototypeOf(value) !== Object.prototype) {
      fail(`${path} must contain only plain JSON objects`);
    }
    if (seen.has(value)) {
      fail(`${path} must not contain circular values`);
    }
    seen.add(value);
    const sanitized = Object.fromEntries(
      Object.entries(value)
        .filter(([key]) => !hiddenField(key))
        .map(([key, child]) => [
          key,
          sanitizeContent(child, `${path}.${key}`, seen),
        ]),
    );
    seen.delete(value);
    return sanitized;
  }
  if (typeof value === "string") {
    if (hiddenContentMarker(value)) {
      fail(
        `${path} contains hidden diagnostic, raw trace, or SQL content`,
        "HIDDEN_EXPORT_CONTENT",
      );
    }
    return value;
  }
  if (
    value === null ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  ) {
    return value;
  }
  fail(`${path} must contain only JSON-compatible values`);
};

const contentString = (value, name) =>
  nonEmpty(sanitizeContent(value, name), name);

const contentStringList = (value, name) => {
  if (!Array.isArray(value)) {
    fail(`${name} must be an array`);
  }
  return value.map((item, index) => contentString(item, `${name}[${index}]`));
};

const deepFreeze = (value) => {
  if (ArrayBuffer.isView(value)) {
    return value;
  }
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) {
      deepFreeze(child);
    }
  }
  return value;
};

const stringList = (value, name) => {
  if (!Array.isArray(value)) {
    fail(`${name} must be an array`);
  }
  return value.map((item, index) => nonEmpty(item, `${name}[${index}]`));
};

const QUANTITATIVE_CONTENT =
  /(?:\p{Sc}\s*\d|\d[\d,.]*\s*(?:%|percent|million|billion|thousand|players?|users?|rows?|units?)|\d[\d,.]*\b(?!\s*(?:days?|hours?)\b))/iu;

const containsQuantitativeValue = (value, seen = new WeakSet()) => {
  if (typeof value === "number") return Number.isFinite(value);
  if (typeof value === "string") return QUANTITATIVE_CONTENT.test(value);
  if (!value || typeof value !== "object") return false;
  if (seen.has(value)) return false;
  seen.add(value);
  const found = Array.isArray(value)
    ? value.some((child) => containsQuantitativeValue(child, seen))
    : Object.values(value).some((child) =>
        containsQuantitativeValue(child, seen),
      );
  seen.delete(value);
  return found;
};

const requireEvidence = (evidenceIds, path, reason) => {
  if (evidenceIds.length === 0) {
    fail(
      `${path} ${reason} but has no evidence`,
      "QUANTITATIVE_EVIDENCE_REQUIRED",
    );
  }
};

const canonicalBlock = (block, sectionIndex, blockIndex, evidenceIds) => {
  const path = `sections[${sectionIndex}].blocks[${blockIndex}]`;
  if (!block || typeof block !== "object") {
    fail(`${path} must be an object`);
  }
  const evidence_ids =
    block.evidence_ids === undefined
      ? []
      : stringList(block.evidence_ids, `${path}.evidence_ids`);
  for (const evidenceId of evidence_ids) {
    if (!evidenceIds.has(evidenceId)) {
      fail(
        `${path} refers to unknown evidence ${evidenceId}`,
        "UNKNOWN_EVIDENCE",
      );
    }
  }

  if (block.type === "paragraph") {
    const text = contentString(block.text, `${path}.text`);
    if (containsQuantitativeValue(text)) {
      requireEvidence(evidence_ids, path, "contains quantitative content");
    }
    return {
      type: "paragraph",
      text,
      evidence_ids,
    };
  }
  if (block.type === "list") {
    if (!Array.isArray(block.items)) {
      fail(`${path}.items must be an array`);
    }
    const items = block.items.map((item, index) => {
      const itemPath = `${path}.items[${index}]`;
      const sanitized = sanitizeContent(item, itemPath);
      return typeof sanitized === "string"
        ? nonEmpty(sanitized, itemPath)
        : sanitized;
    });
    if (containsQuantitativeValue(items)) {
      requireEvidence(evidence_ids, path, "contains quantitative content");
    }
    return {
      type: "list",
      items,
      evidence_ids,
    };
  }
  if (block.type === "figure") {
    const figure = {
      type: "figure",
      artifact_id: contentString(block.artifact_id, `${path}.artifact_id`),
      label: contentString(block.label, `${path}.label`),
      value: sanitizeContent(block.value, `${path}.value`),
      display: contentString(block.display, `${path}.display`),
      comparison:
        block.comparison === undefined
          ? ""
          : sanitizeContent(block.comparison, `${path}.comparison`),
      evidence_ids,
    };
    requireEvidence(evidence_ids, path, "is a quantitative figure");
    return figure;
  }
  if (block.type === "chart") {
    if (!Array.isArray(block.series) || block.series.length === 0) {
      fail(`${path}.series must be a non-empty array`);
    }
    const series = sanitizeContent(block.series, `${path}.series`);
    requireEvidence(evidence_ids, path, "contains chart series");
    return {
      type: "chart",
      artifact_id: contentString(block.artifact_id, `${path}.artifact_id`),
      title: contentString(block.title, `${path}.title`),
      kind: contentString(block.kind, `${path}.kind`),
      series,
      layout:
        block.layout === undefined
          ? {}
          : sanitizeContent(block.layout, `${path}.layout`),
      evidence_ids,
    };
  }
  if (block.type === "table") {
    nonEmpty(block.artifact_id, `${path}.artifact_id`);
    if (!Array.isArray(block.columns) || block.columns.length === 0) {
      fail(`${path}.columns must be a non-empty array`);
    }
    const keys = new Set();
    const columns = block.columns
      .map((column, columnIndex) => {
        if (!column || typeof column !== "object") {
          fail(`${path}.columns[${columnIndex}] must be an object`);
        }
        const rawKey = nonEmpty(
          column.key,
          `${path}.columns[${columnIndex}].key`,
        );
        const rawLabel = nonEmpty(
          column.label,
          `${path}.columns[${columnIndex}].label`,
        );
        if (hiddenField(rawKey) || hiddenField(rawLabel)) {
          return null;
        }
        const key = contentString(
          rawKey,
          `${path}.columns[${columnIndex}].key`,
        );
        const label = contentString(
          rawLabel,
          `${path}.columns[${columnIndex}].label`,
        );
        if (keys.has(key)) {
          fail(`${path} has duplicate column key ${key}`);
        }
        keys.add(key);
        return { key, label };
      })
      .filter(Boolean);
    if (columns.length === 0) {
      fail(`${path}.columns must include at least one exportable column`);
    }
    if (!Array.isArray(block.rows)) {
      fail(`${path}.rows must be an array`);
    }
    const rows = block.rows.map((row, rowIndex) => {
      if (!row || typeof row !== "object" || Array.isArray(row)) {
        fail(`${path}.rows[${rowIndex}] must be an object`);
      }
      return Object.fromEntries(
        columns.map(({ key }) => [
          key,
          Object.hasOwn(row, key)
            ? sanitizeContent(row[key], `${path}.rows[${rowIndex}].${key}`)
            : null,
        ]),
      );
    });
    if (containsQuantitativeValue(rows)) {
      requireEvidence(evidence_ids, path, "contains quantitative table cells");
    }
    return {
      type: "table",
      artifact_id: block.artifact_id,
      columns,
      rows,
      evidence_ids,
    };
  }
  fail(`${path}.type is unsupported`);
};

export function createCanonicalDocument(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    fail("document must be an object");
  }
  if (input.schema_version !== "1.0.0" && input.schema_version !== "1.1.0") {
    fail("schema_version must be 1.0.0 or 1.1.0");
  }
  if (!input.freshness || typeof input.freshness !== "object") {
    fail("freshness must be an object");
  }
  timestamp(input.generated_at, "generated_at");
  timestamp(input.freshness.as_of, "freshness.as_of");
  if (Date.parse(input.freshness.as_of) > Date.parse(input.generated_at)) {
    fail(
      "freshness.as_of cannot be later than generated_at",
      "INVALID_FRESHNESS",
    );
  }
  const caveats = contentStringList(input.caveats, "caveats");

  if (!Array.isArray(input.evidence_refs)) {
    fail("evidence_refs must be an array");
  }
  const evidenceIds = new Set();
  const evidence_refs = input.evidence_refs.map((evidence, index) => {
    const sanitizedEvidence = sanitizeContent(
      evidence,
      `evidence_refs[${index}]`,
    );
    const validation = validateContract("evidence-ref", sanitizedEvidence);
    if (!validation.valid) {
      fail(
        `evidence_refs[${index}] is invalid: ${validation.errors.join("; ")}`,
        "INVALID_EVIDENCE",
      );
    }
    if (evidenceIds.has(evidence.evidence_id)) {
      fail(`evidence id ${evidence.evidence_id} is duplicated`);
    }
    if (Date.parse(sanitizedEvidence.retrieved_at) > Date.parse(input.generated_at)) {
      fail(
        `evidence_refs[${index}].retrieved_at cannot be later than generated_at`,
        "INVALID_FRESHNESS",
      );
    }
    evidenceIds.add(evidence.evidence_id);
    return sanitizedEvidence;
  });

  if (!Array.isArray(input.sections)) {
    fail("sections must be an array");
  }
  const sectionIds = new Set();
  const artifactIds = new Set();
  const sections = input.sections.map((section, sectionIndex) => {
    if (!section || typeof section !== "object") {
      fail(`sections[${sectionIndex}] must be an object`);
    }
    const id = nonEmpty(section.id, `sections[${sectionIndex}].id`);
    if (sectionIds.has(id)) {
      fail(`section id ${id} is duplicated`);
    }
    sectionIds.add(id);
    if (!Array.isArray(section.blocks)) {
      fail(`sections[${sectionIndex}].blocks must be an array`);
    }
    const blocks = section.blocks.map((block, blockIndex) => {
      const canonical = canonicalBlock(
        block,
        sectionIndex,
        blockIndex,
        evidenceIds,
      );
      if (
        canonical.type === "table" ||
        canonical.type === "figure" ||
        canonical.type === "chart"
      ) {
        if (artifactIds.has(canonical.artifact_id)) {
          fail(`content artifact id ${canonical.artifact_id} is duplicated`);
        }
        artifactIds.add(canonical.artifact_id);
      }
      return canonical;
    });
    return {
      id,
      heading: contentString(
        section.heading,
        `sections[${sectionIndex}].heading`,
      ),
      blocks,
    };
  });

  const status =
    input.schema_version === "1.1.0"
      ? input.status === "partial"
        ? "partial"
        : input.status === undefined || input.status === "complete"
          ? "complete"
          : fail("status must be complete or partial")
      : undefined;
  const partial_reasons =
    input.schema_version === "1.1.0"
      ? contentStringList(input.partial_reasons ?? [], "partial_reasons")
      : undefined;
  if (status === "partial" && partial_reasons.length === 0) {
    fail("partial documents must state at least one partial reason");
  }
  if (status === "complete" && partial_reasons.length > 0) {
    fail("complete documents cannot carry partial reasons");
  }

  const canonical = {
    schema_version: input.schema_version,
    document_id: nonEmpty(input.document_id, "document_id"),
    revision_id: nonEmpty(input.revision_id, "revision_id"),
    title: contentString(input.title, "title"),
    generated_at: input.generated_at,
    freshness: {
      as_of: input.freshness.as_of,
      ...(input.freshness.status === undefined
        ? {}
        : {
            status: contentString(input.freshness.status, "freshness.status"),
          }),
    },
    caveats,
    evidence_refs,
    sections,
    ...(status ? { status, partial_reasons } : {}),
  };
  if (Buffer.byteLength(canonicalJson(canonical), "utf8") > MAX_CANONICAL_DOCUMENT_BYTES) {
    fail("canonical document exceeds the export byte limit", "EXPORT_TOO_LARGE");
  }
  return deepFreeze(canonical);
}

const protectedQuantitativeContent = (document) =>
  document.sections.flatMap((section) =>
    section.blocks.flatMap((block, index) => {
      const identity = {
        section_id: section.id,
        block_index: index,
        type: block.type,
      };
      if (block.type === "figure") {
        return [
          {
            ...identity,
            value: block.value,
            display: block.display,
            comparison: block.comparison,
          },
        ];
      }
      if (block.type === "chart") {
        return [{ ...identity, series: block.series }];
      }
      if (block.type === "table") {
        return [
          {
            ...identity,
            quantitative_cells: block.rows.map((row) =>
              block.columns.map(({ key }) =>
                containsQuantitativeValue(row[key]) ? row[key] : null,
              ),
            ),
          },
        ];
      }
      const content = block.type === "paragraph" ? block.text : block.items;
      return containsQuantitativeValue(content)
        ? [{ ...identity, content }]
        : [];
    }),
  );

const protectedMetadata = (document) =>
  canonicalJson({
    document_id: document.document_id,
    revision_id: document.revision_id,
    freshness: document.freshness,
    caveat_count: document.caveats.length,
    ...(document.status
      ? { status: document.status, partial_reasons: document.partial_reasons }
      : {}),
    evidence_refs: document.evidence_refs.map((evidence) => ({
      evidence_id: evidence.evidence_id,
      source_kind: evidence.source_kind,
      source_ref: evidence.source_ref,
      retrieved_at: evidence.retrieved_at,
      source_name: evidence.attributes?.source_name,
      execution_stage_id: evidence.attributes?.execution_stage_id,
      statement_hash: evidence.attributes?.statement_hash,
      result_hash: evidence.attributes?.result_hash,
    })),
    evidence_bindings: document.sections.map((section) => ({
      section_id: section.id,
      blocks: section.blocks.map((block) => ({
        type: block.type,
        ...(block.artifact_id ? { artifact_id: block.artifact_id } : {}),
        evidence_ids: block.evidence_ids,
      })),
    })),
    quantitative_content: protectedQuantitativeContent(document),
  });

export async function prepareAuthorizedDocument(
  input,
  { authorize, redact, authorizationContext } = {},
) {
  const canonical = createCanonicalDocument(input);
  if (typeof authorize !== "function") {
    throw new ExportAuthorizationError("an authorization hook is required");
  }
  const authorization = await authorize({
    document: canonical,
    context: authorizationContext,
  });
  const allowed =
    authorization === true ||
    (authorization &&
      typeof authorization === "object" &&
      authorization.allowed === true);
  if (!allowed) {
    const reason =
      authorization && typeof authorization === "object" && authorization.reason
        ? String(authorization.reason)
        : "export is not authorized";
    throw new ExportAuthorizationError(reason);
  }

  if (redact === undefined) {
    throw new ExportRedactionError();
  }
  if (typeof redact !== "function") {
    fail("redact must be a function");
  }
  const draft = clone(canonical);
  const result = await redact(draft, { context: authorizationContext });
  const redacted = createCanonicalDocument(
    result === undefined ? draft : result,
  );
  if (protectedMetadata(redacted) !== protectedMetadata(canonical)) {
    fail(
      "redaction cannot change document identity, freshness, evidence bindings, or quantitative content",
      "REDACTION_METADATA_CHANGED",
    );
  }
  return redacted;
}

const evidenceSuffix = (ids) => (ids.length ? ` [${ids.join(", ")}]` : "");

const cellText = (value) => {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean")
    return String(value);
  return canonicalJson(value).replace(/\n+$/, "");
};

const markdownCell = (value) =>
  cellText(value)
    .replaceAll("\\", "\\\\")
    .replaceAll("|", "\\|")
    .replaceAll(/\r?\n/g, " ");

export function adaptMarkdown(input) {
  const document = createCanonicalDocument(input);
  const lines = [
    `# ${document.title}`,
    "",
    `- Document: \`${document.document_id}\``,
    `- Revision: \`${document.revision_id}\``,
    `- Generated: ${document.generated_at}`,
    `- Freshness: ${document.freshness.as_of}${
      document.freshness.status ? ` (${document.freshness.status})` : ""
    }`,
    ...(document.status
      ? [
          `- Completeness: ${document.status}`,
          ...(document.partial_reasons.length
            ? [`- Partial reasons: ${document.partial_reasons.join("; ")}`]
            : []),
        ]
      : []),
  ];

  if (document.caveats.length) {
    lines.push(
      "",
      "## Caveats",
      "",
      ...document.caveats.map((item) => `- ${item}`),
    );
  }
  for (const section of document.sections) {
    lines.push("", `## ${section.heading}`, "");
    for (const block of section.blocks) {
      if (block.type === "paragraph") {
        lines.push(`${block.text}${evidenceSuffix(block.evidence_ids)}`, "");
      } else if (block.type === "list") {
        lines.push(
          ...block.items.map(
            (item) =>
              `- ${cellText(item)}${evidenceSuffix(block.evidence_ids)}`,
          ),
          "",
        );
      } else if (block.type === "table") {
        lines.push(
          `Artifact: \`${block.artifact_id}\`${evidenceSuffix(block.evidence_ids)}`,
          "",
          `| ${block.columns.map(({ label }) => markdownCell(label)).join(" | ")} |`,
          `| ${block.columns.map(() => "---").join(" | ")} |`,
          ...block.rows.map(
            (row) =>
              `| ${block.columns.map(({ key }) => markdownCell(row[key])).join(" | ")} |`,
          ),
          "",
        );
      } else if (block.type === "figure") {
        lines.push(
          `- **${block.label}:** ${cellText(block.display || block.value)}${
            block.comparison ? ` — ${cellText(block.comparison)}` : ""
          }${evidenceSuffix(block.evidence_ids)}`,
          "",
        );
      } else {
        lines.push(
          `Chart: **${block.title}** (${block.kind})${evidenceSuffix(block.evidence_ids)}`,
          "",
          "```json",
          canonicalJson({
            series: block.series,
            layout: block.layout,
          }).trimEnd(),
          "```",
          "",
        );
      }
    }
  }
  if (document.evidence_refs.length) {
    lines.push("", "## Evidence", "");
    for (const evidence of document.evidence_refs) {
      lines.push(
        `- \`${evidence.evidence_id}\`: ${evidence.source_ref} (retrieved ${evidence.retrieved_at})`,
      );
    }
  }
  return `${lines
    .join("\n")
    .replaceAll(/\n{3,}/g, "\n\n")
    .trimEnd()}\n`;
}

export function adaptJson(input) {
  return `${canonicalJson(createCanonicalDocument(input)).replace(/\n+$/, "")}\n`;
}

const spreadsheetText = (value) => {
  const text = cellText(value);
  return typeof value === "string" && /^[\u0000-\u0020\u007f-\u009f\uFEFF]*[=+\-@]/u.test(text)
    ? `'${text}`
    : text;
};

const delimitedCell = (value, delimiter) => {
  const text = spreadsheetText(value);
  return /["\r\n]/.test(text) || text.includes(delimiter)
    ? `"${text.replaceAll('"', '""')}"`
    : text;
};

const findTable = (document, artifactId) => {
  nonEmpty(artifactId, "artifactId");
  for (const section of document.sections) {
    const table = section.blocks.find(
      (block) => block.type === "table" && block.artifact_id === artifactId,
    );
    if (table) return table;
  }
  fail(`table artifact ${artifactId} was not found`, "ARTIFACT_NOT_FOUND");
};

export function adaptDelimited(input, artifactId, delimiter = ",") {
  if (delimiter !== "," && delimiter !== "\t") {
    fail("delimiter must be a comma or tab");
  }
  const document = createCanonicalDocument(input);
  const table = findTable(document, artifactId);
  const lines = [
    table.columns
      .map(({ label }) => delimitedCell(label, delimiter))
      .join(delimiter),
    ...table.rows.map((row) =>
      table.columns
        .map(({ key }) => delimitedCell(row[key], delimiter))
        .join(delimiter),
    ),
  ];
  return `${lines.join("\n")}\n`;
}

const utf8 = (value) => new TextEncoder().encode(value);
const concatBytes = (...parts) => {
  const length = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.byteLength;
  }
  return output;
};
const little16 = (value) =>
  new Uint8Array([value & 0xff, (value >>> 8) & 0xff]);
const little32 = (value) =>
  new Uint8Array([
    value & 0xff,
    (value >>> 8) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 24) & 0xff,
  ]);
const big32 = (value) =>
  new Uint8Array([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ]);

const CRC_TABLE = Array.from({ length: 256 }, (_, byte) => {
  let value = byte;
  for (let bit = 0; bit < 8; bit += 1) {
    value = (value & 1) !== 0 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  }
  return value >>> 0;
});
const crc32 = (bytes) => {
  let value = 0xffffffff;
  for (const byte of bytes) {
    value = CRC_TABLE[(value ^ byte) & 0xff] ^ (value >>> 8);
  }
  return (value ^ 0xffffffff) >>> 0;
};

const xml = (value) =>
  String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");

const htmlText = (value) => xml(cellText(value));

export function adaptHtml(input) {
  const document = createCanonicalDocument(input);
  const blocks = document.sections
    .map((section) => {
      const body = section.blocks
        .map((block) => {
          const evidence = block.evidence_ids.length
            ? `<small data-evidence="${xml(block.evidence_ids.join(" "))}">Evidence: ${xml(block.evidence_ids.join(", "))}</small>`
            : "";
          if (block.type === "paragraph") {
            return `<p>${htmlText(block.text)}</p>${evidence}`;
          }
          if (block.type === "list") {
            return `<ul>${block.items.map((item) => `<li>${htmlText(item)}</li>`).join("")}</ul>${evidence}`;
          }
          if (block.type === "figure") {
            return `<figure data-artifact-id="${xml(block.artifact_id)}"><strong>${htmlText(block.label)}</strong>: ${htmlText(block.display || block.value)}${block.comparison ? ` <span>— ${htmlText(block.comparison)}</span>` : ""}${evidence}</figure>`;
          }
          if (block.type === "table") {
            return `<figure data-artifact-id="${xml(block.artifact_id)}"><table><thead><tr>${block.columns.map(({ label }) => `<th>${htmlText(label)}</th>`).join("")}</tr></thead><tbody>${block.rows.map((row) => `<tr>${block.columns.map(({ key }) => `<td>${htmlText(row[key])}</td>`).join("")}</tr>`).join("")}</tbody></table>${evidence}</figure>`;
          }
          return `<figure data-artifact-id="${xml(block.artifact_id)}"><strong>${htmlText(block.title)}</strong><pre>${htmlText(canonicalJson({ kind: block.kind, series: block.series, layout: block.layout }).trimEnd())}</pre>${evidence}</figure>`;
        })
        .join("");
      return `<section id="${xml(section.id)}"><h2>${htmlText(section.heading)}</h2>${body}</section>`;
    })
    .join("");
  const caveats = document.caveats.length
    ? `<section><h2>Caveats</h2><ul>${document.caveats.map((item) => `<li>${htmlText(item)}</li>`).join("")}</ul></section>`
    : "";
  const evidence = document.evidence_refs.length
    ? `<section><h2>Evidence</h2><ul>${document.evidence_refs.map((item) => `<li><code>${xml(item.evidence_id)}</code>: ${htmlText(item.source_ref)} (retrieved ${htmlText(item.retrieved_at)})</li>`).join("")}</ul></section>`
    : "";
  return [
    "<!doctype html>",
    '<html lang="en"><head><meta charset="utf-8">',
    `<title>${htmlText(document.title)}</title>`,
    "<style>body{font:14px system-ui,sans-serif;color:#172033;max-width:1100px;margin:32px auto;padding:0 24px}table{border-collapse:collapse;width:100%;margin:12px 0}th,td{border:1px solid #cbd5e1;padding:7px;text-align:left;vertical-align:top}th{background:#f1f5f9}small{display:block;color:#475569;margin:4px 0 12px}code,pre{white-space:pre-wrap;overflow-wrap:anywhere}.metadata{background:#f8fafc;padding:12px}</style>",
    "</head><body>",
    `<header><h1>${htmlText(document.title)}</h1><dl class="metadata"><dt>Document</dt><dd>${htmlText(document.document_id)}</dd><dt>Revision</dt><dd>${htmlText(document.revision_id)}</dd><dt>Generated</dt><dd>${htmlText(document.generated_at)}</dd><dt>Freshness</dt><dd>${htmlText(document.freshness.as_of)}${document.freshness.status ? ` (${htmlText(document.freshness.status)})` : ""}</dd>${document.status ? `<dt>Completeness</dt><dd>${htmlText(document.status)}</dd>` : ""}</dl></header>`,
    caveats,
    blocks,
    evidence,
    "</body></html>\n",
  ].join("");
}

function zipStore(entries) {
  if (!Array.isArray(entries) || entries.length === 0 || entries.length > MAX_ZIP_ENTRIES) {
    fail("ZIP entry count exceeds the export limit", "EXPORT_TOO_LARGE");
  }
  const locals = [];
  const central = [];
  let offset = 0;
  let total = 0;
  for (const [name, raw] of entries) {
    if (
      typeof name !== "string" ||
      name.length === 0 ||
      name.includes("\\") ||
      name.startsWith("/") ||
      name.split("/").some((part) => part === "." || part === "..")
    ) {
      fail("ZIP entry name is unsafe", "INVALID_BINARY");
    }
    const nameBytes = utf8(name);
    const content = typeof raw === "string" ? utf8(raw) : raw;
    if (!(content instanceof Uint8Array)) {
      fail("ZIP entry content must be bytes or text", "INVALID_BINARY");
    }
    total += content.byteLength;
    if (
      nameBytes.byteLength > 0xffff ||
      content.byteLength > MAX_ZIP_ENTRY_BYTES ||
      total > MAX_ZIP_TOTAL_BYTES
    ) {
      fail("ZIP entry exceeds the export byte limit", "EXPORT_TOO_LARGE");
    }
    const checksum = crc32(content);
    const local = concatBytes(
      little32(0x04034b50),
      little16(20),
      little16(0x0800),
      little16(0),
      little16(0),
      little16(0x0021),
      little32(checksum),
      little32(content.byteLength),
      little32(content.byteLength),
      little16(nameBytes.byteLength),
      little16(0),
      nameBytes,
      content,
    );
    locals.push(local);
    central.push(
      concatBytes(
        little32(0x02014b50),
        little16(20),
        little16(20),
        little16(0x0800),
        little16(0),
        little16(0),
        little16(0x0021),
        little32(checksum),
        little32(content.byteLength),
        little32(content.byteLength),
        little16(nameBytes.byteLength),
        little16(0),
        little16(0),
        little16(0),
        little16(0),
        little32(0),
        little32(offset),
        nameBytes,
      ),
    );
    offset += local.byteLength;
  }
  const directory = concatBytes(...central);
  return concatBytes(
    ...locals,
    directory,
    little32(0x06054b50),
    little16(0),
    little16(0),
    little16(entries.length),
    little16(entries.length),
    little32(directory.byteLength),
    little32(offset),
    little16(0),
  );
}

const spreadsheetCell = (value, reference) => {
  if (typeof value === "number" && Number.isFinite(value)) {
    return `<c r="${reference}"><v>${value}</v></c>`;
  }
  if (typeof value === "boolean") {
    return `<c r="${reference}" t="b"><v>${value ? 1 : 0}</v></c>`;
  }
  const text = spreadsheetText(value);
  return `<c r="${reference}" t="inlineStr"><is><t xml:space="preserve">${xml(text)}</t></is></c>`;
};
const columnName = (index) => {
  let value = index + 1;
  let output = "";
  while (value > 0) {
    value -= 1;
    output = String.fromCharCode(65 + (value % 26)) + output;
    value = Math.floor(value / 26);
  }
  return output;
};
const sheetXml = (rows) =>
  `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>${rows
    .map(
      (row, rowIndex) =>
        `<row r="${rowIndex + 1}">${row
          .map((value, columnIndex) =>
            spreadsheetCell(value, `${columnName(columnIndex)}${rowIndex + 1}`),
          )
          .join("")}</row>`,
    )
    .join("")}</sheetData></worksheet>`;

export function adaptXlsx(input, artifactId) {
  const document = createCanonicalDocument(input);
  const table = findTable(document, artifactId);
  const metadataRows = [
    ["Field", "Value"],
    ["Document", document.document_id],
    ["Revision", document.revision_id],
    ["Generated", document.generated_at],
    ["Freshness", document.freshness.as_of],
    ["Freshness status", document.freshness.status ?? ""],
    ["Completeness", document.status ?? ""],
    ...(document.partial_reasons ?? []).map((reason) => [
      "Partial reason",
      reason,
    ]),
    ...document.caveats.map((caveat) => ["Caveat", caveat]),
    ...document.evidence_refs.map((item) => [
      `Evidence ${item.evidence_id}`,
      `${item.source_ref} (retrieved ${item.retrieved_at})`,
    ]),
  ];
  const dataRows = [
    table.columns.map(({ label }) => label),
    ...table.rows.map((row) => table.columns.map(({ key }) => row[key])),
  ];
  const contentTypes =
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>';
  const rootRels =
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>';
  const workbook =
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Data" sheetId="1" r:id="rId1"/><sheet name="Metadata" sheetId="2" r:id="rId2"/></sheets></workbook>';
  const workbookRels =
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/></Relationships>';
  return zipStore([
    ["[Content_Types].xml", contentTypes],
    ["_rels/.rels", rootRels],
    ["xl/workbook.xml", workbook],
    ["xl/_rels/workbook.xml.rels", workbookRels],
    ["xl/worksheets/sheet1.xml", sheetXml(dataRows)],
    ["xl/worksheets/sheet2.xml", sheetXml(metadataRows)],
  ]);
}

const PDF_PAGE_WIDTH = 612;
const PDF_PAGE_HEIGHT = 792;
const PDF_MARGIN = 42;
const PDF_LINE_HEIGHT = 14;
const PDF_LINES_PER_PAGE = Math.floor(
  (PDF_PAGE_HEIGHT - PDF_MARGIN * 2) / PDF_LINE_HEIGHT,
);
const wrapText = (value, width) => {
  const words = String(value).trim().split(/\s+/);
  const lines = [];
  let line = "";
  for (const original of words) {
    const pieces = [];
    for (let at = 0; at < original.length; at += width) {
      pieces.push(original.slice(at, at + width));
    }
    for (const word of pieces) {
      if (!line) line = word;
      else if (`${line} ${word}`.length <= width) line += ` ${word}`;
      else {
        lines.push(line);
        line = word;
      }
    }
  }
  if (line || lines.length === 0) lines.push(line);
  return lines;
};
const pdfText = (value) =>
  value
    .normalize("NFKD")
    .replace(/[^\x20-\x7e]/g, "?")
    .replaceAll("\\", "\\\\")
    .replaceAll("(", "\\(")
    .replaceAll(")", "\\)");

export function adaptPdf(input) {
  const markdown = adaptMarkdown(input);
  const lines = markdown.split("\n").flatMap((line) => {
    const trimmed = line.trim();
    if (/^```/.test(trimmed) || /^\|\s*:?-+:?/.test(trimmed)) return [];
    const heading = /^(#{1,6})\s+(.+)$/.exec(trimmed);
    const list = /^[-*+]\s+(.+)$/.exec(trimmed);
    const readable = (heading?.[2] ?? list?.[1] ?? trimmed)
      .replace(/\*\*([^*]+)\*\*/g, "$1")
      .replace(/`([^`]+)`/g, "$1")
      .replace(/^\|\s*|\s*\|$/g, "")
      .replace(/\s*\|\s*/g, " | ");
    return wrapText(list ? `- ${readable}` : readable, 88).map((text) => ({
      text,
      size: heading ? (heading[1].length === 1 ? 18 : 13) : 10,
      bold: Boolean(heading),
    }));
  });
  const pages = [];
  for (let at = 0; at < lines.length || at === 0; at += PDF_LINES_PER_PAGE) {
    pages.push(lines.slice(at, at + PDF_LINES_PER_PAGE));
  }
  const objects = [];
  const add = (body) => {
    objects.push(body);
    return objects.length;
  };
  const catalog = add("");
  const pagesObject = add("");
  const font = add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
  const bold = add(
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
  );
  const pageObjects = [];
  for (const page of pages) {
    const commands = ["BT", `${PDF_MARGIN} ${PDF_PAGE_HEIGHT - PDF_MARGIN} Td`];
    page.forEach((line, index) => {
      if (index) commands.push(`0 -${PDF_LINE_HEIGHT} Td`);
      commands.push(
        `/${line.bold ? "F2" : "F1"} ${line.size} Tf`,
        `(${pdfText(line.text)}) Tj`,
      );
    });
    commands.push("ET");
    const stream = commands.join("\n");
    const contentObject = add(
      `<< /Length ${utf8(stream).byteLength} >>\nstream\n${stream}\nendstream`,
    );
    pageObjects.push(
      add(
        `<< /Type /Page /Parent ${pagesObject} 0 R /MediaBox [0 0 ${PDF_PAGE_WIDTH} ${PDF_PAGE_HEIGHT}] /Resources << /Font << /F1 ${font} 0 R /F2 ${bold} 0 R >> >> /Contents ${contentObject} 0 R >>`,
      ),
    );
  }
  objects[catalog - 1] = `<< /Type /Catalog /Pages ${pagesObject} 0 R >>`;
  objects[pagesObject - 1] =
    `<< /Type /Pages /Kids [${pageObjects.map((id) => `${id} 0 R`).join(" ")}] /Count ${pageObjects.length} >>`;
  let output = "%PDF-1.4\n%\xE2\xE3\xCF\xD3\n";
  const offsets = [0];
  objects.forEach((body, index) => {
    offsets.push(utf8(output).byteLength);
    output += `${index + 1} 0 obj\n${body}\nendobj\n`;
  });
  const xref = utf8(output).byteLength;
  output += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  output += offsets
    .slice(1)
    .map((offset) => `${String(offset).padStart(10, "0")} 00000 n \n`)
    .join("");
  output += `trailer\n<< /Size ${objects.length + 1} /Root ${catalog} 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return utf8(output);
}

const FONT = {
  " ": ["00000", "00000", "00000", "00000", "00000", "00000", "00000"],
  "?": ["01110", "10001", "00001", "00010", "00100", "00000", "00100"],
  ".": ["00000", "00000", "00000", "00000", "00000", "00110", "00110"],
  ",": ["00000", "00000", "00000", "00000", "00110", "00110", "00100"],
  ":": ["00000", "00110", "00110", "00000", "00110", "00110", "00000"],
  "-": ["00000", "00000", "00000", "11111", "00000", "00000", "00000"],
  "/": ["00001", "00010", "00100", "01000", "10000", "00000", "00000"],
  _: ["00000", "00000", "00000", "00000", "00000", "00000", "11111"],
  "(": ["00010", "00100", "01000", "01000", "01000", "00100", "00010"],
  ")": ["01000", "00100", "00010", "00010", "00010", "00100", "01000"],
  "[": ["01110", "01000", "01000", "01000", "01000", "01000", "01110"],
  "]": ["01110", "00010", "00010", "00010", "00010", "00010", "01110"],
  "|": ["00100", "00100", "00100", "00100", "00100", "00100", "00100"],
  "#": ["01010", "11111", "01010", "01010", "11111", "01010", "00000"],
  "%": ["11001", "11010", "00100", "01000", "10110", "00110", "00000"],
  0: ["01110", "10001", "10011", "10101", "11001", "10001", "01110"],
  1: ["00100", "01100", "00100", "00100", "00100", "00100", "01110"],
  2: ["01110", "10001", "00001", "00010", "00100", "01000", "11111"],
  3: ["11110", "00001", "00001", "01110", "00001", "00001", "11110"],
  4: ["00010", "00110", "01010", "10010", "11111", "00010", "00010"],
  5: ["11111", "10000", "10000", "11110", "00001", "00001", "11110"],
  6: ["01110", "10000", "10000", "11110", "10001", "10001", "01110"],
  7: ["11111", "00001", "00010", "00100", "01000", "01000", "01000"],
  8: ["01110", "10001", "10001", "01110", "10001", "10001", "01110"],
  9: ["01110", "10001", "10001", "01111", "00001", "00001", "01110"],
  A: ["01110", "10001", "10001", "11111", "10001", "10001", "10001"],
  B: ["11110", "10001", "10001", "11110", "10001", "10001", "11110"],
  C: ["01111", "10000", "10000", "10000", "10000", "10000", "01111"],
  D: ["11110", "10001", "10001", "10001", "10001", "10001", "11110"],
  E: ["11111", "10000", "10000", "11110", "10000", "10000", "11111"],
  F: ["11111", "10000", "10000", "11110", "10000", "10000", "10000"],
  G: ["01111", "10000", "10000", "10111", "10001", "10001", "01111"],
  H: ["10001", "10001", "10001", "11111", "10001", "10001", "10001"],
  I: ["01110", "00100", "00100", "00100", "00100", "00100", "01110"],
  J: ["00001", "00001", "00001", "00001", "10001", "10001", "01110"],
  K: ["10001", "10010", "10100", "11000", "10100", "10010", "10001"],
  L: ["10000", "10000", "10000", "10000", "10000", "10000", "11111"],
  M: ["10001", "11011", "10101", "10101", "10001", "10001", "10001"],
  N: ["10001", "11001", "10101", "10011", "10001", "10001", "10001"],
  O: ["01110", "10001", "10001", "10001", "10001", "10001", "01110"],
  P: ["11110", "10001", "10001", "11110", "10000", "10000", "10000"],
  Q: ["01110", "10001", "10001", "10001", "10101", "10010", "01101"],
  R: ["11110", "10001", "10001", "11110", "10100", "10010", "10001"],
  S: ["01111", "10000", "10000", "01110", "00001", "00001", "11110"],
  T: ["11111", "00100", "00100", "00100", "00100", "00100", "00100"],
  U: ["10001", "10001", "10001", "10001", "10001", "10001", "01110"],
  V: ["10001", "10001", "10001", "10001", "10001", "01010", "00100"],
  W: ["10001", "10001", "10001", "10101", "10101", "10101", "01010"],
  X: ["10001", "10001", "01010", "00100", "01010", "10001", "10001"],
  Y: ["10001", "10001", "01010", "00100", "00100", "00100", "00100"],
  Z: ["11111", "00001", "00010", "00100", "01000", "10000", "11111"],
};

const pngChunk = (name, data) => {
  const kind = utf8(name);
  return concatBytes(
    little32(data.byteLength).reverse(),
    kind,
    data,
    big32(crc32(concatBytes(kind, data))),
  );
};

export function adaptPng(input, artifactId) {
  const document = createCanonicalDocument(input);
  const source = artifactId
    ? adaptDelimited(document, artifactId, "\t")
    : adaptMarkdown(document);
  const wrapped = source
    .split("\n")
    .flatMap((line) => wrapText(line.replaceAll("\t", " | "), 96));
  const scale = 2;
  const width = 96 * 6 * scale + 24;
  const height = Math.max(40, wrapped.length * 9 * scale + 24);
  if (
    width > MAX_PNG_DIMENSION ||
    height > MAX_PNG_DIMENSION ||
    width * height > MAX_PNG_PIXELS
  ) {
    fail("document is too large for a bounded PNG", "EXPORT_TOO_LARGE");
  }
  const pixels = new Uint8Array(width * height * 3).fill(255);
  wrapped.forEach((line, lineIndex) => {
    [...line.normalize("NFKD").toUpperCase()]
      .slice(0, 96)
      .forEach((character, characterIndex) => {
        const glyph = FONT[character] ?? FONT["?"];
        glyph.forEach((row, y) => {
          [...row].forEach((bit, x) => {
            if (bit !== "1") return;
            for (let sy = 0; sy < scale; sy += 1) {
              for (let sx = 0; sx < scale; sx += 1) {
                const px = 12 + characterIndex * 6 * scale + x * scale + sx;
                const py = 12 + lineIndex * 9 * scale + y * scale + sy;
                const offset = (py * width + px) * 3;
                pixels[offset] = 23;
                pixels[offset + 1] = 32;
                pixels[offset + 2] = 51;
              }
            }
          });
        });
      });
  });
  const scanlines = new Uint8Array((width * 3 + 1) * height);
  for (let y = 0; y < height; y += 1) {
    scanlines[y * (width * 3 + 1)] = 0;
    scanlines.set(
      pixels.subarray(y * width * 3, (y + 1) * width * 3),
      y * (width * 3 + 1) + 1,
    );
  }
  const ihdr = concatBytes(
    big32(width),
    big32(height),
    new Uint8Array([8, 2, 0, 0, 0]),
  );
  return concatBytes(
    new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]),
    pngChunk("IHDR", ihdr),
    pngChunk("IDAT", deflateSync(scanlines, { level: 9 })),
    pngChunk("IEND", new Uint8Array()),
  );
}

const startsWithBytes = (value, prefix) =>
  prefix.every((byte, index) => value[index] === byte);

export function validateExportBinary(format, content) {
  if (!(content instanceof Uint8Array) || content.byteLength === 0) {
    fail(`${format} adapter returned no binary content`, "INVALID_BINARY");
  }
  if (content.byteLength > MAX_BINARY_EXPORT_BYTES) {
    fail(`${format} adapter exceeded the binary byte limit`, "EXPORT_TOO_LARGE");
  }
  if (format === "pdf") {
    const text = new TextDecoder("latin1").decode(content);
    const start = /\nstartxref\n(\d+)\n%%EOF\n$/.exec(text);
    const xref = start ? Number(start[1]) : -1;
    const xrefSection =
      xref >= 0
        ? /^xref\n0 (\d+)\n0000000000 65535 f \n((?:\d{10} 00000 n \n)+)trailer\n<< \/Size (\d+) \/Root (\d+) 0 R >>\n/.exec(
            text.slice(xref),
          )
        : null;
    const declaredSize = xrefSection ? Number(xrefSection[1]) : -1;
    const trailerSize = xrefSection ? Number(xrefSection[3]) : -1;
    const rootObject = xrefSection ? Number(xrefSection[4]) : -1;
    const offsets = xrefSection
      ? [...xrefSection[2].matchAll(/(\d{10}) 00000 n \n/g)].map((match) =>
          Number(match[1]),
        )
      : [];
    if (
      !text.startsWith("%PDF-1.4\n") ||
      !start ||
      !Number.isSafeInteger(xref) ||
      text.slice(xref, xref + 5) !== "xref\n" ||
      !xrefSection ||
      declaredSize !== trailerSize ||
      offsets.length !== declaredSize - 1 ||
      rootObject < 1 ||
      rootObject >= declaredSize ||
      offsets.some(
        (offset, index) =>
          !Number.isSafeInteger(offset) ||
          offset <= 0 ||
          offset >= xref ||
          !text.startsWith(`${index + 1} 0 obj\n`, offset),
      )
    ) {
      fail("PDF adapter returned an invalid container", "INVALID_BINARY");
    }
  } else if (format === "png") {
    if (!startsWithBytes(content, [137, 80, 78, 71, 13, 10, 26, 10])) {
      fail("PNG adapter returned an invalid container", "INVALID_BINARY");
    }
    const view = new DataView(
      content.buffer,
      content.byteOffset,
      content.byteLength,
    );
    const chunks = [];
    let idatBytes = 0;
    let offset = 8;
    while (offset < content.byteLength) {
      if (chunks.length >= MAX_PNG_CHUNKS) {
        fail("PNG chunk count exceeds the export limit", "EXPORT_TOO_LARGE");
      }
      if (offset + 12 > content.byteLength) {
        fail("PNG chunk header is truncated", "INVALID_BINARY");
      }
      const length = view.getUint32(offset, false);
      const end = offset + 12 + length;
      if (end > content.byteLength) {
        fail("PNG chunk content is truncated", "INVALID_BINARY");
      }
      const kindBytes = content.slice(offset + 4, offset + 8);
      const kind = new TextDecoder("ascii").decode(kindBytes);
      const data = content.slice(offset + 8, offset + 8 + length);
      if (
        crc32(concatBytes(kindBytes, data)) !== view.getUint32(end - 4, false)
      ) {
        fail(`PNG ${kind} checksum is invalid`, "INVALID_BINARY");
      }
      if (kind === "IDAT") {
        idatBytes += length;
        if (idatBytes > MAX_ZIP_TOTAL_BYTES) {
          fail("PNG image data exceeds the export limit", "EXPORT_TOO_LARGE");
        }
      }
      chunks.push({ kind, length });
      offset = end;
    }
    const width = chunks[0]?.kind === "IHDR" ? view.getUint32(16, false) : 0;
    const height = chunks[0]?.kind === "IHDR" ? view.getUint32(20, false) : 0;
    if (
      offset !== content.byteLength ||
      chunks[0]?.kind !== "IHDR" ||
      chunks[0]?.length !== 13 ||
      width < 1 ||
      height < 1 ||
      width > MAX_PNG_DIMENSION ||
      height > MAX_PNG_DIMENSION ||
      width * height > MAX_PNG_PIXELS ||
      view.getUint8(24) !== 8 ||
      view.getUint8(25) !== 2 ||
      chunks.filter(({ kind }) => kind === "IHDR").length !== 1 ||
      chunks.filter(({ kind }) => kind === "IDAT").length < 1 ||
      chunks.filter(({ kind }) => kind === "IEND").length !== 1 ||
      chunks.at(-1)?.kind !== "IEND" ||
      chunks.at(-1)?.length !== 0
    ) {
      fail("PNG adapter returned an invalid chunk structure", "INVALID_BINARY");
    }
  } else if (format === "xlsx") {
    if (!startsWithBytes(content, [0x50, 0x4b, 0x03, 0x04])) {
      fail("XLSX adapter returned an invalid ZIP magic", "INVALID_BINARY");
    }
    const view = new DataView(
      content.buffer,
      content.byteOffset,
      content.byteLength,
    );
    const names = new Set();
    const localEntries = new Map();
    let totalUncompressed = 0;
    let offset = 0;
    while (
      offset + 4 <= content.byteLength &&
      view.getUint32(offset, true) === 0x04034b50
    ) {
      if (offset + 30 > content.byteLength) {
        fail("XLSX local ZIP header is truncated", "INVALID_BINARY");
      }
      const method = view.getUint16(offset + 8, true);
      const expectedCrc = view.getUint32(offset + 14, true);
      const compressedSize = view.getUint32(offset + 18, true);
      const uncompressedSize = view.getUint32(offset + 22, true);
      const nameLength = view.getUint16(offset + 26, true);
      const extraLength = view.getUint16(offset + 28, true);
      const dataStart = offset + 30 + nameLength + extraLength;
      const end = dataStart + compressedSize;
      if (
        method !== 0 ||
        compressedSize !== uncompressedSize ||
        end > content.byteLength
      ) {
        fail("XLSX ZIP entry is unsupported or truncated", "INVALID_BINARY");
      }
      const name = new TextDecoder().decode(
        content.slice(offset + 30, offset + 30 + nameLength),
      );
      const data = content.slice(dataStart, end);
      if (
        !name ||
        names.has(name) ||
        name.includes("\\") ||
        name.startsWith("/") ||
        name.includes("\0") ||
        /^[A-Za-z]:/.test(name) ||
        name.split("/").some((part) => part === "." || part === "..") ||
        crc32(data) !== expectedCrc
      ) {
        fail("XLSX ZIP entry name or checksum is invalid", "INVALID_BINARY");
      }
      totalUncompressed += uncompressedSize;
      if (
        names.size >= MAX_ZIP_ENTRIES ||
        uncompressedSize > MAX_ZIP_ENTRY_BYTES ||
        totalUncompressed > MAX_ZIP_TOTAL_BYTES
      ) {
        fail("XLSX ZIP content exceeds the export limit", "EXPORT_TOO_LARGE");
      }
      names.add(name);
      localEntries.set(name, {
        crc: expectedCrc,
        compressedSize,
        uncompressedSize,
        offset,
      });
      offset = end;
    }
    const directoryOffset = offset;
    const centralNames = new Set();
    while (
      offset + 4 <= content.byteLength &&
      view.getUint32(offset, true) === 0x02014b50
    ) {
      if (offset + 46 > content.byteLength) {
        fail("XLSX central ZIP header is truncated", "INVALID_BINARY");
      }
      const method = view.getUint16(offset + 10, true);
      const expectedCrc = view.getUint32(offset + 16, true);
      const compressedSize = view.getUint32(offset + 20, true);
      const uncompressedSize = view.getUint32(offset + 24, true);
      const nameLength = view.getUint16(offset + 28, true);
      const extraLength = view.getUint16(offset + 30, true);
      const commentLength = view.getUint16(offset + 32, true);
      const localOffset = view.getUint32(offset + 42, true);
      const end = offset + 46 + nameLength + extraLength + commentLength;
      if (end > content.byteLength) {
        fail("XLSX central ZIP entry is truncated", "INVALID_BINARY");
      }
      const name = new TextDecoder().decode(
        content.slice(offset + 46, offset + 46 + nameLength),
      );
      const local = localEntries.get(name);
      if (
        !local ||
        centralNames.has(name) ||
        method !== 0 ||
        expectedCrc !== local.crc ||
        compressedSize !== local.compressedSize ||
        uncompressedSize !== local.uncompressedSize ||
        localOffset !== local.offset
      ) {
        fail("XLSX central ZIP entry does not match its local entry", "INVALID_BINARY");
      }
      centralNames.add(name);
      offset = end;
    }
    const endRecordOffset = content.byteLength - 22;
    const directorySize = offset - directoryOffset;
    if (
      content.byteLength < 22 ||
      offset !== endRecordOffset ||
      view.getUint32(endRecordOffset, true) !== 0x06054b50 ||
      view.getUint16(endRecordOffset + 4, true) !== 0 ||
      view.getUint16(endRecordOffset + 6, true) !== 0 ||
      view.getUint16(endRecordOffset + 8, true) !== names.size ||
      view.getUint16(endRecordOffset + 10, true) !== names.size ||
      view.getUint32(endRecordOffset + 12, true) !== directorySize ||
      view.getUint32(endRecordOffset + 16, true) !== directoryOffset ||
      view.getUint16(endRecordOffset + 20, true) !== 0 ||
      centralNames.size !== names.size
    ) {
      fail("XLSX central directory is invalid", "INVALID_BINARY");
    }
    for (const required of [
      "[Content_Types].xml",
      "xl/workbook.xml",
      "xl/worksheets/sheet1.xml",
      "xl/worksheets/sheet2.xml",
    ]) {
      if (!names.has(required)) {
        fail(`XLSX adapter omitted ${required}`, "INVALID_BINARY");
      }
    }
  } else {
    fail(
      `binary validation is unsupported for ${String(format)}`,
      "UNSUPPORTED_FORMAT",
    );
  }
  return true;
}

const artifactMetadata = (document) => ({
  document_id: document.document_id,
  revision_id: document.revision_id,
  freshness: clone(document.freshness),
  caveats: clone(document.caveats),
  evidence_refs: clone(document.evidence_refs),
  ...(document.status
    ? {
        status: document.status,
        partial_reasons: clone(document.partial_reasons),
      }
    : {}),
});

const buildExportArtifact = ({
  document,
  format,
  content,
  sourceArtifactId,
  mediaType,
  fileExtension,
}) => {
  const canonical = createCanonicalDocument(document);
  if (typeof content !== "string" && !(content instanceof Uint8Array)) {
    fail("artifact content must be a string or Uint8Array");
  }
  const safeFormat = contentString(format, "format");
  const safeSourceArtifactId = contentString(
    sourceArtifactId ?? "document",
    "sourceArtifactId",
  );
  return deepFreeze({
    artifact_id: [
      canonical.document_id,
      canonical.revision_id,
      safeSourceArtifactId,
      safeFormat,
    ].join(":"),
    format: safeFormat,
    media_type: contentString(mediaType, "mediaType"),
    file_extension: contentString(fileExtension, "fileExtension"),
    ...artifactMetadata(canonical),
    content: typeof content === "string" ? content : new Uint8Array(content),
  });
};

export function createExportArtifact(input) {
  if (
    input?.format === "pdf" ||
    input?.format === "png" ||
    input?.format === "xlsx"
  ) {
    fail(
      "binary artifacts must be created through exportDocument with policy hooks",
      "POLICY_HOOKS_REQUIRED",
    );
  }
  return buildExportArtifact(input);
}

export async function exportDocument(input, options = {}) {
  const document = await prepareAuthorizedDocument(input, options);
  const format = options.format;
  if (
    options.binaryAdapters &&
    !LOADED_EXPORT_ADAPTERS.has(options.binaryAdapters)
  ) {
    fail(
      "binary adapters must come from the compiled ProductManifest export registry",
      "UNSAFE_ADAPTER_REGISTRATION",
    );
  }
  const adapter = options.binaryAdapters?.[format];
  if (adapter) {
    const rendered = await adapter(document, {
      sourceArtifactId: options.sourceArtifactId,
    });
    const content =
      rendered instanceof Uint8Array ? rendered : rendered?.content;
    const expectedMediaType =
      format === "pdf" ? "application/pdf" : "image/png";
    if (
      !(content instanceof Uint8Array) ||
      (rendered?.mediaType !== undefined &&
        rendered.mediaType !== expectedMediaType) ||
      (rendered?.fileExtension !== undefined &&
        rendered.fileExtension !== format)
    ) {
      fail(
        `${format} adapter returned content metadata outside its allowlisted format`,
        "ADAPTER_OUTPUT_MISMATCH",
      );
    }
    validateExportBinary(format, content);
    return buildExportArtifact({
      document,
      format,
      content,
      sourceArtifactId: options.sourceArtifactId,
      mediaType: expectedMediaType,
      fileExtension: format,
    });
  }
  const builtins = {
    markdown: {
      content: () => adaptMarkdown(document),
      mediaType: "text/markdown; charset=utf-8",
      fileExtension: "md",
    },
    json: {
      content: () => adaptJson(document),
      mediaType: "application/json; charset=utf-8",
      fileExtension: "json",
    },
    csv: {
      content: () => adaptDelimited(document, options.sourceArtifactId, ","),
      mediaType: "text/csv; charset=utf-8",
      fileExtension: "csv",
    },
    tsv: {
      content: () => adaptDelimited(document, options.sourceArtifactId, "\t"),
      mediaType: "text/tab-separated-values; charset=utf-8",
      fileExtension: "tsv",
    },
    html: {
      content: () => adaptHtml(document),
      mediaType: "text/html; charset=utf-8",
      fileExtension: "html",
    },
    xlsx: {
      content: () => adaptXlsx(document, options.sourceArtifactId),
      mediaType:
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      fileExtension: "xlsx",
    },
    pdf: {
      content: () => adaptPdf(document),
      mediaType: "application/pdf",
      fileExtension: "pdf",
    },
    png: {
      content: () => adaptPng(document, options.sourceArtifactId),
      mediaType: "image/png",
      fileExtension: "png",
    },
  };
  const builtin = builtins[format];
  if (builtin) {
    const content = builtin.content();
    if (content instanceof Uint8Array) {
      validateExportBinary(format, content);
    }
    return buildExportArtifact({
      document,
      format,
      content,
      sourceArtifactId: options.sourceArtifactId,
      mediaType: builtin.mediaType,
      fileExtension: builtin.fileExtension,
    });
  }

  fail(`unsupported export format ${String(format)}`, "UNSUPPORTED_FORMAT");
}

export function createPptxOutlineDraft(input) {
  const document = createCanonicalDocument(input);
  const slides = [
    {
      slide_id: "title",
      title: document.title,
      section_id: null,
      evidence_ids: [],
    },
    ...document.sections.map((section) => ({
      slide_id: `section_${section.id}`,
      title: section.heading,
      section_id: section.id,
      evidence_ids: [
        ...new Set(section.blocks.flatMap((block) => block.evidence_ids)),
      ].sort(),
    })),
  ];
  const identity = {
    document_id: document.document_id,
    revision_id: document.revision_id,
    slides,
  };
  return deepFreeze({
    schema_version: "1.0.0",
    workflow: "pptx_outline",
    outline_id: `outline_${sha256(canonicalJson(identity)).slice(0, 32)}`,
    source_document_id: document.document_id,
    source_revision_id: document.revision_id,
    state: "draft",
    slides,
  });
}

export function approvePptxOutline(draft, approval) {
  if (!draft || draft.workflow !== "pptx_outline" || draft.state !== "draft") {
    fail("only a PPTX outline draft can be approved", "INVALID_OUTLINE_STATE");
  }
  const approved_by = nonEmpty(approval?.approvedBy, "approvedBy");
  const approved_at = timestamp(approval?.approvedAt, "approvedAt");
  return deepFreeze({
    ...clone(draft),
    state: "approved",
    approved_by,
    approved_at,
  });
}

export async function renderApprovedPptx(approved) {
  if (
    !approved ||
    approved.workflow !== "pptx_outline" ||
    approved.state !== "approved"
  ) {
    fail(
      "PPTX rendering requires an explicitly approved outline",
      "OUTLINE_APPROVAL_REQUIRED",
    );
  }
  // PPTX remains a typed unavailable capability until an approved outline
  // carries independently validated slide content and a separate OPC validator
  // verifies the rendered package. Accepting arbitrary adapter bytes here would
  // incorrectly turn "approved title list" into an approved presentation.
  throw new ExportAdapterUnavailableError("pptx");
}
