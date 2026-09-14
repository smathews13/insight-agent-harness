# Canonical artifacts and deterministic exports

EPIC-06 stores each successfully persisted analytical answer as a logical
artifact and an immutable canonical revision.

## Contract

- Canonical schema: `1.1.0`
- Export adapter contract: `1.2.0`
- Deterministic server formats: Markdown, HTML, JSON, CSV, TSV, and XLSX
- Binary server formats: dependency-free selectable-text PDF plus bounded
  document/table PNG. PDF, PNG, and XLSX bytes are rejected unless their
  magic and container structure validate before egress.
- PPTX remains typed `adapter_unavailable` after outline approval. The approved
  outline contract currently binds only slide titles, section IDs, and evidence
  IDs; it carries no approved block content. Rendering that object would create
  a title-only deck that falsely appears complete. A future adapter first needs
  a content-bearing approved-outline contract and an OOXML interoperability
  validator in the release gate.

The answer adapter carries document and revision IDs, figures, chart series,
tables, sources/citations, caveats, freshness, and current-run `EvidenceRef`
values. Each evidence reference is bound to a completed tool stage by statement
and result hashes; an answer-supplied source label alone is not evidence.
Quantitative blocks require a value-returning governed tool result. Historical
answers can be projected read-only as partial, with unsupported quantitative
blocks omitted; this does not create revision history.
Credential-shaped fields and provider tokens are redacted before the canonical
revision reaches Lakebase, not only when it is later exported.

## Persistence and ownership

Migration 44 creates `artifacts` and `artifact_revisions`. Artifact ownership
and identity plus revision rows are immutable. A single advisory-locked
statement appends the next monotonic revision and advances the logical
artifact's current pointer only to that appended child and only when the
expected pointer still matches. Stale writers conflict rather than overwrite.

Every read is owner-scoped in SQL. Project-bound artifacts additionally require
the server-owned project resolver. Another user's identifier and an unknown
identifier both return 404. Canonical and evidence hashes are validated before
revision content is returned or exported.

The strict answer path uses one database statement to gate ownership and the
run fencing token, append the canonical revision, advance its pointer, and
insert the answer. A failure commits neither the answer nor the revision; the
run is marked persistence-failed and analytical content is withheld.

## API and policy

`/api/v1/artifacts/:artifactId` exposes metadata and revision history; revision
reads stay metadata-only so they cannot bypass export policy or redaction.
Selected content leaves only through deterministic exports and the gated PPTX
outline workflow.
Every export names a selected revision and the `canonical-safe-v1` redaction
profile, checks identity/project access and the `artifact-export` egress
control, applies the deterministic `canonical-safe-v1` secret redaction
profile, validates hashes and evidence, and appends a required audit event.
Hidden diagnostics, raw traces, provider payloads, and SQL are not part of the
canonical adapter. HTML renders revision/freshness/evidence in the document;
XLSX places the same context in a metadata sheet; every exported artifact also
retains it as structured server metadata.

Retention uses bounded adapters. Artifact retention locks candidates and their
logical artifacts, excludes current and artifact/revision legal-held rows in
SQL, and is reinforced by a delete trigger and a restrictive parent foreign key.
Audit retention runs only through a retention job whose legal-hold gate has
already passed.
