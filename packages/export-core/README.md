# Export core

`@insight-agent-harness/export-core` defines the canonical, product-neutral
document and artifact boundary used by exporters. It has no registry
dependencies. Its only package import is the local contracts source, used to
validate `EvidenceRef` values and produce canonical JSON.

The manifest declares contracts as a local `file:` dependency. Builds, tests,
and consumption run from the root npm workspace without a private registry or
package publication step.

The package owns:

- canonical schema `1.1.0` documents with revision identity, completeness,
  freshness, caveats, evidence references, figures, charts, and tables;
- required authorization and redaction hooks that run before any external or
  binary adapter;
- deterministic Markdown, HTML, JSON, CSV, TSV, and XLSX artifacts;
- deterministic selectable-text PDF and bounded document/table PNG renderers;
- an outline-first PPTX contract that requires explicit approval before an
  adapter can run.

Every exported artifact carries document/revision identity, freshness, caveats,
and evidence references as structured metadata. Markdown and JSON also render
that metadata into their content. Delimited formats keep it on the artifact
instead of adding non-tabular rows to the data.

Diagnostics, provider payloads/errors, raw SQL, and raw traces are recursively
removed from evidence extensions, structured list items, table cells, and
undeclared fields before a canonical document reaches an adapter. A redactor
may scrub display content, caveats, and evidence excerpts, but changing
identity, freshness, evidence bindings/source identity, or quantitative
content is rejected. PDF, PNG, and XLSX magic/container structure is validated
before an artifact can leave the package. The low-level deterministic adapters do not perform egress;
external and binary callers use `exportDocument`, which requires both policy
hooks. Product-specific authorization policy, UI rendering, network egress, and
persistence remain outside this package.

Quantitative prose, figures, table cells, and chart series fail closed when
they have no declared `EvidenceRef`. Product adapters may instead omit
unsupported quantitative blocks and mark the canonical revision `partial`;
they may not invent evidence. PPTX remains `ADAPTER_UNAVAILABLE` even after
outline approval because the approved contract currently contains titles and
evidence IDs but no approved slide body content; emitting a title-only OOXML
deck would misrepresent completeness. The release gate also has no independent
PPTX interoperability validator yet.

Product distributions may override only PDF or PNG through an immutable
compiled-adapter allowlist created by `createCompiledExportAdapterRegistry`.
`loadProductExportAdapters` resolves opaque `export-adapter:` refs from the
signed ProductManifest; registrations must use export-core's fixed threat
contract and exactly match the manifest egress and redaction policy refs.
Module paths, runtime registration fields, forged registries, output media-type
changes, and ad hoc renderer objects are rejected. Built-in deterministic
renderers remain available when no compiled override is selected.
