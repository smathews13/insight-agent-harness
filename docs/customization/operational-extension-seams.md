# Operational extension seams

Downstream products consume these neutral interfaces through a committed
`ProductManifest` profile. Shared code does not import an overlay, customer
package, source path, or module specifier. A product-specific implementation is
compiled into its distribution and selected only by an opaque manifest ref.

## Security boundaries

- **Sessions:** `/api/admin/sessions` is super-admin-only. Inventory is
  keyset-paginated and returns pseudonymous subject/deployment refs plus an
  opaque revocation ref. Cookies, token values, raw subjects, and session
  hashes are never returned. Forced revocation updates the authoritative
  Lakebase row, is idempotent, and is audited.
- **Analytical admission:** the durable runtime policy is separate from
  readiness and budget. Runtime input can tighten `open` to `blocked`; it
  cannot clear a block or select another identity, provider, or endpoint.
  Store uncertainty blocks before conversation/run writes and before provider
  invocation. A new committed release policy ref is required to reset the runtime
  policy namespace.
- **Retention:** jobs remain legal-hold-aware, idempotent, append-only, and
  capped at 1,000 records per batch. Built-in Lakebase adapters cover
  conversations, attachments, feedback, historical artifact revisions, and
  audit. MLflow traces and Unity Catalog external resources require compiled
  adapters; absence resolves to `RETENTION_ADAPTER_NOT_INSTALLED` and blocks.
  The production scheduler is inert unless
  `INSIGHT_AGENT_RETENTION_ENABLED=true`; deletion additionally requires an
  explicit `INSIGHT_AGENT_RETENTION_LEGAL_HOLD_ACTIVE=false`, and the kill
  switch is rechecked immediately before each batch.
- **Migrations:** downstream ids, versions, checksums, owners, and committed
  profile refs are unique and verified. Product versions begin at 48. The
  registry appends to an immutable core 1–47 and rejects statements that write
  the upstream migration ledger.
- **Exports:** binary adapters use export-core's fixed threat contract and
  must exactly match the manifest egress and redaction policy refs. Only
  compiled `export-adapter:` registrations resolve. Module, path, import, and
  request-provided registrations are rejected.

## Registration lifecycle

1. Compile the neutral adapter implementation into the downstream build.
2. Add its opaque id to the downstream ProductManifest.
3. Materialize `ProductManifest` and verify its source/canonical hashes.
4. Build the immutable startup registry.
5. Resolve the manifest once. Do not expose registry construction to HTTP,
   request context, runtime settings, or environment-selected module loading.

Downstream applications may implement these interfaces in their own
repositories. The Harness only knows the neutral contracts and opaque profile
ownership.
