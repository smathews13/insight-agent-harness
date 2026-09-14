# Shared contracts

`@insight-agent-harness/contracts` is a private, workspace-local package. It has
no registry configuration and no external runtime or generation dependencies.
The npm workspace and Python project metadata exist only to give local platform
and agent code stable path-based package boundaries.

`ReleaseManifest` is the authoritative signed identity for one app/model
promotion. The Node package exports deterministic canonicalization, Ed25519
signing/verification, immutable upstream-pin checks, measured-observation
comparison, and transaction-level rollback rehearsal. Generated TypeScript and
Python types include both `ReleaseManifest` and the public
`ReleaseKeyRegistry`. Production private keys are never generated here: the CLI
accepts one only through an explicit private-key file, while the repository
contains public keys only.

## Contract policy

- `ProductManifest` is closed: unknown fields fail validation at every level.
  Only `presentation` is marked runtime-editable. Capability, behavioral,
  authorization, data-boundary, operations, export, compatibility, and resource
  bindings require a reviewed release.
- Request, run, evidence, audit, blocked-dependency, and error envelopes accept
  unknown fields so a newer producer can interoperate with an older consumer.
  Known fields and all cross-field safety rules are still validated.
- Data and resource locations are opaque, typed references. Raw customer,
  workspace, catalog, schema, or table values do not belong in these contracts.
- Branding URIs are release-owned `asset://` or `reference:` values. Privileged
  manifests cannot fetch branding from an arbitrary network location.
- `explicit_service_principal` is a separate execution mode, not a request or
  prompt override. It requires reviewed identity policy, answer disclosure,
  data-boundary, and audit declarations.
- External exports and MCP integrations remain disabled unless all required
  policy, adapter, signing-key, redaction, and kill-switch references exist.
- v1.1 uses `strict_persistent_analytics`: a Lakebase binding, bounded run
  limits, reporting-versus-enforcement budget mode, freshness and retention
  policies, and global kill switches are all release-time declarations.

## User scope allowlist

The allowlist is the exact union of the current app's shared
`REQUIRED_USER_API_SCOPES` and `OPTIONAL_USER_API_SCOPES` declarations:

- `platform/app/shared/required-user-api-scopes.ts`
- `platform/app/shared/optional-user-api-scopes.ts`

That union contains the four ask-path scopes (`serving.serving-endpoints`,
`model-serving`, `sql`, and `dashboards.genie`) and the seven optional catalog,
workspace, Vector Search, and Lakebase browse scopes. It deliberately excludes
platform-injected IAM defaults, undeclared aliases, and model-side-only scopes.
Changes to those two shared source contracts must be reviewed and then copied
into both `ProductManifest` and `RequestContext` schemas; the contracts package
does not import app code during generation.

## Generation and checks

From the repository root:

```bash
npm run contracts:generate
npm run contracts:check
npm run contracts:test
```

The generator uses the exact sorted schema bytes for both languages. Generated
TypeScript and Python files carry each source SHA-256 plus a combined schema-set
SHA-256. `contracts:check` compares complete generated output and fails on drift.

## Evidence boundary

`RunEnvelope` provides the smallest shared evidence guarantee: every
`quantitative` content block must name at least one `EvidenceRef`, and every
named reference must exist in that run's evidence collection. Removing the
reference makes the run invalid in both Node and Python tests.

This package does **not** decide whether prose is quantitatively correct, parse
SQL, recompute metrics, or judge evidence quality. Those semantic checks belong
in the later answer/evaluation package; this slice only prevents quantitative
content from crossing the shared boundary without an explicit evidence binding.
