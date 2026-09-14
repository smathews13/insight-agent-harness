# Governed external intelligence

This customer-neutral package defines the boundary between a scheduled,
separately governed collector and analytical evidence. It contains no network
client, Databricks profile, deployment target, customer identifier, credential
provider, registry write, or production storage adapter.

## Trust boundary

1. A reviewed `SourcePolicy` allowlists exact HTTPS hosts and path prefixes and
   names an owner, review policy, review expiry, robots policy, license
   metadata, reviewed parser versions, request-rate/content/claim ceilings, and
   a freshness window.
2. A collector outside this package supplies a `FetchEnvelope`. The requested
   URL, every redirect destination, and the final URL must all satisfy the same
   destination policy. The collector must attest the DNS addresses and actual
   connected address used for every hop; private, loopback, link-local,
   reserved, and otherwise non-public addresses are rejected to prevent
   DNS-rebinding and SSRF routes. Query strings and fragments are intentionally
   unsupported by this strict template.
3. Bytes are content-hashed and written once through `RawSnapshotStore`.
   Production implementations map `GovernedUcVolumeSnapshotStore` to a
   governed Unity Catalog Volume. This repository supplies only
   `LocalFilesystemAdapter` for offline tests.
4. Text is untrusted. Native UTF-8 text is decoded strictly. PDF, archive,
   binary, and other container media are quarantined by default and are never
   decoded with replacement characters. A container can proceed only through a
   `TextExtractionAdapter` in an immutable `CompiledTextExtractorRegistry`
   assembled by trusted application code, and its captured version must be
   explicitly reviewed by the source policy. Extracted page count and UTF-8
   text size are bounded.
   Missing or failed extractors, malformed media signatures, truncation,
   encryption, unsupported compression, and limit violations all quarantine
   the original bytes for manual review without producing claims or evidence.
5. Prompt-injection, PII, and secret scanning runs over native or reviewed
   extracted text before claim parsing. Quarantined bytes use the separate
   `QuarantineSink`; they never enter the normal raw-snapshot store.
   Quarantine records contain rule codes and hashes, not copied source text.
6. Reviewed claim parsers emit `ClaimDraft` values from the already-scanned
   text. The package records retrieval and
   source URLs and license, effective/retrieval timestamps, parser version,
   text-extractor version, content hash, source classification, review
   status/provenance, impact, conflict group, and a contract-shaped evidence ref.
   Production implementations map `ManagedTableClaimRepository` to managed
   Unity Catalog tables.
7. Retrieval exposes only fresh, approved claims. High-impact pending claims
   explicitly require human approval through a `ReviewAuthorizer` bound to the
   source's reviewer policy. Review decisions are one-way and carry an opaque
   review-record reference. Contradictory approved claims remain visible
   together in a `ConflictGroup`; no winner is selected.
   `bind_external_evidence` repeats the freshness and review gate so callers
   cannot bypass selection when attaching evidence to a run.

Claims are evidence only. Subjects and predicates that target tools,
ProductManifest, authorization, permissions, grants, or data boundaries are
rejected. `BoundExternalEvidence` carries only claims, evidence references, and
a fingerprint of release-owned controls, so evidence cannot rewrite those
controls.

## Local checks

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
ruff check .
```

The DAB resource under `resources/templates/` is intentionally not included by
the repository bundle. It is a paused, placeholder-only Lakeflow Jobs boundary
that a downstream owner must connect to reviewed collector and Unity Catalog
adapters.
