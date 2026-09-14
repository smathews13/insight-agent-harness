# Observability

`@insight-agent-harness/observability` is a private, dependency-light local
package for safe cross-system correlation and append-only audit construction.
It uses Node built-ins plus direct workspace-path imports from `contracts` and
`governance`; it has no registry dependencies or network behavior.

The package manifest declares those local packages with `file:` dependencies.
Builds, tests, and consumption run from the root npm workspace without a
private registry or package publication step.

## Boundary

- `corr_` identifiers are bounded printable values. Invalid caller values are
  replaced with a locally minted identifier rather than logged.
- Correlation context joins app request/run IDs, gateway request IDs, and MLflow
  trace IDs without carrying prompts or response content.
- `createAuditEvent` constructs and freezes the shared `AuditEvent` contract.
  `appendAuditEvent` accepts only an append function and revalidates every event;
  no update or delete API is exposed.
- Audit details use a fixed scalar metadata allowlist. Unknown and
  content-bearing fields are omitted by default.
- Payload classification distinguishes safe metadata from secrets, tokens,
  cookies, headers, raw prompts, raw responses, and governed data.
- Redaction and guards support safe diagnostics, but raw prompt/response content,
  credentials, HTTP headers, cookies, and governed records are never safe
  telemetry merely because a secret pattern was not detected.

The package does not configure MLflow or an AI gateway, export traces, persist
events, sample governed data, or decide retention. Hosts own those adapters and
must preserve the append-only and no-content defaults.

## Threat model

The attacker may control correlation headers, metadata keys and values, tool
errors, prompt/response bodies, and nested payloads. They may attempt log
forgery, credential exfiltration, or copying governed records into audit and
trace attributes. Sinks and trusted platform-generated opaque IDs are assumed
to be outside attacker control.

Strict identifier shapes stop newline/content injection. Fixed metadata
allowlists, recursive redaction, contract validation, immutable events, and
negative guards prevent the common accidental disclosure paths. The package
cannot make a sink append-only if the sink implementation later mutates stored
records, and it cannot detect every possible encoded secret; callers should use
opaque references and the safe constructors instead of logging arbitrary data.

## Local checks

```bash
npm test
```
