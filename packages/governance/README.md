# Governance

`@insight-agent-harness/governance` is a private, dependency-free local package
for identity and authorization decisions. It contains neutral policy mechanics;
products supply their own capabilities, subjects, and reviewed policy data.

This package is built, tested, and consumed from the root npm workspace. It
requires no private registry or package publication step.

## Boundary

- A request authorization is accepted only when trusted verification binds the
  same subject and execution mode.
- User authorization, reviewed service-principal execution, and internal system
  execution have separate trusted sources. A request cannot pivot between them.
- Capability decisions consume trusted grants supplied by the host. Request
  fields cannot add scopes or select privileges.
- Tool policies require opaque destination allowlists, response trust and
  maximum content classifications, byte limits, explicit side-effect and
  idempotency declarations, a kill switch, and validation/filtering hooks.
  Runtime decisions enforce each field before returning a filtered response.
- Retried side effects must reuse the initial opaque idempotency key. Active
  kill switches, unapproved destinations, oversized or over-classified
  responses, trust/side-effect mismatches, and hook failures deny.
- Scheduler identity is denied governed evidence and data tools. It can run only
  a policy-declared non-governed action when a separate matching capability
  policy approved that action.
- This package deliberately has no grant-management effect or grant mutation API.
- All missing, malformed, disabled, or mismatched inputs deny. `runIfAllowed`
  invokes work only after an explicit allow decision.
- Generic redaction removes credentials, prompts, responses, governed-data
  fields, and common secret forms before values cross a policy boundary.

This package decides; it does not authenticate tokens, mint credentials, execute
tools, administer Unity Catalog grants, persist policy, or make network calls.
Service-principal bindings and policy documents must be reviewed outside a
request and passed in as trusted configuration.

## Threat model

The attacker may control request JSON, capability and tool names, subject claims,
and strings that later reach errors or audit metadata. They may try to reuse a
verified human subject to select service-principal execution, claim an
unverified scope, inject a credential into diagnostics, turn a tool call into
privilege administration, redirect a tool, overrun a response boundary, replay
a side effect, or use scheduler identity to read governed content. Trusted
gateway/service-binding evidence, reviewed policies, destination resolution,
kill-switch state, and trusted grant lists are outside attacker control.

The package prevents those request-driven pivots and fails closed when evidence
is absent. It does not protect a compromised trusted identity verifier or a host
that labels attacker-controlled values as trusted policy.

## Local checks

```bash
npm test
```
