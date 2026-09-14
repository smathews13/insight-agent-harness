# Agent runtime (Python)

`insight-agent-harness-runtime` is the provider- and product-neutral Python
runtime boundary for governed analytical agents. It contains interfaces and
fail-closed controls only; it does not contain prompts, product tools, provider
SDKs, network clients, or registry configuration.

This remains a Python path package and is consumed directly from the checkout.
No Python registry publication or private package index is required.

## Local path setup

The shared wire contracts remain authoritative. Install both workspace
packages by path:

```bash
python -m pip install -e ../contracts -e .
```

For a no-install test run, the test bootstrap adds `../contracts/src` and this
package's `src` directory to `sys.path`:

```bash
python -m unittest discover -s tests -v
```

Build the runtime package locally with:

```bash
python -m pip wheel --no-deps --no-build-isolation .
```

## Included boundaries

- `IdentityVerifier`, `PolicyEngine`, `GovernedTool`, `AnswerBuilder`, and
  `AuditSink` protocols
- request, verified identity, action, evidence, tool-result, answer, and audit
  value objects
- monotonic deadlines plus hard step, tool-call, and output-byte limits
- bounded retries restricted to idempotent operations, with mandatory
  idempotency keys for retried side effects
- evidence-reference validation for quantitative blocks and summary values
- provider capability decisions that block requested-provider failures by
  default; fallback requires a reviewed `policy:` reference, required
  capability parity, and a successful payload-free audit record
- tool-adapter threat declarations covering destination allowlist references,
  response trust, content classification, response size, side effects,
  idempotency, kill switches, and user-authorized execution by default
- redaction-safe, shared-contract-validated audit hooks that never accept raw
  prompts, action arguments, or result content

The runtime validates wire values by importing
`insight_agent_harness_contracts` from the sibling path package. It does not
copy or fork those schemas.

