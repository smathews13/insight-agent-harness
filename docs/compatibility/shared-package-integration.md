# Shared package integration

The root npm workspace discovers these local JavaScript packages explicitly:

- `@insight-agent-harness/contracts`
- `@insight-agent-harness/governance`
- `@insight-agent-harness/observability`
- `@insight-agent-harness/lakebase`
- `@insight-agent-harness/export-core`
- `@insight-agent-harness/slack-boundary`

`export-core` version `0.2.0` owns canonical artifact schema `1.1.0`,
deterministic text/tabular adapters `1.1.0`, binary adapter contracts, and the
outline-first PPTX approval boundary.

`insight-agent-harness-runtime` remains a Python path package under
`packages/agent-runtime-py`. It is tested with the contracts source on
`PYTHONPATH` and built as a local wheel without resolving dependencies.

Local JavaScript package dependencies use `file:` declarations. No shared
package requires a private or published registry package; builds, tests, and
consumption work directly from this checkout.

## Local verification

```bash
npm ci --ignore-scripts --offline --no-audit --no-fund
npm run shared:test
npm run packages:check
npm run runtime-py:wheel
npm run packages:sbom:test
npm run packages:integrity
```

The optional SPDX inventory is generated solely from local manifests and
lockfiles. It records deterministic package digests, available lockfile
checksums, and an input digest. Generate a commit-bound copy when it is useful:

```bash
npm run packages:sbom:release -- \
  --source-commit 0123456789abcdef0123456789abcdef01234567 \
  --created 2026-09-13T23:45:00Z \
  --output build/release/dependency-inventory.spdx.json
```

This diagnostic is not required by the local build or public mirror.
