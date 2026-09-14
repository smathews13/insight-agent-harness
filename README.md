> **⚠️ Not Official Databricks Software**
> This application is built and maintained by the Databricks field engineering team and is **not an official Databricks product**. It is not covered by Databricks Support SLAs. Your Databricks account team can help you deploy, configure, and troubleshoot this app as part of your engagement.

# Insight Agent Harness

![Insight Agent Harness mark](assets/insight-agent-harness.svg)

Insight Agent Harness is a customer-neutral collection of contracts, policy
helpers, package boundaries, and deterministic release controls for
evidence-backed analytics agents.

## Current status

This is experimental engineering software. Interfaces may change, and the
repository does not claim a hosted service or stable runtime API.

## Published surface

- Cross-language JSON contracts and validators.
- Generic governance, observability, persistence, export, Slack-boundary, and
  Python runtime packages.
- A neutral ProductManifest profile and deterministic generated bindings.
- Ownership, package-integrity, source-stamp, and non-browser boundary tests.
- Neutral integration and extension documentation.

Private deployment overlays, customer material, and product-specific
applications, agents, documentation, and assets are excluded.

## Local validation

The root npm workspace is self-contained: its dependencies are local `file:`
packages and its lockfile contains no private registry URLs.

```bash
npm ci --ignore-scripts --offline
npm run shared:test
npm run shared:check
npm run packages:sources
python3 scripts/materialize-product-manifest.py --profile sample-neutral --check
```

The Python runtime wheel is also built without an index:

```bash
python3 scripts/check_runtime_wheel.py
```

Checks and publication are local owner operations; this repository contains no
GitHub workflows.

## Documentation

The [API access reference](API_ACCESS.md) distinguishes general Databricks Apps
and Model Serving access patterns from contracts actually published by this
harness.

- [Shared package integration](docs/compatibility/shared-package-integration.md)
- [ProductManifest extensions](docs/customization/product-extensions.md)
- [Operational extension seams](docs/customization/operational-extension-seams.md)
- [Canonical artifacts and exports](docs/canonical-artifacts-and-exports.md)

## Support and security

Do not commit credentials, tokens, private hostnames, customer identifiers,
personal addresses, or captured customer traffic. See [SECURITY.md](SECURITY.md)
for private vulnerability reporting and [SUPPORT.md](SUPPORT.md) for the
experimental support posture.
