# Security policy

> **Not Official Databricks Software**
> This application is built and maintained by the Databricks field engineering team and is **not an official Databricks product**. It is not covered by Databricks Support SLAs. Your Databricks account team can help you deploy, configure, and troubleshoot this app as part of your engagement.

Do not open a public issue containing a vulnerability, credential, workspace
identifier, customer name, governed data, trace payload, or deployment log.
Report suspected security issues privately to the repository owner or through
the security channel provided by your Databricks account team.

Include the affected release tag, full commit SHA, artifact digest, impact, and
minimal reproduction. Remove tokens, cookies, authorization headers, secrets,
customer data, and workspace URLs.

Only the latest 1.1 patch is eligible for security fixes. A report is not a
promise of a Databricks security advisory, SLA, or official product response.

## Local security checks

The repository has an offline, deterministic source guard:

```bash
python3 scripts/security_gate.py sast
```

It reports machine-readable JSON and checks high-signal patterns for secret
logging, dynamic command/code execution, unbounded network destinations, SQL
identifier interpolation, token/header persistence, and unsafe deserialization.
This is deliberately described as a heuristic guard, not comprehensive SAST.

The local guard scans tracked, non-excluded source files and refuses tracked
source symlinks. It does not follow data flow, parse every language construct,
prove that a vulnerability is absent, or scan generated build output and
explicitly excluded internal handoff fixtures. It reports evidence hashes, not
matched source text, so a finding does not echo a secret into logs.

There are no inline ignores. A suppression must be an approved entry in
`security/sast-allowlist.json` bound to the finding fingerprint and path, with
an owner, reason, reviewer, review reference, and expiry date. The allowlist's
entry digest detects corruption, while repository review remains responsible
for approving changes. Wildcard, duplicate, overlong, expired, mismatched,
or orphaned entries block. Critical findings cannot be suppressed.

Dependency and attestation adapters remain available as optional diagnostics:

```bash
npm run diagnostics:supply-chain
```

The default dependency check is informational. Missing, stale, malformed, or
lock-mismatched advisory evidence is emitted as a clear `UNVERIFIED` warning and
exits successfully; reported advisory findings remain visible in the JSON.
License entries requiring review are reported without becoming a release gate.
These diagnostics do not gate the local build, public mirror, or practical
release path.

Use the explicit fail-closed security review only when trusted advisory and
attestation verifiers and trust roots are configured:

```bash
python3 scripts/security_gate.py dependency --strict
npm run diagnostics:supply-chain:strict
```

Strict mode rejects unavailable, invalid, stale, mismatched, or unverified
evidence. Credentials and private evidence must stay outside the repository.
