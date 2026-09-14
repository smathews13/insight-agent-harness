# Slack boundary

`@insight-agent-harness/slack-boundary` is the EPIC-09 architecture spike. It is
deliberately **NO-GO** for a production Slack bot. No supported runtime verifier
has proven that a Slack user can execute Databricks work as that same delegated
user, so this package exposes only an authenticated web-app link-out.

The package contains no Slack SDK, HTTP client, credentials, event listener, or
Databricks execution client. It defines and tests:

- normalized Slack event, short-lived signature receipt, retry, edit, deletion,
  idempotency, and workspace/channel/thread-mapping contracts;
- a Slack-user-to-Databricks-user subject-link interface that cannot represent a
  service principal;
- a consent, refresh, revocation, and workspace-change state machine that stores
  only managed credential references, never raw Databricks tokens;
- persistence classification and retention rules that forbid Slack message
  content and token material;
- actor- and thread-bound correlation from Slack event to delegated subject,
  mapped project, run, and evidence;
- a fail-closed, short-lived kill-switch decision;
- an `export-core` adapter that runs authorization and redaction, discards the
  governed document content, and emits a locally validated two-block Slack
  message containing only a same-origin HTTPS link to the authenticated app.

The URL contains only a short-lived, versioned opaque state handle. Its
server-side record is derived from the actor-bound correlation and must be
atomically consumed by the matching authenticated Databricks subject. The
package rejects off-origin/protocol-relative links, stale or replayed lifecycle
events, unverified ingress, stale kill-switch state, and arbitrary persistence
fields.

The package has no Lakebase implementation. If a later production implementation
needs these records, it must reserve app migration **47** and create only the
safe metadata fields represented here. Token values and Slack message bodies
must not be columns, JSON payloads, logs, traces, or evidence extensions.

See `docs/epic-09-slack-architecture-spike.md` for the threat model and the
evidence required to revisit the NO-GO.
