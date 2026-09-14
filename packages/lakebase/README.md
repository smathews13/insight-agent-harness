# Lakebase primitives

`@insight-agent-harness/lakebase` is the generic persistence boundary for the
harness. It has no registry dependencies and makes no connection to a
particular Lakebase instance.

It is built, tested, and consumed as a local root npm workspace package. It
requires no private registry or package publication step.

It owns:

- migration registration and applied-prefix/order validation;
- schema ownership and version decisions;
- optimistic revision checks and immutable updates;
- generic retention policies, candidate selection, and store/executor
  interfaces;
- append-only revision creation and chain validation.

It deliberately does not contain product migrations, schema DDL, customer SQL,
evidence queries, connection credentials, or deployment policy. Product code
supplies migrations and storage adapters from outside this package.

All helpers reject malformed or ambiguous state instead of repairing it
silently. Callers must provide revision IDs and timestamps; this package never
uses wall-clock time or random values, which keeps persistence behavior
deterministic in tests and retries.
