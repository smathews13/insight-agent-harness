# `scripts/`: test instruments for our own demo workspace

> ## INTERNAL ONLY
>
> Excluded from the publication (`../mirror/publish-exclude.txt`). Nothing here
> is part of the bundle, and nothing here may be added to a deploy path. These
> exist to test our demo estate, not to be provisioned into a customer's.

| Path | What it is |
| --- | --- |
| `identity-probe.sh` | Builds and checks the identity probe: a schema the developer can read by name and the app's service principal cannot |

## The identity probe, in one paragraph

Every Unity Catalog catalog in the demo metastore grants `account users` a read,
and that group holds service principals as well as people, so the app's service
principal and the signed-in developer read the same rows from everything. That
makes the requirement that the orchestrator execute as the SIGNED-IN USER
untestable by looking at results: a test asserting "the answer came back and the
numbers look right" passes whether or not identity forwarding works. The probe
is a schema with the opposite property, holding five invented rows whose only
interesting attribute is who can read them. Read the header of
`identity-probe.sh` before changing or deleting anything: the reasoning, and why
the probe could not be put in a Unity Catalog catalog, are written down there in
full.

```bash
PROFILE='<profile>' \
PIA_PROBE_SP_CLIENT_ID=<application-id-of-the-app-service-principal> \
PIA_PROBE_WAREHOUSE_ID=<warehouse the app and the developer can both use> \
PIA_PROBE_CATALOG=<parent catalog> \
  scripts/identity-probe.sh verify
```

`create` recreates the schema, its table and its grants from scratch. `verify`
asserts the instrument is still valid, and fails loudly rather than quietly when
it is not:

- the parent catalog grants a read to `account users`, `users`, any
  `users-clone*` group or the service principal, which the probe would inherit
  and no schema-level grant could take back;
- any of those principals holds any privilege on the schema or the table;
- the developer's read does not return exactly the five rows this script wrote,
  which is what tells a live probe apart from a dropped one;
- the service principal cannot reach the warehouse at all, since a warehouse
  denial reads exactly like the denial being measured;
- the service principal is refused with `TABLE_OR_VIEW_NOT_FOUND` rather than an
  insufficient-privilege error, which is what a dropped probe looks like;
- the service principal succeeds.

The denial this workspace actually produces is explicit rather than
existence-hiding, `SQLSTATE 42501` with `[INSUFFICIENT_PERMISSIONS]`, and the
matcher keys on that pair.

One thing it reports but does not fail on: the probe is unreadable **by name**,
not unreadable. Neither Unity Catalog nor table access control governs reads by
storage path, and the storage under this workspace is broadly granted. Tests
must read the probe by three-part name, which is what the app does.
