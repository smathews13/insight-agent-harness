# ProductManifest extension contract

`ProductManifest` is the only supported customization boundary between the
Harness and a downstream distribution. It is closed at every level: unknown
fields fail materialization, and manifest values cannot select an identity,
grant Unity Catalog access, or name an arbitrary endpoint.

## Slots

| Manifest slot | Overlay directory | Owns |
| --- | --- | --- |
| `branding` | `assets/` | Public-safe marks, icons, palette references |
| `navigation` | `navigation/` | Labels and ordered entries for routes the upstream already exposes |
| `loading` | `loading/` | Optional loading treatment and accessible status labels |
| `prompts` | `prompts/` | Versioned system/task prompt packs |
| `knowledge` | `knowledge/` | Product terminology and retrieval packs |
| `tool_registry` | `tools/` | Selection from upstream governed adapters |
| `genie_mode` | `genie/` | Genie mode, role labels, and curated-space references |
| `resources` | `resources/` | Bundle bindings and generated resource names |
| `migrations` | `migrations/` | Product-owned migration bodies for the upstream runner |
| `settings` | `settings/` | Safe defaults and presentation chrome |
| `export_chrome` | `export/` | Document title, public-safe assets, footer, and egress labels |

Slot values are opaque `extension:<slot>/<name>` references, not filesystem or
module import paths. Upstream source never imports `overlays/`, and downstream
content is copied only under generated `.harness/extensions/`.

The upstream migration ledger is immutable through core migration 47.
Downstream migration sets begin at version 48; they append through the
`migrations` slot and never renumber or replace core migrations.

Operational implementations use immutable compiled registries bound to the
same committed ProductManifest. Session administration, analytical admission, retention,
migrations, and exports are documented in
[`operational-extension-seams.md`](operational-extension-seams.md).

The browser receives only product/presentation values, capability status, and
the five presentation-safe extension references. Prompt, knowledge, tool,
Genie, resource, authorization, and data-boundary references remain server-side.

## Security invariants

- Tool ids must resolve in an upstream governed registry.
- Genie evidence always executes with the verified authorization mode.
- Resource references cannot create grants or broaden the data boundary.
- Runtime-editable settings are an explicit allowlist.
- Export chrome cannot disable redaction or egress policy.
- Product code that needs a new behavior adds a neutral upstream seam first.
