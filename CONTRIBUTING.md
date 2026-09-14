# Contributing

The private internal repository is the source of truth. Shared changes belong in
the Harness; product names, prompts, knowledge, tool selection, Genie spaces,
resources, settings, migrations, and export chrome belong in a downstream
overlay.

Before proposing a shared change:

1. add or extend a neutral ProductManifest seam;
2. preserve user authorization and fail-closed data boundaries;
3. add contract and negative-boundary tests;
4. run ownership, neutral-surface, materialization, type, lint, and unit checks;
5. do not add GitHub workflows, a live upstream `overlays/` directory, customer
   identifiers, or a new `LEGACY_PRODUCT_*` compatibility alias.
