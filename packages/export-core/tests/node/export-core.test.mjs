import assert from "node:assert/strict";
import test from "node:test";

import {
  ExportAdapterUnavailableError,
  EXPORT_ADAPTER_THREAT_CONTRACT,
  ExportAuthorizationError,
  ExportRedactionError,
  approvePptxOutline,
  adaptDelimited,
  adaptHtml,
  adaptJson,
  adaptMarkdown,
  adaptPdf,
  adaptPng,
  adaptXlsx,
  createCanonicalDocument,
  createCompiledExportAdapterRegistry,
  createExportArtifact,
  createPptxOutlineDraft,
  exportDocument,
  loadProductExportAdapters,
  renderApprovedPptx,
  validateExportBinary,
} from "../../src/index.js";

const documentFixture = () => ({
  schema_version: "1.0.0",
  document_id: "doc_report",
  revision_id: "rev_7",
  title: "Usage report",
  generated_at: "2026-09-13T20:00:00.000Z",
  freshness: {
    as_of: "2026-09-13T19:55:00.000Z",
    status: "current",
  },
  caveats: ["Preliminary values"],
  evidence_refs: [
    {
      schema_version: "1.0.0",
      evidence_id: "ev_usage",
      source_kind: "dataset",
      source_ref: "dataset:usage-daily",
      retrieved_at: "2026-09-13T19:55:00Z",
      excerpt: "Daily usage",
      details: {
        summary: "Governed evidence",
        diagnostics: { prompt: "must not escape" },
      },
      raw_trace: { prompt: "must not escape" },
      provider_payload: { token: "must not escape" },
      sql: "SELECT secret FROM governed_table",
    },
  ],
  sections: [
    {
      id: "summary",
      heading: "Summary",
      blocks: [
        {
          type: "paragraph",
          text: "Usage was stable.",
          evidence_ids: ["ev_usage"],
          raw_trace: "must not escape",
        },
        {
          type: "list",
          items: [
            "Public item",
            {
              label: "Structured item",
              nested: {
                value: 1,
                hidden_diagnostics: { secret: "must not escape" },
              },
            },
          ],
          evidence_ids: ["ev_usage"],
        },
        {
          type: "table",
          artifact_id: "usage_table",
          columns: [
            { key: "team", label: "Team" },
            { key: "units", label: "Units" },
            { key: "context", label: "Context" },
            { key: "raw_trace", label: "Raw trace" },
          ],
          rows: [
            {
              team: "A, Inc.",
              units: 12,
              context: {
                region: "us",
                raw_traces: [{ secret: "must not escape" }],
              },
              raw_trace: "must not escape",
              hidden_diagnostic: "secret",
            },
            { team: "B", units: 9, context: { region: "eu" } },
          ],
          evidence_ids: ["ev_usage"],
        },
      ],
    },
  ],
  diagnostics: { prompt: "hidden" },
  raw_traces: [{ token: "hidden" }],
});

const allow = () => true;
const redactIdentity = (document) => document;
const compiledBinaryAdapters = (formats, adapter) => {
  const ref = `export-adapter:sample-neutral/${formats.join("-")}`;
  return loadProductExportAdapters(
    {
      external_enabled: true,
      formats,
      adapter_refs: [ref],
      egress_policy_ref: "policy:export-egress-v1",
      redaction_profile_ref: "policy:export-redaction-v1",
    },
    createCompiledExportAdapterRegistry([
      {
        ref,
        owner: "sample-neutral",
        formats,
        adapter,
        threatContractRef: EXPORT_ADAPTER_THREAT_CONTRACT,
        egressPolicyRef: "policy:export-egress-v1",
        redactionProfileRef: "policy:export-redaction-v1",
      },
    ]),
  );
};

test("ProductManifest export registration selects compiled allowlisted adapters only", () => {
  const adapter = async () => new Uint8Array([1, 2, 3]);
  const registry = createCompiledExportAdapterRegistry([
    {
      ref: "export-adapter:sample-neutral/pdf",
      owner: "sample-neutral",
      formats: ["pdf"],
      adapter,
      threatContractRef: EXPORT_ADAPTER_THREAT_CONTRACT,
      egressPolicyRef: "policy:export-egress-v1",
      redactionProfileRef: "policy:export-redaction-v1",
    },
  ]);
  const selected = loadProductExportAdapters(
    {
      external_enabled: true,
      formats: ["pdf"],
      adapter_refs: ["export-adapter:sample-neutral/pdf"],
      egress_policy_ref: "policy:export-egress-v1",
      redaction_profile_ref: "policy:export-redaction-v1",
    },
    registry,
  );
  assert.equal(selected.pdf, adapter);
  assert.equal("register" in registry, false);
  assert.throws(
    () =>
      loadProductExportAdapters(
        {
          external_enabled: true,
          formats: ["pdf"],
          adapter_refs: ["export-adapter:request/module-path"],
          egress_policy_ref: "policy:export-egress-v1",
          redaction_profile_ref: "policy:export-redaction-v1",
        },
        registry,
      ),
    ExportAdapterUnavailableError,
  );
});

test("export adapter registry rejects module loading, policy drift, and forged registries", () => {
  assert.throws(
    () =>
      createCompiledExportAdapterRegistry([
        {
          ref: "export-adapter:sample-neutral/pdf",
          owner: "sample-neutral",
          formats: ["pdf"],
          adapter: async () => new Uint8Array(),
          module: "../../downstream/adapter.js",
          threatContractRef: EXPORT_ADAPTER_THREAT_CONTRACT,
          egressPolicyRef: "policy:export-egress-v1",
          redactionProfileRef: "policy:export-redaction-v1",
        },
      ]),
    /unsupported fields/,
  );
  const registry = createCompiledExportAdapterRegistry([
    {
      ref: "export-adapter:sample-neutral/pdf",
      owner: "sample-neutral",
      formats: ["pdf"],
      adapter: async () => new Uint8Array(),
      threatContractRef: EXPORT_ADAPTER_THREAT_CONTRACT,
      egressPolicyRef: "policy:export-egress-v1",
      redactionProfileRef: "policy:export-redaction-v1",
    },
  ]);
  assert.throws(
    () =>
      loadProductExportAdapters(
        {
          external_enabled: true,
          formats: ["pdf"],
          adapter_refs: ["export-adapter:sample-neutral/pdf"],
          egress_policy_ref: "policy:other-egress",
          redaction_profile_ref: "policy:export-redaction-v1",
        },
        registry,
      ),
    /does not match ProductManifest policy contracts/,
  );
  assert.throws(
    () =>
      createCompiledExportAdapterRegistry([
        {
          ref: "export-adapter:other/pdf",
          owner: "sample-neutral",
          formats: ["pdf"],
          adapter: async () => new Uint8Array(),
          threatContractRef: EXPORT_ADAPTER_THREAT_CONTRACT,
          egressPolicyRef: "policy:export-egress-v1",
          redactionProfileRef: "policy:export-redaction-v1",
        },
      ]),
    /invalid/,
  );
  assert.throws(
    () =>
      loadProductExportAdapters(
        {
          external_enabled: true,
          formats: ["pdf"],
          adapter_refs: ["export-adapter:sample-neutral/pdf"],
          egress_policy_ref: "policy:export-egress-v1",
          redaction_profile_ref: "policy:export-redaction-v1",
        },
        { resolve: registry.resolve },
      ),
    /registry created from compiled registrations/,
  );
});

const CRC_TABLE = Array.from({ length: 256 }, (_, byte) => {
  let value = byte;
  for (let bit = 0; bit < 8; bit += 1) {
    value = (value & 1) !== 0 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  }
  return value >>> 0;
});
const crc32 = (bytes) => {
  let value = 0xffffffff;
  for (const byte of bytes) value = CRC_TABLE[(value ^ byte) & 0xff] ^ (value >>> 8);
  return (value ^ 0xffffffff) >>> 0;
};

test("canonical documents exclude diagnostics, traces, and undeclared row fields", () => {
  const canonical = createCanonicalDocument(documentFixture());
  assert.equal(Object.hasOwn(canonical, "diagnostics"), false);
  assert.equal(Object.hasOwn(canonical, "raw_traces"), false);
  assert.deepEqual(canonical.sections[0].blocks[1].items[1], {
    label: "Structured item",
    nested: { value: 1 },
  });
  assert.deepEqual(canonical.sections[0].blocks[2].rows[0], {
    team: "A, Inc.",
    units: 12,
    context: { region: "us" },
  });
  assert.doesNotMatch(adaptJson(canonical), /hidden|secret|prompt/);
  assert.doesNotMatch(adaptJson(canonical), /provider_payload|SELECT secret/);
});

test("content-bearing hidden diagnostics and traces are rejected recursively", () => {
  for (const mutate of [
    (document) => {
      document.sections[0].blocks[1].items[1].nested.value =
        "raw trace payload";
    },
    (document) => {
      document.sections[0].blocks[2].rows[0].context.note =
        "hidden diagnostics dump";
    },
    (document) => {
      document.evidence_refs[0].excerpt = "raw_trace payload";
    },
    (document) => {
      document.evidence_refs[0].details.summary = "hidden-diagnostic payload";
    },
  ]) {
    const document = documentFixture();
    mutate(document);
    assert.throws(
      () => createCanonicalDocument(document),
      /contains hidden diagnostic, raw trace, or SQL content/,
    );
  }
});

test("canonical documents reject SQL-bearing content and impossible freshness", () => {
  const sql = documentFixture();
  sql.sections[0].blocks[0].text = "SELECT secret FROM governed_table";
  assert.throws(() => createCanonicalDocument(sql), /raw trace, or SQL content/);

  const future = documentFixture();
  future.freshness.as_of = "2026-09-13T20:00:01.000Z";
  assert.throws(() => createCanonicalDocument(future), /cannot be later than generated_at/);

  const futureEvidence = documentFixture();
  futureEvidence.evidence_refs[0].retrieved_at = "2026-09-13T20:00:01.000Z";
  assert.throws(() => createCanonicalDocument(futureEvidence), /retrieved_at cannot be later/);
});

test("Markdown and JSON deterministically preserve export metadata", () => {
  const document = documentFixture();
  assert.equal(adaptJson(document), adaptJson(structuredClone(document)));
  assert.match(adaptJson(document), /[^\n]\n$/);
  assert.doesNotMatch(adaptJson(document), /\n\n$/);
  const markdown = adaptMarkdown(document);
  assert.match(markdown, /Revision: `rev_7`/);
  assert.match(markdown, /Freshness: 2026-09-13T19:55:00.000Z \(current\)/);
  assert.match(markdown, /Preliminary values/);
  assert.match(markdown, /ev_usage/);
  assert.doesNotMatch(markdown, /raw_trace|must not escape/);
});

test("CSV and TSV are deterministic and artifact metadata preserves context", async () => {
  const document = documentFixture();
  assert.equal(
    adaptDelimited(document, "usage_table", ","),
    'Team,Units,Context\n"A, Inc.",12,"{""region"":""us""}"\nB,9,"{""region"":""eu""}"\n',
  );
  assert.equal(
    adaptDelimited(document, "usage_table", "\t"),
    'Team\tUnits\tContext\nA, Inc.\t12\t"{""region"":""us""}"\nB\t9\t"{""region"":""eu""}"\n',
  );

  const artifact = await exportDocument(document, {
    format: "csv",
    sourceArtifactId: "usage_table",
    authorize: allow,
    redact: redactIdentity,
  });
  assert.equal(artifact.revision_id, "rev_7");
  assert.deepEqual(artifact.freshness, document.freshness);
  assert.deepEqual(artifact.caveats, document.caveats);
  assert.deepEqual(
    artifact.evidence_refs,
    createCanonicalDocument(document).evidence_refs,
  );
});

test("CSV, TSV, and XLSX neutralize spreadsheet formula injection without changing numeric cells", () => {
  const document = documentFixture();
  document.sections[0].blocks[2].rows[0].team = "=HYPERLINK(\"https://invalid.example\")";
  document.sections[0].blocks[2].rows[1].team = "\t-2+3";
  document.sections[0].blocks[2].rows[1].units = -9;

  const csv = adaptDelimited(document, "usage_table", ",");
  const tsv = adaptDelimited(document, "usage_table", "\t");
  const xlsx = new TextDecoder().decode(adaptXlsx(document, "usage_table"));
  assert.match(csv, /"'=HYPERLINK/);
  assert.match(tsv, /'\t-2\+3/);
  assert.match(csv, /,-9,/);
  assert.match(xlsx, /&apos;=HYPERLINK/);
  assert.match(xlsx, /<v>-9<\/v>/);
  assert.doesNotMatch(xlsx, /<f>/);
});

test("HTML and XLSX deterministically preserve revision, freshness, evidence, and safe content", async () => {
  const document = documentFixture();
  const html = adaptHtml(document);
  assert.equal(html, adaptHtml(structuredClone(document)));
  assert.match(html, /<!doctype html>/);
  assert.match(html, /rev_7/);
  assert.match(html, /2026-09-13T19:55:00.000Z/);
  assert.match(html, /ev_usage/);
  assert.doesNotMatch(html, /SELECT secret|must not escape|raw_trace/);

  const xlsx = adaptXlsx(document, "usage_table");
  assert.deepEqual(xlsx, adaptXlsx(structuredClone(document), "usage_table"));
  assert.deepEqual([...xlsx.slice(0, 4)], [0x50, 0x4b, 0x03, 0x04]);
  assert.equal(validateExportBinary("xlsx", xlsx), true);
  const workbook = new TextDecoder("latin1").decode(xlsx);
  assert.match(workbook, /xl\/workbook.xml/);
  assert.match(workbook, /rev_7/);
  assert.match(workbook, /ev_usage/);
  assert.doesNotMatch(workbook, /SELECT secret|must not escape|raw_trace/);

  for (const format of ["html", "xlsx"]) {
    const artifact = await exportDocument(document, {
      format,
      sourceArtifactId: format === "xlsx" ? "usage_table" : undefined,
      authorize: allow,
      redact: redactIdentity,
    });
    assert.equal(artifact.revision_id, "rev_7");
    assert.deepEqual(artifact.freshness, document.freshness);
    assert.deepEqual(
      artifact.evidence_refs,
      createCanonicalDocument(document).evidence_refs,
    );
  }
});

test("HTML and PDF escape active markup and PDF string delimiters", () => {
  const document = documentFixture();
  document.title = "<script>alert(\"title\")</script>";
  document.sections[0].blocks[0].text =
    "<img src=x onerror=alert(1)> (draft) \\ end";
  const html = adaptHtml(document);
  const pdf = new TextDecoder("latin1").decode(adaptPdf(document));

  assert.doesNotMatch(html, /<script>|<img /);
  assert.match(html, /&lt;script&gt;/);
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.match(pdf, /\\\(draft\\\) \\\\ end/);
  assert.doesNotMatch(pdf, /\(<img src=x onerror=alert\(1\)> \(draft\)/);
});

test("dependency-free PDF and bounded document/table PNG adapters emit validated deterministic binaries", async () => {
  const document = documentFixture();
  const pdf = adaptPdf(document);
  const documentPng = adaptPng(document);
  const tablePng = adaptPng(document, "usage_table");
  assert.deepEqual(pdf, adaptPdf(structuredClone(document)));
  assert.deepEqual(documentPng, adaptPng(structuredClone(document)));
  assert.notDeepEqual(documentPng, tablePng);
  assert.equal(new TextDecoder("latin1").decode(pdf.slice(0, 8)), "%PDF-1.4");
  assert.deepEqual(
    [...documentPng.slice(0, 8)],
    [137, 80, 78, 71, 13, 10, 26, 10],
  );
  assert.equal(validateExportBinary("pdf", pdf), true);
  assert.equal(validateExportBinary("png", documentPng), true);
  assert.doesNotMatch(
    new TextDecoder("latin1").decode(pdf),
    /SELECT secret|must not escape|raw_trace/,
  );
  for (const [format, original, offset] of [
    ["pdf", pdf, pdf.byteLength - 8],
    ["png", documentPng, 40],
    ["xlsx", adaptXlsx(document, "usage_table"), 40],
  ]) {
    const corrupted = original.slice();
    corrupted[offset] ^= 1;
    assert.throws(
      () => validateExportBinary(format, corrupted),
      /invalid|truncated|omitted|checksum|does not match/i,
    );
  }

  for (const [format, sourceArtifactId] of [
    ["pdf", undefined],
    ["png", undefined],
    ["png", "usage_table"],
  ]) {
    const artifact = await exportDocument(document, {
      format,
      sourceArtifactId,
      authorize: allow,
      redact: redactIdentity,
    });
    assert.equal(artifact.revision_id, "rev_7");
    assert.deepEqual(artifact.freshness, document.freshness);
    assert.ok(artifact.content instanceof Uint8Array);
  }
});

test("binary validators reject unsafe XLSX paths and oversized PNG dimensions", () => {
  const document = documentFixture();
  const xlsx = adaptXlsx(document, "usage_table").slice();
  const originalName = new TextEncoder().encode("[Content_Types].xml");
  const unsafeName = new TextEncoder().encode("../evil_payload.xml");
  assert.equal(originalName.byteLength, unsafeName.byteLength);
  for (let offset = 0; offset <= xlsx.byteLength - originalName.byteLength; offset += 1) {
    if (originalName.every((byte, index) => xlsx[offset + index] === byte)) {
      xlsx.set(unsafeName, offset);
    }
  }
  assert.throws(() => validateExportBinary("xlsx", xlsx), /entry name or checksum is invalid/);

  const png = adaptPng(document).slice();
  const view = new DataView(png.buffer, png.byteOffset, png.byteLength);
  view.setUint32(16, 9000, false);
  const ihdrTypeAndData = png.slice(12, 29);
  view.setUint32(29, crc32(ihdrTypeAndData), false);
  assert.throws(() => validateExportBinary("png", png), /invalid chunk structure/);
});

test("PNG rendering refuses resource-amplifying documents before allocating pixels", () => {
  const document = documentFixture();
  document.sections[0].blocks[0].text = "safe words ".repeat(100_000).trim();
  assert.throws(() => adaptPng(document), /too large for a bounded PNG/);
});

test("exports deny missing and negative authorization decisions", async () => {
  await assert.rejects(
    exportDocument(documentFixture(), {
      format: "json",
      redact: redactIdentity,
    }),
    ExportAuthorizationError,
  );
  let redactionCalled = false;
  await assert.rejects(
    exportDocument(documentFixture(), {
      format: "json",
      authorize: () => ({ allowed: false, reason: "scope denied" }),
      redact: () => {
        redactionCalled = true;
      },
    }),
    /scope denied/,
  );
  assert.equal(redactionCalled, false);
});

test("external exports reject missing redaction policy hooks", async () => {
  const document = documentFixture();
  document.sections[0].blocks[0].text = "secret: customer-password";
  await assert.rejects(
    exportDocument(document, { format: "json", authorize: allow }),
    ExportRedactionError,
  );

  const artifact = await exportDocument(document, {
    format: "json",
    authorize: allow,
    redact: (candidate) => {
      candidate.sections[0].blocks[0].text = "[redacted]";
    },
  });
  assert.doesNotMatch(artifact.content, /customer-password/);
});

test("redaction may change content but cannot change revision identity", async () => {
  const artifact = await exportDocument(documentFixture(), {
    format: "json",
    authorize: allow,
    redact: (document) => {
      document.sections[0].blocks[0].text = "[redacted]";
    },
  });
  assert.match(artifact.content, /\[redacted\]/);

  await assert.rejects(
    exportDocument(documentFixture(), {
      format: "json",
      authorize: allow,
      redact: (document) => {
        document.revision_id = "rev_8";
      },
    }),
    /redaction cannot change document identity/,
  );
});

test("redaction cannot remove evidence or caveats", async () => {
  await assert.rejects(
    exportDocument(documentFixture(), {
      format: "markdown",
      authorize: allow,
      redact: (document) => {
        document.evidence_refs = [];
        document.caveats = [];
        document.sections[0].blocks[0].evidence_ids = [];
        document.sections[0].blocks[1].evidence_ids = [];
        document.sections[0].blocks[2].evidence_ids = [];
      },
    }),
    /quantitative content but has no evidence|redaction cannot change document identity/,
  );
});

test("redaction may scrub evidence excerpts but cannot alter evidence identity", async () => {
  for (const mutate of [
    (document) => {
      document.evidence_refs[0].excerpt = "[redacted]";
    },
    (document) => {
      document.evidence_refs[0].details.summary = "[redacted]";
    },
  ]) {
    const artifact = await exportDocument(documentFixture(), {
      format: "json",
      authorize: allow,
      redact: mutate,
    });
    assert.match(artifact.content, /\[redacted\]/);
  }

  await assert.rejects(
    exportDocument(documentFixture(), {
      format: "json",
      authorize: allow,
      redact: (document) => {
        document.evidence_refs[0].source_ref = "dataset:other";
      },
    }),
    /redaction cannot change document identity/,
  );
});

test("redaction cannot inject hidden diagnostic content", async () => {
  await assert.rejects(
    exportDocument(documentFixture(), {
      format: "json",
      authorize: allow,
      redact: (document) => {
        document.sections[0].blocks[0].text = "raw trace payload";
      },
    }),
    /contains hidden diagnostic, raw trace, or SQL content/,
  );
});

test("redaction cannot alter revision or freshness metadata", async () => {
  for (const mutate of [
    (document) => {
      document.revision_id = "rev_8";
    },
    (document) => {
      document.freshness.as_of = "2026-09-13T19:56:00.000Z";
    },
    (document) => {
      document.freshness.status = "stale";
    },
  ]) {
    await assert.rejects(
      exportDocument(documentFixture(), {
        format: "json",
        authorize: allow,
        redact: mutate,
      }),
      /redaction cannot change document identity/,
    );
  }
});

test("redaction cannot detach content from preserved evidence", async () => {
  await assert.rejects(
    exportDocument(documentFixture(), {
      format: "markdown",
      authorize: allow,
      redact: (document) => {
        document.sections[0].blocks[0].evidence_ids = [];
      },
    }),
    /redaction cannot change document identity/,
  );
});

test("redaction cannot rewrite quantitative strings stored in table cells", async () => {
  const document = documentFixture();
  document.sections[0].blocks[2].rows[0].units = "12%";
  await assert.rejects(
    exportDocument(document, {
      format: "json",
      authorize: allow,
      redact: (candidate) => {
        candidate.sections[0].blocks[2].rows[0].units = "99%";
      },
    }),
    /redaction cannot change document identity/,
  );
});

test("binary formats require policy hooks and preserve only canonical metadata", async () => {
  assert.throws(
    () =>
      createExportArtifact({
        document: documentFixture(),
        format: "png",
        content: new Uint8Array([1]),
        mediaType: "image/png",
        fileExtension: "png",
      }),
    /must be created through exportDocument with policy hooks/,
  );

  await assert.rejects(
    exportDocument(documentFixture(), {
      format: "png",
      redact: redactIdentity,
    }),
    ExportAuthorizationError,
  );

  await assert.rejects(
    exportDocument(documentFixture(), {
      format: "png",
      authorize: allow,
    }),
    ExportRedactionError,
  );

  await assert.rejects(
    exportDocument(documentFixture(), {
      format: "png",
      authorize: allow,
      redact: redactIdentity,
      binaryAdapters: { png: () => adaptPng(documentFixture()) },
    }),
    /must come from the compiled ProductManifest export registry/,
  );

  let adapterCalled = false;
  await assert.rejects(
    exportDocument(documentFixture(), {
      format: "png",
      redact: redactIdentity,
      binaryAdapters: compiledBinaryAdapters(["png"], () => {
        adapterCalled = true;
        return adaptPng(documentFixture());
      }),
    }),
    ExportAuthorizationError,
  );
  await assert.rejects(
    exportDocument(documentFixture(), {
      format: "png",
      authorize: allow,
      binaryAdapters: compiledBinaryAdapters(["png"], () => {
        adapterCalled = true;
        return adaptPng(documentFixture());
      }),
    }),
    ExportRedactionError,
  );
  assert.equal(adapterCalled, false);

  await assert.rejects(
    exportDocument(documentFixture(), {
      format: "png",
      authorize: allow,
      redact: redactIdentity,
      binaryAdapters: compiledBinaryAdapters(["png"], () => ({
        content: adaptPng(documentFixture()),
        mediaType: "application/pdf",
      })),
    }),
    /content metadata outside its allowlisted format/,
  );

  const compiledArtifact = await exportDocument(documentFixture(), {
    format: "png",
    authorize: allow,
    redact: redactIdentity,
    binaryAdapters: compiledBinaryAdapters(["png"], (document) => {
      adapterCalled = true;
      return {
        content: adaptPng(document),
        mediaType: "image/png",
        fileExtension: "png",
        metadata: { raw_trace: "must not escape" },
      };
    }),
  });
  assert.equal(adapterCalled, true);
  assert.equal(compiledArtifact.media_type, "image/png");
  assert.equal(compiledArtifact.file_extension, "png");
  assert.equal(Object.hasOwn(compiledArtifact, "metadata"), false);

  const artifact = await exportDocument(documentFixture(), {
    format: "png",
    authorize: allow,
    redact: redactIdentity,
  });
  assert.deepEqual(
    [...artifact.content.slice(0, 8)],
    [137, 80, 78, 71, 13, 10, 26, 10],
  );
  assert.equal(artifact.media_type, "image/png");
  assert.equal(artifact.revision_id, "rev_7");
  assert.equal(Object.hasOwn(artifact, "metadata"), false);
  assert.doesNotMatch(
    JSON.stringify(artifact),
    /must not escape|rev_tampered|raw_trace/,
  );
});

test("unknown evidence references fail before authorization", async () => {
  const document = documentFixture();
  document.sections[0].blocks[0].evidence_ids = ["ev_missing"];
  await assert.rejects(
    exportDocument(document, {
      format: "json",
      authorize: allow,
      redact: redactIdentity,
    }),
    /unknown evidence/,
  );
});

test("quantitative figures, tables, and chart series require known evidence", () => {
  const document = documentFixture();
  document.sections[0].blocks.push(
    {
      type: "figure",
      artifact_id: "players_total",
      label: "Players",
      value: 42,
      display: "42",
      evidence_ids: [],
    },
    {
      type: "chart",
      artifact_id: "players_chart",
      title: "Players",
      kind: "bar",
      series: [{ x: ["A"], y: [42] }],
      evidence_ids: [],
    },
  );
  assert.throws(
    () => createCanonicalDocument(document),
    /quantitative figure but has no evidence/,
  );
  document.sections[0].blocks.at(-2).evidence_ids = ["ev_usage"];
  assert.throws(
    () => createCanonicalDocument(document),
    /chart series but has no evidence/,
  );
  document.sections[0].blocks.at(-1).evidence_ids = ["ev_usage"];
  const canonical = createCanonicalDocument(document);
  assert.equal(canonical.sections[0].blocks.at(-2).value, 42);
  assert.deepEqual(canonical.sections[0].blocks.at(-1).series[0].y, [42]);
});

test("PPTX remains typed unavailable even when an arbitrary adapter is supplied", async () => {
  const document = { ...documentFixture(), schema_version: "1.1.0" };
  const draft = createPptxOutlineDraft(document);
  assert.equal(draft.state, "draft");
  await assert.rejects(
    renderApprovedPptx(draft),
    /explicitly approved outline/,
  );
  const approved = approvePptxOutline(draft, {
    approvedBy: "user:test",
    approvedAt: "2026-09-13T20:01:00.000Z",
  });
  await assert.rejects(
    renderApprovedPptx(approved, {
      adapter: () => new Uint8Array([0x50, 0x4b, 0x03, 0x04]),
    }),
    ExportAdapterUnavailableError,
  );
});
