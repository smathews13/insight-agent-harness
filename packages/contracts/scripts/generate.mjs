import { createHash } from "node:crypto";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const SCHEMA_DIRECTORY = new URL("../schemas/", import.meta.url);
const TYPESCRIPT_OUTPUT = new URL("../src/generated/types.ts", import.meta.url);
const PYTHON_OUTPUT = new URL(
  "../src/insight_agent_harness_contracts/generated.py",
  import.meta.url,
);
const CHECK = process.argv.includes("--check");

const schemaFiles = readdirSync(SCHEMA_DIRECTORY)
  .filter((name) => name.endsWith(".schema.json"))
  .sort();
const schemas = new Map();
const hashes = {};

for (const fileName of schemaFiles) {
  const bytes = readFileSync(new URL(fileName, SCHEMA_DIRECTORY));
  schemas.set(fileName, JSON.parse(bytes.toString("utf8")));
  hashes[fileName] = createHash("sha256").update(bytes).digest("hex");
}

const combinedHash = createHash("sha256");
for (const fileName of schemaFiles) {
  combinedHash.update(fileName);
  combinedHash.update("\0");
  combinedHash.update(readFileSync(new URL(fileName, SCHEMA_DIRECTORY)));
  combinedHash.update("\0");
}
const schemaSetHash = combinedHash.digest("hex");

function schemaForRef(ref, rootSchema) {
  if (ref.startsWith("#/")) {
    return ref
      .slice(2)
      .split("/")
      .map((part) => part.replaceAll("~1", "/").replaceAll("~0", "~"))
      .reduce((value, part) => value?.[part], rootSchema);
  }
  const fileName = ref.split("#", 1)[0];
  const schema = schemas.get(fileName);
  if (!schema) throw new Error(`Unknown schema reference: ${ref}`);
  return schema;
}

function tsLiteral(value) {
  return JSON.stringify(value);
}

function tsType(schema, rootSchema = schema) {
  if (schema.$ref)
    return tsType(schemaForRef(schema.$ref, rootSchema), rootSchema);
  if (schema.const !== undefined) return tsLiteral(schema.const);
  if (schema.enum) return schema.enum.map(tsLiteral).join(" | ");
  if (schema.anyOf && !schema.type)
    return schema.anyOf.map((item) => tsType(item, rootSchema)).join(" | ");
  if (Array.isArray(schema.type)) {
    return schema.type
      .map((type) => tsType({ ...schema, type }, rootSchema))
      .join(" | ");
  }
  if (schema.type === "string") return "string";
  if (schema.type === "number" || schema.type === "integer") return "number";
  if (schema.type === "boolean") return "boolean";
  if (schema.type === "null") return "null";
  if (schema.type === "array")
    return `ReadonlyArray<${tsType(schema.items ?? {}, rootSchema)}>`;
  if (schema.type === "object" || schema.properties) {
    const required = new Set(schema.required ?? []);
    const lines = Object.entries(schema.properties ?? {}).map(
      ([name, property]) =>
        `  readonly ${JSON.stringify(name)}${required.has(name) ? "" : "?"}: ${tsType(property, rootSchema)};`,
    );
    if (schema.additionalProperties !== false) {
      const additional =
        schema.additionalProperties &&
        typeof schema.additionalProperties === "object"
          ? tsType(schema.additionalProperties, rootSchema)
          : "unknown";
      lines.push(`  readonly [key: string]: ${additional};`);
    }
    return `{\n${lines.join("\n")}\n}`;
  }
  return "unknown";
}

function pyLiteral(value) {
  if (value === null) return "None";
  if (value === true) return "True";
  if (value === false) return "False";
  return JSON.stringify(value);
}

function pythonClassName(value) {
  return value
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((part) => `${part[0].toUpperCase()}${part.slice(1)}`)
    .join("");
}

const pythonDefinitions = new Map();

function pyType(schema, nameHint = "AnonymousObject", rootSchema = schema) {
  if (schema.$ref)
    return pyType(schemaForRef(schema.$ref, rootSchema), nameHint, rootSchema);
  if (schema.const !== undefined) return `Literal[${pyLiteral(schema.const)}]`;
  if (schema.enum) return `Literal[${schema.enum.map(pyLiteral).join(", ")}]`;
  if (schema.anyOf && !schema.type) return "Any";
  if (Array.isArray(schema.type)) {
    return schema.type
      .map((type) => pyType({ ...schema, type }, nameHint, rootSchema))
      .join(" | ");
  }
  if (schema.type === "string") return "str";
  if (schema.type === "number") return "int | float";
  if (schema.type === "integer") return "int";
  if (schema.type === "boolean") return "bool";
  if (schema.type === "null") return "None";
  if (schema.type === "array") {
    return `list[${pyType(schema.items ?? {}, `${nameHint}Item`, rootSchema)}]`;
  }
  if (schema.type === "object" || schema.properties) {
    const properties = Object.entries(schema.properties ?? {});
    if (properties.length === 0) {
      const additional =
        schema.additionalProperties &&
        typeof schema.additionalProperties === "object"
          ? pyType(schema.additionalProperties, `${nameHint}Value`, rootSchema)
          : "Any";
      return `dict[str, ${additional}]`;
    }
    registerPythonDefinition(nameHint, schema, rootSchema);
    return nameHint;
  }
  return "Any";
}

function pythonArguments(value) {
  const arguments_ = [];
  let start = 0;
  let depth = 0;
  let quoted = false;
  let escaped = false;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (quoted) {
      if (escaped) {
        escaped = false;
      } else if (character === "\\") {
        escaped = true;
      } else if (character === '"') {
        quoted = false;
      }
      continue;
    }
    if (character === '"') {
      quoted = true;
    } else if ("[({".includes(character)) {
      depth += 1;
    } else if ("])}".includes(character)) {
      depth -= 1;
    } else if (character === "," && depth === 0) {
      arguments_.push(value.slice(start, index).trim());
      start = index + 1;
    }
  }
  arguments_.push(value.slice(start).trim());
  return arguments_;
}

function formattedPythonLiteral(prefix, literal, nested = false) {
  const arguments_ = pythonArguments(literal);
  const itemIndent = nested ? "            " : "        ";
  const closingIndent = nested ? "        " : "    ";
  const inlineItems = `${itemIndent}${arguments_.join(", ")}`;
  const lines = nested
    ? [`${prefix}list[`, `${closingIndent}Literal[`]
    : [`${prefix}Literal[`];
  if (inlineItems.length <= 100) {
    lines.push(inlineItems);
  } else {
    lines.push(...arguments_.map((argument) => `${itemIndent}${argument},`));
  }
  lines.push(`${closingIndent}]`);
  if (nested) lines.push("    ]");
  return lines;
}

function pythonPropertyLines(propertyName, propertyType) {
  const prefix = `    ${propertyName}: `;
  if (`${prefix}${propertyType}`.length <= 100) {
    return [`${prefix}${propertyType}`];
  }
  if (propertyType.startsWith("Literal[") && propertyType.endsWith("]")) {
    return formattedPythonLiteral(
      prefix,
      propertyType.slice("Literal[".length, -1),
    );
  }
  if (
    propertyType.startsWith("list[Literal[") &&
    propertyType.endsWith("]]")
  ) {
    return formattedPythonLiteral(
      `${prefix}`,
      propertyType.slice("list[Literal[".length, -2),
      true,
    );
  }
  return [`${prefix}${propertyType}`];
}

function registerPythonDefinition(name, schema, rootSchema = schema) {
  if (pythonDefinitions.has(name)) return;
  pythonDefinitions.set(name, "");
  const required = new Set(schema.required ?? []);
  const properties = Object.entries(schema.properties ?? {}).map(
    ([propertyName, property]) => [
      propertyName,
      pyType(property, `${name}${pythonClassName(propertyName)}`, rootSchema),
    ],
  );
  const optional = properties.filter(
    ([propertyName]) => !required.has(propertyName),
  );
  const requiredProperties = properties.filter(([propertyName]) =>
    required.has(propertyName),
  );
  const lines = [];
  if (optional.length > 0) {
    lines.push(`class _${name}Optional(TypedDict, total=False):`);
    for (const [propertyName, propertyType] of optional) {
      lines.push(...pythonPropertyLines(propertyName, propertyType));
    }
    lines.push("", "", `class ${name}(_${name}Optional):`);
  } else {
    lines.push(`class ${name}(TypedDict):`);
  }
  if (requiredProperties.length === 0) {
    lines.push("    pass");
  } else {
    for (const [propertyName, propertyType] of requiredProperties) {
      lines.push(...pythonPropertyLines(propertyName, propertyType));
    }
  }
  pythonDefinitions.set(name, lines.join("\n"));
}

function hashLines(prefix) {
  return schemaFiles.map((name) => `${prefix}${name}: sha256:${hashes[name]}`);
}

function riskMetadata() {
  const manifest = schemas.get("product-manifest.schema.json");
  return Object.fromEntries(
    Object.entries(manifest.properties)
      .filter(([, section]) => section["x-risk-class"])
      .map(([name, section]) => [
        name,
        {
          risk_class: section["x-risk-class"],
          runtime_editable: section["x-runtime-editable"],
        },
      ]),
  );
}

function generateTypescript() {
  const blocks = [];
  blocks.push(
    "// Generated by scripts/generate.mjs. DO NOT EDIT.",
    `// Schema set: sha256:${schemaSetHash}`,
    ...hashLines("// "),
    "",
  );
  for (const fileName of schemaFiles) {
    const schema = schemas.get(fileName);
    blocks.push(`export type ${schema.title} = ${tsType(schema, schema)};`, "");
  }
  blocks.push(
    `export const MANIFEST_RISK_METADATA = ${JSON.stringify(riskMetadata(), null, 2)} as const;`,
    "",
  );
  return `${blocks.join("\n")}`;
}

function generatePython() {
  pythonDefinitions.clear();
  for (const fileName of schemaFiles) {
    const schema = schemas.get(fileName);
    registerPythonDefinition(schema.title, schema, schema);
  }

  const blocks = [];
  blocks.push(
    '"""Generated contract types. Do not edit."""',
    "",
    "from __future__ import annotations",
    "",
    "from typing import Any, Literal, TypedDict",
    "",
    `SCHEMA_SET_SHA256 = "${schemaSetHash}"`,
    "SCHEMA_SHA256 = {",
  );
  for (const fileName of schemaFiles) {
    blocks.push(
      `    ${JSON.stringify(fileName)}: ${JSON.stringify(hashes[fileName])},`,
    );
  }
  blocks.push("}", "", "");

  for (const definition of pythonDefinitions.values()) {
    blocks.push(definition, "", "");
  }

  const metadata = riskMetadata();
  blocks.push(
    "MANIFEST_RISK_METADATA = {",
    ...Object.entries(metadata).map(
      ([name, values]) =>
        `    ${JSON.stringify(name)}: {"risk_class": ${JSON.stringify(values.risk_class)}, "runtime_editable": ${values.runtime_editable ? "True" : "False"}},`,
    ),
    "}",
    "",
  );
  return `${blocks.join("\n")}`;
}

function writeOrCheck(url, content) {
  if (CHECK) {
    let existing;
    try {
      existing = readFileSync(url, "utf8");
    } catch {
      throw new Error(
        `Generated file is missing: ${fileURLToPath(url).replace(`${ROOT}/`, "")}`,
      );
    }
    if (existing !== content) {
      throw new Error(
        `Generated file drift: ${fileURLToPath(url).replace(`${ROOT}/`, "")}. Run npm run generate.`,
      );
    }
    return;
  }
  writeFileSync(url, content, "utf8");
}

writeOrCheck(TYPESCRIPT_OUTPUT, generateTypescript());
writeOrCheck(PYTHON_OUTPUT, generatePython());
console.log(
  `${CHECK ? "Checked" : "Generated"} ${schemaFiles.length} schemas (sha256:${schemaSetHash}).`,
);
