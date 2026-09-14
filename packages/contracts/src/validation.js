import { readFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';

const SCHEMA_DIRECTORIES = [
  // Workspace/path package layout.
  new URL('../schemas/', import.meta.url),
  // A bundled consumer may place schemas beside its emitted entrypoint.
  new URL('./schemas/', import.meta.url),
];
const schemaCache = new Map();

function loadSchema(name) {
  const fileName = name.endsWith('.schema.json') ? name : `${name}.schema.json`;
  if (!schemaCache.has(fileName)) {
    let loaded;
    let lastError;
    for (const directory of SCHEMA_DIRECTORIES) {
      try {
        loaded = JSON.parse(readFileSync(new URL(fileName, directory), 'utf8'));
        break;
      } catch (error) {
        lastError = error;
      }
    }
    if (!loaded) throw lastError;
    schemaCache.set(fileName, loaded);
  }
  return schemaCache.get(fileName);
}

function typeMatches(value, type) {
  if (type === 'null') return value === null;
  if (type === 'array') return Array.isArray(value);
  if (type === 'object') return value !== null && typeof value === 'object' && !Array.isArray(value);
  if (type === 'integer') return Number.isInteger(value);
  if (type === 'number') return typeof value === 'number' && Number.isFinite(value);
  return typeof value === type;
}

function stableValue(value) {
  if (value && typeof value === 'object') {
    if (Array.isArray(value)) return `[${value.map(stableValue).join(',')}]`;
    return `{${Object.keys(value).sort().map((key) => `${key}:${stableValue(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function localRef(rootSchema, ref) {
  return ref
    .slice(2)
    .split('/')
    .map((part) => part.replaceAll('~1', '/').replaceAll('~0', '~'))
    .reduce((current, part) => current?.[part], rootSchema);
}

function validateSchema(value, schema, path, errors, rootSchema = schema) {
  if (schema.$ref) {
    const referenced = schema.$ref.startsWith('#/')
      ? localRef(rootSchema, schema.$ref)
      : loadSchema(schema.$ref);
    if (!referenced) {
      errors.push(`${path}: schema reference ${schema.$ref} could not be resolved`);
      return;
    }
    validateSchema(value, referenced, path, errors, schema.$ref.startsWith('#/') ? rootSchema : referenced);
    return;
  }

  if (schema.const !== undefined && !isDeepStrictEqual(value, schema.const)) {
    errors.push(`${path}: must equal ${JSON.stringify(schema.const)}`);
    return;
  }
  if (schema.enum && !schema.enum.some((candidate) => isDeepStrictEqual(value, candidate))) {
    errors.push(`${path}: must be one of ${schema.enum.map(JSON.stringify).join(', ')}`);
    return;
  }
  if (schema.anyOf) {
    const matches = schema.anyOf.some((candidate) => {
      const candidateErrors = [];
      validateSchema(value, candidate, path, candidateErrors, rootSchema);
      return candidateErrors.length === 0;
    });
    if (!matches) errors.push(`${path}: must match one approved shape`);
  }

  if (schema.type) {
    const accepted = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!accepted.some((type) => typeMatches(value, type))) {
      errors.push(`${path}: must be ${accepted.join(' or ')}`);
      return;
    }
  }

  if (typeof value === 'string') {
    if (schema.minLength !== undefined && value.length < schema.minLength) {
      errors.push(`${path}: must contain at least ${schema.minLength} characters`);
    }
    if (schema.maxLength !== undefined && value.length > schema.maxLength) {
      errors.push(`${path}: must contain at most ${schema.maxLength} characters`);
    }
    if (schema.pattern && !(new RegExp(schema.pattern, 'u')).test(value)) {
      errors.push(`${path}: has an unsafe or unsupported format`);
    }
  }

  if (typeof value === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) {
      errors.push(`${path}: must be at least ${schema.minimum}`);
    }
    if (schema.maximum !== undefined && value > schema.maximum) {
      errors.push(`${path}: must be at most ${schema.maximum}`);
    }
  }

  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) {
      errors.push(`${path}: must contain at least ${schema.minItems} items`);
    }
    if (schema.maxItems !== undefined && value.length > schema.maxItems) {
      errors.push(`${path}: must contain at most ${schema.maxItems} items`);
    }
    if (schema.uniqueItems) {
      const values = value.map(stableValue);
      if (new Set(values).size !== values.length) errors.push(`${path}: items must be unique`);
    }
    if (schema.items) {
      value.forEach((item, index) =>
        validateSchema(item, schema.items, `${path}[${index}]`, errors, rootSchema)
      );
    }
  }

  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    const properties = schema.properties ?? {};
    for (const required of schema.required ?? []) {
      if (!Object.hasOwn(value, required)) errors.push(`${path}.${required}: is required`);
    }
    if (schema.minProperties !== undefined && Object.keys(value).length < schema.minProperties) {
      errors.push(`${path}: must contain at least ${schema.minProperties} properties`);
    }
    if (schema.maxProperties !== undefined && Object.keys(value).length > schema.maxProperties) {
      errors.push(`${path}: must contain at most ${schema.maxProperties} properties`);
    }
    for (const [key, item] of Object.entries(value)) {
      if (Object.hasOwn(properties, key)) {
        validateSchema(item, properties[key], `${path}.${key}`, errors, rootSchema);
      } else if (schema.additionalProperties === false) {
        errors.push(`${path}.${key}: unknown field is not allowed`);
      } else if (schema.additionalProperties && typeof schema.additionalProperties === 'object') {
        validateSchema(item, schema.additionalProperties, `${path}.${key}`, errors, rootSchema);
      }
    }
  }
}

function versionTuple(value) {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(value ?? '');
  return match ? match.slice(1).map(Number) : null;
}

function versionAtLeast(value, floor) {
  const candidate = versionTuple(value);
  const minimum = versionTuple(floor);
  if (!candidate || !minimum) return false;
  for (let index = 0; index < 3; index += 1) {
    if (candidate[index] !== minimum[index]) return candidate[index] > minimum[index];
  }
  return true;
}

function validateProductManifest(value, errors) {
  const capabilities = value.capabilities?.items ?? [];
  const byId = new Map();
  for (const capability of capabilities) {
    if (byId.has(capability.id)) errors.push(`$.capabilities.items: duplicate capability id ${capability.id}`);
    byId.set(capability.id, capability);
  }
  for (const capability of capabilities) {
    for (const dependency of capability.dependencies ?? []) {
      if (!byId.has(dependency)) {
        errors.push(`$.capabilities.items.${capability.id}: unknown dependency ${dependency}`);
      } else if (capability.enabled && !byId.get(dependency).enabled) {
        errors.push(`$.capabilities.items.${capability.id}: enabled capability depends on disabled ${dependency}`);
      }
    }
  }

  for (const toolId of value.tools?.enabled_tool_ids ?? []) {
    const capability = byId.get(toolId);
    if (!capability) {
      errors.push(`$.tools.enabled_tool_ids: unknown capability ${toolId}`);
    } else if (!capability.enabled) {
      errors.push(`$.tools.enabled_tool_ids: disabled capability ${toolId}`);
    }
  }

  const authorization = value.authorization ?? {};
  if (!(authorization.supported_modes ?? []).includes(authorization.default_mode)) {
    errors.push('$.authorization.default_mode: must be present in supported_modes');
  }
  if (authorization.default_mode === 'user_authorization') {
    if (!(authorization.user_scopes?.length > 0)) {
      errors.push('$.authorization.user_scopes: user_authorization requires at least one approved scope');
    }
    for (const tool of authorization.evidence_tools ?? []) {
      if (tool.auth_mode === 'explicit_service_principal') {
        errors.push(`$.authorization.evidence_tools.${tool.capability_id}: user_authorization forbids service-principal-only evidence tools`);
      }
    }
  }
  if ((authorization.supported_modes ?? []).includes('explicit_service_principal')) {
    for (const field of [
      'service_principal_policy_ref',
      'answer_label_disclosure_ref',
      'service_principal_data_boundary_ref',
      'audit_mode',
    ]) {
      if (!authorization[field]) {
        errors.push(`$.authorization.${field}: is required for explicit_service_principal`);
      }
    }
  }

  if ((value.genie?.space_refs ?? []).length !== (value.genie?.required_space_roles ?? []).length) {
    errors.push('$.genie.required_space_roles: must map one role to each space_ref');
  }
  if (value.genie?.mode === 'genie_only') {
    if (value.genie.allow_agent_authored_sql !== false) {
      errors.push('$.genie.allow_agent_authored_sql: genie_only requires false');
    }
    if (capabilities.some((capability) => capability.enabled && capability.kind === 'agent_sql')) {
      errors.push('$.capabilities.items: genie_only forbids enabled agent-authored SQL');
    }
  }

  if (value.operations?.mcp?.enabled) {
    for (const field of ['registered_adapter_ref', 'destination_policy_ref', 'signing_key_ref', 'kill_switch_ref']) {
      if (!value.operations.mcp[field]) errors.push(`$.operations.mcp.${field}: is required when MCP is enabled`);
    }
  }

  if (value.exports?.external_enabled) {
    for (const field of ['egress_policy_ref', 'redaction_profile_ref']) {
      if (!value.exports[field]) errors.push(`$.exports.${field}: is required for external export`);
    }
  }

  if (
    value.operations?.readiness_policy === 'strict_persistent_analytics'
    && !(value.resources?.bindings ?? []).some((binding) => binding.kind === 'lakebase_database')
  ) {
    errors.push('$.resources.bindings: strict_persistent_analytics requires a Lakebase database binding');
  }

  if (value.operations?.budget?.mode === 'enforced') {
    for (const field of ['reservation_policy_ref', 'reconciliation_policy_ref']) {
      if (!value.operations.budget[field]) {
        errors.push(`$.operations.budget.${field}: is required when budget enforcement is enabled`);
      }
    }
  }

  for (const [index, alias] of (value.compatibility?.aliases ?? []).entries()) {
    if (!versionAtLeast(alias.removal_version, '1.2.0')) {
      errors.push(`$.compatibility.aliases[${index}].removal_version: must be at least 1.2.0`);
    }
    if (/^(?:ADAPT_|LEGACY_PRODUCT_)/.test(alias.target) && alias.legacy_fixture !== true) {
      errors.push(`$.compatibility.aliases[${index}].target: new aliases cannot target legacy product names`);
    }
  }
}

function validateRequestContext(value, errors) {
  if (value.authorization?.mode === 'user_authorization' && !(value.authorization.scopes?.length > 0)) {
    errors.push('$.authorization.scopes: user_authorization requires at least one approved scope');
  }
  for (const field of ['authorization_mode', 'execution_mode']) {
    if (Object.hasOwn(value.input ?? {}, field)) {
      errors.push(`$.input.${field}: prompts cannot override the authenticated execution mode`);
    }
  }
}

function validateRunEnvelope(value, errors) {
  if (value.status === 'complete') {
    if (!value.output) errors.push('$.output: complete runs require output');
    if (value.error) errors.push('$.error: complete runs cannot contain an error');
    if (value.blocked_dependencies?.length) {
      errors.push('$.blocked_dependencies: complete runs cannot remain blocked');
    }
  } else if (value.status === 'blocked') {
    if (!(value.blocked_dependencies?.length > 0)) {
      errors.push('$.blocked_dependencies: blocked runs require at least one dependency');
    }
  } else if (value.status === 'error' && !value.error) {
    errors.push('$.error: error runs require an error envelope');
  }

  const evidenceIds = new Set((value.evidence ?? []).map((evidence) => evidence.evidence_id));
  for (const [index, block] of (value.output?.content_blocks ?? []).entries()) {
    if (block.kind === 'quantitative' && !(block.evidence_refs?.length > 0)) {
      errors.push(`$.output.content_blocks[${index}].evidence_refs: quantitative content requires evidence`);
    }
    for (const evidenceRef of block.evidence_refs ?? []) {
      if (!evidenceIds.has(evidenceRef)) {
        errors.push(`$.output.content_blocks[${index}].evidence_refs: unknown evidence ${evidenceRef}`);
      }
    }
  }
}

function validateErrorEnvelope(value, errors) {
  if (value.code === 'blocked_dependency' && !value.blocked_dependency) {
    errors.push('$.blocked_dependency: blocked_dependency errors require dependency detail');
  }
}

export function validateContract(schemaName, value) {
  const errors = [];
  validateSchema(value, loadSchema(schemaName), '$', errors);
  if (errors.length === 0) {
    const normalized = schemaName.replace(/\.schema\.json$/, '');
    if (normalized === 'product-manifest') validateProductManifest(value, errors);
    if (normalized === 'request-context') validateRequestContext(value, errors);
    if (normalized === 'run-envelope') validateRunEnvelope(value, errors);
    if (normalized === 'error-envelope') validateErrorEnvelope(value, errors);
  }
  return { valid: errors.length === 0, errors };
}

export function validateRuntimeManifestChange(before, after) {
  const errors = [
    ...validateContract('product-manifest', before).errors,
    ...validateContract('product-manifest', after).errors,
  ];
  const schema = loadSchema('product-manifest');
  for (const [section, sectionSchema] of Object.entries(schema.properties)) {
    if (sectionSchema['x-runtime-editable'] === false && !isDeepStrictEqual(before[section], after[section])) {
      errors.push(`$.${section}: privileged section is not runtime-editable`);
    }
  }
  return { valid: errors.length === 0, errors };
}

export function validateRequestAgainstManifest(request, manifest) {
  const errors = [
    ...validateContract('request-context', request).errors,
    ...validateContract('product-manifest', manifest).errors,
  ];
  if (request.authorization?.mode !== manifest.authorization?.default_mode) {
    errors.push('$.authorization.mode: request cannot switch the manifest execution mode');
  }
  return { valid: errors.length === 0, errors };
}

export function manifestRiskMetadata() {
  const schema = loadSchema('product-manifest');
  return Object.fromEntries(
    Object.entries(schema.properties)
      .filter(([, section]) => section['x-risk-class'])
      .map(([name, section]) => [
        name,
        {
          risk_class: section['x-risk-class'],
          runtime_editable: section['x-runtime-editable'],
        },
      ]),
  );
}
