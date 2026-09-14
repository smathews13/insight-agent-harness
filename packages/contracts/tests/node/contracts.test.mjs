import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  manifestRiskMetadata,
  validateContract,
  validateRequestAgainstManifest,
  validateRuntimeManifestChange,
} from '../../src/validation.js';

const fixtures = JSON.parse(
  readFileSync(new URL('../../fixtures/contracts.json', import.meta.url), 'utf8'),
);
const clone = (value) => structuredClone(value);

const validFixtures = [
  ['product-manifest', 'valid_neutral_manifest'],
  ['request-context', 'user_auth_request'],
  ['evidence-ref', 'evidence'],
  ['run-envelope', 'complete_run'],
  ['blocked-dependency', 'blocked_dependency'],
  ['error-envelope', 'error_envelope'],
  ['run-envelope', 'blocked_run'],
  ['audit-event', 'audit_event'],
  ['evidence-ref', 'legacy_forward_compatible_wire'],
];

for (const [schemaName, fixtureName] of validFixtures) {
  test(`${fixtureName} satisfies ${schemaName}`, () => {
    assert.deepEqual(validateContract(schemaName, fixtures[fixtureName]), {
      valid: true,
      errors: [],
    });
  });
}

test('removing evidence from quantitative content fails', () => {
  const result = validateContract('run-envelope', fixtures.quantitative_without_evidence);
  assert.equal(result.valid, false);
  assert.match(result.errors.join('\n'), /quantitative content requires evidence/);
});

test('privileged manifest sections cannot change at runtime', () => {
  const change = fixtures.invalid_privileged_runtime_change;
  const after = clone(fixtures[change.before_fixture]);
  after[change.replace.section] = change.replace.value;
  const result = validateRuntimeManifestChange(fixtures[change.before_fixture], after);
  assert.equal(result.valid, false);
  assert.match(result.errors.join('\n'), /privileged section is not runtime-editable/);
});

test('presentation remains the only runtime-editable manifest section', () => {
  const after = clone(fixtures.valid_neutral_manifest);
  after.presentation.title = 'Neutral Analysis';
  assert.equal(
    validateRuntimeManifestChange(fixtures.valid_neutral_manifest, after).valid,
    true,
  );
});

test('privileged manifests reject unknown fields', () => {
  const manifest = clone(fixtures.valid_neutral_manifest);
  manifest.authorization.unreviewed_mode = true;
  const result = validateContract('product-manifest', manifest);
  assert.equal(result.valid, false);
  assert.match(result.errors.join('\n'), /unknown field is not allowed/);
});

test('legacy product aliases require an explicit fixture marker', () => {
  const legacy = fixtures.legacy_alias_manifest;
  const marked = clone(fixtures[legacy.base_fixture]);
  marked.compatibility.aliases = [legacy.alias];
  assert.equal(validateContract('product-manifest', marked).valid, true);

  const unmarked = clone(marked);
  delete unmarked.compatibility.aliases[0].legacy_fixture;
  const result = validateContract('product-manifest', unmarked);
  assert.equal(result.valid, false);
  assert.match(result.errors.join('\n'), /cannot target legacy product names/);
});

test('compatibility alias removal versions start at 1.2.0', () => {
  const manifest = clone(fixtures.valid_neutral_manifest);
  manifest.compatibility.aliases[0].removal_version = '1.1.9';
  const result = validateContract('product-manifest', manifest);
  assert.equal(result.valid, false);
  assert.match(result.errors.join('\n'), /must be at least 1\.2\.0/);
});

test('user authorization requires scopes and user-authorized evidence tools', () => {
  const manifest = clone(fixtures.valid_neutral_manifest);
  manifest.authorization.user_scopes = [];
  manifest.authorization.evidence_tools[0].auth_mode = 'explicit_service_principal';
  const result = validateContract('product-manifest', manifest);
  assert.equal(result.valid, false);
  assert.match(result.errors.join('\n'), /requires at least one approved scope/);
  assert.match(result.errors.join('\n'), /forbids service-principal-only evidence tools/);
});

test('genie-only mode forbids agent-authored SQL', () => {
  const manifest = clone(fixtures.valid_neutral_manifest);
  manifest.genie.allow_agent_authored_sql = true;
  manifest.capabilities.items.push({
    id: 'direct_sql',
    kind: 'agent_sql',
    enabled: true,
    dependencies: [],
  });
  const result = validateContract('product-manifest', manifest);
  assert.equal(result.valid, false);
  assert.match(result.errors.join('\n'), /genie_only/);
});

test('MCP enablement requires all privileged references', () => {
  const manifest = clone(fixtures.valid_neutral_manifest);
  manifest.operations.mcp.enabled = true;
  const result = validateContract('product-manifest', manifest);
  assert.equal(result.valid, false);
  assert.equal(result.errors.filter((error) => /operations\.mcp/.test(error)).length, 4);
});

test('external export requires egress and redaction policy references', () => {
  const manifest = clone(fixtures.valid_neutral_manifest);
  manifest.exports.external_enabled = true;
  const result = validateContract('product-manifest', manifest);
  assert.equal(result.valid, false);
  assert.match(result.errors.join('\n'), /egress_policy_ref/);
  assert.match(result.errors.join('\n'), /redaction_profile_ref/);
});

test('data boundaries accept opaque references rather than raw object names', () => {
  const manifest = clone(fixtures.valid_neutral_manifest);
  manifest.data_boundary.permitted_dataset_refs = ['raw_catalog.raw_schema.raw_table'];
  const result = validateContract('product-manifest', manifest);
  assert.equal(result.valid, false);
  assert.match(result.errors.join('\n'), /unsafe or unsupported format/);
});

test('enabled capabilities require present, enabled dependencies', () => {
  const manifest = clone(fixtures.valid_neutral_manifest);
  manifest.capabilities.items[0].enabled = false;
  manifest.capabilities.items[1].dependencies.push('missing_capability');
  const result = validateContract('product-manifest', manifest);
  assert.equal(result.valid, false);
  assert.match(result.errors.join('\n'), /depends on disabled/);
  assert.match(result.errors.join('\n'), /unknown dependency/);
});

test('tool registry and Genie roles resolve only declared capabilities and spaces', () => {
  const manifest = clone(fixtures.valid_neutral_manifest);
  manifest.tools.enabled_tool_ids.push('missing_tool');
  manifest.genie.required_space_roles = [];
  const result = validateContract('product-manifest', manifest);
  assert.equal(result.valid, false);
  assert.match(result.errors.join('\n'), /unknown capability missing_tool/);
  assert.match(result.errors.join('\n'), /one role to each space_ref/);
});

test('risk metadata includes every required risk class', () => {
  const classes = new Set(
    Object.values(manifestRiskMetadata()).map((metadata) => metadata.risk_class),
  );
  assert.deepEqual(
    classes,
    new Set([
      'presentation',
      'behavioral',
      'governed_capability',
      'identity_security',
      'data_boundary',
      'operations',
      'resource_binding',
    ]),
  );
});

test('branding URIs allow only local asset or reviewed reference schemes', () => {
  for (const iconUri of ['https://example.invalid/icon.svg', 'icons/raw-icon.svg']) {
    const manifest = clone(fixtures.valid_neutral_manifest);
    manifest.presentation.icon_uri = iconUri;
    const result = validateContract('product-manifest', manifest);
    assert.equal(result.valid, false);
    assert.match(result.errors.join('\n'), /approved shape/);
  }
});

test('user scope allowlist exactly covers current required and optional app scopes', () => {
  const request = clone(fixtures.user_auth_request);
  request.authorization.scopes = [
    'catalog.catalogs:read',
    'catalog.schemas:read',
    'catalog.tables:read',
    'dashboards.genie',
    'model-serving',
    'postgres',
    'serving.serving-endpoints',
    'sql',
    'vectorsearch.vector-search-endpoints:read',
    'vectorsearch.vector-search-indexes:read',
    'workspace.workspace:read',
  ];
  assert.equal(validateContract('request-context', request).valid, true);
  request.authorization.scopes.push('files.files');
  assert.equal(validateContract('request-context', request).valid, false);
});

test('schema scope allowlists stay aligned with shared app scope contracts', () => {
  const readScopeArray = (fileName, exportName) => {
    const text = readFileSync(
      new URL(`../../../../platform/app/shared/${fileName}`, import.meta.url),
      'utf8',
    );
    const constants = Object.fromEntries(
      [...text.matchAll(/export const ([A-Z0-9_]+) = '([^']+)' as const;/g)].map(
        ([, name, value]) => [name, value],
      ),
    );
    const body = new RegExp(`export const ${exportName} = \\[([\\s\\S]*?)\\] as const;`)
      .exec(text)?.[1]
      ?.replaceAll(/\/\/.*$/gm, '');
    assert.ok(body, `${exportName} must remain a literal shared scope array`);
    return body
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean)
      .map((item) => {
        const literal = /^'([^']+)'$/.exec(item)?.[1];
        return literal ?? constants[item];
      });
  };
  const expected = [
    ...readScopeArray('required-user-api-scopes.ts', 'REQUIRED_USER_API_SCOPES'),
    ...readScopeArray('optional-user-api-scopes.ts', 'OPTIONAL_USER_API_SCOPES'),
  ].sort();
  const productSchema = JSON.parse(
    readFileSync(new URL('../../schemas/product-manifest.schema.json', import.meta.url), 'utf8'),
  );
  const requestSchema = JSON.parse(
    readFileSync(new URL('../../schemas/request-context.schema.json', import.meta.url), 'utf8'),
  );
  assert.deepEqual(
    [...productSchema.properties.authorization.properties.user_scopes.items.enum].sort(),
    expected,
  );
  assert.deepEqual(
    [...requestSchema.properties.authorization.properties.scopes.items.enum].sort(),
    expected,
  );
});

test('explicit service-principal mode requires separate policy declarations', () => {
  const generic = clone(fixtures.valid_neutral_manifest);
  generic.authorization.default_mode = 'service_principal';
  generic.authorization.supported_modes = ['service_principal'];
  assert.equal(validateContract('product-manifest', generic).valid, false);

  const manifest = clone(fixtures.valid_neutral_manifest);
  manifest.authorization.default_mode = 'explicit_service_principal';
  manifest.authorization.supported_modes = ['explicit_service_principal'];
  manifest.authorization.user_scopes = [];
  manifest.authorization.evidence_tools[0].auth_mode = 'explicit_service_principal';
  const missing = validateContract('product-manifest', manifest);
  assert.equal(missing.valid, false);
  assert.equal(
    missing.errors.filter((error) => /required for explicit_service_principal/.test(error)).length,
    4,
  );

  Object.assign(manifest.authorization, {
    service_principal_policy_ref: 'policy:explicit-sp',
    answer_label_disclosure_ref: 'policy:sp-answer-disclosure',
    service_principal_data_boundary_ref: 'policy:sp-data-boundary',
    audit_mode: 'full',
  });
  assert.equal(validateContract('product-manifest', manifest).valid, true);
});

test('prompt payloads cannot override execution mode', () => {
  const request = clone(fixtures.user_auth_request);
  request.input.execution_mode = 'explicit_service_principal';
  const result = validateContract('request-context', request);
  assert.equal(result.valid, false);
  assert.match(result.errors.join('\n'), /prompts cannot override/);
});

test('requests cannot switch the manifest execution mode', () => {
  const request = clone(fixtures.user_auth_request);
  request.authorization.mode = 'explicit_service_principal';
  request.authorization.scopes = [];
  const result = validateRequestAgainstManifest(request, fixtures.valid_neutral_manifest);
  assert.equal(result.valid, false);
  assert.match(result.errors.join('\n'), /request cannot switch/);
});

test('runtime manifest changes cannot switch execution mode', () => {
  const manifest = clone(fixtures.valid_neutral_manifest);
  manifest.authorization.default_mode = 'explicit_service_principal';
  manifest.authorization.supported_modes = ['explicit_service_principal'];
  manifest.authorization.user_scopes = [];
  manifest.authorization.evidence_tools[0].auth_mode = 'explicit_service_principal';
  Object.assign(manifest.authorization, {
    service_principal_policy_ref: 'policy:explicit-sp',
    answer_label_disclosure_ref: 'policy:sp-answer-disclosure',
    service_principal_data_boundary_ref: 'policy:sp-data-boundary',
    audit_mode: 'full',
  });
  const result = validateRuntimeManifestChange(fixtures.valid_neutral_manifest, manifest);
  assert.equal(result.valid, false);
  assert.match(result.errors.join('\n'), /authorization: privileged section/);
});

test('strict persistent analytics requires a Lakebase binding', () => {
  const missingPolicy = clone(fixtures.valid_neutral_manifest);
  delete missingPolicy.operations.readiness_policy;
  assert.equal(validateContract('product-manifest', missingPolicy).valid, false);

  const manifest = clone(fixtures.valid_neutral_manifest);
  manifest.resources.bindings = manifest.resources.bindings.filter(
    (binding) => binding.kind !== 'lakebase_database',
  );
  const result = validateContract('product-manifest', manifest);
  assert.equal(result.valid, false);
  assert.match(result.errors.join('\n'), /requires a Lakebase database binding/);
});

test('enforced budgets require reservation and reconciliation policies', () => {
  const manifest = clone(fixtures.valid_neutral_manifest);
  manifest.operations.budget.mode = 'enforced';
  const missing = validateContract('product-manifest', manifest);
  assert.equal(missing.valid, false);
  assert.match(missing.errors.join('\n'), /reservation_policy_ref/);
  assert.match(missing.errors.join('\n'), /reconciliation_policy_ref/);

  manifest.operations.budget.reservation_policy_ref = 'policy:budget-reservation';
  manifest.operations.budget.reconciliation_policy_ref = 'policy:budget-reconciliation';
  assert.equal(validateContract('product-manifest', manifest).valid, true);
});

test('operational limits are bounded and resource identifiers stay opaque', () => {
  const manifest = clone(fixtures.valid_neutral_manifest);
  manifest.operations.limits.max_run_seconds = 901;
  manifest.resources.bindings[0].ref = 'raw-resource-id';
  const result = validateContract('product-manifest', manifest);
  assert.equal(result.valid, false);
  assert.match(result.errors.join('\n'), /must be at most 900/);
  assert.match(result.errors.join('\n'), /unsafe or unsupported format/);
});
