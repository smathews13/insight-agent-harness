"""Generated contract types. Do not edit."""

from __future__ import annotations

from typing import Any, Literal, TypedDict

SCHEMA_SET_SHA256 = "4e7c32ebc3039ea945f3198839f16cbc9518e35b7f20732e0eb6ac660d8c3226"
SCHEMA_SHA256 = {
    "audit-event.schema.json": "13bec985a09d96dcdfc8ee78784917ed7bde1634e768e4cc05f4400b00871c91",
    "blocked-dependency.schema.json": "799e85b8b464e0d9b9098f42eaddfc2628b955b8032f70f71cef49573dc73ccf",
    "error-envelope.schema.json": "db94171c9baee58ade3cee9d3624330e618391c3845b426356a6b8e55cb818b9",
    "evidence-ref.schema.json": "3428cf971bbf22837ef58ee3b4547b22e0b3abf1088e1d592795d432d57faf59",
    "product-manifest.schema.json": "ca1c716178ad78a148c82ff9c5fa27cb17ea29ae63d77c0a9c096aeffdaece3f",
    "release-key-registry.schema.json": "5a7085ddc8a14bdba82233ba7a70932aedd85d6bcba2c155de470a60ff3df8dc",
    "release-manifest.schema.json": "e6a130f86b003901b3f4feb47626caf1e6d4072cac9ad2093ada0c9e954e5726",
    "request-context.schema.json": "23d529915827db51b9e59c7377c33799edce31ef864508d765d34414a2769c7c",
    "run-envelope.schema.json": "4cc4374f2f4fbb47858f0e98ec8583dbbdd1ea416c6c16e559a952333e83ea6c",
}


class _AuditEventOptional(TypedDict, total=False):
    details: AuditEventDetails


class AuditEvent(_AuditEventOptional):
    schema_version: Literal["1.0.0"]
    event_id: str
    event_type: Literal[
        "request", "authorization", "tool_call", "export", "configuration_change", "run_completed"
    ]
    occurred_at: str
    actor: AuditEventActor
    action: str
    target_ref: str
    outcome: Literal["allowed", "denied", "blocked", "failed", "succeeded"]
    correlation_id: str


class AuditEventActor(TypedDict):
    mode: Literal["user_authorization", "explicit_service_principal", "system"]
    subject_ref: str


class _AuditEventDetailsOptional(TypedDict, total=False):
    artifact_id: str
    export_id: str
    revision_ref: str
    canonical_sha256: str
    format: Literal["markdown", "json", "csv", "tsv", "html", "xlsx", "pdf", "png", "pptx"]
    redaction_profile_ref: str


class AuditEventDetails(_AuditEventDetailsOptional):
    pass


class BlockedDependency(TypedDict):
    schema_version: Literal["1.0.0"]
    dependency_id: str
    kind: Literal[
        "capability",
        "resource",
        "authorization",
        "policy",
        "adapter",
        "signing_key",
        "kill_switch",
        "egress",
    ]
    ref: str
    reason_code: Literal[
        "missing", "unavailable", "unauthorized", "disabled", "invalid_configuration"
    ]
    message: str
    retryable: bool


class _ErrorEnvelopeOptional(TypedDict, total=False):
    blocked_dependency: ErrorEnvelopeBlockedDependency
    correlation_id: str


class ErrorEnvelope(_ErrorEnvelopeOptional):
    schema_version: Literal["1.0.0"]
    code: Literal[
        "invalid_request", "unauthorized", "blocked_dependency", "policy_denied", "internal_error"
    ]
    message: str
    retryable: bool


class ErrorEnvelopeBlockedDependency(TypedDict):
    schema_version: Literal["1.0.0"]
    dependency_id: str
    kind: Literal[
        "capability",
        "resource",
        "authorization",
        "policy",
        "adapter",
        "signing_key",
        "kill_switch",
        "egress",
    ]
    ref: str
    reason_code: Literal[
        "missing", "unavailable", "unauthorized", "disabled", "invalid_configuration"
    ]
    message: str
    retryable: bool


class _EvidenceRefOptional(TypedDict, total=False):
    excerpt: str
    attributes: dict[str, str | int | float | bool | None]


class EvidenceRef(_EvidenceRefOptional):
    schema_version: Literal["1.0.0"]
    evidence_id: str
    source_kind: Literal["genie_query", "tool_result", "document", "dataset"]
    source_ref: str
    retrieved_at: str


class ProductManifest(TypedDict):
    schema_version: Literal["1.0.0"]
    product: ProductManifestProduct
    presentation: ProductManifestPresentation
    extensions: ProductManifestExtensions
    capabilities: ProductManifestCapabilities
    knowledge: ProductManifestKnowledge
    tools: ProductManifestTools
    genie: ProductManifestGenie
    resources: ProductManifestResources
    settings: ProductManifestSettings
    authorization: ProductManifestAuthorization
    collaboration: ProductManifestCollaboration
    data_boundary: ProductManifestDataBoundary
    operations: ProductManifestOperations
    exports: ProductManifestExports
    compatibility: ProductManifestCompatibility


class ProductManifestProduct(TypedDict):
    id: str
    display_name: str
    version: str
    description: str


class _ProductManifestPresentationOptional(TypedDict, total=False):
    icon_uri: str


class ProductManifestPresentation(_ProductManifestPresentationOptional):
    title: str
    theme: Literal["light", "dark", "system"]


class ProductManifestExtensions(TypedDict):
    branding: str
    navigation: str
    loading: str
    prompts: str
    knowledge: str
    tool_registry: str
    genie_mode: str
    resources: str
    migrations: str
    settings: str
    export_chrome: str


class ProductManifestCapabilities(TypedDict):
    items: list[ProductManifestCapabilitiesItemsItem]


class ProductManifestCapabilitiesItemsItem(TypedDict):
    id: str
    kind: Literal["answer", "genie_query", "evidence_tool", "agent_sql", "export"]
    enabled: bool
    dependencies: list[str]


class _ProductManifestKnowledgeOptional(TypedDict, total=False):
    prompt_pack_refs: list[str]


class ProductManifestKnowledge(_ProductManifestKnowledgeOptional):
    source_refs: list[str]


class ProductManifestTools(TypedDict):
    registry_refs: list[str]
    enabled_tool_ids: list[str]


class ProductManifestGenie(TypedDict):
    mode: Literal["genie_only", "hybrid", "disabled"]
    allow_agent_authored_sql: bool
    space_refs: list[str]
    required_space_roles: list[str]


class _ProductManifestResourcesOptional(TypedDict, total=False):
    bundle_target: str
    generated_name_prefix: str


class ProductManifestResources(_ProductManifestResourcesOptional):
    bindings: list[ProductManifestResourcesBindingsItem]


class ProductManifestResourcesBindingsItem(TypedDict):
    name: str
    kind: Literal[
        "genie_space",
        "sql_warehouse",
        "serving_endpoint",
        "vector_index",
        "volume",
        "experiment",
        "lakebase_database",
        "databricks_app",
        "secret",
        "unity_catalog_schema",
        "job",
    ]
    ref: str


class ProductManifestSettings(TypedDict):
    defaults_ref: str
    runtime_editable_keys: list[str]


class _ProductManifestAuthorizationOptional(TypedDict, total=False):
    service_principal_policy_ref: str
    answer_label_disclosure_ref: str
    service_principal_data_boundary_ref: str
    audit_mode: Literal["full", "security_relevant"]


class ProductManifestAuthorization(_ProductManifestAuthorizationOptional):
    default_mode: Literal["user_authorization", "explicit_service_principal"]
    supported_modes: list[Literal["user_authorization", "explicit_service_principal"]]
    user_scopes: list[
        Literal[
            "catalog.catalogs:read",
            "catalog.schemas:read",
            "catalog.tables:read",
            "dashboards.genie",
            "model-serving",
            "postgres",
            "serving.serving-endpoints",
            "sql",
            "vectorsearch.vector-search-endpoints:read",
            "vectorsearch.vector-search-indexes:read",
            "workspace.workspace:read",
        ]
    ]
    evidence_tools: list[ProductManifestAuthorizationEvidenceToolsItem]


class ProductManifestAuthorizationEvidenceToolsItem(TypedDict):
    capability_id: str
    auth_mode: Literal["user_authorization", "explicit_service_principal"]


class ProductManifestCollaboration(TypedDict):
    team_authority: Literal["account_scim_read_only"]
    project_roles: list[Literal["owner", "editor", "contributor", "viewer", "auditor"]]
    membership_sources: list[Literal["direct_user", "account_scim_team"]]
    project_context_policy_ref: str
    snapshot_targets: list[Literal["run", "artifact"]]


class ProductManifestDataBoundary(TypedDict):
    boundary_policy_ref: str
    permitted_dataset_refs: list[str]


class ProductManifestOperations(TypedDict):
    readiness_policy: Literal["strict_persistent_analytics"]
    limits: ProductManifestOperationsLimits
    budget: ProductManifestOperationsBudget
    freshness_policy_refs: list[str]
    retention_policy_ref: str
    kill_switch_refs: list[str]
    mcp: ProductManifestOperationsMcp


class ProductManifestOperationsLimits(TypedDict):
    max_run_seconds: int
    max_tool_calls: int
    max_steps: int
    max_output_bytes: int


class _ProductManifestOperationsBudgetOptional(TypedDict, total=False):
    reservation_policy_ref: str
    reconciliation_policy_ref: str


class ProductManifestOperationsBudget(_ProductManifestOperationsBudgetOptional):
    mode: Literal["reporting_only", "enforced"]
    reporting_policy_ref: str


class _ProductManifestOperationsMcpOptional(TypedDict, total=False):
    registered_adapter_ref: str
    destination_policy_ref: str
    signing_key_ref: str
    kill_switch_ref: str


class ProductManifestOperationsMcp(_ProductManifestOperationsMcpOptional):
    enabled: bool
    direct_fallback_mode: Literal["blocked", "same_user_audited"]


class _ProductManifestExportsOptional(TypedDict, total=False):
    egress_policy_ref: str
    redaction_profile_ref: str
    chrome_ref: str
    document_title: str


class ProductManifestExports(_ProductManifestExportsOptional):
    external_enabled: bool
    formats: list[Literal["markdown", "html", "pdf", "json", "csv", "tsv", "xlsx", "png"]]
    adapter_refs: list[str]


class ProductManifestCompatibility(TypedDict):
    minimum_platform_version: str
    registry_ref: str
    aliases: list[ProductManifestCompatibilityAliasesItem]


class _ProductManifestCompatibilityAliasesItemOptional(TypedDict, total=False):
    legacy_fixture: bool


class ProductManifestCompatibilityAliasesItem(_ProductManifestCompatibilityAliasesItemOptional):
    alias: str
    target: str
    owner: str
    telemetry_key: str
    removal_version: str


class ReleaseKeyRegistry(TypedDict):
    schema_version: Literal["1.0.0"]
    keys: list[ReleaseKeyRegistryKeysItem]


class ReleaseKeyRegistryKeysItem(TypedDict):
    key_id: str
    algorithm: Literal["Ed25519"]
    public_key_pem: str
    status: Literal["active", "retired", "revoked"]


class ReleaseManifest(TypedDict):
    schema_version: Literal["1.0.0"]
    manifest_id: str
    manifest_content_sha256: str
    release_id: ReleaseManifestReleaseId
    source_commit: str
    release_source_sha256: str
    app_source_sha256: str
    model_source_sha256: str
    upstream_tag: str
    upstream_sha: str
    upstream_artifact_sha256: str
    upstream_attestation: ReleaseManifestUpstreamAttestation
    app_artifact_sha256: str
    model_artifact_sha256: str
    registered_model: ReleaseManifestRegisteredModel
    prompt_pack_sha256: str
    policy_version: str
    product_manifest_sha256: str
    shared_packages: list[ReleaseManifestSharedPackagesItem]
    artifact_contract: ReleaseManifestArtifactContract
    lakebase: ReleaseManifestLakebase
    authorization: ReleaseManifestAuthorization
    data_boundary_fingerprint: str
    genie_curation_fingerprints: list[ReleaseManifestGenieCurationFingerprintsItem]
    enabled_capability_mcp_fingerprint: str
    evaluation: ReleaseManifestEvaluation
    controls: ReleaseManifestControls
    deploy_artifact_sha256: str
    resource_bindings_fingerprint: str
    observations: list[ReleaseManifestObservationsItem]
    signer_key_id: str
    signed_at: str
    approval_record_id: str
    signature: ReleaseManifestSignature


class ReleaseManifestReleaseId(TypedDict):
    product: str
    upstream: str
    overlay: str
    app_artifact: str
    model_artifact: str


class _ReleaseManifestUpstreamAttestationOptional(TypedDict, total=False):
    evidence_sha256: str


class ReleaseManifestUpstreamAttestation(_ReleaseManifestUpstreamAttestationOptional):
    status: Literal["verified", "unverified", "not_available"]
    verifier: str


class ReleaseManifestRegisteredModel(TypedDict):
    version: str
    ref_sha256: str


class ReleaseManifestSharedPackagesItem(TypedDict):
    name: str
    version: str
    artifact_sha256: str


class ReleaseManifestArtifactContract(TypedDict):
    canonical_schema_version: Literal["1.1.0"]
    export_adapter_version: Literal["1.2.0"]
    supported_formats: list[Literal["csv", "html", "json", "markdown", "pdf", "png", "tsv", "xlsx"]]
    binary_adapters: ReleaseManifestArtifactContractBinaryAdapters


class ReleaseManifestArtifactContractBinaryAdapters(TypedDict):
    pdf: Literal["available", "unavailable"]
    png: Literal["available", "unavailable"]
    pptx: Literal["available", "unavailable"]
    xlsx: Literal["available", "unavailable"]


class ReleaseManifestLakebase(TypedDict):
    migration_version: int
    rollback_floor: int


class ReleaseManifestAuthorization(TypedDict):
    auth_mode: Literal["user_authorization", "explicit_service_principal"]
    oauth_scopes: list[str]


class ReleaseManifestGenieCurationFingerprintsItem(TypedDict):
    role: str
    sha256: str


class ReleaseManifestEvaluation(TypedDict):
    suite_version: str
    dataset_version: str
    scorer_versions: list[ReleaseManifestEvaluationScorerVersionsItem]
    gate_result_digests: list[ReleaseManifestEvaluationGateResultDigestsItem]


class ReleaseManifestEvaluationScorerVersionsItem(TypedDict):
    name: str
    version: str
    sha256: str


class ReleaseManifestEvaluationGateResultDigestsItem(TypedDict):
    name: str
    sha256: str


class ReleaseManifestControls(TypedDict):
    audit_schema_version: str
    audit_policy_ref: str
    retention_policy_ref: str
    budget_policy_ref: str
    budget_mode: Literal["reporting_only", "enforced"]
    reservation_mode: Literal["none", "atomic_expected_maximum"]


class _ReleaseManifestObservationsItemOptional(TypedDict, total=False):
    observed_sha256: str


class ReleaseManifestObservationsItem(_ReleaseManifestObservationsItemOptional):
    name: Literal[
        "source_commit",
        "release_source",
        "app_source",
        "model_source",
        "upstream_pin",
        "app_artifact",
        "model_artifact",
        "registered_model",
        "product_manifest",
        "authorization",
        "lakebase_migration",
        "data_boundary",
        "genie_curation",
        "shared_packages",
        "artifact_schema",
        "export_adapters",
        "capabilities",
        "evaluation_gate",
        "audit_schema",
        "retention_policy",
        "budget_policy",
        "deploy_artifact",
    ]
    status: Literal["verified", "unverified", "failed"]


class ReleaseManifestSignature(TypedDict):
    algorithm: Literal["Ed25519"]
    value: str


class RequestContext(TypedDict):
    schema_version: Literal["1.0.0"]
    request_id: str
    correlation_id: str
    requested_at: str
    authorization: RequestContextAuthorization
    requested_capability: str
    input: RequestContextInput


class _RequestContextAuthorizationOptional(TypedDict, total=False):
    scopes: list[
        Literal[
            "catalog.catalogs:read",
            "catalog.schemas:read",
            "catalog.tables:read",
            "dashboards.genie",
            "model-serving",
            "postgres",
            "serving.serving-endpoints",
            "sql",
            "vectorsearch.vector-search-endpoints:read",
            "vectorsearch.vector-search-indexes:read",
            "workspace.workspace:read",
        ]
    ]


class RequestContextAuthorization(_RequestContextAuthorizationOptional):
    mode: Literal["user_authorization", "explicit_service_principal"]
    subject_ref: str


class _RequestContextInputOptional(TypedDict, total=False):
    conversation_ref: str
    project_ref: str


class RequestContextInput(_RequestContextInputOptional):
    prompt: str


class _RunEnvelopeOptional(TypedDict, total=False):
    completed_at: str
    artifact_ref: str
    revision_ref: str
    output: RunEnvelopeOutput
    evidence: list[RunEnvelopeEvidenceItem]
    blocked_dependencies: list[RunEnvelopeBlockedDependenciesItem]
    error: RunEnvelopeError


class RunEnvelope(_RunEnvelopeOptional):
    schema_version: Literal["1.0.0"]
    run_id: str
    request_id: str
    status: Literal["complete", "blocked", "error"]
    started_at: str


class RunEnvelopeOutput(TypedDict):
    summary: str
    content_blocks: list[RunEnvelopeOutputContentBlocksItem]


class RunEnvelopeOutputContentBlocksItem(TypedDict):
    block_id: str
    kind: Literal["text", "table", "quantitative"]
    content: str
    evidence_refs: list[str]


class _RunEnvelopeEvidenceItemOptional(TypedDict, total=False):
    excerpt: str
    attributes: dict[str, str | int | float | bool | None]


class RunEnvelopeEvidenceItem(_RunEnvelopeEvidenceItemOptional):
    schema_version: Literal["1.0.0"]
    evidence_id: str
    source_kind: Literal["genie_query", "tool_result", "document", "dataset"]
    source_ref: str
    retrieved_at: str


class RunEnvelopeBlockedDependenciesItem(TypedDict):
    schema_version: Literal["1.0.0"]
    dependency_id: str
    kind: Literal[
        "capability",
        "resource",
        "authorization",
        "policy",
        "adapter",
        "signing_key",
        "kill_switch",
        "egress",
    ]
    ref: str
    reason_code: Literal[
        "missing", "unavailable", "unauthorized", "disabled", "invalid_configuration"
    ]
    message: str
    retryable: bool


class _RunEnvelopeErrorOptional(TypedDict, total=False):
    blocked_dependency: RunEnvelopeErrorBlockedDependency
    correlation_id: str


class RunEnvelopeError(_RunEnvelopeErrorOptional):
    schema_version: Literal["1.0.0"]
    code: Literal[
        "invalid_request", "unauthorized", "blocked_dependency", "policy_denied", "internal_error"
    ]
    message: str
    retryable: bool


class RunEnvelopeErrorBlockedDependency(TypedDict):
    schema_version: Literal["1.0.0"]
    dependency_id: str
    kind: Literal[
        "capability",
        "resource",
        "authorization",
        "policy",
        "adapter",
        "signing_key",
        "kill_switch",
        "egress",
    ]
    ref: str
    reason_code: Literal[
        "missing", "unavailable", "unauthorized", "disabled", "invalid_configuration"
    ]
    message: str
    retryable: bool


MANIFEST_RISK_METADATA = {
    "product": {"risk_class": "presentation", "runtime_editable": False},
    "presentation": {"risk_class": "presentation", "runtime_editable": True},
    "extensions": {"risk_class": "behavioral", "runtime_editable": False},
    "capabilities": {"risk_class": "governed_capability", "runtime_editable": False},
    "knowledge": {"risk_class": "behavioral", "runtime_editable": False},
    "tools": {"risk_class": "governed_capability", "runtime_editable": False},
    "genie": {"risk_class": "behavioral", "runtime_editable": False},
    "resources": {"risk_class": "resource_binding", "runtime_editable": False},
    "settings": {"risk_class": "operations", "runtime_editable": False},
    "authorization": {"risk_class": "identity_security", "runtime_editable": False},
    "collaboration": {"risk_class": "identity_security", "runtime_editable": False},
    "data_boundary": {"risk_class": "data_boundary", "runtime_editable": False},
    "operations": {"risk_class": "operations", "runtime_editable": False},
    "exports": {"risk_class": "data_boundary", "runtime_editable": False},
    "compatibility": {"risk_class": "identity_security", "runtime_editable": False},
}
