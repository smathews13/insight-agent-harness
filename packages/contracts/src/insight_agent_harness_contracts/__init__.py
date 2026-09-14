"""Shared, workspace-local Insight Agent Harness contracts."""

from .generated import (
    MANIFEST_RISK_METADATA,
    SCHEMA_SET_SHA256,
    SCHEMA_SHA256,
    AuditEvent,
    BlockedDependency,
    ErrorEnvelope,
    EvidenceRef,
    ProductManifest,
    ReleaseKeyRegistry,
    ReleaseManifest,
    RequestContext,
    RunEnvelope,
)
from .validation import (
    manifest_risk_metadata,
    validate_contract,
    validate_request_against_manifest,
    validate_runtime_manifest_change,
)

__all__ = [
    "AuditEvent",
    "BlockedDependency",
    "ErrorEnvelope",
    "EvidenceRef",
    "MANIFEST_RISK_METADATA",
    "ProductManifest",
    "ReleaseKeyRegistry",
    "ReleaseManifest",
    "RequestContext",
    "RunEnvelope",
    "SCHEMA_SET_SHA256",
    "SCHEMA_SHA256",
    "manifest_risk_metadata",
    "validate_contract",
    "validate_request_against_manifest",
    "validate_runtime_manifest_change",
]
