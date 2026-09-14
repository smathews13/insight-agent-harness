"""Fail-closed contracts for governed internal and external intelligence.

The package deliberately accepts already-fetched bytes. It has no HTTP client,
credential provider, tool registry, ProductManifest writer, or grant API.
"""

from __future__ import annotations

import hashlib
import ipaddress
import itertools
import json
import posixpath
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Protocol
from urllib.parse import unquote, urlsplit

_OPAQUE_REF = re.compile(r"^[a-z][a-z0-9_.-]{1,63}:[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")
_SOURCE_ID = re.compile(r"^src_[a-z0-9][a-z0-9_-]{2,63}$")
_PARSER_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_LICENSE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
_MEDIA_TYPE = re.compile(
    r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,63}$"
)
_RFC3339_UTC = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)
_URL_ENCODED_PATH_DELIMITER = re.compile(r"%(?:2e|2f|5c)", re.IGNORECASE)
_PROTECTED_PREFIXES = (
    "authorization:",
    "boundary:",
    "data-boundary:",
    "egress-policy:",
    "identity:",
    "manifest:",
    "mcp:",
    "oauth:",
    "permission:",
    "policy:",
    "product-manifest:",
    "resource-binding:",
    "role:",
    "scope:",
    "tool:",
)
_PROTECTED_PREDICATES = {
    "auth_mode",
    "authorization",
    "capability",
    "data_boundary",
    "egress_policy",
    "grant",
    "identity",
    "mcp",
    "oauth_scope",
    "permission",
    "product_manifest",
    "resource_binding",
    "role",
    "run_as",
    "scope",
    "tool",
    "tool_definition",
}


class PolicyDenied(ValueError):
    """Raised before bytes from an unapproved route enter governed storage."""


class ProtectedControlTarget(ValueError):
    """Raised when evidence attempts to represent a control-plane mutation."""


class SourceClassification(str, Enum):
    INTERNAL = "internal"
    EXTERNAL = "external"
    MIXED = "mixed"


class ReviewStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    QUARANTINED = "quarantined"


class ClaimImpact(str, Enum):
    STANDARD = "standard"
    HIGH = "high"


class FindingKind(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    PII = "pii"
    SECRET = "secret"


def parse_timestamp(value: str) -> datetime:
    """Parse a UTC RFC3339 timestamp, rejecting naive and non-UTC values."""

    if not isinstance(value, str) or not _RFC3339_UTC.fullmatch(value):
        raise ValueError("timestamps must use an RFC3339 UTC Z suffix")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("timestamps must be UTC")
    return parsed


def format_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("timestamps must be timezone-aware UTC")
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class SourcePolicy:
    """A reviewed source allowlist entry and its collection obligations."""

    source_id: str
    owner_ref: str
    reviewer_policy_ref: str
    classification: SourceClassification
    allowed_hosts: tuple[str, ...]
    allowed_path_prefixes: tuple[str, ...]
    allowed_parser_versions: tuple[str, ...]
    license_id: str
    license_metadata_ref: str
    robots_policy: str
    max_requests_per_minute: int
    max_content_bytes: int
    max_claims: int
    max_claim_value_bytes: int
    freshness_seconds: int
    reviewed_at: str
    review_expires_at: str

    def __post_init__(self) -> None:
        if not _SOURCE_ID.fullmatch(self.source_id):
            raise ValueError("source_id must be a stable src_ identifier")
        if not _OPAQUE_REF.fullmatch(self.owner_ref):
            raise ValueError("owner_ref must be opaque")
        if not _OPAQUE_REF.fullmatch(self.reviewer_policy_ref):
            raise ValueError("reviewer_policy_ref must be opaque")
        if not isinstance(self.classification, SourceClassification):
            raise ValueError("source classification is invalid")
        if self.classification is SourceClassification.MIXED:
            raise ValueError("one allowlist entry cannot itself be mixed")
        if not self.allowed_hosts or any(
            not _is_safe_allowlisted_host(host) for host in self.allowed_hosts
        ):
            raise ValueError("allowed_hosts must contain exact lowercase host names")
        if not self.allowed_path_prefixes:
            raise ValueError("allowed_path_prefixes must not be empty")
        for prefix in self.allowed_path_prefixes:
            try:
                normalized = _canonical_url_path(prefix)
            except PolicyDenied as exc:
                raise ValueError("allowed_path_prefixes must be canonical absolute paths") from exc
            if normalized != prefix.rstrip("/") and not (prefix == "/" and normalized == "/"):
                raise ValueError("allowed_path_prefixes must be canonical absolute paths")
        if not self.allowed_parser_versions or any(
            not _PARSER_VERSION.fullmatch(version) for version in self.allowed_parser_versions
        ):
            raise ValueError("allowed_parser_versions must name reviewed parser versions")
        if not _LICENSE_ID.fullmatch(self.license_id) or not _OPAQUE_REF.fullmatch(
            self.license_metadata_ref
        ):
            raise ValueError("reviewed license metadata is required")
        if self.robots_policy != "respect":
            raise ValueError("robots_policy must be respect")
        if self.max_requests_per_minute < 1:
            raise ValueError("max_requests_per_minute must be positive")
        if self.max_content_bytes < 1:
            raise ValueError("max_content_bytes must be positive")
        if self.max_claims < 1:
            raise ValueError("max_claims must be positive")
        if self.max_claim_value_bytes < 1:
            raise ValueError("max_claim_value_bytes must be positive")
        if self.freshness_seconds < 1:
            raise ValueError("freshness_seconds must be positive")
        if parse_timestamp(self.reviewed_at) >= parse_timestamp(self.review_expires_at):
            raise ValueError("source review must expire after it was performed")

    def assert_review_current(self, at: str) -> None:
        instant = parse_timestamp(at)
        if instant < parse_timestamp(self.reviewed_at):
            raise PolicyDenied("source policy was not yet reviewed")
        if instant >= parse_timestamp(self.review_expires_at):
            raise PolicyDenied("source policy review has expired")


@dataclass(frozen=True)
class NetworkDestination:
    """DNS result observed by the collector for one requested or redirected URL."""

    url: str
    resolved_addresses: tuple[str, ...]
    connected_address: str

    def __post_init__(self) -> None:
        if not self.url or not self.resolved_addresses:
            raise ValueError("network destination URL and resolved addresses are required")
        if len(set(self.resolved_addresses)) != len(self.resolved_addresses):
            raise ValueError("resolved addresses must not contain duplicates")
        if len(self.resolved_addresses) > 16:
            raise ValueError("network destination has too many resolved addresses")
        for address in self.resolved_addresses:
            try:
                parsed_address = ipaddress.ip_address(address)
            except ValueError as exc:
                raise ValueError("resolved address must be an IP literal") from exc
            if str(parsed_address) != address:
                raise ValueError("resolved address must use canonical notation")
        if self.connected_address not in self.resolved_addresses:
            raise ValueError("connected address must be one of the resolved addresses")


@dataclass(frozen=True)
class FetchEnvelope:
    """Bytes and compliance facts supplied by a separately governed collector."""

    source_id: str
    requested_url: str
    final_url: str
    redirect_chain: tuple[str, ...]
    network_destinations: tuple[NetworkDestination, ...]
    retrieved_at: str
    effective_at: str
    body: bytes
    media_type: str
    robots_allowed: bool
    license_id: str
    rate_limit_max_requests_per_minute: int

    def __post_init__(self) -> None:
        parse_timestamp(self.retrieved_at)
        parse_timestamp(self.effective_at)
        if not isinstance(self.body, bytes) or not self.body:
            raise ValueError("body must contain fetched bytes")
        if not isinstance(self.media_type, str) or not _MEDIA_TYPE.fullmatch(self.media_type):
            raise ValueError("media_type must be a canonical MIME type")


class SourceRegistry:
    """Exact-host destination policy, including every redirect destination."""

    def __init__(self, policies: Sequence[SourcePolicy]) -> None:
        indexed = {}
        for policy in policies:
            if policy.source_id in indexed:
                raise ValueError(f"duplicate source policy: {policy.source_id}")
            indexed[policy.source_id] = policy
        self._policies = indexed

    def policy_for(self, source_id: str) -> SourcePolicy:
        try:
            return self._policies[source_id]
        except KeyError as exc:
            raise PolicyDenied("source is not on the reviewed allowlist") from exc

    @staticmethod
    def _validate_url(policy: SourcePolicy, url: str) -> None:
        if (
            not isinstance(url, str)
            or len(url) > 2048
            or not url.startswith("https://")
            or any(ord(character) < 0x20 or character.isspace() for character in url)
        ):
            raise PolicyDenied("URL is not a canonical HTTPS destination")
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.hostname is None
            or parsed.hostname.lower() not in policy.allowed_hosts
            or parsed.port not in (None, 443)
            or parsed.query
            or parsed.fragment
        ):
            raise PolicyDenied("URL destination is outside the reviewed allowlist")
        normalized = _canonical_url_path(parsed.path or "/")
        allowed = any(
            normalized == prefix.rstrip("/") or normalized.startswith(prefix.rstrip("/") + "/")
            for prefix in policy.allowed_path_prefixes
        )
        if not allowed:
            raise PolicyDenied("URL path is outside the reviewed allowlist")

    def validate(self, envelope: FetchEnvelope) -> SourcePolicy:
        policy = self.policy_for(envelope.source_id)
        policy.assert_review_current(envelope.retrieved_at)
        destinations = (
            envelope.requested_url,
            *envelope.redirect_chain,
            envelope.final_url,
        )
        if len(envelope.redirect_chain) > 5:
            raise PolicyDenied("redirect limit exceeded")
        if envelope.redirect_chain and envelope.redirect_chain[-1] != envelope.final_url:
            raise PolicyDenied("final URL does not match the recorded redirect chain")
        for destination in destinations:
            self._validate_url(policy, destination)
        expected_destinations = set(destinations)
        observed_destinations = {}
        for network_destination in envelope.network_destinations:
            if network_destination.url in observed_destinations:
                raise PolicyDenied("network destination attestation contains duplicate URLs")
            observed_destinations[network_destination.url] = network_destination.resolved_addresses
        if set(observed_destinations) != expected_destinations:
            raise PolicyDenied("network destination attestation is incomplete")
        for addresses in observed_destinations.values():
            if any(not ipaddress.ip_address(address).is_global for address in addresses):
                raise PolicyDenied("network destination resolved to a non-public address")
        if envelope.robots_allowed is not True:
            raise PolicyDenied("robots policy denied collection")
        if envelope.license_id != policy.license_id:
            raise PolicyDenied("observed license does not match reviewed policy")
        if (
            envelope.rate_limit_max_requests_per_minute < 1
            or envelope.rate_limit_max_requests_per_minute > policy.max_requests_per_minute
        ):
            raise PolicyDenied("collector rate limit exceeds reviewed policy")
        if len(envelope.body) > policy.max_content_bytes:
            raise PolicyDenied("content exceeds reviewed byte limit")
        if parse_timestamp(envelope.effective_at) > parse_timestamp(envelope.retrieved_at):
            raise PolicyDenied("effective timestamp cannot be after retrieval")
        return policy


@dataclass(frozen=True)
class ScanFinding:
    kind: FindingKind
    rule_id: str


class UntrustedTextScanner:
    """Conservative local scanner. Findings are codes only; raw text is omitted."""

    _RULES = (
        (
            FindingKind.PROMPT_INJECTION,
            "injection.ignore-instructions",
            re.compile(
                r"\b(ignore|disregard|override)\b.{0,40}\b"
                r"(instruction|prompt|policy|system message)s?\b",
                re.IGNORECASE | re.DOTALL,
            ),
        ),
        (
            FindingKind.PROMPT_INJECTION,
            "injection.tool-or-secret",
            re.compile(
                r"\b(call|invoke|run|use)\b.{0,30}\btool\b|"
                r"\b(exfiltrate|reveal|print)\b.{0,30}\b(secret|token|credential)s?\b",
                re.IGNORECASE | re.DOTALL,
            ),
        ),
        (
            FindingKind.PROMPT_INJECTION,
            "injection.role-or-system-prompt",
            re.compile(
                r"\b(system|developer)\s+(prompt|message|instruction)s?\b|"
                r"\byou\s+are\s+(?:now\s+)?(?:chatgpt|an?\s+assistant|the\s+system)\b",
                re.IGNORECASE,
            ),
        ),
        (
            FindingKind.PII,
            "pii.email",
            re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
        ),
        (
            FindingKind.PII,
            "pii.ssn",
            re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        ),
        (
            FindingKind.PII,
            "pii.payment-card",
            re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        ),
        (
            FindingKind.SECRET,
            "secret.bearer",
            re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE),
        ),
        (
            FindingKind.SECRET,
            "secret.assignment",
            re.compile(
                r"\b(api[_ -]?key|client[_ -]?secret|password|private[_ -]?key|"
                r"access[_ -]?token)\b[\"']?\s*[:=]\s*[\"']?[^\s,\"'}]{6,}",
                re.IGNORECASE,
            ),
        ),
        (
            FindingKind.SECRET,
            "secret.private-key",
            re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        ),
        (
            FindingKind.SECRET,
            "secret.provider-token",
            re.compile(
                r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|"
                r"\bdapi[a-f0-9]{32,}\b|"
                r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
                re.IGNORECASE,
            ),
        ),
        (
            FindingKind.SECRET,
            "secret.jwt",
            re.compile(
                r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
            ),
        ),
    )

    def scan(self, body: bytes, _media_type: str) -> tuple[ScanFinding, ...]:
        # Scan all bytes, including PDFs and other containers. Reviewed parsers
        # may later extract text from any media type, so MIME cannot be a bypass.
        text = body.decode("utf-8", errors="replace")
        return tuple(
            ScanFinding(kind, rule_id)
            for kind, rule_id, pattern in self._RULES
            if pattern.search(text)
        )


@dataclass(frozen=True)
class RawSnapshot:
    snapshot_id: str
    source_id: str
    requested_url: str
    final_url: str
    redirect_chain: tuple[str, ...]
    network_destinations: tuple[NetworkDestination, ...]
    retrieved_at: str
    effective_at: str
    content_hash: str
    media_type: str
    byte_count: int
    owner_ref: str
    reviewer_policy_ref: str
    license_id: str
    license_metadata_ref: str
    robots_policy: str
    rate_limit_max_requests_per_minute: int
    freshness_seconds: int
    source_classification: SourceClassification
    review_status: ReviewStatus
    finding_codes: tuple[str, ...] = ()

    def to_metadata(self) -> Mapping[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "source_id": self.source_id,
            "requested_url": self.requested_url,
            "final_url": self.final_url,
            "redirect_chain": list(self.redirect_chain),
            "network_destinations": [
                {
                    "url": destination.url,
                    "resolved_addresses": list(destination.resolved_addresses),
                    "connected_address": destination.connected_address,
                }
                for destination in self.network_destinations
            ],
            "retrieved_at": self.retrieved_at,
            "effective_at": self.effective_at,
            "content_hash": self.content_hash,
            "media_type": self.media_type,
            "byte_count": self.byte_count,
            "owner_ref": self.owner_ref,
            "reviewer_policy_ref": self.reviewer_policy_ref,
            "license_id": self.license_id,
            "license_metadata_ref": self.license_metadata_ref,
            "robots_policy": self.robots_policy,
            "rate_limit_max_requests_per_minute": (self.rate_limit_max_requests_per_minute),
            "freshness_seconds": self.freshness_seconds,
            "source_classification": self.source_classification.value,
            "review_status": self.review_status.value,
            "finding_codes": list(self.finding_codes),
        }


@dataclass(frozen=True)
class ClaimDraft:
    subject_ref: str
    predicate: str
    value: str
    impact: ClaimImpact = ClaimImpact.STANDARD
    conflict_group: str = ""
    supporting_classifications: tuple[SourceClassification, ...] = ()


@dataclass(frozen=True)
class NormalizedClaim:
    claim_id: str
    source_id: str
    snapshot_ref: str
    requested_url: str
    final_url: str
    subject_ref: str
    predicate: str
    value: str
    retrieved_at: str
    effective_at: str
    fresh_until: str
    parser_version: str
    content_hash: str
    owner_ref: str
    reviewer_policy_ref: str
    license_id: str
    license_metadata_ref: str
    review_status: ReviewStatus
    source_classification: SourceClassification
    impact: ClaimImpact
    conflict_group: str = ""
    reviewed_by_ref: str = ""
    reviewed_at: str = ""
    review_record_ref: str = ""

    def evidence_ref(self) -> Mapping[str, Any]:
        attributes = {
            "effective_at": self.effective_at,
            "parser_version": self.parser_version,
            "content_hash": self.content_hash,
            "requested_url": self.requested_url,
            "final_url": self.final_url,
            "fresh_until": self.fresh_until,
            "license_id": self.license_id,
            "license_metadata_ref": self.license_metadata_ref,
            "owner_ref": self.owner_ref,
            "reviewer_policy_ref": self.reviewer_policy_ref,
            "review_status": self.review_status.value,
            "reviewed_by_ref": self.reviewed_by_ref,
            "reviewed_at": self.reviewed_at,
            "review_record_ref": self.review_record_ref,
            "source_classification": self.source_classification.value,
            "conflict_group": self.conflict_group,
        }
        return {
            "schema_version": "1.0.0",
            "evidence_id": "ev_" + self.claim_id.removeprefix("claim_"),
            "source_kind": "document",
            "source_ref": self.snapshot_ref,
            "retrieved_at": self.retrieved_at,
            "attributes": attributes,
        }

    def to_record(self) -> Mapping[str, Any]:
        return {
            "claim_id": self.claim_id,
            "source_id": self.source_id,
            "snapshot_ref": self.snapshot_ref,
            "requested_url": self.requested_url,
            "final_url": self.final_url,
            "subject_ref": self.subject_ref,
            "predicate": self.predicate,
            "value": self.value,
            "retrieved_at": self.retrieved_at,
            "effective_at": self.effective_at,
            "fresh_until": self.fresh_until,
            "parser_version": self.parser_version,
            "content_hash": self.content_hash,
            "owner_ref": self.owner_ref,
            "reviewer_policy_ref": self.reviewer_policy_ref,
            "license_id": self.license_id,
            "license_metadata_ref": self.license_metadata_ref,
            "review_status": self.review_status.value,
            "source_classification": self.source_classification.value,
            "impact": self.impact.value,
            "conflict_group": self.conflict_group,
            "reviewed_by_ref": self.reviewed_by_ref,
            "reviewed_at": self.reviewed_at,
            "review_record_ref": self.review_record_ref,
            "evidence_ref": self.evidence_ref(),
        }


@dataclass(frozen=True)
class QuarantineRecord:
    snapshot_ref: str
    source_id: str
    retrieved_at: str
    finding_codes: tuple[str, ...]
    content_hash: str


@dataclass(frozen=True)
class IngestionResult:
    snapshot: RawSnapshot
    claims: tuple[NormalizedClaim, ...]
    quarantine: QuarantineRecord | None = None


class RawSnapshotStore(Protocol):
    """Production implementations should map this port to a governed UC Volume."""

    def put_once(self, snapshot: RawSnapshot, body: bytes) -> None: ...


class GovernedUcVolumeSnapshotStore(RawSnapshotStore, Protocol):
    """Port for immutable snapshot bytes rooted at one governed UC Volume."""

    @property
    def volume_ref(self) -> str: ...


class ManagedClaimRepository(Protocol):
    """Production implementations should append these records to managed tables."""

    def append(self, claims: Sequence[NormalizedClaim]) -> None: ...


class ManagedTableClaimRepository(ManagedClaimRepository, Protocol):
    """Port for normalized claim rows in one Unity Catalog managed table."""

    @property
    def table_ref(self) -> str: ...


class QuarantineSink(Protocol):
    """Production implementations should isolate these records from retrieval."""

    def put_quarantined(
        self, snapshot: RawSnapshot, body: bytes, record: QuarantineRecord
    ) -> None: ...


class ClaimParser(Protocol):
    @property
    def parser_version(self) -> str: ...

    def parse(self, snapshot: RawSnapshot, body: bytes) -> Sequence[ClaimDraft]: ...


class ReviewAuthorizer(Protocol):
    """Verifies that a human may act under the claim's reviewed owner policy."""

    def is_authorized(
        self, reviewer_ref: str, reviewer_policy_ref: str, reviewed_at: str
    ) -> bool: ...


def classify_sources(
    classifications: Sequence[SourceClassification],
) -> SourceClassification:
    flattened = set()
    for classification in classifications:
        if classification is SourceClassification.MIXED:
            flattened.update({SourceClassification.INTERNAL, SourceClassification.EXTERNAL})
        else:
            flattened.add(classification)
    if flattened == {SourceClassification.INTERNAL}:
        return SourceClassification.INTERNAL
    if flattened == {SourceClassification.EXTERNAL}:
        return SourceClassification.EXTERNAL
    return SourceClassification.MIXED


def _assert_evidence_target(subject_ref: str, predicate: str) -> None:
    lowered_subject = subject_ref.lower()
    lowered_predicate = re.sub(r"[-.]+", "_", predicate.lower())
    if (
        any(lowered_subject.startswith(prefix) for prefix in _PROTECTED_PREFIXES)
        or lowered_predicate in _PROTECTED_PREDICATES
        or lowered_predicate.startswith("authorization_")
        or lowered_predicate.startswith("data_boundary_")
        or lowered_predicate.startswith("grant_")
        or lowered_predicate.startswith("mcp_")
        or lowered_predicate.startswith("oauth_")
        or lowered_predicate.startswith("permission_")
        or lowered_predicate.startswith("product_manifest_")
        or lowered_predicate.startswith("resource_binding_")
        or lowered_predicate.startswith("role_")
        or lowered_predicate.startswith("scope_")
        or lowered_predicate.startswith("tool_")
    ):
        raise ProtectedControlTarget(
            "external evidence cannot target tools, ProductManifest, permissions, "
            "authorization, or data boundaries"
        )
    if not _OPAQUE_REF.fullmatch(subject_ref):
        raise ValueError("subject_ref must be opaque")
    if not re.fullmatch(r"[a-z][a-z0-9_.-]{1,95}", predicate):
        raise ValueError("predicate must be a stable lowercase identifier")


def _is_safe_allowlisted_host(host: str) -> bool:
    if (
        not isinstance(host, str)
        or host != host.lower()
        or "*" in host
        or "/" in host
        or host.endswith(".")
        or host == "localhost"
        or host.endswith((".localhost", ".local", ".internal"))
        or len(host) > 253
        or ".." in host
        or not re.fullmatch(r"[a-z0-9.-]+", host)
        or any(label.startswith("-") or label.endswith("-") for label in host.split("."))
    ):
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return True
    return False


def _canonical_url_path(path: str) -> str:
    if not path.startswith("/") or "\\" in path or "\x00" in path:
        raise PolicyDenied("URL path is not canonical")
    if _URL_ENCODED_PATH_DELIMITER.search(path):
        raise PolicyDenied("URL path contains an encoded delimiter")
    decoded_path = unquote(path)
    if (
        "\\" in decoded_path
        or "\x00" in decoded_path
        or any(ord(character) < 0x20 for character in decoded_path)
    ):
        raise PolicyDenied("URL path is not canonical")
    if unquote(decoded_path) != decoded_path:
        raise PolicyDenied("URL path contains nested percent encoding")
    normalized = posixpath.normpath(decoded_path)
    if normalized != decoded_path.rstrip("/") and not (
        decoded_path == "/" and normalized == "/"
    ):
        raise PolicyDenied("URL path is not canonical")
    return normalized


def _validate_draft(draft: ClaimDraft, policy: SourcePolicy) -> None:
    if not isinstance(draft, ClaimDraft):
        raise ValueError("reviewed parsers must emit ClaimDraft values")
    _assert_evidence_target(draft.subject_ref, draft.predicate)
    if not isinstance(draft.value, str) or not draft.value:
        raise ValueError("claim value must be a non-empty string")
    if len(draft.value.encode("utf-8")) > policy.max_claim_value_bytes:
        raise PolicyDenied("normalized claim value exceeds reviewed byte limit")
    if not isinstance(draft.impact, ClaimImpact):
        raise ValueError("claim impact is invalid")
    if draft.conflict_group and not _OPAQUE_REF.fullmatch(draft.conflict_group):
        raise ValueError("conflict_group must be an opaque reference")
    if any(
        not isinstance(classification, SourceClassification)
        for classification in draft.supporting_classifications
    ):
        raise ValueError("supporting source classification is invalid")


class ExternalIntelligenceIngestor:
    """Validates, snapshots, scans, normalizes, and appends evidence claims."""

    def __init__(
        self,
        registry: SourceRegistry,
        snapshots: RawSnapshotStore,
        claims: ManagedClaimRepository,
        quarantine: QuarantineSink,
        scanner: UntrustedTextScanner | None = None,
    ) -> None:
        self._registry = registry
        self._snapshots = snapshots
        self._claims = claims
        self._quarantine = quarantine
        self._scanner = scanner or UntrustedTextScanner()

    def ingest(self, envelope: FetchEnvelope, parser: ClaimParser) -> IngestionResult:
        policy = self._registry.validate(envelope)
        if not _PARSER_VERSION.fullmatch(parser.parser_version):
            raise ValueError("parser_version is invalid")
        if parser.parser_version not in policy.allowed_parser_versions:
            raise PolicyDenied("parser version is not approved for this source")
        url_metadata = "\n".join(
            unquote(url)
            for url in (
                envelope.requested_url,
                *envelope.redirect_chain,
                envelope.final_url,
            )
        ).encode("utf-8")
        if self._scanner.scan(url_metadata, "text/plain"):
            raise PolicyDenied("URL metadata contains sensitive or instruction-like content")
        content_hash = _sha256(envelope.body)
        finding_codes = tuple(
            sorted(
                {
                    finding.rule_id
                    for finding in self._scanner.scan(envelope.body, envelope.media_type)
                }
            )
        )
        snapshot_id = (
            "snap_"
            + _sha256(
                _canonical(
                    {
                        "source_id": envelope.source_id,
                        "requested_url": envelope.requested_url,
                        "final_url": envelope.final_url,
                        "redirect_chain": envelope.redirect_chain,
                        "network_destinations": [
                            {
                                "url": destination.url,
                                "resolved_addresses": destination.resolved_addresses,
                                "connected_address": destination.connected_address,
                            }
                            for destination in envelope.network_destinations
                        ],
                        "retrieved_at": envelope.retrieved_at,
                        "effective_at": envelope.effective_at,
                        "content_hash": content_hash,
                    }
                ).encode("utf-8")
            )[:32]
        )
        review_status = ReviewStatus.QUARANTINED if finding_codes else ReviewStatus.PENDING
        snapshot = RawSnapshot(
            snapshot_id=snapshot_id,
            source_id=envelope.source_id,
            requested_url=envelope.requested_url,
            final_url=envelope.final_url,
            redirect_chain=envelope.redirect_chain,
            network_destinations=envelope.network_destinations,
            retrieved_at=envelope.retrieved_at,
            effective_at=envelope.effective_at,
            content_hash=content_hash,
            media_type=envelope.media_type,
            byte_count=len(envelope.body),
            owner_ref=policy.owner_ref,
            reviewer_policy_ref=policy.reviewer_policy_ref,
            license_id=policy.license_id,
            license_metadata_ref=policy.license_metadata_ref,
            robots_policy=policy.robots_policy,
            rate_limit_max_requests_per_minute=(envelope.rate_limit_max_requests_per_minute),
            freshness_seconds=policy.freshness_seconds,
            source_classification=policy.classification,
            review_status=review_status,
            finding_codes=finding_codes,
        )
        if finding_codes:
            record = QuarantineRecord(
                snapshot_ref="snapshot:" + snapshot.snapshot_id,
                source_id=snapshot.source_id,
                retrieved_at=snapshot.retrieved_at,
                finding_codes=finding_codes,
                content_hash=content_hash,
            )
            self._quarantine.put_quarantined(snapshot, envelope.body, record)
            return IngestionResult(snapshot=snapshot, claims=(), quarantine=record)

        drafts = tuple(
            itertools.islice(parser.parse(snapshot, envelope.body), policy.max_claims + 1)
        )
        if len(drafts) > policy.max_claims:
            raise PolicyDenied("reviewed parser emitted too many claims")
        for draft in drafts:
            _validate_draft(draft, policy)
        extracted_finding_codes = tuple(
            sorted(
                {
                    finding.rule_id
                    for draft in drafts
                    for finding in self._scanner.scan(
                        _canonical(
                            {
                                "subject_ref": draft.subject_ref,
                                "predicate": draft.predicate,
                                "value": draft.value,
                                "conflict_group": draft.conflict_group,
                            }
                        ).encode("utf-8"),
                        "text/plain",
                    )
                }
            )
        )
        if extracted_finding_codes:
            snapshot = replace(
                snapshot,
                review_status=ReviewStatus.QUARANTINED,
                finding_codes=extracted_finding_codes,
            )
            record = QuarantineRecord(
                snapshot_ref="snapshot:" + snapshot.snapshot_id,
                source_id=snapshot.source_id,
                retrieved_at=snapshot.retrieved_at,
                finding_codes=extracted_finding_codes,
                content_hash=content_hash,
            )
            self._quarantine.put_quarantined(snapshot, envelope.body, record)
            return IngestionResult(snapshot=snapshot, claims=(), quarantine=record)

        self._snapshots.put_once(snapshot, envelope.body)
        normalized = []
        for draft in drafts:
            classification = classify_sources(
                (policy.classification, *draft.supporting_classifications)
            )
            stable = {
                "source_id": envelope.source_id,
                "snapshot_id": snapshot.snapshot_id,
                "subject_ref": draft.subject_ref,
                "predicate": draft.predicate,
                "value": draft.value,
                "effective_at": envelope.effective_at,
                "parser_version": parser.parser_version,
                "conflict_group": draft.conflict_group,
            }
            claim_id = "claim_" + _sha256(_canonical(stable).encode("utf-8"))[:24]
            normalized.append(
                NormalizedClaim(
                    claim_id=claim_id,
                    source_id=envelope.source_id,
                    snapshot_ref="snapshot:" + snapshot.snapshot_id,
                    requested_url=envelope.requested_url,
                    final_url=envelope.final_url,
                    subject_ref=draft.subject_ref,
                    predicate=draft.predicate,
                    value=draft.value,
                    retrieved_at=envelope.retrieved_at,
                    effective_at=envelope.effective_at,
                    fresh_until=format_timestamp(
                        parse_timestamp(envelope.effective_at)
                        + timedelta(seconds=policy.freshness_seconds)
                    ),
                    parser_version=parser.parser_version,
                    content_hash=content_hash,
                    owner_ref=policy.owner_ref,
                    reviewer_policy_ref=policy.reviewer_policy_ref,
                    license_id=policy.license_id,
                    license_metadata_ref=policy.license_metadata_ref,
                    review_status=ReviewStatus.PENDING,
                    source_classification=classification,
                    impact=draft.impact,
                    conflict_group=draft.conflict_group,
                )
            )
        self._claims.append(normalized)
        return IngestionResult(snapshot=snapshot, claims=tuple(normalized))


def record_human_review(
    claim: NormalizedClaim,
    *,
    approved: bool,
    reviewer_ref: str,
    reviewed_at: str,
    review_record_ref: str,
    authorizer: ReviewAuthorizer,
) -> NormalizedClaim:
    """Create a reviewed claim revision without mutating normalized evidence."""

    if not _OPAQUE_REF.fullmatch(reviewer_ref) or not reviewer_ref.startswith("user:"):
        raise ValueError("human reviewer_ref must be an opaque user")
    if not _OPAQUE_REF.fullmatch(review_record_ref) or not review_record_ref.startswith("review:"):
        raise ValueError("review_record_ref must be an opaque review record")
    if claim.review_status is not ReviewStatus.PENDING:
        raise ValueError("only pending claims may receive a review decision")
    parse_timestamp(reviewed_at)
    if parse_timestamp(reviewed_at) < parse_timestamp(claim.retrieved_at):
        raise ValueError("review cannot predate retrieval")
    if parse_timestamp(reviewed_at) >= parse_timestamp(claim.fresh_until):
        raise ValueError("stale claims cannot receive a review decision")
    if not authorizer.is_authorized(
        reviewer_ref,
        claim.reviewer_policy_ref,
        reviewed_at,
    ):
        raise PolicyDenied("reviewer is not authorized by the source review policy")
    return replace(
        claim,
        review_status=(ReviewStatus.APPROVED if approved else ReviewStatus.REJECTED),
        reviewed_by_ref=reviewer_ref,
        reviewed_at=reviewed_at,
        review_record_ref=review_record_ref,
    )


@dataclass(frozen=True)
class WithheldClaim:
    claim: NormalizedClaim
    reason: str


@dataclass(frozen=True)
class ConflictGroup:
    conflict_group: str
    claims: tuple[NormalizedClaim, ...]


@dataclass(frozen=True)
class ClaimSelection:
    claims: tuple[NormalizedClaim, ...]
    conflicts: tuple[ConflictGroup, ...]
    withheld: tuple[WithheldClaim, ...]


def select_claims(claims: Sequence[NormalizedClaim], *, as_of: str) -> ClaimSelection:
    """Return only current reviewed claims and preserve every active conflict."""

    instant = parse_timestamp(as_of)
    visible = []
    withheld = []
    for claim in claims:
        if instant < parse_timestamp(claim.effective_at):
            withheld.append(WithheldClaim(claim, "not_yet_effective"))
        elif instant >= parse_timestamp(claim.fresh_until):
            withheld.append(WithheldClaim(claim, "stale"))
        elif claim.review_status is not ReviewStatus.APPROVED:
            reason = (
                "human_approval_required"
                if claim.impact is ClaimImpact.HIGH and claim.review_status is ReviewStatus.PENDING
                else "review_not_approved"
            )
            withheld.append(WithheldClaim(claim, reason))
        elif not claim.reviewed_by_ref or not claim.reviewed_at or not claim.review_record_ref:
            withheld.append(WithheldClaim(claim, "review_provenance_missing"))
        elif instant < parse_timestamp(claim.reviewed_at):
            withheld.append(WithheldClaim(claim, "review_not_yet_effective"))
        else:
            visible.append(claim)

    grouped: dict[str, list[NormalizedClaim]] = {}
    for claim in visible:
        if claim.conflict_group:
            grouped.setdefault(claim.conflict_group, []).append(claim)
    conflicts = tuple(
        ConflictGroup(group, tuple(group_claims))
        for group, group_claims in sorted(grouped.items())
        if len({_canonical(claim.value) for claim in group_claims}) > 1
    )
    return ClaimSelection(tuple(visible), conflicts, tuple(withheld))


@dataclass(frozen=True)
class ControlPlaneBaseline:
    """Release-owned controls external evidence is structurally unable to edit."""

    tool_refs: tuple[str, ...]
    product_manifest_sha256: str
    permission_refs: tuple[str, ...]
    data_boundary_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", self.product_manifest_sha256):
            raise ValueError("product_manifest_sha256 must be a lowercase SHA-256 digest")
        ref_groups = (
            ("tool:", self.tool_refs),
            ("permission:", self.permission_refs),
            ("boundary:", self.data_boundary_refs),
        )
        for prefix, refs in ref_groups:
            if any(not _OPAQUE_REF.fullmatch(ref) or not ref.startswith(prefix) for ref in refs):
                raise ValueError(f"control-plane references must use the {prefix} namespace")

    @property
    def fingerprint(self) -> str:
        return _sha256(
            _canonical(
                {
                    "tool_refs": self.tool_refs,
                    "product_manifest_sha256": self.product_manifest_sha256,
                    "permission_refs": self.permission_refs,
                    "data_boundary_refs": self.data_boundary_refs,
                }
            ).encode("utf-8")
        )


@dataclass(frozen=True)
class BoundExternalEvidence:
    """Evidence-only view carrying a fingerprint, never mutable control values."""

    claims: tuple[NormalizedClaim, ...]
    evidence_refs: tuple[Mapping[str, Any], ...]
    conflicts: tuple[ConflictGroup, ...]
    control_plane_fingerprint: str


def bind_external_evidence(
    claims: Sequence[NormalizedClaim],
    control_plane: ControlPlaneBaseline,
    *,
    as_of: str,
) -> BoundExternalEvidence:
    selected = select_claims(claims, as_of=as_of)
    if selected.withheld:
        raise PolicyDenied(
            "external evidence must be approved, effective, and fresh before binding"
        )
    for claim in claims:
        _assert_evidence_target(claim.subject_ref, claim.predicate)
    return BoundExternalEvidence(
        claims=selected.claims,
        evidence_refs=tuple(claim.evidence_ref() for claim in selected.claims),
        conflicts=selected.conflicts,
        control_plane_fingerprint=control_plane.fingerprint,
    )
