"""Provider-neutral runtime value objects.

Wire-facing constructors deliberately validate through the sibling contracts
package instead of duplicating its schemas.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ContractValueError(ValueError):
    """Raised when a value does not satisfy a shared wire contract."""


class AuthorizationMode(str, Enum):
    USER_AUTHORIZATION = "user_authorization"
    EXPLICIT_SERVICE_PRINCIPAL = "explicit_service_principal"
    SYSTEM = "system"


class ActionEffect(str, Enum):
    READ_ONLY = "read_only"
    SIDE_EFFECT = "side_effect"


class ToolResultStatus(str, Enum):
    SUCCEEDED = "succeeded"
    DENIED = "denied"
    BLOCKED = "blocked"
    FAILED = "failed"


class ResponseTrust(str, Enum):
    UNTRUSTED = "untrusted"
    VALIDATED = "validated"
    TRUSTED = "trusted"


class ContentClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class AnswerBlockKind(str, Enum):
    TEXT = "text"
    TABLE = "table"
    QUANTITATIVE = "quantitative"


@dataclass(frozen=True)
class RequestAuthorization:
    mode: AuthorizationMode
    subject_ref: str
    scopes: tuple[str, ...] = ()


@dataclass(frozen=True)
class RequestContext:
    request_id: str
    correlation_id: str
    requested_at: str
    authorization: RequestAuthorization
    requested_capability: str
    prompt: str
    conversation_ref: str | None = None

    @classmethod
    def from_contract(cls, value: Mapping[str, Any]) -> RequestContext:
        """Create a runtime context after shared-schema validation."""

        try:
            from insight_agent_harness_contracts import validate_contract
        except ImportError as exc:  # pragma: no cover - packaging diagnostic
            raise RuntimeError(
                "install the sibling packages/contracts project or add its src "
                "directory to PYTHONPATH"
            ) from exc

        wire = dict(value)
        validation = validate_contract("request-context", wire)
        if not validation["valid"]:
            raise ContractValueError("; ".join(validation["errors"]))
        authorization = wire["authorization"]
        request_input = wire["input"]
        return cls(
            request_id=wire["request_id"],
            correlation_id=wire["correlation_id"],
            requested_at=wire["requested_at"],
            authorization=RequestAuthorization(
                mode=AuthorizationMode(authorization["mode"]),
                subject_ref=authorization["subject_ref"],
                scopes=tuple(authorization.get("scopes", ())),
            ),
            requested_capability=wire["requested_capability"],
            prompt=request_input["prompt"],
            conversation_ref=request_input.get("conversation_ref"),
        )


@dataclass(frozen=True)
class VerifiedIdentity:
    """Identity proven by a trusted verifier, never by request text."""

    subject_ref: str
    mode: AuthorizationMode
    scopes: tuple[str, ...] = ()
    assurance_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class Action:
    action_id: str
    name: str
    capability: str
    target_ref: str
    effect: ActionEffect = ActionEffect.READ_ONLY
    arguments: Mapping[str, Any] = field(default_factory=dict)
    idempotency_key: str | None = None


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason_code: str
    policy_refs: tuple[str, ...]
    message: str = ""


@dataclass(frozen=True)
class EvidenceRef:
    evidence_id: str
    source_kind: str
    source_ref: str
    retrieved_at: str
    excerpt: str | None = None
    attributes: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_contract(cls, value: Mapping[str, Any]) -> EvidenceRef:
        try:
            from insight_agent_harness_contracts import validate_contract
        except ImportError as exc:  # pragma: no cover - packaging diagnostic
            raise RuntimeError(
                "install the sibling packages/contracts project or add its src "
                "directory to PYTHONPATH"
            ) from exc

        wire = dict(value)
        validation = validate_contract("evidence-ref", wire)
        if not validation["valid"]:
            raise ContractValueError("; ".join(validation["errors"]))
        return cls(
            evidence_id=wire["evidence_id"],
            source_kind=wire["source_kind"],
            source_ref=wire["source_ref"],
            retrieved_at=wire["retrieved_at"],
            excerpt=wire.get("excerpt"),
            attributes=wire.get("attributes", {}),
        )


@dataclass(frozen=True)
class ToolResult:
    tool_ref: str
    status: ToolResultStatus
    content: Any
    evidence: tuple[EvidenceRef, ...] = ()
    response_trust: ResponseTrust = ResponseTrust.UNTRUSTED
    content_classification: ContentClassification = ContentClassification.INTERNAL
    retryable: bool = False
    byte_count: int = 0


@dataclass(frozen=True)
class AnswerBlock:
    block_id: str
    kind: AnswerBlockKind
    content: str
    evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class Answer:
    summary: str
    blocks: tuple[AnswerBlock, ...]
    evidence: tuple[EvidenceRef, ...]

    @classmethod
    def from_run_contract(cls, value: Mapping[str, Any]) -> Answer:
        """Consume a shared run-envelope value produced by either language."""

        try:
            from insight_agent_harness_contracts import validate_contract
        except ImportError as exc:  # pragma: no cover - packaging diagnostic
            raise RuntimeError(
                "install the sibling packages/contracts project or add its src "
                "directory to PYTHONPATH"
            ) from exc

        wire = dict(value)
        validation = validate_contract("run-envelope", wire)
        if not validation["valid"]:
            raise ContractValueError("; ".join(validation["errors"]))
        if wire["status"] != "complete":
            raise ContractValueError("only complete run envelopes contain answers")
        output = wire["output"]
        return cls(
            summary=output["summary"],
            blocks=tuple(
                AnswerBlock(
                    block_id=block["block_id"],
                    kind=AnswerBlockKind(block["kind"]),
                    content=block["content"],
                    evidence_refs=tuple(block["evidence_refs"]),
                )
                for block in output["content_blocks"]
            ),
            evidence=tuple(
                EvidenceRef.from_contract(evidence) for evidence in wire.get("evidence", ())
            ),
        )


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    event_type: str
    occurred_at: str
    actor_mode: AuthorizationMode
    actor_subject_ref: str
    action: str
    target_ref: str
    outcome: str
    correlation_id: str
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_contract(self) -> Mapping[str, Any]:
        return {
            "schema_version": "1.0.0",
            "event_id": self.event_id,
            "event_type": self.event_type,
            "occurred_at": self.occurred_at,
            "actor": {
                "mode": self.actor_mode.value,
                "subject_ref": self.actor_subject_ref,
            },
            "action": self.action,
            "target_ref": self.target_ref,
            "outcome": self.outcome,
            "correlation_id": self.correlation_id,
            "details": dict(self.details),
        }


def evidence_by_id(evidence: Sequence[EvidenceRef]) -> Mapping[str, EvidenceRef]:
    """Index evidence while rejecting ambiguous duplicate identifiers."""

    indexed = {}
    for item in evidence:
        if item.evidence_id in indexed:
            raise ValueError(f"duplicate evidence id: {item.evidence_id}")
        indexed[item.evidence_id] = item
    return indexed
