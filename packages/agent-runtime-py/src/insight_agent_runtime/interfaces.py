"""Ports implemented by product, provider, and infrastructure adapters."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from .models import (
    Action,
    Answer,
    AuditEvent,
    EvidenceRef,
    PolicyDecision,
    RequestContext,
    ToolResult,
    VerifiedIdentity,
)

if TYPE_CHECKING:
    from .controls import ToolAdapterThreatPolicy


@runtime_checkable
class IdentityVerifier(Protocol):
    """Verifies platform-owned identity material for one request."""

    def verify(self, context: RequestContext) -> VerifiedIdentity: ...


@runtime_checkable
class PolicyEngine(Protocol):
    """Makes an explicit allow/deny decision for a verified actor and action."""

    def authorize(
        self,
        context: RequestContext,
        identity: VerifiedIdentity,
        action: Action,
    ) -> PolicyDecision: ...


@runtime_checkable
class GovernedTool(Protocol):
    """A tool that exposes its threat policy before execution."""

    @property
    def tool_ref(self) -> str: ...

    @property
    def threat_policy(self) -> ToolAdapterThreatPolicy: ...

    def invoke(
        self,
        context: RequestContext,
        identity: VerifiedIdentity,
        action: Action,
    ) -> ToolResult: ...


@runtime_checkable
class AnswerBuilder(Protocol):
    """Builds an answer from governed results and explicit evidence."""

    def build(
        self,
        context: RequestContext,
        results: Sequence[ToolResult],
        evidence: Sequence[EvidenceRef],
    ) -> Answer: ...


@runtime_checkable
class AuditSink(Protocol):
    """Receives already-redacted audit events."""

    def emit(self, event: AuditEvent) -> None: ...


@runtime_checkable
class KillSwitch(Protocol):
    """Resolves a release-owned kill-switch reference."""

    def is_active(self, kill_switch_ref: str) -> bool: ...
