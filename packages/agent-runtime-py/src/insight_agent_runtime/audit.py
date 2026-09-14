"""Redaction-safe audit hooks for runtime control points."""

from __future__ import annotations

import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from .interfaces import AuditSink
from .models import Action, AuditEvent, RequestContext, ToolResult, VerifiedIdentity

_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*")
_EMAIL = re.compile(r"(?<![\w.-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])")


@dataclass(frozen=True)
class RedactionProfile:
    sensitive_key_fragments: tuple[str, ...] = (
        "authorization",
        "cookie",
        "credential",
        "email",
        "password",
        "prompt",
        "secret",
        "token",
    )
    max_string_length: int = 512
    max_collection_items: int = 32
    max_depth: int = 4

    def __post_init__(self) -> None:
        if not 32 <= self.max_string_length <= 4096:
            raise ValueError("max_string_length must be in [32, 4096]")
        if not 1 <= self.max_collection_items <= 32:
            raise ValueError("max_collection_items must be in [1, 32]")
        if not 1 <= self.max_depth <= 8:
            raise ValueError("max_depth must be in [1, 8]")


_DEFAULT_REDACTION_PROFILE = RedactionProfile()


class AuditRedactor:
    def __init__(self, profile: RedactionProfile = _DEFAULT_REDACTION_PROFILE) -> None:
        self.profile = profile

    def sanitize(self, value: Any, *, depth: int = 0) -> Any:
        if depth >= self.profile.max_depth:
            return "[TRUNCATED]"
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, str):
            cleaned = _BEARER.sub("[REDACTED]", value)
            cleaned = _EMAIL.sub("[REDACTED]", cleaned)
            if len(cleaned) > self.profile.max_string_length:
                return cleaned[: self.profile.max_string_length] + "…"
            return cleaned
        if isinstance(value, bytes):
            return "[REDACTED_BYTES]"
        if isinstance(value, Mapping):
            sanitized = {}
            for index, (key, item) in enumerate(value.items()):
                if index >= self.profile.max_collection_items:
                    sanitized["_truncated"] = True
                    break
                normalized_key = str(key)[:128]
                if any(
                    fragment in normalized_key.lower()
                    for fragment in self.profile.sensitive_key_fragments
                ):
                    sanitized[normalized_key] = "[REDACTED]"
                else:
                    sanitized[normalized_key] = self.sanitize(item, depth=depth + 1)
            return sanitized
        if isinstance(value, Sequence):
            return [
                self.sanitize(item, depth=depth + 1)
                for item in value[: self.profile.max_collection_items]
            ]
        return f"[UNSUPPORTED:{type(value).__name__}]"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


class RedactionSafeAuditHooks:
    """Builds contract-valid events without logging prompts or tool payloads."""

    def __init__(
        self,
        sink: AuditSink,
        *,
        redactor: AuditRedactor | None = None,
        now: Callable[[], str] = _utc_now,
        event_id: Callable[[], str] | None = None,
    ) -> None:
        self._sink = sink
        self._redactor = redactor or AuditRedactor()
        self._now = now
        self._event_id = event_id or (lambda: "audit_" + uuid.uuid4().hex)

    def authorization(
        self,
        context: RequestContext,
        identity: VerifiedIdentity,
        *,
        allowed: bool,
        policy_refs: Sequence[str],
        reason_code: str,
    ) -> AuditEvent:
        return self._emit(
            context,
            identity,
            event_type="authorization",
            action="authorization.evaluate",
            target_ref="capability:" + context.requested_capability,
            outcome="allowed" if allowed else "denied",
            details={
                "policy_refs": list(policy_refs),
                "reason_code": reason_code,
                "scope_count": len(identity.scopes),
            },
        )

    def tool_call(
        self,
        context: RequestContext,
        identity: VerifiedIdentity,
        action: Action,
        *,
        result: ToolResult,
        attempt: int,
    ) -> AuditEvent:
        return self._emit(
            context,
            identity,
            event_type="tool_call",
            action=action.name,
            target_ref=action.target_ref,
            outcome=result.status.value,
            details={
                "action_id": action.action_id,
                "attempt": attempt,
                "byte_count": result.byte_count,
                "content_classification": result.content_classification.value,
                "evidence_count": len(result.evidence),
                "response_trust": result.response_trust.value,
                "retryable": result.retryable,
                "tool_ref": result.tool_ref,
            },
        )

    def run_completed(
        self,
        context: RequestContext,
        identity: VerifiedIdentity,
        *,
        outcome: str,
        run_ref: str,
        steps: int,
        tool_calls: int,
        output_bytes: int,
    ) -> AuditEvent:
        return self._emit(
            context,
            identity,
            event_type="run_completed",
            action="run.complete",
            target_ref=run_ref,
            outcome=outcome,
            details={
                "steps": steps,
                "tool_calls": tool_calls,
                "output_bytes": output_bytes,
            },
        )

    def _emit(
        self,
        context: RequestContext,
        identity: VerifiedIdentity,
        *,
        event_type: str,
        action: str,
        target_ref: str,
        outcome: str,
        details: Mapping[str, Any],
    ) -> AuditEvent:
        event = AuditEvent(
            event_id=self._event_id(),
            event_type=event_type,
            occurred_at=self._now(),
            actor_mode=identity.mode,
            actor_subject_ref=identity.subject_ref,
            action=action,
            target_ref=target_ref,
            outcome=outcome,
            correlation_id=context.correlation_id,
            details=self._redactor.sanitize(details),
        )
        try:
            from insight_agent_harness_contracts import validate_contract
        except ImportError as exc:  # pragma: no cover - packaging diagnostic
            raise RuntimeError(
                "install the sibling packages/contracts project or add its src "
                "directory to PYTHONPATH"
            ) from exc
        validation = validate_contract("audit-event", dict(event.to_contract()))
        if not validation["valid"]:
            raise ValueError("invalid audit event: {}".format("; ".join(validation["errors"])))
        self._sink.emit(event)
        return event
