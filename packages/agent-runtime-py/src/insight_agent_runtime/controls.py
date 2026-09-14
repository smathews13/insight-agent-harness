"""Bounded execution, retry, provider, and tool-adapter controls."""

from __future__ import annotations

import time
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Callable, Protocol, TypeVar, Union

from .models import (
    Action,
    ActionEffect,
    AuthorizationMode,
    ContentClassification,
    PolicyDecision,
    ResponseTrust,
    VerifiedIdentity,
)

T = TypeVar("T")


class RuntimeControlError(RuntimeError):
    """Base class for fail-closed runtime control failures."""


class DeadlineExceeded(RuntimeControlError):
    pass


class LimitExceeded(RuntimeControlError):
    pass


class UnsafeRetryError(RuntimeControlError):
    pass


class RetryExhaustedError(RuntimeControlError):
    def __init__(self, attempts: int, last_error: Exception) -> None:
        super().__init__(f"retry attempts exhausted after {attempts} attempts")
        self.attempts = attempts
        self.last_error = last_error


class ToolThreatPolicyError(RuntimeControlError):
    pass


@dataclass(frozen=True)
class RuntimeLimits:
    """Run bounds aligned with the shared product-manifest maxima."""

    deadline_seconds: float
    max_steps: int
    max_tool_calls: int
    max_output_bytes: int

    def __post_init__(self) -> None:
        if not 0 < self.deadline_seconds <= 900:
            raise ValueError("deadline_seconds must be in (0, 900]")
        if not 1 <= self.max_steps <= 64:
            raise ValueError("max_steps must be in [1, 64]")
        if not 1 <= self.max_tool_calls <= 128:
            raise ValueError("max_tool_calls must be in [1, 128]")
        if not 1024 <= self.max_output_bytes <= 10_485_760:
            raise ValueError("max_output_bytes must be in [1024, 10485760]")


class Deadline:
    """Monotonic deadline suitable for checking around provider calls."""

    def __init__(
        self,
        timeout_seconds: float,
        *,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._monotonic = monotonic
        self._expires_at = monotonic() + timeout_seconds

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self._expires_at - self._monotonic())

    def check(self) -> None:
        if self.remaining_seconds <= 0:
            raise DeadlineExceeded("runtime deadline exceeded")


class LimitTracker:
    """Tracks steps, tool calls, and emitted bytes without soft overages."""

    def __init__(self, limits: RuntimeLimits) -> None:
        self.limits = limits
        self.steps = 0
        self.tool_calls = 0
        self.output_bytes = 0

    def record_step(self, count: int = 1) -> None:
        self.steps = self._bounded_total("step", self.steps, count, self.limits.max_steps)

    def record_tool_call(self, count: int = 1) -> None:
        self.tool_calls = self._bounded_total(
            "tool call", self.tool_calls, count, self.limits.max_tool_calls
        )

    def record_output(self, value: object) -> None:
        size = len(value) if isinstance(value, bytes) else len(str(value).encode("utf-8"))
        self.output_bytes = self._bounded_total(
            "output byte", self.output_bytes, size, self.limits.max_output_bytes
        )

    @staticmethod
    def _bounded_total(label: str, current: int, increment: int, maximum: int) -> int:
        if increment < 0:
            raise ValueError(f"{label} increment cannot be negative")
        total = current + increment
        if total > maximum:
            raise LimitExceeded(f"{label} limit exceeded")
        return total


@dataclass(frozen=True)
class BoundedRetryPolicy:
    """Retry policy that cannot make unsafe side effects or unbounded attempts."""

    max_attempts: int = 3
    initial_delay_seconds: float = 0.1
    backoff_multiplier: float = 2.0
    max_delay_seconds: float = 2.0

    def __post_init__(self) -> None:
        if not 1 <= self.max_attempts <= 5:
            raise ValueError("max_attempts must be in [1, 5]")
        if not 0 <= self.initial_delay_seconds <= 5:
            raise ValueError("initial_delay_seconds must be in [0, 5]")
        if not 1 <= self.backoff_multiplier <= 4:
            raise ValueError("backoff_multiplier must be in [1, 4]")
        if not 0 <= self.max_delay_seconds <= 30:
            raise ValueError("max_delay_seconds must be in [0, 30]")

    def run(
        self,
        operation: Callable[[], T],
        *,
        idempotent: bool,
        side_effecting: bool = False,
        idempotency_key: str | None = None,
        is_retryable: Callable[[Exception], bool],
        deadline: Deadline | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> T:
        if self.max_attempts > 1 and not idempotent:
            raise UnsafeRetryError("multi-attempt retries require an idempotent operation")
        if side_effecting and self.max_attempts > 1 and not idempotency_key:
            raise UnsafeRetryError("side-effecting retries require a stable idempotency key")

        delay = self.initial_delay_seconds
        last_error: Exception | None = None
        for attempt in range(1, self.max_attempts + 1):
            if deadline is not None:
                deadline.check()
            try:
                return operation()
            except Exception as exc:
                last_error = exc
                if not is_retryable(exc):
                    raise
                if attempt == self.max_attempts:
                    break
                bounded_delay = min(delay, self.max_delay_seconds)
                if deadline is not None:
                    if bounded_delay >= deadline.remaining_seconds:
                        raise DeadlineExceeded("retry delay would exceed runtime deadline") from exc
                sleep(bounded_delay)
                delay = min(
                    self.max_delay_seconds,
                    delay * self.backoff_multiplier,
                )

        assert last_error is not None
        raise RetryExhaustedError(self.max_attempts, last_error) from last_error


@dataclass(frozen=True)
class ProviderCapabilities:
    provider_ref: str
    capabilities: frozenset[str]
    enabled: bool = True
    priority: int = 100

    def __post_init__(self) -> None:
        if not self.provider_ref or ":" not in self.provider_ref:
            raise ValueError("provider_ref must be an opaque typed reference")
        if not 0 <= self.priority <= 10_000:
            raise ValueError("priority must be in [0, 10000]")


@dataclass(frozen=True)
class ProviderRequirement:
    required: frozenset[str]
    preferred: frozenset[str] = frozenset()


@dataclass(frozen=True)
class ProviderDecision:
    selected_provider_ref: str | None
    fallback_used: bool
    reason: str
    missing_capabilities: tuple[str, ...] = ()
    fallback_policy_ref: str | None = None

    @property
    def allowed(self) -> bool:
        return self.selected_provider_ref is not None


@dataclass(frozen=True)
class ProviderFallbackAuditRecord:
    """Payload-free record proving an explicitly governed provider fallback."""

    requested_provider_ref: str
    selected_provider_ref: str
    reason: str
    fallback_policy_ref: str
    required_capabilities: tuple[str, ...]


class ProviderFallbackAuditSink(Protocol):
    def record(self, event: ProviderFallbackAuditRecord) -> None: ...


ProviderFallbackAuditTarget = Union[
    Callable[[ProviderFallbackAuditRecord], None],
    ProviderFallbackAuditSink,
]


class ProviderCapabilityMatrix:
    """Selects a capable provider and makes every fallback explicit."""

    def __init__(self, providers: Iterable[ProviderCapabilities]) -> None:
        provider_list = tuple(providers)
        self._providers = {provider.provider_ref: provider for provider in provider_list}
        if len(self._providers) != len(provider_list):
            raise ValueError("provider references must be unique")

    def decide(
        self,
        requirement: ProviderRequirement,
        *,
        requested_provider_ref: str | None = None,
        fallback_policy_ref: str | None = None,
        fallback_audit: ProviderFallbackAuditTarget | None = None,
    ) -> ProviderDecision:
        requested = (
            self._providers.get(requested_provider_ref)
            if requested_provider_ref is not None
            else None
        )
        if requested_provider_ref is not None and requested is None:
            failure_reason = "requested provider is not registered"
            missing = ()
        elif requested is not None:
            missing = tuple(sorted(requirement.required - requested.capabilities))
            if requested.enabled and not missing:
                return ProviderDecision(
                    requested.provider_ref,
                    False,
                    "requested provider satisfies all required capabilities",
                )
            failure_reason = (
                "requested provider is disabled"
                if not requested.enabled
                else "requested provider lacks required capabilities"
            )
        else:
            failure_reason = ""
            missing = ()

        fallback_requested = requested_provider_ref is not None
        if fallback_requested:
            if not fallback_policy_ref:
                return ProviderDecision(
                    None,
                    False,
                    failure_reason + "; explicit reviewed fallback_policy_ref is required",
                    missing,
                )
            if not isinstance(fallback_policy_ref, str) or not fallback_policy_ref.startswith(
                "policy:"
            ):
                return ProviderDecision(
                    None,
                    False,
                    failure_reason + "; fallback policy reference is invalid",
                    missing,
                )
            if fallback_audit is None:
                return ProviderDecision(
                    None,
                    False,
                    failure_reason + "; fallback audit sink is required",
                    missing,
                    fallback_policy_ref,
                )

        candidates = [
            provider
            for provider in self._providers.values()
            if provider.enabled
            and requirement.required.issubset(provider.capabilities)
            and provider.provider_ref != requested_provider_ref
        ]
        if not candidates:
            return ProviderDecision(
                None,
                False,
                (
                    failure_reason + "; no fallback provider has required capability parity"
                    if fallback_requested
                    else "no enabled provider satisfies all required capabilities"
                ),
                missing,
                fallback_policy_ref,
            )
        candidates.sort(
            key=lambda provider: (
                len(requirement.preferred - provider.capabilities),
                provider.priority,
                provider.provider_ref,
            )
        )
        selected = candidates[0]
        if not fallback_requested:
            return ProviderDecision(
                selected.provider_ref,
                False,
                "best capable provider selected",
            )

        fallback_reason = (
            failure_reason + "; reviewed policy permits a capability-equivalent fallback"
        )
        audit_record = ProviderFallbackAuditRecord(
            requested_provider_ref=requested_provider_ref,
            selected_provider_ref=selected.provider_ref,
            reason=fallback_reason,
            fallback_policy_ref=fallback_policy_ref,
            required_capabilities=tuple(sorted(requirement.required)),
        )
        try:
            if callable(fallback_audit):
                fallback_audit(audit_record)
            else:
                fallback_audit.record(audit_record)
        except Exception:
            return ProviderDecision(
                None,
                False,
                failure_reason + "; fallback audit failed closed",
                missing,
                fallback_policy_ref,
            )
        return ProviderDecision(
            selected.provider_ref,
            True,
            fallback_reason,
            missing,
            fallback_policy_ref,
        )


_CLASSIFICATION_ORDER = {
    ContentClassification.PUBLIC: 0,
    ContentClassification.INTERNAL: 1,
    ContentClassification.CONFIDENTIAL: 2,
    ContentClassification.RESTRICTED: 3,
}


@dataclass(frozen=True)
class ToolAdapterThreatPolicy:
    """Static threat declaration required before a tool can be invoked."""

    policy_ref: str
    destination_allowlist_refs: tuple[str, ...]
    response_trust: ResponseTrust
    maximum_content_classification: ContentClassification
    max_response_bytes: int
    effect: ActionEffect
    idempotent: bool
    require_idempotency_key: bool
    kill_switch_ref: str
    allowed_authorization_modes: tuple[AuthorizationMode, ...] = (
        AuthorizationMode.USER_AUTHORIZATION,
    )

    def __post_init__(self) -> None:
        refs = (
            self.policy_ref,
            self.kill_switch_ref,
            *self.destination_allowlist_refs,
        )
        if not self.destination_allowlist_refs:
            raise ValueError("at least one destination allowlist reference is required")
        if any(not ref or ":" not in ref for ref in refs):
            raise ValueError("threat-policy references must be opaque typed references")
        if not 1 <= self.max_response_bytes <= 10_485_760:
            raise ValueError("max_response_bytes must be in [1, 10485760]")
        if not self.allowed_authorization_modes:
            raise ValueError("at least one authorization mode is required")
        if self.effect is ActionEffect.SIDE_EFFECT:
            if not self.idempotent:
                raise ValueError("side-effecting adapters must be idempotent")
            if not self.require_idempotency_key:
                raise ValueError("side-effecting adapters must require an idempotency key")

    def authorize_invocation(
        self,
        action: Action,
        *,
        identity: VerifiedIdentity,
        destination_allowlist_ref: str,
        kill_switch_active: bool,
    ) -> PolicyDecision:
        policy_refs = (self.policy_ref, self.kill_switch_ref)
        if kill_switch_active:
            return PolicyDecision(
                False,
                "kill_switch_active",
                policy_refs,
                "tool adapter is disabled by its kill switch",
            )
        if identity.mode not in self.allowed_authorization_modes:
            return PolicyDecision(
                False,
                "execution_identity_not_allowed",
                policy_refs,
                "governed tools deny system and internal execution by default",
            )
        if destination_allowlist_ref not in self.destination_allowlist_refs:
            return PolicyDecision(
                False,
                "destination_not_allowlisted",
                policy_refs,
                "destination is not covered by an approved allowlist reference",
            )
        if action.effect is not self.effect:
            return PolicyDecision(
                False,
                "side_effect_mismatch",
                policy_refs,
                "action side effects do not match the adapter declaration",
            )
        if self.require_idempotency_key and not action.idempotency_key:
            return PolicyDecision(
                False,
                "idempotency_key_required",
                policy_refs,
                "adapter requires a stable idempotency key",
            )
        return PolicyDecision(True, "allowed", policy_refs)

    def validate_response(
        self,
        *,
        byte_count: int,
        content_classification: ContentClassification,
        response_trust: ResponseTrust,
    ) -> None:
        if byte_count < 0 or byte_count > self.max_response_bytes:
            raise ToolThreatPolicyError("tool response exceeds its declared size limit")
        if (
            _CLASSIFICATION_ORDER[content_classification]
            > _CLASSIFICATION_ORDER[self.maximum_content_classification]
        ):
            raise ToolThreatPolicyError("tool response exceeds its approved content classification")
        if response_trust is not self.response_trust:
            raise ToolThreatPolicyError(
                "tool response trust does not match the adapter declaration"
            )
