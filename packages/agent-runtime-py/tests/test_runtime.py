from __future__ import annotations

# These package roots are intentionally injected before the local imports.
# ruff: noqa: E402
import json
import sys
import unittest
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
CONTRACTS_ROOT = PACKAGE_ROOT.parent / "contracts"
sys.path.insert(0, str(PACKAGE_ROOT / "src"))
sys.path.insert(0, str(CONTRACTS_ROOT / "src"))

from insight_agent_harness_contracts import validate_contract
from insight_agent_runtime import (
    Action,
    ActionEffect,
    Answer,
    AnswerBlock,
    AnswerBlockKind,
    AuditRedactor,
    AuthorizationMode,
    BoundedRetryPolicy,
    ContentClassification,
    Deadline,
    DeadlineExceeded,
    EvidenceRef,
    LimitExceeded,
    LimitTracker,
    ProductExtensionRefs,
    ProviderCapabilities,
    ProviderCapabilityMatrix,
    ProviderRequirement,
    QuantitativeAnswerValidator,
    RedactionSafeAuditHooks,
    RequestContext,
    ResponseTrust,
    RetryExhaustedError,
    RuntimeLimits,
    ToolAdapterThreatPolicy,
    ToolResult,
    ToolResultStatus,
    ToolThreatPolicyError,
    UnsafeRetryError,
    VerifiedIdentity,
    compose_responses_agent,
)

FIXTURES = json.loads(
    (CONTRACTS_ROOT / "fixtures" / "contracts.json").read_text(encoding="utf-8")
)


class _CompatibleModel:
    def predict(self) -> None:
        pass

    def predict_stream(self) -> None:
        pass


class ProductCompositionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = {
            "extensions": {
                "prompts": "extension:prompts/sample-neutral",
                "knowledge": "extension:knowledge/sample-neutral",
                "tool_registry": "extension:tools/sample-neutral",
            }
        }
        self.refs = ProductExtensionRefs.from_manifest(self.manifest)

    def test_composes_only_an_extension_bound_to_manifest_refs(self) -> None:
        model = _CompatibleModel()
        self.assertIs(
            compose_responses_agent(self.manifest, self.refs, lambda: model),
            model,
        )

    def test_rejects_extension_ref_drift(self) -> None:
        called = False

        def factory() -> _CompatibleModel:
            nonlocal called
            called = True
            return _CompatibleModel()

        drifted = ProductExtensionRefs(
            prompts="extension:prompts/other",
            knowledge=self.refs.knowledge,
            tool_registry=self.refs.tool_registry,
        )
        with self.assertRaisesRegex(RuntimeError, "signed ProductManifest"):
            compose_responses_agent(self.manifest, drifted, factory)
        self.assertFalse(called, "a rejected extension must not execute its factory")

    def test_extension_refs_are_data_identifiers_not_paths(self) -> None:
        for value in (
            "../../privileged",
            "extension:prompts/../../privileged",
            "extension:prompts//privileged",
            "extension:knowledge/sample-neutral",
            "extension:tools/sample-neutral",
        ):
            manifest = {
                "extensions": {
                    **self.manifest["extensions"],
                    "prompts": value,
                }
            }
            with self.subTest(value=value), self.assertRaisesRegex(
                RuntimeError, "extension reference"
            ):
                ProductExtensionRefs.from_manifest(manifest)


def make_context() -> RequestContext:
    return RequestContext.from_contract(FIXTURES["user_auth_request"])


def make_identity() -> VerifiedIdentity:
    return VerifiedIdentity(
        subject_ref="principal:requesting-user",
        mode=AuthorizationMode.USER_AUTHORIZATION,
        scopes=("sql",),
        assurance_refs=("identity:verified",),
    )


class CrossLanguageContractTests(unittest.TestCase):
    def test_consumes_shared_request_fixture_by_path(self) -> None:
        fixture = FIXTURES["user_auth_request"]
        self.assertTrue(validate_contract("request-context", fixture)["valid"])
        context = RequestContext.from_contract(fixture)
        self.assertEqual(context.request_id, "req_neutral_001")
        self.assertEqual(context.authorization.scopes, ("sql",))

    def test_consumes_shared_complete_run_fixture_by_path(self) -> None:
        fixture = FIXTURES["complete_run"]
        self.assertTrue(validate_contract("run-envelope", fixture)["valid"])
        answer = Answer.from_run_contract(fixture)
        self.assertTrue(QuantitativeAnswerValidator().validate(answer).valid)
        self.assertEqual(answer.evidence[0].evidence_id, "ev_neutral_001")


class LimitAndRetryTests(unittest.TestCase):
    def test_hard_limits_fail_before_recording_an_overage(self) -> None:
        tracker = LimitTracker(
            RuntimeLimits(
                deadline_seconds=30,
                max_steps=2,
                max_tool_calls=1,
                max_output_bytes=1024,
            )
        )
        tracker.record_step(2)
        tracker.record_tool_call()
        tracker.record_output(b"x" * 1024)
        with self.assertRaises(LimitExceeded):
            tracker.record_step()
        with self.assertRaises(LimitExceeded):
            tracker.record_tool_call()
        with self.assertRaises(LimitExceeded):
            tracker.record_output("x")
        self.assertEqual((tracker.steps, tracker.tool_calls, tracker.output_bytes), (2, 1, 1024))

    def test_deadline_uses_monotonic_time(self) -> None:
        clock = [10.0]
        deadline = Deadline(2.0, monotonic=lambda: clock[0])
        clock[0] = 11.5
        self.assertEqual(deadline.remaining_seconds, 0.5)
        clock[0] = 12.0
        with self.assertRaises(DeadlineExceeded):
            deadline.check()

    def test_retry_is_bounded_and_backed_off(self) -> None:
        attempts = []
        sleeps = []

        def operation() -> str:
            attempts.append(len(attempts) + 1)
            if len(attempts) < 3:
                raise TimeoutError("temporary")
            return "ok"

        result = BoundedRetryPolicy(
            max_attempts=3,
            initial_delay_seconds=0.25,
            backoff_multiplier=2,
            max_delay_seconds=1,
        ).run(
            operation,
            idempotent=True,
            is_retryable=lambda error: isinstance(error, TimeoutError),
            sleep=sleeps.append,
        )
        self.assertEqual(result, "ok")
        self.assertEqual(attempts, [1, 2, 3])
        self.assertEqual(sleeps, [0.25, 0.5])

    def test_retry_rejects_unsafe_operations(self) -> None:
        policy = BoundedRetryPolicy(max_attempts=2)
        with self.assertRaises(UnsafeRetryError):
            policy.run(
                lambda: None,
                idempotent=False,
                is_retryable=lambda error: True,
            )
        with self.assertRaises(UnsafeRetryError):
            policy.run(
                lambda: None,
                idempotent=True,
                side_effecting=True,
                is_retryable=lambda error: True,
            )

    def test_retry_reports_exhaustion(self) -> None:
        with self.assertRaises(RetryExhaustedError) as raised:
            BoundedRetryPolicy(
                max_attempts=2,
                initial_delay_seconds=0,
            ).run(
                lambda: (_ for _ in ()).throw(TimeoutError("temporary")),
                idempotent=True,
                is_retryable=lambda error: True,
                sleep=lambda delay: None,
            )
        self.assertEqual(raised.exception.attempts, 2)


class ProviderDecisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.matrix = ProviderCapabilityMatrix(
            provider
            for provider in (
                ProviderCapabilities(
                    "provider:primary",
                    frozenset({"chat"}),
                    priority=1,
                ),
                ProviderCapabilities(
                    "provider:analytics",
                    frozenset({"chat", "structured_output", "tool_calls"}),
                    priority=2,
                ),
            )
        )
        self.requirement = ProviderRequirement(
            required=frozenset({"chat", "tool_calls"}),
            preferred=frozenset({"structured_output"}),
        )

    def test_requested_provider_blocks_without_silent_fallback(self) -> None:
        decision = self.matrix.decide(
            self.requirement,
            requested_provider_ref="provider:primary",
        )
        self.assertFalse(decision.allowed)
        self.assertFalse(decision.fallback_used)
        self.assertIn("fallback_policy_ref is required", decision.reason)
        self.assertEqual(decision.missing_capabilities, ("tool_calls",))

    def test_fallback_blocks_without_policy_even_with_audit_sink(self) -> None:
        audited = []
        decision = self.matrix.decide(
            self.requirement,
            requested_provider_ref="provider:primary",
            fallback_audit=audited.append,
        )
        self.assertFalse(decision.allowed)
        self.assertIn("fallback_policy_ref is required", decision.reason)
        self.assertEqual(audited, [])

    def test_bare_boolean_cannot_enable_fallback(self) -> None:
        with self.assertRaises(TypeError):
            self.matrix.decide(
                self.requirement,
                requested_provider_ref="provider:primary",
                allow_fallback=True,
            )

        audited = []
        decision = self.matrix.decide(
            self.requirement,
            requested_provider_ref="provider:primary",
            fallback_policy_ref=True,
            fallback_audit=audited.append,
        )
        self.assertFalse(decision.allowed)
        self.assertIn("policy reference is invalid", decision.reason)
        self.assertEqual(audited, [])

    def test_fallback_blocks_without_audit_sink(self) -> None:
        decision = self.matrix.decide(
            self.requirement,
            requested_provider_ref="provider:primary",
            fallback_policy_ref="policy:reviewed-provider-fallback",
        )
        self.assertFalse(decision.allowed)
        self.assertIn("audit sink is required", decision.reason)

    def test_fallback_blocks_without_required_capability_parity(self) -> None:
        audited = []
        matrix = ProviderCapabilityMatrix(
            (
                ProviderCapabilities("provider:primary", frozenset({"chat"})),
                ProviderCapabilities("provider:alternate", frozenset({"chat"})),
            )
        )
        decision = matrix.decide(
            self.requirement,
            requested_provider_ref="provider:primary",
            fallback_policy_ref="policy:reviewed-provider-fallback",
            fallback_audit=audited.append,
        )
        self.assertFalse(decision.allowed)
        self.assertIn("required capability parity", decision.reason)
        self.assertEqual(audited, [])

    def test_approved_explicit_fallback_is_audited_and_reported(self) -> None:
        audited = []
        decision = self.matrix.decide(
            self.requirement,
            requested_provider_ref="provider:primary",
            fallback_policy_ref="policy:reviewed-provider-fallback",
            fallback_audit=audited.append,
        )
        self.assertEqual(decision.selected_provider_ref, "provider:analytics")
        self.assertTrue(decision.fallback_used)
        self.assertEqual(
            decision.fallback_policy_ref,
            "policy:reviewed-provider-fallback",
        )
        self.assertEqual(len(audited), 1)
        self.assertEqual(audited[0].requested_provider_ref, "provider:primary")
        self.assertEqual(audited[0].selected_provider_ref, "provider:analytics")
        self.assertEqual(
            audited[0].fallback_policy_ref,
            "policy:reviewed-provider-fallback",
        )
        self.assertEqual(
            audited[0].required_capabilities,
            ("chat", "tool_calls"),
        )
        self.assertNotIn("prompt", vars(audited[0]))

    def test_audit_failure_denies_fallback(self) -> None:
        def fail_audit(event) -> None:
            raise RuntimeError("audit unavailable")

        decision = self.matrix.decide(
            self.requirement,
            requested_provider_ref="provider:primary",
            fallback_policy_ref="policy:reviewed-provider-fallback",
            fallback_audit=fail_audit,
        )
        self.assertFalse(decision.allowed)
        self.assertFalse(decision.fallback_used)
        self.assertIn("audit failed closed", decision.reason)

    def test_unrequested_selection_uses_capability_matrix(self) -> None:
        decision = self.matrix.decide(self.requirement)
        self.assertEqual(decision.selected_provider_ref, "provider:analytics")
        self.assertFalse(decision.fallback_used)


class ToolThreatPolicyTests(unittest.TestCase):
    def make_policy(self) -> ToolAdapterThreatPolicy:
        return ToolAdapterThreatPolicy(
            policy_ref="policy:tool-threat",
            destination_allowlist_refs=("policy:approved-destinations",),
            response_trust=ResponseTrust.VALIDATED,
            maximum_content_classification=ContentClassification.CONFIDENTIAL,
            max_response_bytes=128,
            effect=ActionEffect.SIDE_EFFECT,
            idempotent=True,
            require_idempotency_key=True,
            kill_switch_ref="control:tool-stop",
        )

    def make_action(self, key: str = "idem-001") -> Action:
        return Action(
            action_id="action_001",
            name="tool.invoke",
            capability="export",
            target_ref="tool:neutral-export",
            effect=ActionEffect.SIDE_EFFECT,
            idempotency_key=key or None,
        )

    def test_invocation_requires_destination_key_and_inactive_switch(self) -> None:
        policy = self.make_policy()
        allowed = policy.authorize_invocation(
            self.make_action(),
            identity=make_identity(),
            destination_allowlist_ref="policy:approved-destinations",
            kill_switch_active=False,
        )
        self.assertTrue(allowed.allowed)
        self.assertEqual(
            policy.authorize_invocation(
                self.make_action(),
                identity=make_identity(),
                destination_allowlist_ref="policy:other",
                kill_switch_active=False,
            ).reason_code,
            "destination_not_allowlisted",
        )
        self.assertEqual(
            policy.authorize_invocation(
                self.make_action(""),
                identity=make_identity(),
                destination_allowlist_ref="policy:approved-destinations",
                kill_switch_active=False,
            ).reason_code,
            "idempotency_key_required",
        )
        self.assertEqual(
            policy.authorize_invocation(
                self.make_action(),
                identity=make_identity(),
                destination_allowlist_ref="policy:approved-destinations",
                kill_switch_active=True,
            ).reason_code,
            "kill_switch_active",
        )

    def test_system_and_internal_execution_are_denied_by_default(self) -> None:
        policy = self.make_policy()
        for mode in (
            AuthorizationMode.SYSTEM,
            AuthorizationMode.EXPLICIT_SERVICE_PRINCIPAL,
        ):
            identity = VerifiedIdentity(
                subject_ref="principal:internal-runtime",
                mode=mode,
            )
            decision = policy.authorize_invocation(
                self.make_action(),
                identity=identity,
                destination_allowlist_ref="policy:approved-destinations",
                kill_switch_active=False,
            )
            self.assertFalse(decision.allowed)
            self.assertEqual(
                decision.reason_code,
                "execution_identity_not_allowed",
            )

    def test_side_effect_adapter_must_be_idempotent(self) -> None:
        with self.assertRaises(ValueError):
            ToolAdapterThreatPolicy(
                policy_ref="policy:tool-threat",
                destination_allowlist_refs=("policy:approved-destinations",),
                response_trust=ResponseTrust.UNTRUSTED,
                maximum_content_classification=ContentClassification.INTERNAL,
                max_response_bytes=128,
                effect=ActionEffect.SIDE_EFFECT,
                idempotent=False,
                require_idempotency_key=True,
                kill_switch_ref="control:tool-stop",
            )

    def test_response_enforces_size_classification_and_trust(self) -> None:
        policy = self.make_policy()
        policy.validate_response(
            byte_count=128,
            content_classification=ContentClassification.CONFIDENTIAL,
            response_trust=ResponseTrust.VALIDATED,
        )
        with self.assertRaises(ToolThreatPolicyError):
            policy.validate_response(
                byte_count=129,
                content_classification=ContentClassification.CONFIDENTIAL,
                response_trust=ResponseTrust.VALIDATED,
            )
        with self.assertRaises(ToolThreatPolicyError):
            policy.validate_response(
                byte_count=1,
                content_classification=ContentClassification.RESTRICTED,
                response_trust=ResponseTrust.VALIDATED,
            )
        with self.assertRaises(ToolThreatPolicyError):
            policy.validate_response(
                byte_count=1,
                content_classification=ContentClassification.INTERNAL,
                response_trust=ResponseTrust.TRUSTED,
            )


class EvidenceValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.evidence = EvidenceRef(
            evidence_id="ev_metric_001",
            source_kind="dataset",
            source_ref="dataset:approved-metrics",
            retrieved_at="2026-01-15T12:00:01Z",
        )

    def test_quantitative_blocks_require_known_evidence(self) -> None:
        answer = Answer(
            summary="Metric: 42",
            blocks=(
                AnswerBlock(
                    "block_metric_001",
                    AnswerBlockKind.QUANTITATIVE,
                    "Metric: 42",
                    (),
                ),
            ),
            evidence=(self.evidence,),
        )
        validation = QuantitativeAnswerValidator().validate(answer)
        self.assertFalse(validation.valid)
        self.assertIn(
            "quantitative_evidence_required",
            {issue.code for issue in validation.issues},
        )

    def test_summary_quantities_must_be_bound_in_a_block(self) -> None:
        answer = Answer(
            summary="Metric: 43",
            blocks=(
                AnswerBlock(
                    "block_metric_001",
                    AnswerBlockKind.QUANTITATIVE,
                    "Metric: 42",
                    ("ev_metric_001",),
                ),
            ),
            evidence=(self.evidence,),
        )
        validation = QuantitativeAnswerValidator().validate(answer)
        self.assertIn(
            "unbound_summary_quantity",
            {issue.code for issue in validation.issues},
        )


class MemoryAuditSink:
    def __init__(self) -> None:
        self.events = []

    def emit(self, event) -> None:
        self.events.append(event)


class AuditTests(unittest.TestCase):
    def test_redactor_removes_secret_bearing_values(self) -> None:
        sanitized = AuditRedactor().sanitize(
            {
                "prompt": "show a private metric",
                "nested": {
                    "access_token": "secret-value",
                    "message": "Bearer abc.def and user@example.com",
                },
            }
        )
        rendered = json.dumps(sanitized)
        self.assertNotIn("private metric", rendered)
        self.assertNotIn("secret-value", rendered)
        self.assertNotIn("abc.def", rendered)
        self.assertNotIn("user@example.com", rendered)

    def test_hooks_emit_redacted_contract_valid_metadata_only(self) -> None:
        sink = MemoryAuditSink()
        hooks = RedactionSafeAuditHooks(
            sink,
            now=lambda: "2026-01-15T12:00:02Z",
            event_id=lambda: "audit_runtime_001",
        )
        action = Action(
            action_id="action_001",
            name="tool.invoke",
            capability="query_evidence",
            target_ref="tool:neutral-query",
            arguments={"prompt": "must never enter audit details"},
        )
        result = ToolResult(
            tool_ref="tool:neutral-query",
            status=ToolResultStatus.SUCCEEDED,
            content={"secret": "must never enter audit details"},
            response_trust=ResponseTrust.VALIDATED,
            content_classification=ContentClassification.INTERNAL,
            byte_count=32,
        )
        event = hooks.tool_call(
            make_context(),
            make_identity(),
            action,
            result=result,
            attempt=1,
        )
        self.assertEqual(sink.events, [event])
        rendered = json.dumps(event.to_contract())
        self.assertNotIn("must never enter audit details", rendered)
        self.assertTrue(validate_contract("audit-event", event.to_contract())["valid"])


if __name__ == "__main__":
    unittest.main()

