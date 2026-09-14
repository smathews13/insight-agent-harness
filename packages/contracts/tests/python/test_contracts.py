from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from insight_agent_harness_contracts.validation import (
    manifest_risk_metadata,
    validate_contract,
    validate_request_against_manifest,
    validate_runtime_manifest_change,
)

FIXTURES = json.loads(
    (Path(__file__).resolve().parents[2] / "fixtures" / "contracts.json").read_text(
        encoding="utf-8"
    )
)

VALID_FIXTURES = [
    ("product-manifest", "valid_neutral_manifest"),
    ("request-context", "user_auth_request"),
    ("evidence-ref", "evidence"),
    ("run-envelope", "complete_run"),
    ("blocked-dependency", "blocked_dependency"),
    ("error-envelope", "error_envelope"),
    ("run-envelope", "blocked_run"),
    ("audit-event", "audit_event"),
    ("evidence-ref", "legacy_forward_compatible_wire"),
]


class ContractTests(unittest.TestCase):
    def test_removing_evidence_from_quantitative_content_fails(self) -> None:
        result = validate_contract(
            "run-envelope", FIXTURES["quantitative_without_evidence"]
        )
        self.assertFalse(result["valid"])
        self.assertIn("quantitative content requires evidence", "\n".join(result["errors"]))

    def test_privileged_manifest_sections_cannot_change_at_runtime(self) -> None:
        change = FIXTURES["invalid_privileged_runtime_change"]
        before = FIXTURES[change["before_fixture"]]
        after = copy.deepcopy(before)
        after[change["replace"]["section"]] = change["replace"]["value"]
        result = validate_runtime_manifest_change(before, after)
        self.assertFalse(result["valid"])
        self.assertIn(
            "privileged section is not runtime-editable", "\n".join(result["errors"])
        )

    def test_presentation_is_the_only_runtime_editable_manifest_section(self) -> None:
        after = copy.deepcopy(FIXTURES["valid_neutral_manifest"])
        after["presentation"]["title"] = "Neutral Analysis"
        self.assertTrue(
            validate_runtime_manifest_change(
                FIXTURES["valid_neutral_manifest"], after
            )["valid"]
        )

    def test_privileged_manifests_reject_unknown_fields(self) -> None:
        manifest = copy.deepcopy(FIXTURES["valid_neutral_manifest"])
        manifest["authorization"]["unreviewed_mode"] = True
        result = validate_contract("product-manifest", manifest)
        self.assertFalse(result["valid"])
        self.assertIn("unknown field is not allowed", "\n".join(result["errors"]))

    def test_legacy_product_aliases_require_fixture_marker(self) -> None:
        legacy = FIXTURES["legacy_alias_manifest"]
        marked = copy.deepcopy(FIXTURES[legacy["base_fixture"]])
        marked["compatibility"]["aliases"] = [legacy["alias"]]
        self.assertTrue(validate_contract("product-manifest", marked)["valid"])

        unmarked = copy.deepcopy(marked)
        del unmarked["compatibility"]["aliases"][0]["legacy_fixture"]
        result = validate_contract("product-manifest", unmarked)
        self.assertFalse(result["valid"])
        self.assertIn(
            "cannot target legacy product names", "\n".join(result["errors"])
        )

    def test_compatibility_alias_removal_versions_start_at_1_2_0(self) -> None:
        manifest = copy.deepcopy(FIXTURES["valid_neutral_manifest"])
        manifest["compatibility"]["aliases"][0]["removal_version"] = "1.1.9"
        result = validate_contract("product-manifest", manifest)
        self.assertFalse(result["valid"])
        self.assertIn("must be at least 1.2.0", "\n".join(result["errors"]))

    def test_user_authorization_requires_scopes_and_user_evidence_tools(self) -> None:
        manifest = copy.deepcopy(FIXTURES["valid_neutral_manifest"])
        manifest["authorization"]["user_scopes"] = []
        manifest["authorization"]["evidence_tools"][0][
            "auth_mode"
        ] = "explicit_service_principal"
        result = validate_contract("product-manifest", manifest)
        errors = "\n".join(result["errors"])
        self.assertFalse(result["valid"])
        self.assertIn("requires at least one approved scope", errors)
        self.assertIn("forbids service-principal-only evidence tools", errors)

    def test_genie_only_mode_forbids_agent_authored_sql(self) -> None:
        manifest = copy.deepcopy(FIXTURES["valid_neutral_manifest"])
        manifest["genie"]["allow_agent_authored_sql"] = True
        manifest["capabilities"]["items"].append(
            {
                "id": "direct_sql",
                "kind": "agent_sql",
                "enabled": True,
                "dependencies": [],
            }
        )
        result = validate_contract("product-manifest", manifest)
        self.assertFalse(result["valid"])
        self.assertIn("genie_only", "\n".join(result["errors"]))

    def test_mcp_enablement_requires_all_privileged_references(self) -> None:
        manifest = copy.deepcopy(FIXTURES["valid_neutral_manifest"])
        manifest["operations"]["mcp"]["enabled"] = True
        result = validate_contract("product-manifest", manifest)
        self.assertFalse(result["valid"])
        self.assertEqual(
            len(
                [
                    error
                    for error in result["errors"]
                    if "operations.mcp" in error
                ]
            ),
            4,
        )

    def test_external_export_requires_egress_and_redaction_refs(self) -> None:
        manifest = copy.deepcopy(FIXTURES["valid_neutral_manifest"])
        manifest["exports"]["external_enabled"] = True
        result = validate_contract("product-manifest", manifest)
        errors = "\n".join(result["errors"])
        self.assertFalse(result["valid"])
        self.assertIn("egress_policy_ref", errors)
        self.assertIn("redaction_profile_ref", errors)

    def test_data_boundaries_use_opaque_references_not_raw_object_names(self) -> None:
        manifest = copy.deepcopy(FIXTURES["valid_neutral_manifest"])
        manifest["data_boundary"]["permitted_dataset_refs"] = [
            "raw_catalog.raw_schema.raw_table"
        ]
        result = validate_contract("product-manifest", manifest)
        self.assertFalse(result["valid"])
        self.assertIn("unsafe or unsupported format", "\n".join(result["errors"]))

    def test_enabled_capabilities_require_present_enabled_dependencies(self) -> None:
        manifest = copy.deepcopy(FIXTURES["valid_neutral_manifest"])
        manifest["capabilities"]["items"][0]["enabled"] = False
        manifest["capabilities"]["items"][1]["dependencies"].append(
            "missing_capability"
        )
        result = validate_contract("product-manifest", manifest)
        errors = "\n".join(result["errors"])
        self.assertFalse(result["valid"])
        self.assertIn("depends on disabled", errors)
        self.assertIn("unknown dependency", errors)

    def test_risk_metadata_includes_every_required_class(self) -> None:
        classes = {
            metadata["risk_class"] for metadata in manifest_risk_metadata().values()
        }
        self.assertEqual(
            classes,
            {
                "presentation",
                "behavioral",
                "governed_capability",
                "identity_security",
                "data_boundary",
                "operations",
                "resource_binding",
            },
        )

    def test_branding_uris_allow_only_asset_or_reference_schemes(self) -> None:
        for icon_uri in ("https://example.invalid/icon.svg", "icons/raw-icon.svg"):
            manifest = copy.deepcopy(FIXTURES["valid_neutral_manifest"])
            manifest["presentation"]["icon_uri"] = icon_uri
            result = validate_contract("product-manifest", manifest)
            self.assertFalse(result["valid"])
            self.assertIn("approved shape", "\n".join(result["errors"]))

    def test_scope_allowlist_matches_required_and_optional_app_scopes(self) -> None:
        request = copy.deepcopy(FIXTURES["user_auth_request"])
        request["authorization"]["scopes"] = [
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
        self.assertTrue(validate_contract("request-context", request)["valid"])
        request["authorization"]["scopes"].append("files.files")
        self.assertFalse(validate_contract("request-context", request)["valid"])

    def test_explicit_service_principal_requires_separate_policies(self) -> None:
        generic = copy.deepcopy(FIXTURES["valid_neutral_manifest"])
        generic["authorization"]["default_mode"] = "service_principal"
        generic["authorization"]["supported_modes"] = ["service_principal"]
        self.assertFalse(validate_contract("product-manifest", generic)["valid"])

        manifest = copy.deepcopy(FIXTURES["valid_neutral_manifest"])
        authorization = manifest["authorization"]
        authorization["default_mode"] = "explicit_service_principal"
        authorization["supported_modes"] = ["explicit_service_principal"]
        authorization["user_scopes"] = []
        authorization["evidence_tools"][0][
            "auth_mode"
        ] = "explicit_service_principal"
        missing = validate_contract("product-manifest", manifest)
        self.assertFalse(missing["valid"])
        self.assertEqual(
            len(
                [
                    error
                    for error in missing["errors"]
                    if "required for explicit_service_principal" in error
                ]
            ),
            4,
        )
        authorization.update(
            {
                "service_principal_policy_ref": "policy:explicit-sp",
                "answer_label_disclosure_ref": "policy:sp-answer-disclosure",
                "service_principal_data_boundary_ref": "policy:sp-data-boundary",
                "audit_mode": "full",
            }
        )
        self.assertTrue(validate_contract("product-manifest", manifest)["valid"])

    def test_prompt_payload_cannot_override_execution_mode(self) -> None:
        request = copy.deepcopy(FIXTURES["user_auth_request"])
        request["input"]["execution_mode"] = "explicit_service_principal"
        result = validate_contract("request-context", request)
        self.assertFalse(result["valid"])
        self.assertIn("prompts cannot override", "\n".join(result["errors"]))

    def test_request_cannot_switch_manifest_execution_mode(self) -> None:
        request = copy.deepcopy(FIXTURES["user_auth_request"])
        request["authorization"]["mode"] = "explicit_service_principal"
        request["authorization"]["scopes"] = []
        result = validate_request_against_manifest(
            request, FIXTURES["valid_neutral_manifest"]
        )
        self.assertFalse(result["valid"])
        self.assertIn("request cannot switch", "\n".join(result["errors"]))

    def test_runtime_manifest_change_cannot_switch_execution_mode(self) -> None:
        manifest = copy.deepcopy(FIXTURES["valid_neutral_manifest"])
        authorization = manifest["authorization"]
        authorization.update(
            {
                "default_mode": "explicit_service_principal",
                "supported_modes": ["explicit_service_principal"],
                "user_scopes": [],
                "service_principal_policy_ref": "policy:explicit-sp",
                "answer_label_disclosure_ref": "policy:sp-answer-disclosure",
                "service_principal_data_boundary_ref": "policy:sp-data-boundary",
                "audit_mode": "full",
            }
        )
        authorization["evidence_tools"][0][
            "auth_mode"
        ] = "explicit_service_principal"
        result = validate_runtime_manifest_change(
            FIXTURES["valid_neutral_manifest"], manifest
        )
        self.assertFalse(result["valid"])
        self.assertIn(
            "authorization: privileged section", "\n".join(result["errors"])
        )

    def test_strict_persistent_analytics_requires_lakebase(self) -> None:
        missing_policy = copy.deepcopy(FIXTURES["valid_neutral_manifest"])
        del missing_policy["operations"]["readiness_policy"]
        self.assertFalse(
            validate_contract("product-manifest", missing_policy)["valid"]
        )

        manifest = copy.deepcopy(FIXTURES["valid_neutral_manifest"])
        manifest["resources"]["bindings"] = [
            binding
            for binding in manifest["resources"]["bindings"]
            if binding["kind"] != "lakebase_database"
        ]
        result = validate_contract("product-manifest", manifest)
        self.assertFalse(result["valid"])
        self.assertIn(
            "requires a Lakebase database binding", "\n".join(result["errors"])
        )

    def test_enforced_budget_requires_reservation_and_reconciliation(self) -> None:
        manifest = copy.deepcopy(FIXTURES["valid_neutral_manifest"])
        budget = manifest["operations"]["budget"]
        budget["mode"] = "enforced"
        missing = validate_contract("product-manifest", manifest)
        errors = "\n".join(missing["errors"])
        self.assertFalse(missing["valid"])
        self.assertIn("reservation_policy_ref", errors)
        self.assertIn("reconciliation_policy_ref", errors)
        budget["reservation_policy_ref"] = "policy:budget-reservation"
        budget["reconciliation_policy_ref"] = "policy:budget-reconciliation"
        self.assertTrue(validate_contract("product-manifest", manifest)["valid"])

    def test_limits_are_bounded_and_resource_refs_are_opaque(self) -> None:
        manifest = copy.deepcopy(FIXTURES["valid_neutral_manifest"])
        manifest["operations"]["limits"]["max_run_seconds"] = 901
        manifest["resources"]["bindings"][0]["ref"] = "raw-resource-id"
        result = validate_contract("product-manifest", manifest)
        errors = "\n".join(result["errors"])
        self.assertFalse(result["valid"])
        self.assertIn("must be at most 900", errors)
        self.assertIn("unsafe or unsupported format", errors)


def _make_valid_fixture_test(schema_name: str, fixture_name: str):
    def test_fixture(self: ContractTests) -> None:
        self.assertEqual(
            validate_contract(schema_name, FIXTURES[fixture_name]),
            {"valid": True, "errors": []},
        )

    return test_fixture


for _schema_name, _fixture_name in VALID_FIXTURES:
    setattr(
        ContractTests,
        f"test_{_fixture_name}_satisfies_{_schema_name.replace('-', '_')}",
        _make_valid_fixture_test(_schema_name, _fixture_name),
    )


if __name__ == "__main__":
    unittest.main()
