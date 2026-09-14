"""Dependency-free runtime validation for the shared contract schemas."""

from __future__ import annotations

import json
import re
from functools import cache
from pathlib import Path
from typing import Any

SCHEMA_DIRECTORIES = (
    # Workspace/path package layout.
    Path(__file__).resolve().parents[2] / "schemas",
    # MLflow code_paths layout: package and schemas are siblings.
    Path(__file__).resolve().parent.parent / "schemas",
)


@cache
def _load_schema(name: str) -> dict[str, Any]:
    file_name = name if name.endswith(".schema.json") else f"{name}.schema.json"
    for directory in SCHEMA_DIRECTORIES:
        path = directory / file_name
        if path.is_file():
            return json.loads(path.read_text(encoding="utf-8"))
    searched = ", ".join(str(directory / file_name) for directory in SCHEMA_DIRECTORIES)
    raise FileNotFoundError(f"contract schema {file_name} was not found; searched {searched}")


def _type_matches(value: Any, expected: str) -> bool:
    if expected == "null":
        return value is None
    if expected == "array":
        return isinstance(value, list)
    if expected == "object":
        return isinstance(value, dict)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return False


def _validate_schema(
    value: Any,
    schema: dict[str, Any],
    path: str,
    errors: list[str],
    root_schema: dict[str, Any] | None = None,
) -> None:
    root_schema = root_schema or schema
    if "$ref" in schema:
        reference = schema["$ref"]
        if reference.startswith("#/"):
            referenced: Any = root_schema
            for part in reference[2:].split("/"):
                referenced = referenced.get(part.replace("~1", "/").replace("~0", "~"))
            if not isinstance(referenced, dict):
                errors.append(f"{path}: schema reference {reference} could not be resolved")
                return
            _validate_schema(value, referenced, path, errors, root_schema)
        else:
            referenced = _load_schema(reference)
            _validate_schema(value, referenced, path, errors, referenced)
        return

    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: must equal {schema['const']!r}")
        return
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: must be one of {schema['enum']!r}")
        return
    if "anyOf" in schema:
        matches = False
        for candidate in schema["anyOf"]:
            candidate_errors: list[str] = []
            _validate_schema(value, candidate, path, candidate_errors, root_schema)
            if not candidate_errors:
                matches = True
                break
        if not matches:
            errors.append(f"{path}: must match one approved shape")

    if "type" in schema:
        accepted = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_type_matches(value, expected) for expected in accepted):
            errors.append(f"{path}: must be {' or '.join(accepted)}")
            return

    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{path}: must contain at least {schema['minLength']} characters")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{path}: must contain at most {schema['maxLength']} characters")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            errors.append(f"{path}: has an unsafe or unsupported format")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: must be at least {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: must be at most {schema['maximum']}")

    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{path}: must contain at least {schema['minItems']} items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path}: must contain at most {schema['maxItems']} items")
        if schema.get("uniqueItems"):
            normalized = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value]
            if len(set(normalized)) != len(normalized):
                errors.append(f"{path}: items must be unique")
        if "items" in schema:
            for index, item in enumerate(value):
                _validate_schema(item, schema["items"], f"{path}[{index}]", errors, root_schema)

    if isinstance(value, dict):
        properties = schema.get("properties", {})
        for required in schema.get("required", []):
            if required not in value:
                errors.append(f"{path}.{required}: is required")
        if "minProperties" in schema and len(value) < schema["minProperties"]:
            errors.append(f"{path}: must contain at least {schema['minProperties']} properties")
        if "maxProperties" in schema and len(value) > schema["maxProperties"]:
            errors.append(f"{path}: must contain at most {schema['maxProperties']} properties")
        for key, item in value.items():
            if key in properties:
                _validate_schema(item, properties[key], f"{path}.{key}", errors, root_schema)
            elif schema.get("additionalProperties") is False:
                errors.append(f"{path}.{key}: unknown field is not allowed")
            elif isinstance(schema.get("additionalProperties"), dict):
                _validate_schema(
                    item,
                    schema["additionalProperties"],
                    f"{path}.{key}",
                    errors,
                    root_schema,
                )


def _version_at_least(value: str | None, floor: str) -> bool:
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", value or "")
    minimum = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", floor)
    return bool(
        match and minimum and tuple(map(int, match.groups())) >= tuple(map(int, minimum.groups()))
    )


def _validate_product_manifest(value: dict[str, Any], errors: list[str]) -> None:
    capabilities = value.get("capabilities", {}).get("items", [])
    by_id: dict[str, dict[str, Any]] = {}
    for capability in capabilities:
        capability_id = capability.get("id")
        if capability_id in by_id:
            errors.append(f"$.capabilities.items: duplicate capability id {capability_id}")
        by_id[capability_id] = capability
    for capability in capabilities:
        for dependency in capability.get("dependencies", []):
            if dependency not in by_id:
                errors.append(
                    f"$.capabilities.items.{capability.get('id')}: unknown dependency {dependency}"
                )
            elif capability.get("enabled") and not by_id[dependency].get("enabled"):
                errors.append(
                    f"$.capabilities.items.{capability.get('id')}: enabled capability "
                    f"depends on disabled {dependency}"
                )

    tools = value.get("tools", {})
    for tool_id in tools.get("enabled_tool_ids", []):
        capability = by_id.get(tool_id)
        if not capability:
            errors.append(f"$.tools.enabled_tool_ids: unknown capability {tool_id}")
        elif not capability.get("enabled"):
            errors.append(f"$.tools.enabled_tool_ids: disabled capability {tool_id}")

    authorization = value.get("authorization", {})
    if authorization.get("default_mode") not in authorization.get("supported_modes", []):
        errors.append("$.authorization.default_mode: must be present in supported_modes")
    if authorization.get("default_mode") == "user_authorization":
        if not authorization.get("user_scopes"):
            errors.append(
                "$.authorization.user_scopes: user_authorization requires at least "
                "one approved scope"
            )
        for tool in authorization.get("evidence_tools", []):
            if tool.get("auth_mode") == "explicit_service_principal":
                errors.append(
                    "$.authorization.evidence_tools."
                    f"{tool.get('capability_id')}: user_authorization forbids "
                    "service-principal-only evidence tools"
                )
    if "explicit_service_principal" in authorization.get("supported_modes", []):
        for field in (
            "service_principal_policy_ref",
            "answer_label_disclosure_ref",
            "service_principal_data_boundary_ref",
            "audit_mode",
        ):
            if not authorization.get(field):
                errors.append(
                    f"$.authorization.{field}: is required for explicit_service_principal"
                )

    genie = value.get("genie", {})
    if len(genie.get("space_refs", [])) != len(genie.get("required_space_roles", [])):
        errors.append("$.genie.required_space_roles: must map one role to each space_ref")
    if genie.get("mode") == "genie_only":
        if genie.get("allow_agent_authored_sql") is not False:
            errors.append("$.genie.allow_agent_authored_sql: genie_only requires false")
        if any(
            capability.get("enabled") and capability.get("kind") == "agent_sql"
            for capability in capabilities
        ):
            errors.append("$.capabilities.items: genie_only forbids enabled agent-authored SQL")

    mcp = value.get("operations", {}).get("mcp", {})
    if mcp.get("enabled"):
        for field in (
            "registered_adapter_ref",
            "destination_policy_ref",
            "signing_key_ref",
            "kill_switch_ref",
        ):
            if not mcp.get(field):
                errors.append(f"$.operations.mcp.{field}: is required when MCP is enabled")

    exports = value.get("exports", {})
    if exports.get("external_enabled"):
        for field in ("egress_policy_ref", "redaction_profile_ref"):
            if not exports.get(field):
                errors.append(f"$.exports.{field}: is required for external export")

    operations = value.get("operations", {})
    if operations.get("readiness_policy") == "strict_persistent_analytics" and not any(
        binding.get("kind") == "lakebase_database"
        for binding in value.get("resources", {}).get("bindings", [])
    ):
        errors.append(
            "$.resources.bindings: strict_persistent_analytics requires a Lakebase database binding"
        )

    budget = operations.get("budget", {})
    if budget.get("mode") == "enforced":
        for field in ("reservation_policy_ref", "reconciliation_policy_ref"):
            if not budget.get(field):
                errors.append(
                    f"$.operations.budget.{field}: is required when budget enforcement is enabled"
                )

    for index, alias in enumerate(value.get("compatibility", {}).get("aliases", [])):
        if not _version_at_least(alias.get("removal_version"), "1.2.0"):
            errors.append(
                f"$.compatibility.aliases[{index}].removal_version: must be at least 1.2.0"
            )
        if re.match(r"^(?:ADAPT_|LEGACY_PRODUCT_)", alias.get("target", "")) and not alias.get(
            "legacy_fixture"
        ):
            errors.append(
                f"$.compatibility.aliases[{index}].target: new aliases cannot "
                "target legacy product names"
            )


def _validate_request_context(value: dict[str, Any], errors: list[str]) -> None:
    authorization = value.get("authorization", {})
    if authorization.get("mode") == "user_authorization" and not authorization.get("scopes"):
        errors.append(
            "$.authorization.scopes: user_authorization requires at least one approved scope"
        )
    for field in ("authorization_mode", "execution_mode"):
        if field in value.get("input", {}):
            errors.append(
                f"$.input.{field}: prompts cannot override the authenticated execution mode"
            )


def _validate_run_envelope(value: dict[str, Any], errors: list[str]) -> None:
    status = value.get("status")
    if status == "complete":
        if not value.get("output"):
            errors.append("$.output: complete runs require output")
        if value.get("error"):
            errors.append("$.error: complete runs cannot contain an error")
        if value.get("blocked_dependencies"):
            errors.append("$.blocked_dependencies: complete runs cannot remain blocked")
    elif status == "blocked":
        if not value.get("blocked_dependencies"):
            errors.append("$.blocked_dependencies: blocked runs require at least one dependency")
    elif status == "error" and not value.get("error"):
        errors.append("$.error: error runs require an error envelope")

    evidence_ids = {evidence.get("evidence_id") for evidence in value.get("evidence", [])}
    content_blocks = value.get("output", {}).get("content_blocks", [])
    for index, block in enumerate(content_blocks):
        references = block.get("evidence_refs", [])
        if block.get("kind") == "quantitative" and not references:
            errors.append(
                f"$.output.content_blocks[{index}].evidence_refs: "
                "quantitative content requires evidence"
            )
        for evidence_ref in references:
            if evidence_ref not in evidence_ids:
                errors.append(
                    f"$.output.content_blocks[{index}].evidence_refs: "
                    f"unknown evidence {evidence_ref}"
                )


def _validate_error_envelope(value: dict[str, Any], errors: list[str]) -> None:
    if value.get("code") == "blocked_dependency" and not value.get("blocked_dependency"):
        errors.append("$.blocked_dependency: blocked_dependency errors require dependency detail")


def validate_contract(schema_name: str, value: Any) -> dict[str, Any]:
    """Validate schema shape plus contract cross-field invariants."""

    errors: list[str] = []
    _validate_schema(value, _load_schema(schema_name), "$", errors)
    if not errors and isinstance(value, dict):
        normalized = schema_name.removesuffix(".schema.json")
        if normalized == "product-manifest":
            _validate_product_manifest(value, errors)
        elif normalized == "request-context":
            _validate_request_context(value, errors)
        elif normalized == "run-envelope":
            _validate_run_envelope(value, errors)
        elif normalized == "error-envelope":
            _validate_error_envelope(value, errors)
    return {"valid": not errors, "errors": errors}


def validate_runtime_manifest_change(
    before: dict[str, Any], after: dict[str, Any]
) -> dict[str, Any]:
    """Reject changes to sections marked non-runtime-editable by the schema."""

    errors = [
        *validate_contract("product-manifest", before)["errors"],
        *validate_contract("product-manifest", after)["errors"],
    ]
    schema = _load_schema("product-manifest")
    for section, section_schema in schema["properties"].items():
        if section_schema.get("x-runtime-editable") is False and before.get(section) != after.get(
            section
        ):
            errors.append(f"$.{section}: privileged section is not runtime-editable")
    return {"valid": not errors, "errors": errors}


def validate_request_against_manifest(
    request: dict[str, Any], manifest: dict[str, Any]
) -> dict[str, Any]:
    """Validate a request and prohibit request-selected execution identities."""

    errors = [
        *validate_contract("request-context", request)["errors"],
        *validate_contract("product-manifest", manifest)["errors"],
    ]
    if request.get("authorization", {}).get("mode") != manifest.get("authorization", {}).get(
        "default_mode"
    ):
        errors.append("$.authorization.mode: request cannot switch the manifest execution mode")
    return {"valid": not errors, "errors": errors}


def manifest_risk_metadata() -> dict[str, dict[str, Any]]:
    """Return risk class and runtime editability derived from schema metadata."""

    return {
        name: {
            "risk_class": section["x-risk-class"],
            "runtime_editable": section["x-runtime-editable"],
        }
        for name, section in _load_schema("product-manifest")["properties"].items()
        if "x-risk-class" in section
    }
