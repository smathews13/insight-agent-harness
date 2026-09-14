"""Product-neutral composition of a manifest-bound ResponsesAgent extension."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

_EXTENSION_REF_PREFIXES = {
    "prompts": "extension:prompts/",
    "knowledge": "extension:knowledge/",
    "tool_registry": "extension:tools/",
}
_REF_SEGMENT = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")


def _validated_ref(field: str, value: Any) -> str:
    prefix = _EXTENSION_REF_PREFIXES[field]
    if not isinstance(value, str) or not value.startswith(prefix):
        raise RuntimeError(
            f"ProductManifest agent extension reference {field!r} must start with {prefix!r}"
        )
    suffix = value.removeprefix(prefix)
    parts = suffix.split("/")
    if (
        not suffix
        or len(value) > 320
        or any(part in {"", ".", ".."} or not _REF_SEGMENT.fullmatch(part) for part in parts)
    ):
        raise RuntimeError(
            f"ProductManifest agent extension reference {field!r} is not a canonical data ref"
        )
    return value


@dataclass(frozen=True)
class ProductExtensionRefs:
    """The privileged extension references an agent implementation consumes."""

    prompts: str
    knowledge: str
    tool_registry: str

    @classmethod
    def from_manifest(cls, manifest: Mapping[str, Any]) -> ProductExtensionRefs:
        extensions = manifest.get("extensions")
        if not isinstance(extensions, Mapping):
            raise RuntimeError("ProductManifest extensions must be an object")
        values = {
            field: _validated_ref(field, extensions.get(field))
            for field in ("prompts", "knowledge", "tool_registry")
        }
        return cls(**values)


def compose_responses_agent(
    manifest: Mapping[str, Any],
    extension_refs: ProductExtensionRefs,
    factory: Callable[[], Any],
) -> Any:
    """Build an extension only after its privileged refs match the signed manifest."""

    declared = ProductExtensionRefs.from_manifest(manifest)
    if extension_refs != declared:
        raise RuntimeError("agent extension references do not match the signed ProductManifest")
    model = factory()
    if not callable(getattr(model, "predict", None)) or not callable(
        getattr(model, "predict_stream", None)
    ):
        raise TypeError("agent extension factory must return a ResponsesAgent-compatible model")
    return model
