"""Validation and canonical payload construction for review template versions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal, cast

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from jsonschema.exceptions import SchemaError  # type: ignore[import-untyped]
from reviewedproof.domain.portable_json import validate_portable_json_object
from reviewedproof.verification.kernel import canonical_json_bytes, sha256_bytes

AssuranceLevel = Literal["A0", "A1", "A2", "A3"]

_STATEMENT_TYPES = {
    "reviewed",
    "reviewed_and_approved",
    "independently_verified",
    "custom",
}
_ASSURANCE_LEVELS = {"A0", "A1", "A2", "A3"}
_REASON_CODE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")
_PROHIBITED_CLAIMS = (
    "certified",
    "zero knowledge",
    "audited",
    "legally binding",
    "identity verified",
)
_PROHIBITED_PATTERN = re.compile(
    r"(?<!\w)(?:" + "|".join(re.escape(term) for term in _PROHIBITED_CLAIMS) + r")(?!\w)",
    re.IGNORECASE,
)


class TemplateValidationError(ValueError):
    """Template input violates the current canonical template contract."""


@dataclass(frozen=True, slots=True)
class PreparedTemplateVersion:
    """Validated fields and their canonical representation."""

    exact_text: str
    purpose_schema: dict[str, object]
    scope_schema: dict[str, object]
    declarations: tuple[str, ...]
    minimum_assurance_level: AssuranceLevel
    completion_policy: dict[str, object]
    canonical_bytes: bytes
    canonical_sha256: bytes
    validity_duration_seconds: int | None = None


def prepare_template_version(
    *,
    exact_text: str,
    purpose_schema: object,
    scope_schema: object,
    declarations: object,
    minimum_assurance_level: str,
    completion_policy: object,
    validity_duration_seconds: int | None = None,
    legacy_statement_type: str | None = None,
) -> PreparedTemplateVersion:
    """Validate a request or stored row and build its signed semantic payload."""
    # Only stored historical templates supply this field, to preserve their hashes.
    if legacy_statement_type is not None and legacy_statement_type not in _STATEMENT_TYPES:
        raise TemplateValidationError("legacy statement type is invalid")
    if type(exact_text) is not str or not 1 <= len(exact_text) <= 10_000:
        raise TemplateValidationError("exact_text must contain 1 to 10000 characters")
    if minimum_assurance_level not in _ASSURANCE_LEVELS:
        raise TemplateValidationError("minimum_assurance_level is invalid")
    if validity_duration_seconds is not None and (
        type(validity_duration_seconds) is not int
        or not 1 <= validity_duration_seconds <= 9_007_199_254_740_991
    ):
        raise TemplateValidationError("validity_duration_seconds is invalid")
    if type(declarations) not in (list, tuple):
        raise TemplateValidationError("declarations must be an array")
    declaration_values = cast(list[object] | tuple[object, ...], declarations)
    if len(declaration_values) > 20 or any(
        type(value) is not str or len(value) > 500 for value in declaration_values
    ):
        raise TemplateValidationError("declarations are invalid")
    declaration_strings = tuple(cast(str, value) for value in declaration_values)
    if any(_PROHIBITED_PATTERN.search(value) for value in (exact_text, *declaration_strings)):
        raise TemplateValidationError("template contains a prohibited claim")

    try:
        validate_portable_json_object(purpose_schema)
        validate_portable_json_object(scope_schema)
    except ValueError:
        raise TemplateValidationError("purpose_schema or scope_schema is invalid") from None
    purpose = cast(dict[str, object], purpose_schema)
    scope = cast(dict[str, object], scope_schema)
    _reject_external_references(purpose)
    _reject_external_references(scope)
    try:
        Draft202012Validator.check_schema(purpose)
        Draft202012Validator.check_schema(scope)
    except SchemaError:
        raise TemplateValidationError("purpose_schema or scope_schema is invalid") from None

    policy = validate_completion_policy(completion_policy)
    payload: dict[str, object] = {
        "completion_policy": policy,
        "declarations": list(declaration_strings),
        "exact_text": exact_text,
        "minimum_assurance_level": minimum_assurance_level,
        "purpose_schema": purpose,
        "revocation_policy": {},
        "scope_schema": scope,
        "validity_duration_seconds": validity_duration_seconds,
    }
    if legacy_statement_type is not None:
        payload["statement_type"] = legacy_statement_type
    try:
        canonical = canonical_json_bytes(payload)
    except ValueError:
        raise TemplateValidationError("template payload is not canonical JSON") from None
    return PreparedTemplateVersion(
        exact_text=exact_text,
        purpose_schema=purpose,
        scope_schema=scope,
        declarations=declaration_strings,
        minimum_assurance_level=cast(AssuranceLevel, minimum_assurance_level),
        completion_policy=policy,
        canonical_bytes=canonical,
        canonical_sha256=sha256_bytes(canonical),
        validity_duration_seconds=validity_duration_seconds,
    )


def validate_completion_policy(value: object) -> dict[str, object]:
    """Validate and return the exact supported completion-policy object."""
    if type(value) is not dict:
        raise TemplateValidationError("completion_policy must be an object")
    policy = cast(dict[object, object], value)
    policy_type = policy.get("type")
    if policy_type in ("all_required", "any_reviewer"):
        if set(policy) != {"type"}:
            raise TemplateValidationError("completion_policy fields are invalid")
        return {"type": cast(str, policy_type)}
    if policy_type == "threshold":
        threshold = policy.get("threshold")
        if set(policy) != {"type", "threshold"} or type(threshold) is not int:
            raise TemplateValidationError("threshold completion_policy is invalid")
        if not 1 <= threshold <= 100:
            raise TemplateValidationError("threshold completion_policy is invalid")
        return {"threshold": threshold, "type": "threshold"}
    if policy_type == "role_quorum":
        required_roles = policy.get("required_roles")
        if set(policy) != {"type", "required_roles"} or type(required_roles) is not list:
            raise TemplateValidationError("role_quorum completion_policy is invalid")
        roles = cast(list[object], required_roles)
        if (
            not 1 <= len(roles) <= 100
            or any(
                type(role) is not str or _REASON_CODE.fullmatch(role) is None or len(role) > 100
                for role in roles
            )
            or len(set(cast(list[str], roles))) != len(roles)
            or roles != sorted(cast(list[str], roles))
        ):
            raise TemplateValidationError("role_quorum required_roles are invalid")
        return {"required_roles": list(cast(list[str], roles)), "type": "role_quorum"}
    raise TemplateValidationError("completion_policy type is invalid")


def _reject_external_references(value: object) -> None:
    stack = [value]
    while stack:
        current = stack.pop()
        if type(current) is list:
            stack.extend(cast(list[object], current))
        elif type(current) is dict:
            mapping = cast(dict[str, object], current)
            for key, item in mapping.items():
                if key in ("$ref", "$dynamicRef") and (
                    type(item) is not str or not item.startswith("#")
                ):
                    raise TemplateValidationError("JSON Schema references must be local")
                stack.append(item)
