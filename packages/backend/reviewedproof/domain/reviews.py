"""Pure validation and canonical preparation for S3 review creation."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import NoReturn, cast

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from jsonschema.exceptions import SchemaError, ValidationError  # type: ignore[import-untyped]
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource, Unresolvable
from referencing.jsonschema import DRAFT202012
from reviewedproof.domain.portable_json import validate_portable_json_object
from reviewedproof.domain.templates import PreparedTemplateVersion, validate_completion_policy
from reviewedproof.verification.kernel import (
    canonical_json_bytes,
    package_entry_leaf_hash,
    package_root,
    sha256_bytes,
)

_MAX_PACKAGE_BYTES = 200_000_000
_MAX_FILE_BYTES = 20_000_000
_PURPOSE_BYTES = 1_000
_SCOPE_BYTES = 2_000
_ROLE_CODE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")
_SCHEMA_NAMES = ("common.v1.schema.json", "package-manifest.v1.schema.json")


class ReviewValidationError(ValueError):
    """Review input violates the approved S3 creation contract."""


@dataclass(frozen=True, slots=True)
class ReviewerInput:
    """One normalized reviewer identifier and frozen policy role."""

    normalized_email: bytes
    role: str
    required: bool


@dataclass(frozen=True, slots=True)
class PreparedPackageEntry:
    """Validated entry fields and canonical digests ready for persistence."""

    position: int
    entry_identifier: str
    name: str | None
    media_type: str
    byte_length: int
    content_sha256: bytes
    required: bool
    canonical_bytes: bytes
    leaf_hash: bytes


@dataclass(frozen=True, slots=True)
class PreparedPackage:
    """Validated exact manifest, preserving supplied array order."""

    manifest_identifier: str
    package_name: str | None
    entry_count: int
    package_root: bytes
    canonical_bytes: bytes
    canonical_sha256: bytes
    entries: tuple[PreparedPackageEntry, ...]


@dataclass(frozen=True, slots=True)
class PreparedReview:
    """All current mutable review inputs after semantic validation."""

    client_reference: str | None
    completion_policy: dict[str, object]
    disclosure_policy: dict[str, object]
    purpose_values: dict[str, object]
    scope_values: dict[str, object]
    purpose_text: str
    scope_text: str
    reviewers: tuple[ReviewerInput, ...]
    expires_at: datetime
    package: PreparedPackage


def prepare_review(
    *,
    template: PreparedTemplateVersion,
    package_manifest: object,
    purpose_values: object,
    scope_values: object,
    completion_policy: object,
    disclosure_policy: object,
    reviewers: Sequence[ReviewerInput],
    expires_at: datetime,
    client_reference: str | None,
    now: datetime,
) -> PreparedReview:
    """Validate current review inputs and derive deterministic package/purpose/scope data."""
    if client_reference is not None and (
        type(client_reference) is not str or len(client_reference) > 200
    ):
        raise ReviewValidationError("client_reference must be null or at most 200 characters")
    _require_future_exact_utc(expires_at, now)

    try:
        policy = validate_completion_policy(completion_policy)
    except ValueError:
        raise ReviewValidationError("completion_policy is invalid") from None
    if canonical_json_bytes(policy) != canonical_json_bytes(template.completion_policy):
        raise ReviewValidationError("completion_policy must equal the published template policy")
    disclosure = _validate_disclosure_policy(disclosure_policy)
    prepared_reviewers = _validate_reviewers(reviewers)
    _validate_policy_participants(policy, prepared_reviewers)
    package = _prepare_package(package_manifest)
    purpose, purpose_text = _validate_template_values(
        purpose_values,
        template.purpose_schema,
        field="purpose_values",
        max_bytes=_PURPOSE_BYTES,
    )
    scope, scope_text = _validate_template_values(
        scope_values,
        template.scope_schema,
        field="scope_values",
        max_bytes=_SCOPE_BYTES,
    )
    return PreparedReview(
        client_reference=client_reference,
        completion_policy=policy,
        disclosure_policy=disclosure,
        purpose_values=purpose,
        scope_values=scope,
        purpose_text=purpose_text,
        scope_text=scope_text,
        reviewers=prepared_reviewers,
        expires_at=expires_at,
        package=package,
    )


def validate_reviewer(value: ReviewerInput) -> ReviewerInput:
    """Validate one already-normalized reviewer input for create or add-reviewer."""
    if type(value) is not ReviewerInput:
        raise ReviewValidationError("reviewer input is invalid")
    if type(value.normalized_email) is not bytes or not 1 <= len(value.normalized_email) <= 320:
        raise ReviewValidationError("reviewer email must contain 1 to 320 ASCII bytes")
    try:
        value.normalized_email.decode("ascii")
    except UnicodeDecodeError:
        raise ReviewValidationError("reviewer email must use ASCII") from None
    if (
        type(value.role) is not str
        or len(value.role) > 100
        or _ROLE_CODE.fullmatch(value.role) is None
    ):
        raise ReviewValidationError("reviewer role is invalid")
    if type(value.required) is not bool:
        raise ReviewValidationError("reviewer required must be boolean")
    return value


def _validate_reviewers(reviewers: Sequence[ReviewerInput]) -> tuple[ReviewerInput, ...]:
    if type(reviewers) not in (list, tuple) or not 1 <= len(reviewers) <= 100:
        raise ReviewValidationError("reviewers must contain 1 to 100 items")
    prepared = tuple(validate_reviewer(value) for value in reviewers)
    if len({value.normalized_email for value in prepared}) != len(prepared):
        raise ReviewValidationError("reviewer emails must be unique")
    return prepared


def _validate_policy_participants(
    policy: Mapping[str, object], reviewers: tuple[ReviewerInput, ...]
) -> None:
    policy_type = policy["type"]
    if policy_type == "all_required" and not any(reviewer.required for reviewer in reviewers):
        raise ReviewValidationError("all_required needs at least one required reviewer")
    if policy_type == "any_reviewer" and any(reviewer.required for reviewer in reviewers):
        raise ReviewValidationError("any_reviewer cannot contain required reviewers")
    if policy_type == "threshold" and cast(int, policy["threshold"]) > len(reviewers):
        raise ReviewValidationError("completion threshold exceeds reviewer count")
    if policy_type == "role_quorum":
        required_roles = set(cast(list[str], policy["required_roles"]))
        if not required_roles.issubset({reviewer.role for reviewer in reviewers}):
            raise ReviewValidationError("completion roles must exist in the reviewer set")


def _validate_disclosure_policy(value: object) -> dict[str, object]:
    if type(value) is not dict:
        raise ReviewValidationError("disclosure_policy must be an object")
    policy = cast(dict[object, object], value)
    if set(policy) != {"mode", "show_organisation", "show_reviewer_name"}:
        raise ReviewValidationError("disclosure_policy fields are invalid")
    mode = policy["mode"]
    show_organisation = policy["show_organisation"]
    show_reviewer_name = policy["show_reviewer_name"]
    if mode not in ("public", "link_only", "organisation_only"):
        raise ReviewValidationError("disclosure_policy mode is invalid")
    if type(show_organisation) is not bool or type(show_reviewer_name) is not bool:
        raise ReviewValidationError("disclosure_policy flags must be boolean")
    return {
        "mode": cast(str, mode),
        "show_organisation": show_organisation,
        "show_reviewer_name": show_reviewer_name,
    }


def _prepare_package(value: object) -> PreparedPackage:
    try:
        canonical = canonical_json_bytes(value)
        _package_validator().validate(value)
    except (SchemaError, Unresolvable, ValidationError, ValueError):
        raise ReviewValidationError("package_manifest is invalid") from None
    manifest = cast(dict[str, object], value)
    entries = cast(list[dict[str, object]], manifest["entries"])
    count = cast(int, manifest["entry_count"])
    if count != len(entries):
        raise ReviewValidationError("package entry_count does not match entries")
    positions = [cast(int, entry["position"]) for entry in entries]
    if sorted(positions) != list(range(count)):
        raise ReviewValidationError("package positions must be unique and consecutive")
    entry_ids = [cast(str, entry["entry_id"]) for entry in entries]
    if len(set(entry_ids)) != count:
        raise ReviewValidationError("package entry_id values must be unique")
    if sum(cast(int, entry["byte_length"]) for entry in entries) > _MAX_PACKAGE_BYTES:
        raise ReviewValidationError("package exceeds 200 MB")
    if any(cast(int, entry["byte_length"]) > _MAX_FILE_BYTES for entry in entries):
        raise ReviewValidationError("file exceeds 20 MB")
    try:
        calculated_root = package_root(entries)
    except ValueError:
        raise ReviewValidationError("package entries are invalid") from None
    if calculated_root != manifest["package_root"]:
        raise ReviewValidationError("package_root does not match entries")

    prepared_entries = tuple(
        PreparedPackageEntry(
            position=cast(int, entry["position"]),
            entry_identifier=cast(str, entry["entry_id"]),
            name=cast(str | None, entry["name"]),
            media_type=cast(str, entry["media_type"]),
            byte_length=cast(int, entry["byte_length"]),
            content_sha256=bytes.fromhex(
                cast(str, cast(dict[str, object], entry["content_hash"])["value"])
            ),
            required=cast(bool, entry["required"]),
            canonical_bytes=canonical_json_bytes(entry),
            leaf_hash=bytes.fromhex(package_entry_leaf_hash(entry)),
        )
        for entry in entries
    )
    return PreparedPackage(
        manifest_identifier=cast(str, manifest["manifest_id"]),
        package_name=cast(str | None, manifest["package_name"]),
        entry_count=count,
        package_root=bytes.fromhex(calculated_root),
        canonical_bytes=canonical,
        canonical_sha256=sha256_bytes(canonical),
        entries=prepared_entries,
    )


def _validate_template_values(
    value: object,
    schema: dict[str, object],
    *,
    field: str,
    max_bytes: int,
) -> tuple[dict[str, object], str]:
    try:
        validate_portable_json_object(value)
        _resolve_all_local_references(schema)
        Draft202012Validator(
            schema,
            registry=Registry(retrieve=_reject_retrieval),  # type: ignore[call-arg]
            format_checker=Draft202012Validator.FORMAT_CHECKER,
        ).validate(value)
        canonical = canonical_json_bytes(value)
    except (SchemaError, Unresolvable, ValidationError, ValueError):
        raise ReviewValidationError(f"{field} does not match the published template") from None
    if len(canonical) > max_bytes:
        raise ReviewValidationError(f"{field} canonical text exceeds {max_bytes} UTF-8 bytes")
    return cast(dict[str, object], value), canonical.decode("utf-8")


def _resolve_all_local_references(schema: dict[str, object]) -> None:
    """Resolve every declared fragment without allowing retrieval."""
    resource = Resource.from_contents(schema, default_specification=DRAFT202012)
    resolver = Registry(  # type: ignore[call-arg]
        retrieve=_reject_retrieval
    ).resolver_with_root(resource)
    stack = [(resource, resolver)]
    while stack:
        current, current_resolver = stack.pop()
        contents = current.contents
        if type(contents) is bool:
            continue
        if type(contents) is not dict:
            raise ReviewValidationError("template schema resource must be an object")
        mapping = cast(dict[str, object], contents)
        for keyword in ("$ref", "$dynamicRef"):
            reference = mapping.get(keyword)
            if reference is not None:
                if type(reference) is not str or not reference.startswith("#"):
                    raise ReviewValidationError(
                        "template schema references must be local fragments"
                    )
                current_resolver.lookup(reference)
        for subresource in current.subresources():
            stack.append((subresource, current_resolver.in_subresource(subresource)))


def _require_future_exact_utc(value: datetime, now: datetime) -> None:
    if type(value) is not datetime or value.tzinfo != UTC or value.microsecond != 0:
        raise ReviewValidationError("expires_at must be exact UTC whole seconds")
    if value <= now:
        raise ReviewValidationError("expires_at must be in the future")


@lru_cache(maxsize=1)
def _package_validator() -> Draft202012Validator:
    loaded = {name: _load_schema(name) for name in _SCHEMA_NAMES}
    registry: Registry[dict[str, object]] = Registry(  # type: ignore[call-arg]
        retrieve=_reject_retrieval
    )
    for schema in loaded.values():
        schema_id = schema.get("$id")
        if type(schema_id) is not str:
            raise RuntimeError("runtime schema lacks an identifier")
        registry = registry.with_resource(
            schema_id,
            Resource.from_contents(schema, default_specification=DRAFT202012),
        )
    return Draft202012Validator(
        loaded["package-manifest.v1.schema.json"],
        registry=registry,
    )


def _load_schema(name: str) -> dict[str, object]:
    packaged = resources.files("reviewedproof").joinpath("_schemas", name)
    try:
        raw = packaged.read_text(encoding="utf-8")
    except FileNotFoundError:
        source = Path(__file__).resolve().parents[4] / "documentation" / "schemas" / name
        raw = source.read_text(encoding="utf-8")
    value = json.loads(raw)
    if type(value) is not dict:
        raise RuntimeError("runtime schema must contain a JSON object")
    return cast(dict[str, object], value)


def _reject_retrieval(uri: str) -> NoReturn:
    raise NoSuchResource(uri)
