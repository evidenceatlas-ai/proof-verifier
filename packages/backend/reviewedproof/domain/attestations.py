"""Server-built canonical unsigned attestation payload."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import cast

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012
from reviewedproof.domain.reviews import _load_schema
from reviewedproof.verification.kernel import canonical_json_bytes, sha256_bytes


@dataclass(frozen=True, slots=True)
class PreparedAttestation:
    payload: dict[str, object]
    canonical_bytes: bytes
    canonical_sha256: bytes


def prepare_attestation(payload: dict[str, object]) -> PreparedAttestation:
    """Validate the server projection, then preserve its RFC 8785 bytes."""
    schema_version = payload.get("schema_version")
    if schema_version not in {
        "rproof.attestation.v1",
        "rproof.attestation.v2",
        "rproof.attestation.v3",
    }:
        raise ValueError("attestation schema_version is unsupported")
    _validator(cast(str, schema_version)).validate(payload)
    canonical = canonical_json_bytes(payload)
    return PreparedAttestation(payload, canonical, sha256_bytes(canonical))


@lru_cache(maxsize=3)
def _validator(schema_version: str) -> Draft202012Validator:
    common = _load_schema("common.v1.schema.json")
    attestation = _load_schema(f"{schema_version.removeprefix('rproof.')}.schema.json")
    registry: Registry[dict[str, object]] = Registry()
    registry = registry.with_resource(
        cast(str, common["$id"]),
        Resource.from_contents(common, default_specification=DRAFT202012),
    )
    return Draft202012Validator(attestation, registry=registry)
