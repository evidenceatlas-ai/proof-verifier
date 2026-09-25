"""Exact compact JWS construction for server-prepared attestations."""

from __future__ import annotations

import base64
import hmac
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from typing import cast

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012
from reviewedproof.domain.attestations import PreparedAttestation, prepare_attestation
from reviewedproof.domain.reviews import _load_schema
from reviewedproof.ports import Signer
from reviewedproof.verification.kernel import canonical_json_bytes, sha256_bytes

_KID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


@dataclass(frozen=True, slots=True)
class SignedAttestation:
    """Compact attestation JWS and data needed by the next proof stage."""

    compact_jws: str
    timestamp_subject_sha256: bytes
    development_only: bool


@dataclass(frozen=True, slots=True)
class PreparedOperationalKeyStatement:
    """Schema-valid operational-key statement and its exact canonical bytes."""

    payload: dict[str, object]
    canonical_bytes: bytes
    not_before: datetime
    not_after: datetime


@dataclass(frozen=True, slots=True)
class SignedOperationalKeyStatement:
    """Canonical operational-key statement and its root signature."""

    canonical_statement: bytes
    compact_jws: str
    development_only: bool


@dataclass(frozen=True, slots=True)
class SignedPortableRecord:
    """Exact canonical JSON and compact JWS produced for one portable record."""

    canonical_payload: bytes
    compact_jws: bytes
    development_only: bool


def sign_attestation(
    prepared: PreparedAttestation, *, kid: str, signer: Signer
) -> SignedAttestation:
    """Sign one validated server projection as an exact ES256 compact JWS."""
    rebuilt = prepare_attestation(prepared.payload)
    if not hmac.compare_digest(rebuilt.canonical_bytes, prepared.canonical_bytes) or not (
        hmac.compare_digest(rebuilt.canonical_sha256, prepared.canonical_sha256)
    ):
        raise ValueError("prepared attestation does not match its canonical payload and digest")
    schema_version = cast(str, rebuilt.payload["schema_version"])
    compact = _sign_compact(
        rebuilt.canonical_bytes,
        kid=kid,
        cty="application/rproof-attestation+json",
        schema=schema_version,
        typ="application/rproof-attestation+jws",
        signer=signer,
    )
    return SignedAttestation(
        compact_jws=compact.decode("ascii"),
        timestamp_subject_sha256=sha256_bytes(compact),
        development_only=signer.development_only,
    )


def prepare_operational_key_statement(
    payload: dict[str, object],
) -> PreparedOperationalKeyStatement:
    """Validate one operational-key statement and preserve canonical bytes."""
    _operational_key_statement_validator().validate(payload)
    try:
        not_before = datetime.strptime(
            cast(str, payload["not_before"]), "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=UTC)
        not_after = datetime.strptime(
            cast(str, payload["not_after"]), "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=UTC)
    except ValueError:
        raise ValueError("operational key validity must use exact UTC timestamps") from None
    if not_before >= not_after:
        raise ValueError("operational key validity window must have positive duration")
    return PreparedOperationalKeyStatement(
        payload,
        canonical_json_bytes(payload),
        not_before,
        not_after,
    )


def sign_operational_key_statement(
    payload: dict[str, object], *, root_kid: str, signer: Signer
) -> SignedOperationalKeyStatement:
    """Sign one schema-valid operational-key statement with an explicit root ID."""
    prepared = prepare_operational_key_statement(payload)
    if signer.development_only and prepared.payload["environment"] != "development":
        raise ValueError("development signer can sign only development key statements")
    compact = _sign_compact(
        prepared.canonical_bytes,
        kid=root_kid,
        cty="application/rproof-operational-key-statement+json",
        schema="rproof.operational-key-statement.v1",
        typ="application/rproof-operational-key-statement+jws",
        signer=signer,
    )
    return SignedOperationalKeyStatement(
        canonical_statement=prepared.canonical_bytes,
        compact_jws=compact.decode("ascii"),
        development_only=signer.development_only,
    )


def sign_bundle_manifest(
    canonical_payload: bytes, *, kid: str, signer: Signer
) -> SignedPortableRecord:
    """Sign one already validated canonical bundle manifest."""
    schema_version = _bundle_manifest_schema_version(canonical_payload)
    return _sign_portable_record(
        canonical_payload,
        kid=kid,
        cty="application/rproof-bundle-manifest+json",
        schema=schema_version,
        typ="application/rproof-bundle-manifest+jws",
        signer=signer,
    )


def _bundle_manifest_schema_version(canonical_payload: bytes) -> str:
    try:
        payload = json.loads(canonical_payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("bundle manifest is not valid JSON") from None
    if canonical_json_bytes(payload) != canonical_payload:
        raise ValueError("bundle manifest is not exact canonical JSON")
    schema_version = payload.get("schema_version") if type(payload) is dict else None
    if schema_version not in {
        "rproof.bundle-manifest.v1",
        "rproof.bundle-manifest.v2",
        "rproof.bundle-manifest.v3",
    }:
        raise ValueError("bundle manifest schema_version is unsupported")
    return cast(str, schema_version)


def sign_status_snapshot(
    canonical_payload: bytes, *, kid: str, signer: Signer
) -> SignedPortableRecord:
    """Sign one already validated canonical lifecycle status snapshot."""
    return _sign_portable_record(
        canonical_payload,
        kid=kid,
        cty="application/rproof-status-snapshot+json",
        schema="rproof.status-snapshot.v1",
        typ="application/rproof-status-snapshot+jws",
        signer=signer,
    )


def sign_lifecycle_event(
    canonical_payload: bytes, *, kid: str, signer: Signer
) -> SignedPortableRecord:
    """Sign one already validated canonical lifecycle event."""
    return _sign_portable_record(
        canonical_payload,
        kid=kid,
        cty="application/rproof-lifecycle-event+json",
        schema="rproof.lifecycle-event.v1",
        typ="application/rproof-lifecycle-event+jws",
        signer=signer,
    )


def sign_review_completion(
    canonical_payload: bytes, *, kid: str, signer: Signer
) -> SignedPortableRecord:
    """Sign one already validated canonical review-completion record."""
    return _sign_portable_record(
        canonical_payload,
        kid=kid,
        cty="application/rproof-review-completion+json",
        schema="rproof.review-completion.v1",
        typ="application/rproof-review-completion+jws",
        signer=signer,
    )


def sign_key_history(
    canonical_payload: bytes, *, root_kid: str, signer: Signer
) -> SignedPortableRecord:
    """Sign one prebuilt key-history snapshot directly with the trust root."""
    return _sign_portable_record(
        canonical_payload,
        kid=root_kid,
        cty="application/rproof-key-history+json",
        schema="rproof.key-history.v1",
        typ="application/rproof-key-history+jws",
        signer=signer,
    )


def _sign_portable_record(
    canonical_payload: bytes,
    *,
    kid: str,
    cty: str,
    schema: str,
    typ: str,
    signer: Signer,
) -> SignedPortableRecord:
    if type(canonical_payload) is not bytes or not canonical_payload:
        raise ValueError("portable signed payload must be non-empty bytes")
    compact = _sign_compact(
        canonical_payload,
        kid=kid,
        cty=cty,
        schema=schema,
        typ=typ,
        signer=signer,
    )
    return SignedPortableRecord(canonical_payload, compact, signer.development_only)


def _sign_compact(
    payload: bytes,
    *,
    kid: str,
    cty: str,
    schema: str,
    typ: str,
    signer: Signer,
) -> bytes:
    _validate_kid(kid)
    protected = canonical_json_bytes(
        {"alg": "ES256", "cty": cty, "kid": kid, "rproof_schema": schema, "typ": typ}
    )
    signing_input = b".".join((_base64url(protected), _base64url(payload)))
    signature = signer.sign(kid, "ES256", sha256_bytes(signing_input))
    _validate_jose_es256_signature(signature)
    return b".".join((signing_input, _base64url(signature)))


def _base64url(value: bytes) -> bytes:
    return base64.urlsafe_b64encode(value).rstrip(b"=")


def _validate_jose_es256_signature(signature: bytes) -> None:
    if type(signature) is not bytes or len(signature) != 64:
        raise ValueError("ES256 signer must return a 64-byte JOSE signature")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not 1 <= r < _P256_ORDER or not 1 <= s < _P256_ORDER:
        raise ValueError("ES256 signature scalars must be in the P-256 range")


def _validate_kid(kid: str) -> None:
    if type(kid) is not str or _KID.fullmatch(kid) is None:
        raise ValueError("kid must match the ReviewedProof protected-header contract")


@lru_cache(maxsize=1)
def _operational_key_statement_validator() -> Draft202012Validator:
    common = _load_schema("common.v1.schema.json")
    statement = _load_schema("operational-key-statement.v1.schema.json")
    registry: Registry[dict[str, object]] = Registry()
    registry = registry.with_resource(
        cast(str, common["$id"]),
        Resource.from_contents(common, default_specification=DRAFT202012),
    )
    return Draft202012Validator(
        statement,
        registry=registry,
    )
