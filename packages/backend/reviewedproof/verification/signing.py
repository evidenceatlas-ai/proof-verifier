"""Authenticate operational keys and exact attestation compact JWS records."""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from jsonschema.exceptions import ValidationError  # type: ignore[import-untyped]
from reviewedproof.domain.attestations import PreparedAttestation, prepare_attestation
from reviewedproof.domain.proofs import (
    PreparedOperationalKeyStatement,
    prepare_operational_key_statement,
)
from reviewedproof.verification.kernel import (
    canonical_json_bytes,
    p256_fingerprint_sha256,
)

_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_KID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


@dataclass(frozen=True, slots=True)
class AuthenticatedAttestation:
    """Exact evidence authenticated for persistence by the proof worker."""

    attestation_jws: str
    operational_key_statement: bytes
    operational_key_statement_jws: str


@dataclass(frozen=True, slots=True)
class AuthenticatedOperationalKey:
    """One root-authenticated, purpose-bound operational public key."""

    kid: str
    purpose: str
    environment: str
    public_jwk: dict[str, object]
    not_before: datetime
    not_after: datetime


_PORTABLE_RECORD_PROFILES = {
    "rproof.attestation.v1": (
        "application/rproof-attestation+json",
        "application/rproof-attestation+jws",
        "attestation-signing",
    ),
    "rproof.attestation.v2": (
        "application/rproof-attestation+json",
        "application/rproof-attestation+jws",
        "attestation-signing",
    ),
    "rproof.attestation.v3": (
        "application/rproof-attestation+json",
        "application/rproof-attestation+jws",
        "attestation-signing",
    ),
    "rproof.bundle-manifest.v1": (
        "application/rproof-bundle-manifest+json",
        "application/rproof-bundle-manifest+jws",
        "bundle-signing",
    ),
    "rproof.bundle-manifest.v2": (
        "application/rproof-bundle-manifest+json",
        "application/rproof-bundle-manifest+jws",
        "bundle-signing",
    ),
    "rproof.bundle-manifest.v3": (
        "application/rproof-bundle-manifest+json",
        "application/rproof-bundle-manifest+jws",
        "bundle-signing",
    ),
    "rproof.lifecycle-event.v1": (
        "application/rproof-lifecycle-event+json",
        "application/rproof-lifecycle-event+jws",
        "lifecycle-status-signing",
    ),
    "rproof.review-completion.v1": (
        "application/rproof-review-completion+json",
        "application/rproof-review-completion+jws",
        "lifecycle-status-signing",
    ),
    "rproof.status-snapshot.v1": (
        "application/rproof-status-snapshot+json",
        "application/rproof-status-snapshot+jws",
        "lifecycle-status-signing",
    ),
    "rproof.verifier-release.v1": (
        "application/rproof-verifier-release+json",
        "application/rproof-verifier-release+jws",
        "offline-verifier-release",
    ),
}


def authenticate_operational_key_statement(
    *,
    operational_key_statement: bytes,
    operational_key_statement_jws: bytes,
    root_jwk: Mapping[str, object],
    pinned_root_fingerprint_sha256: str,
    root_kid: str,
    expected_purpose: str,
    expected_environment: str,
) -> AuthenticatedOperationalKey:
    """Authenticate one root-signed statement and its fixed purpose/environment."""
    _validate_policy_inputs(
        pinned_root_fingerprint_sha256=pinned_root_fingerprint_sha256,
        root_kid=root_kid,
        expected_operational_purpose=expected_purpose,
        expected_environment=expected_environment,
    )
    try:
        statement_jws_text = operational_key_statement_jws.decode("ascii")
    except (AttributeError, UnicodeDecodeError):
        raise ValueError("operational key statement JWS must be ASCII bytes") from None

    root_fingerprint = p256_fingerprint_sha256(root_jwk)
    if not hmac.compare_digest(root_fingerprint, pinned_root_fingerprint_sha256):
        raise ValueError("root JWK does not match externally pinned fingerprint")
    root_key = _p256_public_key(root_jwk)
    prepared_statement = _decode_exact_statement(operational_key_statement)
    statement = prepared_statement.payload
    _verify_compact_jws(
        statement_jws_text,
        expected_header={
            "alg": "ES256",
            "cty": "application/rproof-operational-key-statement+json",
            "kid": root_kid,
            "rproof_schema": "rproof.operational-key-statement.v1",
            "typ": "application/rproof-operational-key-statement+jws",
        },
        expected_payload=operational_key_statement,
        public_key=root_key,
    )
    if statement["root_fingerprint_sha256"] != pinned_root_fingerprint_sha256:
        raise ValueError("key statement root fingerprint does not match external pin")
    if statement["purpose"] != expected_purpose:
        raise ValueError("operational key purpose does not match fixed record policy")
    if statement["environment"] != expected_environment:
        raise ValueError("operational key environment does not match caller policy")
    operational_kid = cast(str, statement["kid"])
    operational_jwk = cast(dict[str, object], statement["jwk"])
    _p256_public_key(operational_jwk)
    return AuthenticatedOperationalKey(
        kid=operational_kid,
        purpose=expected_purpose,
        environment=expected_environment,
        public_jwk=operational_jwk,
        not_before=prepared_statement.not_before,
        not_after=prepared_statement.not_after,
    )


def require_operational_key_valid_at(
    operational_key: AuthenticatedOperationalKey, signing_time: datetime
) -> None:
    """Require one authenticated operational key at an authenticated record time."""
    if type(signing_time) is not datetime or signing_time.utcoffset() is None:
        raise ValueError("portable record time must be timezone-aware")
    if not (operational_key.not_before <= signing_time.astimezone(UTC) < operational_key.not_after):
        raise ValueError("operational key is not valid at signing time")


def authenticate_portable_record_signature(
    *,
    canonical_payload: bytes,
    compact_jws: bytes,
    schema_version: str,
    operational_key: AuthenticatedOperationalKey,
) -> None:
    """Authenticate a record after its operational statement is trusted."""
    profile = _PORTABLE_RECORD_PROFILES.get(schema_version)
    if profile is None:
        raise ValueError("portable record schema has no supported signing profile")
    cty, typ, expected_purpose = profile
    if type(canonical_payload) is not bytes or not canonical_payload:
        raise ValueError("portable record payload must be non-empty bytes")
    if operational_key.purpose != expected_purpose:
        raise ValueError("operational key purpose does not match fixed record policy")
    try:
        compact_text = compact_jws.decode("ascii")
    except (AttributeError, UnicodeDecodeError):
        raise ValueError("portable compact JWS must be ASCII bytes") from None
    _verify_compact_jws(
        compact_text,
        expected_header={
            "alg": "ES256",
            "cty": cty,
            "kid": operational_key.kid,
            "rproof_schema": schema_version,
            "typ": typ,
        },
        expected_payload=canonical_payload,
        public_key=_p256_public_key(operational_key.public_jwk),
    )


def authenticate_key_distrust_event(
    *,
    canonical_payload: bytes,
    compact_jws: str,
    root_jwk: Mapping[str, object],
    root_kid: str,
) -> None:
    """Authenticate one fixed-profile distrust event directly under its trust root."""
    _verify_compact_jws(
        compact_jws,
        expected_header={
            "alg": "ES256",
            "cty": "application/rproof-key-distrust-event+json",
            "kid": root_kid,
            "rproof_schema": "rproof.key-distrust-event.v1",
            "typ": "application/rproof-key-distrust-event+jws",
        },
        expected_payload=canonical_payload,
        public_key=_p256_public_key(root_jwk),
    )


def authenticate_key_history(
    *, canonical_payload: bytes, compact_jws: str, root_jwk: Mapping[str, object], root_kid: str
) -> None:
    """Authenticate one fixed-profile key-history snapshot under its trust root."""
    _verify_compact_jws(
        compact_jws,
        expected_header={
            "alg": "ES256",
            "cty": "application/rproof-key-history+json",
            "kid": root_kid,
            "rproof_schema": "rproof.key-history.v1",
            "typ": "application/rproof-key-history+jws",
        },
        expected_payload=canonical_payload,
        public_key=_p256_public_key(root_jwk),
    )


def authenticate_attestation_jws(
    *,
    attestation: PreparedAttestation,
    attestation_jws: str,
    operational_key_statement: bytes,
    operational_key_statement_jws: str,
    root_jwk: Mapping[str, object],
    pinned_root_fingerprint_sha256: str,
    root_kid: str,
    expected_operational_purpose: str,
    expected_environment: str,
    signing_time: datetime,
) -> AuthenticatedAttestation:
    """Authenticate one explicit root -> operational key -> attestation chain."""
    try:
        statement_jws_bytes = operational_key_statement_jws.encode("ascii")
    except (AttributeError, UnicodeEncodeError):
        raise ValueError("operational key statement JWS must be ASCII") from None
    operational_key = authenticate_operational_key_statement(
        operational_key_statement=operational_key_statement,
        operational_key_statement_jws=statement_jws_bytes,
        root_jwk=root_jwk,
        pinned_root_fingerprint_sha256=pinned_root_fingerprint_sha256,
        root_kid=root_kid,
        expected_purpose=expected_operational_purpose,
        expected_environment=expected_environment,
    )
    require_operational_key_valid_at(operational_key, signing_time)
    rebuilt = prepare_attestation(attestation.payload)
    if not hmac.compare_digest(rebuilt.canonical_bytes, attestation.canonical_bytes) or not (
        hmac.compare_digest(rebuilt.canonical_sha256, attestation.canonical_sha256)
    ):
        raise ValueError("prepared attestation does not match its canonical payload and digest")
    authenticate_portable_record_signature(
        canonical_payload=rebuilt.canonical_bytes,
        compact_jws=attestation_jws.encode("ascii"),
        schema_version=cast(str, rebuilt.payload["schema_version"]),
        operational_key=operational_key,
    )
    return AuthenticatedAttestation(
        attestation_jws=attestation_jws,
        operational_key_statement=operational_key_statement,
        operational_key_statement_jws=operational_key_statement_jws,
    )


def _decode_exact_statement(value: bytes) -> PreparedOperationalKeyStatement:
    if type(value) is not bytes:
        raise ValueError("operational key statement must be bytes")
    try:
        decoded = json.loads(value.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("operational key statement must be UTF-8 JSON") from None
    if type(decoded) is not dict:
        raise ValueError("operational key statement must be a JSON object")
    statement = cast(dict[str, object], decoded)
    try:
        prepared = prepare_operational_key_statement(statement)
    except (ValidationError, ValueError):
        raise ValueError("operational key statement does not satisfy its schema") from None
    if not hmac.compare_digest(prepared.canonical_bytes, value):
        raise ValueError("operational key statement bytes are not exact canonical JSON")
    return prepared


def _verify_compact_jws(
    compact: str,
    *,
    expected_header: dict[str, object],
    expected_payload: bytes,
    public_key: ec.EllipticCurvePublicKey,
) -> None:
    if type(compact) is not str:
        raise ValueError("compact JWS must be a string")
    try:
        compact_bytes = compact.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("compact JWS must use ASCII") from None
    segments = compact.split(".")
    if len(segments) != 3:
        raise ValueError("compact JWS must contain three segments")
    protected, payload, signature = (_decode_base64url(item) for item in segments)
    if not hmac.compare_digest(protected, canonical_json_bytes(expected_header)):
        raise ValueError("compact JWS protected header does not match expected profile")
    if not hmac.compare_digest(payload, expected_payload):
        raise ValueError("compact JWS payload does not match expected canonical bytes")
    der_signature = _jose_es256_to_der(signature)
    signing_input = compact_bytes.rsplit(b".", 1)[0]
    try:
        public_key.verify(der_signature, signing_input, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise ValueError("compact JWS signature is invalid") from None


def _decode_base64url(segment: str) -> bytes:
    return decode_base64url(segment)


def decode_base64url(segment: str) -> bytes:
    """Decode one strict unpadded canonical base64url segment."""
    if _BASE64URL.fullmatch(segment) is None:
        raise ValueError("compact JWS segments must use unpadded base64url")
    try:
        decoded = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (binascii.Error, ValueError):
        raise ValueError("compact JWS segment is invalid base64url") from None
    encoded = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if encoded != segment:
        raise ValueError("compact JWS segment is not canonical base64url")
    return decoded


def _jose_es256_to_der(signature: bytes) -> bytes:
    if len(signature) != 64:
        raise ValueError("ES256 compact JWS signature must contain 64 bytes")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not 1 <= r < _P256_ORDER or not 1 <= s < _P256_ORDER:
        raise ValueError("ES256 signature scalars must be in the P-256 range")
    return utils.encode_dss_signature(r, s)


def _p256_public_key(jwk: Mapping[str, object]) -> ec.EllipticCurvePublicKey:
    p256_fingerprint_sha256(jwk)
    x = int.from_bytes(_decode_jwk_coordinate(cast(str, jwk["x"])), "big")
    y = int.from_bytes(_decode_jwk_coordinate(cast(str, jwk["y"])), "big")
    try:
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    except ValueError:
        raise ValueError("P-256 JWK coordinates do not identify a curve point") from None


def _decode_jwk_coordinate(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=")


def _validate_policy_inputs(
    *,
    pinned_root_fingerprint_sha256: str,
    root_kid: str,
    expected_operational_purpose: str,
    expected_environment: str,
) -> None:
    if (
        type(pinned_root_fingerprint_sha256) is not str
        or _SHA256_HEX.fullmatch(pinned_root_fingerprint_sha256) is None
    ):
        raise ValueError("pinned root fingerprint must be lowercase SHA-256 hexadecimal")
    if type(root_kid) is not str or _KID.fullmatch(root_kid) is None:
        raise ValueError("root kid must match the protected-header contract")
    if type(expected_operational_purpose) is not str or not expected_operational_purpose:
        raise ValueError("expected operational purpose must be explicit")
    if expected_environment not in {"production", "staging", "development"}:
        raise ValueError("expected environment must be explicit and supported")
