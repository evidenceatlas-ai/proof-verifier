"""Strict RFC 3161 request construction and timestamp-response validation."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import cast

from asn1crypto import algos, cms, core, pem, tsp, x509  # type: ignore[import-untyped]
from pyhanko.keys import load_certs_from_pemder_data
from pyhanko.sign.validation.generic_cms import validate_tst_signed_data
from pyhanko.sign.validation.status import TimestampSignatureStatus
from pyhanko_certvalidator import ValidationContext
from reviewedproof.ports import TimestampResult

SHA256_OID = "2.16.840.1.101.3.4.2.1"
_GENERALIZED_TIME = re.compile(rb"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d{1,9}))?Z$")
_PORTABLE_UTC_TIME = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$")


class TimestampValidationError(ValueError):
    """Timestamp response failed a required binding or trust check."""


def build_timestamp_request(message_digest: bytes, nonce: int, policy_oid: str) -> bytes:
    """Encode exact supplied SHA-256 digest, positive nonce and policy."""
    _validate_inputs(message_digest, nonce)
    try:
        policy = core.ObjectIdentifier(policy_oid)
    except (TypeError, ValueError) as exc:
        raise ValueError("timestamp policy OID is invalid") from exc
    return cast(
        bytes,
        tsp.TimeStampReq(
            {
                "version": "v1",
                "message_imprint": tsp.MessageImprint(
                    {
                        "hash_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
                        "hashed_message": message_digest,
                    }
                ),
                "req_policy": policy,
                "nonce": core.Integer(nonce),
                "cert_req": True,
            }
        ).dump(),
    )


def nonce_sha256(nonce: int) -> bytes:
    """Hash minimal unsigned big-endian bytes of a positive RFC 3161 nonce."""
    if type(nonce) is not int or nonce <= 0:
        raise ValueError("timestamp nonce must be a positive integer")
    encoded = nonce.to_bytes((nonce.bit_length() + 7) // 8, "big")
    return sha256(encoded).digest()


def timestamp_response_nonce(response_bytes: bytes) -> int:
    """Read the positive nonce committed by one structurally valid RFC 3161 reply."""
    _, tst_info = _timestamp_token_parts(response_bytes)
    nonce = tst_info["nonce"].native
    if type(nonce) is not int or nonce <= 0:
        raise TimestampValidationError("timestamp response nonce must be positive")
    return nonce


def validate_timestamp_response(
    response_bytes: bytes,
    *,
    message_digest: bytes,
    nonce: int,
    policy_oid: str,
    provider: str,
    trust_roots_pem: bytes,
    intermediate_certificates_pem: bytes = b"",
    now: datetime,
    time_tolerance: timedelta,
    development_only: bool,
) -> TimestampResult:
    """Validate original RFC 3161 reply using asn1crypto and pyHanko.

    S5 local/contract validation performs no revocation-network fetching and
    treats absent revocation data as non-fatal. It makes no live-provider
    revocation claim.
    """
    if type(now) is not datetime or now.utcoffset() is None:
        raise ValueError("timestamp validation time must be timezone-aware")
    if time_tolerance <= timedelta(0):
        raise ValueError("timestamp time tolerance must be positive")
    return _validate_timestamp_response(
        response_bytes,
        message_digest=message_digest,
        nonce=nonce,
        policy_oid=policy_oid,
        provider=provider,
        trust_roots_pem=trust_roots_pem,
        intermediate_certificates_pem=intermediate_certificates_pem,
        plausibility=(now, time_tolerance),
        development_only=development_only,
    )


def validate_archived_timestamp_response(
    response_bytes: bytes,
    *,
    message_digest: bytes,
    nonce: int,
    policy_oid: str,
    provider: str,
    trust_roots_pem: bytes,
    intermediate_certificates_pem: bytes = b"",
    development_only: bool,
) -> TimestampResult:
    """Validate retained RFC 3161 evidence without a present-clock recency test."""
    return _validate_timestamp_response(
        response_bytes,
        message_digest=message_digest,
        nonce=nonce,
        policy_oid=policy_oid,
        provider=provider,
        trust_roots_pem=trust_roots_pem,
        intermediate_certificates_pem=intermediate_certificates_pem,
        plausibility=None,
        development_only=development_only,
    )


def _validate_timestamp_response(
    response_bytes: bytes,
    *,
    message_digest: bytes,
    nonce: int,
    policy_oid: str,
    provider: str,
    trust_roots_pem: bytes,
    intermediate_certificates_pem: bytes,
    plausibility: tuple[datetime, timedelta] | None,
    development_only: bool,
) -> TimestampResult:
    _validate_inputs(message_digest, nonce)
    if type(response_bytes) is not bytes or not response_bytes:
        raise TimestampValidationError("timestamp response must be non-empty bytes")
    if type(provider) is not str or not provider:
        raise ValueError("timestamp provider must be explicit")

    signed_data, tst_info = _timestamp_token_parts(response_bytes)

    imprint = tst_info["message_imprint"]
    if imprint["hash_algorithm"]["algorithm"].dotted != SHA256_OID:
        raise TimestampValidationError("timestamp message-imprint algorithm is not SHA-256")
    returned_digest = imprint["hashed_message"].native
    if returned_digest != message_digest:
        raise TimestampValidationError("timestamp message imprint does not match request")
    if tst_info["nonce"].native != nonce:
        raise TimestampValidationError("timestamp nonce does not match request")
    if tst_info["policy"].dotted != policy_oid:
        raise TimestampValidationError("timestamp policy does not match configured policy")

    gen_time_value = tst_info["gen_time"]
    token_gen_time = format_generalized_time(gen_time_value.contents)
    generation_time = gen_time_value.native
    if not isinstance(generation_time, datetime) or generation_time.utcoffset() is None:
        raise TimestampValidationError("timestamp generation time is not UTC")
    if plausibility is not None:
        now, time_tolerance = plausibility
        if abs(now.astimezone(UTC) - generation_time.astimezone(UTC)) > time_tolerance:
            raise TimestampValidationError(
                "timestamp generation time is outside configured tolerance"
            )

    trust_roots = _load_certificates(trust_roots_pem, "timestamp trust roots")
    intermediates = _load_certificates(
        intermediate_certificates_pem, "timestamp intermediate certificates", allow_empty=True
    )
    validation_context = ValidationContext(
        trust_roots=trust_roots,
        other_certs=intermediates,
        moment=generation_time,
        best_signature_time=generation_time,
        allow_fetching=False,
        revocation_mode="soft-fail",
        time_tolerance=timedelta(0),
    )
    try:
        status_kwargs = asyncio.run(
            validate_tst_signed_data(signed_data, validation_context, message_digest)
        )
        status = TimestampSignatureStatus(**status_kwargs)
    except Exception as exc:
        raise TimestampValidationError(
            "timestamp CMS signature or certificate chain is invalid"
        ) from exc
    if not status.intact or not status.valid:
        raise TimestampValidationError("timestamp CMS signature is invalid")
    if not status.trusted or status.validation_path is None:
        raise TimestampValidationError("timestamp signer is not trusted by configured roots")
    _require_exclusive_critical_timestamp_eku(status.signing_cert)

    return TimestampResult(
        response_bytes=response_bytes,
        certificate_chain_pem=_path_to_pem(status.validation_path),
        provider=provider,
        policy_oid=policy_oid,
        message_imprint_sha256=message_digest,
        nonce_sha256=nonce_sha256(nonce),
        token_gen_time=token_gen_time,
        development_only=development_only,
    )


def _timestamp_token_parts(response_bytes: bytes) -> tuple[cms.SignedData, tsp.TSTInfo]:
    if type(response_bytes) is not bytes or not response_bytes:
        raise TimestampValidationError("timestamp response must be non-empty bytes")
    try:
        response = tsp.TimeStampResp.load(response_bytes, strict=True)
        if response["status"]["status"].native != "granted":
            raise TimestampValidationError("timestamp response status is not granted")
        token = response["time_stamp_token"]
        if token.native is None or token["content_type"].native != "signed_data":
            raise TimestampValidationError("timestamp response has no signed timestamp token")
        signed_data = token["content"]
        if not isinstance(signed_data, cms.SignedData):
            raise TimestampValidationError("timestamp token content is not CMS SignedData")
        tst_info = signed_data["encap_content_info"]["content"].parsed
        if not isinstance(tst_info, tsp.TSTInfo):
            raise TimestampValidationError("timestamp token does not contain TSTInfo")
        return signed_data, tst_info
    except TimestampValidationError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise TimestampValidationError("timestamp response is not valid DER RFC 3161 data") from exc


def _validate_inputs(message_digest: bytes, nonce: int) -> None:
    if type(message_digest) is not bytes or len(message_digest) != 32:
        raise ValueError("timestamp message digest must be exactly 32 bytes")
    if type(nonce) is not int or nonce <= 0:
        raise ValueError("timestamp nonce must be a positive integer")


def format_generalized_time(contents: bytes) -> str:
    """Render exact RFC 3161 GeneralizedTime contents as portable UTC text."""
    match = _GENERALIZED_TIME.fullmatch(contents)
    if match is None:
        raise TimestampValidationError(
            "timestamp generation time must be UTC with at most nine fractional digits"
        )
    year, month, day, hour, minute, second, fraction = match.groups()
    suffix = b"" if fraction is None else b"." + fraction
    return (
        year
        + b"-"
        + month
        + b"-"
        + day
        + b"T"
        + hour
        + b":"
        + minute
        + b":"
        + second
        + suffix
        + b"Z"
    ).decode("ascii")


def parse_portable_utc_time(value: str) -> tuple[datetime, int]:
    """Return one portable UTC instant as its whole second and nanoseconds."""
    match = _PORTABLE_UTC_TIME.fullmatch(value) if type(value) is str else None
    if match is None:
        raise TimestampValidationError(
            "portable time must be UTC with at most nine fraction digits"
        )
    try:
        second = datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        raise TimestampValidationError("portable time is not a valid UTC instant") from None
    fraction = match.group(2) or ""
    return second, int((fraction + "000000000")[:9])


def portable_utc_times_equal(left: str, right: str) -> bool:
    """Compare portable UTC text by exact instant while retaining either source spelling."""
    return parse_portable_utc_time(left) == parse_portable_utc_time(right)


_format_generalized_time = format_generalized_time


def _load_certificates(
    encoded: bytes, label: str, *, allow_empty: bool = False
) -> list[x509.Certificate]:
    if type(encoded) is not bytes or (not encoded and not allow_empty):
        raise ValueError(f"{label} must be supplied as PEM or DER bytes")
    if not encoded:
        return []
    try:
        certificates = list(load_certs_from_pemder_data(encoded))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} are invalid") from exc
    if not certificates and not allow_empty:
        raise ValueError(f"{label} must contain at least one certificate")
    return certificates


def _require_exclusive_critical_timestamp_eku(cert: x509.Certificate) -> None:
    matches = [
        extension
        for extension in cert["tbs_certificate"]["extensions"]
        if extension["extn_id"].native == "extended_key_usage"
    ]
    if len(matches) != 1:
        raise TimestampValidationError(
            "timestamp signer must have one extended-key-usage extension"
        )
    extension = matches[0]
    usages = extension["extn_value"].parsed.native
    if extension["critical"].native is not True or usages != ["time_stamping"]:
        raise TimestampValidationError(
            "timestamp signer EKU must be critical and exclusively time stamping"
        )


def _path_to_pem(path: Iterable[x509.Certificate]) -> bytes:
    certificates = list(path)
    if not certificates:
        raise TimestampValidationError("timestamp validation produced no certificate chain")
    return b"".join(
        pem.armor("CERTIFICATE", certificate.dump()) for certificate in reversed(certificates)
    )
