"""Structured Python verification outcome for one portable evidence bundle."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from hashlib import sha256
from typing import cast

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012
from reviewedproof.verification.artefacts import ArtefactInput as ArtefactInput
from reviewedproof.verification.artefacts import match_artefacts
from reviewedproof.verification.bundles import (
    BundleIncompleteError,
    BundleSafetyError,
    BundleUnsupportedError,
    BundleValidationError,
    CanonicalLifecycleRecords,
    load_verification_result_schemas,
    validate_lifecycle_bindings,
)
from reviewedproof.verification.lifecycle import (
    CarriedLifecycleEvent,
    LifecycleEvaluation,
    LifecycleValidationError,
    apply_predefined_expiry,
    evaluate_lifecycle,
    validate_completion,
)
from reviewedproof.verification.timestamp import (
    TimestampValidationError,
    parse_portable_utc_time,
)
from reviewedproof.verification.verifier import (
    AuthenticatedRproof,
    EvidenceAuthenticationError,
    VerifierPolicyError,
    authenticate_rproof,
    authenticate_signed_record,
)

_CHECK_NAMES = (
    "archive_safety",
    "bundle_manifest",
    "bundle_signature",
    "operational_key_statements",
    "package_manifest",
    "attestation",
    "attestation_signature",
    "identity_assurance",
    "organisation_authority",
    "timestamp",
    "lifecycle",
)
_P1_VALID_REASONS = {
    "archive_safety": "archive_safe",
    "bundle_manifest": "bundle_manifest_valid",
    "bundle_signature": "bundle_signature_valid",
    "operational_key_statements": "operational_keys_valid",
    "package_manifest": "package_manifest_valid",
    "attestation": "attestation_valid",
    "attestation_signature": "attestation_signature_valid",
    "timestamp": "timestamp_valid",
}
_ADVERSE_STATUSES = {"valid_but_revoked", "superseded", "expired"}


@dataclass(frozen=True, slots=True)
class VerificationOutcome:
    """Schema-valid verification result and its documented process exit code."""

    result: dict[str, object]
    exit_code: int


def verify_rproof(
    archive_bytes: bytes,
    *,
    trust_store_bytes: bytes,
    verified_at: datetime,
    artefacts: Sequence[ArtefactInput] = (),
    allow_non_production: bool = False,
    verifier_version: str = "0.1.0",
) -> VerificationOutcome:
    """Run the complete bundle-only Python verification pipeline."""
    verified_at_text = _verified_at_text(verified_at)
    if type(verifier_version) is not str or not 1 <= len(verifier_version) <= 100:
        raise ValueError("verifier version must contain 1 to 100 characters")
    if type(archive_bytes) is not bytes or type(trust_store_bytes) is not bytes:
        raise ValueError("bundle and trust store inputs must be bytes")

    try:
        authenticated = authenticate_rproof(
            archive_bytes,
            trust_store_bytes=trust_store_bytes,
            verified_at=verified_at,
            allow_non_production=allow_non_production,
        )
    except (
        BundleSafetyError,
        BundleIncompleteError,
        BundleUnsupportedError,
        BundleValidationError,
        EvidenceAuthenticationError,
        VerifierPolicyError,
    ) as error:
        return _failure_outcome(
            archive_bytes=archive_bytes,
            trust_store_bytes=trust_store_bytes,
            verified_at=verified_at_text,
            verifier_version=verifier_version,
            error=error,
            authenticated=None,
        )

    try:
        lifecycle_records = validate_lifecycle_bindings(
            authenticated.parsed,
            canonical_schema_files={
                path.removeprefix("schemas/"): content
                for path, content in authenticated.parsed.components.items()
                if path.startswith("schemas/")
            },
        )
        _authenticate_lifecycle_records(authenticated, lifecycle_records, verified_at)
        lifecycle = evaluate_lifecycle(
            attestation=authenticated.attestation,
            bundle_manifest=authenticated.parsed.manifest,
            status_snapshot=lifecycle_records.status_snapshot,
            events=tuple(
                CarriedLifecycleEvent(
                    event,
                    authenticated.parsed.components[
                        f"evidence/lifecycle/events/{sequence:04d}.json"
                    ],
                )
                for sequence, event in enumerate(lifecycle_records.events, start=1)
            ),
        )
        if lifecycle_records.completion is not None:
            validate_completion(
                attestation=authenticated.attestation,
                bundle_manifest=authenticated.parsed.manifest,
                completion=lifecycle_records.completion,
            )
        if parse_portable_utc_time(authenticated.timestamp.token_gen_time) > (
            lifecycle.generated_at.replace(microsecond=0),
            lifecycle.generated_at.microsecond * 1000,
        ):
            raise LifecycleValidationError(
                "signed status snapshot predates the authenticated timestamp"
            )
        status = apply_predefined_expiry(
            attestation=authenticated.attestation,
            status=lifecycle.status,
            evaluated_at=verified_at,
        )
    except BundleUnsupportedError as error:
        return _failure_outcome(
            archive_bytes=archive_bytes,
            trust_store_bytes=trust_store_bytes,
            verified_at=verified_at_text,
            verifier_version=verifier_version,
            error=error,
            authenticated=authenticated,
            check_name="lifecycle",
        )
    except EvidenceAuthenticationError as error:
        return _failure_outcome(
            archive_bytes=archive_bytes,
            trust_store_bytes=trust_store_bytes,
            verified_at=verified_at_text,
            verifier_version=verifier_version,
            error=error,
            authenticated=authenticated,
        )
    except (BundleValidationError, LifecycleValidationError, TimestampValidationError) as error:
        return _failure_outcome(
            archive_bytes=archive_bytes,
            trust_store_bytes=trust_store_bytes,
            verified_at=verified_at_text,
            verifier_version=verifier_version,
            error=error,
            authenticated=authenticated,
            check_name="lifecycle",
        )

    artefact_check, matched_entry_ids = match_artefacts(authenticated.package, artefacts)
    checks = _p1_checks(authenticated)
    checks["lifecycle"] = _check("valid", "lifecycle_valid")
    receipt_integrity = _check("valid", "receipt_integrity_valid")
    if status == "invalid":
        exit_code = 2
    elif status == "incomplete_proof":
        exit_code = 4
    elif artefact_check["state"] == "invalid":
        exit_code = 3
    elif status in _ADVERSE_STATUSES:
        exit_code = 7
    else:
        exit_code = 0

    result: dict[str, object] = {
        "artefact_match": artefact_check,
        "bundle_sha256": sha256(archive_bytes).hexdigest(),
        "checks": checks,
        "current_status_checked": False,
        "environment": authenticated.environment,
        "execution_mode": "cli",
        "matched_entry_ids": list(matched_entry_ids),
        "receipt_id": authenticated.attestation["receipt_id"],
        "receipt_integrity": receipt_integrity,
        "schema_version": "rproof.verification-result.v1",
        "status": status,
        "trust_store_sha256": authenticated.trust_store_sha256,
        "trust_store_version": authenticated.trust_store_version,
        "verified_as_of": cast(str, lifecycle_records.status_snapshot["generated_at"]),
        "verified_at": verified_at_text,
        "verifier_version": verifier_version,
        "warnings": _success_warnings(
            authenticated,
            lifecycle,
            artefact_check,
            completion_present=lifecycle_records.completion is not None,
            verified_at=verified_at,
        ),
    }
    return _validated_outcome(result, exit_code)


def _authenticate_lifecycle_records(
    authenticated: AuthenticatedRproof,
    lifecycle_records: CanonicalLifecycleRecords,
    verified_at: datetime,
) -> None:
    records_by_path = {record.path: record for record in authenticated.records}
    paths = ["evidence/lifecycle/status-snapshot.json"]
    paths.extend(
        f"evidence/lifecycle/events/{sequence:04d}.json"
        for sequence, _ in enumerate(lifecycle_records.events, start=1)
    )
    if lifecycle_records.completion is not None:
        paths.append("review/completion.json")
    for path in paths:
        record = records_by_path.get(path)
        if record is None:
            raise BundleValidationError(f"bundle lacks signed lifecycle record {path}")
        authenticate_signed_record(authenticated, record, verified_at=verified_at)


def _failure_outcome(
    *,
    archive_bytes: bytes,
    trust_store_bytes: bytes,
    verified_at: str,
    verifier_version: str,
    error: ValueError,
    authenticated: AuthenticatedRproof | None,
    check_name: str | None = None,
) -> VerificationOutcome:
    failed_check = check_name or cast(str, getattr(error, "check_name", "bundle_manifest"))
    if failed_check not in _CHECK_NAMES:
        failed_check = "bundle_manifest"
    if isinstance(error, BundleSafetyError):
        state, reason_code, status, exit_code = "invalid", "unsafe_archive", "invalid", 6
    elif isinstance(error, BundleIncompleteError):
        state, reason_code, status, exit_code = (
            "not_present",
            "required_evidence_missing",
            "incomplete_proof",
            4,
        )
    elif isinstance(error, BundleUnsupportedError):
        state, reason_code, status, exit_code = (
            "unsupported",
            "unsupported_evidence",
            "unsupported",
            5,
        )
    else:
        state, reason_code, status, exit_code = (
            "invalid",
            f"{failed_check}_invalid",
            "invalid",
            2,
        )
    checks = _p1_checks(authenticated) if authenticated is not None else _unchecked_checks()
    checks[failed_check] = _check(state, reason_code)
    warnings = [
        "Current receipt status was not established by this verification.",
        "Local artefact comparison was not performed because required evidence "
        "verification failed.",
        "Later operational-key distrust information may be unknown to this verifier release.",
    ]
    if authenticated is not None and authenticated.environment != "production":
        warnings.insert(0, "Non-production evidence accepted under explicit test-mode policy.")
    result: dict[str, object] = {
        "artefact_match": _check("not_checked", "evidence_verification_failed"),
        "bundle_sha256": sha256(archive_bytes).hexdigest(),
        "checks": checks,
        "current_status_checked": False,
        "environment": None if authenticated is None else authenticated.environment,
        "execution_mode": "cli",
        "matched_entry_ids": [],
        "receipt_id": None if authenticated is None else authenticated.attestation["receipt_id"],
        "receipt_integrity": _check(state, reason_code),
        "schema_version": "rproof.verification-result.v1",
        "status": status,
        "trust_store_sha256": sha256(trust_store_bytes).hexdigest(),
        "trust_store_version": (
            "unknown" if authenticated is None else authenticated.trust_store_version
        ),
        "verified_as_of": None,
        "verified_at": verified_at,
        "verifier_version": verifier_version,
        "warnings": warnings,
    }
    return _validated_outcome(result, exit_code)


def _p1_checks(
    authenticated: AuthenticatedRproof | None,
) -> dict[str, dict[str, str]]:
    checks = _unchecked_checks()
    if authenticated is None:
        return checks
    for name, reason in _P1_VALID_REASONS.items():
        checks[name] = _check("valid", reason)
    checks["identity_assurance"] = _check("valid", "identity_assurance_claim_authenticated")
    if authenticated.attestation["organisation_authority"] is None:
        checks["organisation_authority"] = _check("not_present", "no_authority_claim")
    else:
        checks["organisation_authority"] = _check(
            "valid", "organisation_authority_claim_authenticated"
        )
    return checks


def _unchecked_checks() -> dict[str, dict[str, str]]:
    return {
        name: _check("not_checked", "not_checked_due_to_earlier_failure") for name in _CHECK_NAMES
    }


def _success_warnings(
    authenticated: AuthenticatedRproof,
    lifecycle: LifecycleEvaluation,
    artefact_check: dict[str, str],
    *,
    completion_present: bool,
    verified_at: datetime,
) -> list[str]:
    warnings: list[str] = []
    if authenticated.environment != "production":
        warnings.append("Non-production evidence accepted under explicit test-mode policy.")
    warnings.extend(
        (
            "Cryptographic evidence is valid as of the signed status snapshot. "
            "Current revocation status after that time was not checked.",
            "Later operational-key distrust information may be unknown to this verifier release.",
        )
    )
    if lifecycle.generated_at > verified_at.astimezone(UTC):
        warnings.append(
            "The signed evidence time is later than the local verifier clock; check the "
            "local clock."
        )
    elif verified_at.astimezone(UTC) >= lifecycle.next_update_due_at:
        warnings.append(
            "The signed status update horizon has passed; later withdrawal status remains unknown."
        )
    if artefact_check["state"] == "not_checked":
        warnings.append(
            f"Local artefact comparison was not completed: {artefact_check['reason_code']}."
        )
    elif artefact_check["state"] == "invalid":
        warnings.append("One or more selected artefacts did not match the authenticated package.")
    warnings.append(
        "Identity and organisation authority are authenticated issuer-carried claims; "
        "no live provider or organisation check was performed."
    )
    warnings.append(
        "The timestamp certificate path was checked at genTime without an online "
        "certificate-revocation lookup."
    )
    warnings.append(
        "The proof authenticates the carried review statement; it does not establish "
        "reviewer competence or review correctness."
    )
    if completion_present:
        warnings.append(
            "Completion validates the frozen carried policy only; other linked receipts "
            "and current quorum were not independently checked."
        )
    return warnings


def _verified_at_text(value: datetime) -> str:
    if type(value) is not datetime or value.utcoffset() is None or value.microsecond != 0:
        raise ValueError("verified_at must be a timezone-aware whole-second datetime")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _check(state: str, reason_code: str) -> dict[str, str]:
    return {"reason_code": reason_code, "state": state}


def _validated_outcome(result: dict[str, object], exit_code: int) -> VerificationOutcome:
    _verification_result_validator().validate(result)
    return VerificationOutcome(result, exit_code)


@lru_cache(maxsize=1)
def _verification_result_validator() -> Draft202012Validator:
    schemas = load_verification_result_schemas()
    loaded = {name: cast(dict[str, object], json.loads(source)) for name, source in schemas.items()}
    registry: Registry[dict[str, object]] = Registry()
    for schema in loaded.values():
        registry = registry.with_resource(
            cast(str, schema["$id"]),
            Resource.from_contents(schema, default_specification=DRAFT202012),
        )
    return Draft202012Validator(
        loaded["verification-result.v1.schema.json"],
        registry=registry,
        format_checker=FormatChecker(),
    )
