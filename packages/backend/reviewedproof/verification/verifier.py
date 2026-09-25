"""Ordered cryptographic authentication for one portable ReviewedProof bundle."""

from __future__ import annotations

import hmac
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import cast

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from jsonschema.exceptions import ValidationError  # type: ignore[import-untyped]
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012
from reviewedproof.ports import TimestampResult
from reviewedproof.verification.bundles import (
    MANIFEST_PATH,
    BundleUnsupportedError,
    BundleValidationError,
    OperationalKeyLayout,
    ParsedRproofBundle,
    SignedRecordReference,
    load_bundle_schemas,
    load_verifier_policy_schemas,
    parse_rproof_bundle,
    signed_record_references,
    validate_attestation_bindings,
    validate_operational_key_bindings,
    validate_package_manifest,
    validate_timestamp_bindings,
)
from reviewedproof.verification.kernel import canonical_json_bytes, p256_fingerprint_sha256
from reviewedproof.verification.signing import (
    AuthenticatedOperationalKey,
    authenticate_key_distrust_event,
    authenticate_operational_key_statement,
    authenticate_portable_record_signature,
    require_operational_key_valid_at,
)
from reviewedproof.verification.timestamp import (
    TimestampValidationError,
    parse_portable_utc_time,
    portable_utc_times_equal,
    timestamp_response_nonce,
    validate_archived_timestamp_response,
)


class VerifierPolicyError(ValueError):
    """External verifier trust policy is invalid or does not trust the evidence."""

    def __init__(self, message: str, *, check_name: str = "operational_key_statements") -> None:
        super().__init__(message)
        self.check_name = check_name


class EvidenceAuthenticationError(ValueError):
    """Structurally valid evidence fails signature, trust or authenticated-time checks."""

    def __init__(self, message: str, *, check_name: str) -> None:
        super().__init__(message)
        self.check_name = check_name


@dataclass(frozen=True, slots=True)
class AuthenticatedRproof:
    """Authenticated records retained for the later lifecycle and result stages."""

    parsed: ParsedRproofBundle
    records: tuple[SignedRecordReference, ...]
    operational_keys: dict[str, AuthenticatedOperationalKey]
    root: dict[str, object]
    operational_key_distrust_events: tuple[dict[str, object], ...]
    package: dict[str, object]
    attestation: dict[str, object]
    timestamp: TimestampResult
    trust_store_version: str
    trust_store_sha256: str
    environment: str


def authenticate_signed_record(
    authenticated: AuthenticatedRproof,
    record: SignedRecordReference,
    *,
    verified_at: datetime,
) -> None:
    """Authenticate one carried record after its canonical schema validation."""
    if record not in authenticated.records:
        raise BundleValidationError("signed record is not part of the parsed bundle")
    if type(verified_at) is not datetime or verified_at.utcoffset() is None:
        raise VerifierPolicyError("verification time must be timezone-aware")
    key = authenticated.operational_keys.get(record.kid)
    if key is None:
        raise EvidenceAuthenticationError(
            "signed record has no authenticated operational key",
            check_name="operational_key_statements",
        )
    _authenticate_record(authenticated.parsed, record, key)
    signing_time_text = _record_signing_time(authenticated, record)
    signing_time = _authority_datetime(
        signing_time_text, "record signing time", _record_check_name(record)
    )
    _require_authenticated_record_time(
        authenticated.root,
        key,
        record,
        signing_time_text,
        signing_time,
        authenticated.operational_key_distrust_events,
        verified_at,
        authenticated.parsed,
    )


def authenticate_rproof(
    archive_bytes: bytes,
    *,
    trust_store_bytes: bytes,
    verified_at: datetime,
    allow_non_production: bool = False,
    canonical_schema_files: dict[str, bytes] | None = None,
) -> AuthenticatedRproof:
    """Authenticate the non-lifecycle prefix of the mandatory verifier pipeline."""
    if type(verified_at) is not datetime or verified_at.utcoffset() is None:
        raise VerifierPolicyError("verification time must be timezone-aware")
    if type(allow_non_production) is not bool:
        raise VerifierPolicyError("non-production policy must be an explicit boolean")

    schemas = canonical_schema_files or load_bundle_schemas(
        include_lifecycle_events=True,
        include_review_completion=True,
    )
    parsed = parse_rproof_bundle(archive_bytes, canonical_schema_files=schemas)

    trust_store = _load_trust_store(trust_store_bytes)
    environment = cast(str, trust_store["environment"])
    if environment != "production" and not allow_non_production:
        raise VerifierPolicyError("non-production evidence requires explicit test-mode policy")
    root = _select_root(parsed, trust_store)
    tsa_policy = _select_tsa_policy(parsed, trust_store)
    distrust_events = _authenticate_distrust_events(root, environment)

    records = signed_record_references(parsed)
    layout = validate_operational_key_bindings(parsed, records, canonical_schema_files=schemas)
    if (
        layout.root_kid != root["kid"]
        or layout.environment != environment
        or layout.root_fingerprint_sha256 != root["fingerprint_sha256"]
    ):
        raise VerifierPolicyError("bundle signing authority does not match external trust policy")
    operational_keys = _authenticate_operational_keys(parsed, records, layout, root)

    manifest_record = _record(records, MANIFEST_PATH)
    _authenticate_record(parsed, manifest_record, operational_keys[manifest_record.kid])
    manifest_time_text = cast(str, parsed.manifest["created_at"])
    manifest_time = _authority_datetime(
        manifest_time_text, "bundle creation time", "bundle_signature"
    )
    _require_authenticated_record_time(
        root,
        operational_keys[manifest_record.kid],
        manifest_record,
        manifest_time_text,
        manifest_time,
        distrust_events,
        verified_at,
        parsed,
    )

    try:
        package = validate_package_manifest(parsed, canonical_schema_files=schemas)
    except BundleUnsupportedError:
        raise
    except BundleValidationError as error:
        raise EvidenceAuthenticationError(
            "package manifest validation failed", check_name="package_manifest"
        ) from error
    try:
        attestation = validate_attestation_bindings(parsed, package, canonical_schema_files=schemas)
    except BundleUnsupportedError:
        raise
    except BundleValidationError as error:
        raise EvidenceAuthenticationError(
            "attestation validation failed", check_name="attestation"
        ) from error
    attestation_record = _record(records, "receipt/attestation.json")
    _authenticate_record(parsed, attestation_record, operational_keys[attestation_record.kid])

    try:
        timestamp_evidence = validate_timestamp_bindings(parsed, canonical_schema_files=schemas)
    except BundleUnsupportedError:
        raise
    except BundleValidationError as error:
        raise EvidenceAuthenticationError(
            "timestamp evidence validation failed", check_name="timestamp"
        ) from error
    timestamp = _authenticate_timestamp(parsed, timestamp_evidence, tsa_policy, environment)

    token_time_text = timestamp.token_gen_time
    token_time = _authority_datetime(token_time_text, "timestamp generation time", "timestamp")
    _require_authenticated_record_time(
        root,
        operational_keys[attestation_record.kid],
        attestation_record,
        token_time_text,
        token_time,
        distrust_events,
        verified_at,
        parsed,
    )
    _require_attestation_chronology(attestation, token_time_text, manifest_time_text)

    return AuthenticatedRproof(
        parsed=parsed,
        records=records,
        operational_keys=operational_keys,
        root=root,
        operational_key_distrust_events=distrust_events,
        package=package,
        attestation=attestation,
        timestamp=timestamp,
        trust_store_version=cast(str, trust_store["trust_store_version"]),
        trust_store_sha256=sha256(trust_store_bytes).hexdigest(),
        environment=environment,
    )


def _load_trust_store(content: bytes) -> dict[str, object]:
    if type(content) is not bytes or not content:
        raise VerifierPolicyError("external trust store must be non-empty bytes")
    try:
        value = json.loads(content)
        if type(value) is not dict or canonical_json_bytes(value) != content:
            raise VerifierPolicyError("external trust store must use canonical JSON bytes")
        schemas = load_verifier_policy_schemas()
        loaded: dict[str, dict[str, object]] = {}
        registry: Registry[dict[str, object]] = Registry()
        for name, source in schemas.items():
            schema = json.loads(source)
            if type(schema) is not dict or type(schema.get("$id")) is not str:
                raise VerifierPolicyError(f"verifier policy schema {name} is invalid")
            loaded[name] = cast(dict[str, object], schema)
            registry = registry.with_resource(
                cast(str, schema["$id"]),
                Resource.from_contents(schema, default_specification=DRAFT202012),
            )
        Draft202012Validator(
            loaded["trust-store.v1.schema.json"],
            registry=registry,
            format_checker=FormatChecker(),
        ).validate(value)
    except VerifierPolicyError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, ValueError) as error:
        raise VerifierPolicyError("external trust store does not satisfy its schema") from error
    return cast(dict[str, object], value)


def _select_root(parsed: ParsedRproofBundle, trust_store: dict[str, object]) -> dict[str, object]:
    try:
        fingerprint_line = parsed.components["trust/root-fingerprint.txt"].decode("ascii")
    except UnicodeDecodeError as error:
        raise BundleValidationError("bundled root fingerprint is not ASCII") from error
    if not re.fullmatch(r"sha256:[0-9a-f]{64}\n", fingerprint_line):
        raise BundleValidationError("bundled root fingerprint is invalid")
    fingerprint = fingerprint_line[7:-1]
    candidates = [
        cast(dict[str, object], root)
        for root in cast(list[object], trust_store["reviewedproof_roots"])
        if cast(dict[str, object], root)["fingerprint_sha256"] == fingerprint
    ]
    if len(candidates) != 1:
        raise VerifierPolicyError("bundle root is not uniquely trusted by this release")
    root = candidates[0]
    if root["status"] == "distrusted":
        raise VerifierPolicyError("bundle root is distrusted by this release")
    try:
        actual = p256_fingerprint_sha256(cast(dict[str, object], root["jwk"]))
    except ValueError as error:
        raise VerifierPolicyError("external root JWK is invalid") from error
    if not hmac.compare_digest(actual, fingerprint):
        raise VerifierPolicyError("external root JWK does not match its fingerprint")
    return root


def _select_tsa_policy(
    parsed: ParsedRproofBundle, trust_store: dict[str, object]
) -> dict[str, object]:
    try:
        evidence = json.loads(parsed.components["evidence/timestamp/evidence.json"])
        provider = evidence["provider"]
        policy_oid = evidence["policy_oid"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise BundleValidationError("timestamp evidence cannot select external policy") from error
    if type(provider) is not str or type(policy_oid) is not str:
        raise BundleValidationError("timestamp evidence cannot select external policy")
    candidates = [
        cast(dict[str, object], policy)
        for policy in cast(list[object], trust_store["tsa_policies"])
        if cast(dict[str, object], policy)["tsa_id"] == provider
        and policy_oid in cast(list[str], cast(dict[str, object], policy)["policy_oids"])
    ]
    if len(candidates) != 1:
        raise VerifierPolicyError(
            "timestamp authority and policy are not uniquely trusted", check_name="timestamp"
        )
    return candidates[0]


def _authenticate_distrust_events(
    root: dict[str, object], environment: str
) -> tuple[dict[str, object], ...]:
    events: list[dict[str, object]] = []
    event_ids: set[str] = set()
    previous_digest: str | None = None
    entries = cast(list[dict[str, object]], root["operational_key_distrust_events"])
    for sequence, entry in enumerate(entries, start=1):
        event = cast(dict[str, object], entry["event"])
        canonical = canonical_json_bytes(event)
        try:
            authenticate_key_distrust_event(
                canonical_payload=canonical,
                compact_jws=cast(str, entry["jws"]),
                root_jwk=cast(dict[str, object], root["jwk"]),
                root_kid=cast(str, root["kid"]),
            )
        except ValueError as error:
            raise VerifierPolicyError(
                "operational key distrust event signature is invalid"
            ) from error
        event_id = cast(str, event["event_id"])
        recorded_at = _policy_datetime(
            cast(str, event["recorded_at"]), "distrust event recorded_at"
        )
        time_range = cast(dict[str, object], event["affected_signing_time_range"])
        starts_at = _policy_datetime(cast(str, time_range["from"]), "distrust range start")
        through_text = cast(str | None, time_range["through"])
        through = (
            None if through_text is None else _policy_datetime(through_text, "distrust range end")
        )
        if (
            event["sequence"] != sequence
            or event["previous_distrust_event_sha256"] != previous_digest
            or event["environment"] != environment
            or event_id in event_ids
            or (through is not None and starts_at > through)
        ):
            raise VerifierPolicyError("operational key distrust event chain is invalid")
        _require_root_valid_at(root, recorded_at)
        event_ids.add(event_id)
        previous_digest = sha256(canonical).hexdigest()
        events.append(event)
    return tuple(events)


def _authenticate_operational_keys(
    parsed: ParsedRproofBundle,
    records: tuple[SignedRecordReference, ...],
    layout: OperationalKeyLayout,
    root: dict[str, object],
) -> dict[str, AuthenticatedOperationalKey]:
    keys: dict[str, AuthenticatedOperationalKey] = {}
    for record in records:
        if record.kid in keys:
            continue
        stem = f"trust/operational-key-statements/{record.kid}"
        try:
            keys[record.kid] = authenticate_operational_key_statement(
                operational_key_statement=parsed.components[f"{stem}.json"],
                operational_key_statement_jws=parsed.components[f"{stem}.jws"],
                root_jwk=cast(dict[str, object], root["jwk"]),
                pinned_root_fingerprint_sha256=cast(str, root["fingerprint_sha256"]),
                root_kid=cast(str, root["kid"]),
                expected_purpose=record.purpose,
                expected_environment=layout.environment,
            )
        except ValueError as error:
            raise EvidenceAuthenticationError(
                "operational key statement authentication failed",
                check_name="operational_key_statements",
            ) from error
    return keys


def _record(records: tuple[SignedRecordReference, ...], path: str) -> SignedRecordReference:
    matches = [record for record in records if record.path == path]
    if len(matches) != 1:
        raise BundleValidationError(f"bundle lacks one required signed record at {path}")
    return matches[0]


def _authenticate_record(
    parsed: ParsedRproofBundle,
    record: SignedRecordReference,
    key: AuthenticatedOperationalKey,
) -> None:
    if record.path == MANIFEST_PATH:
        payload = parsed.manifest_json
        compact = parsed.manifest_jws
    else:
        payload = parsed.components[record.path]
        compact = parsed.components[record.jws_path]
    try:
        authenticate_portable_record_signature(
            canonical_payload=payload,
            compact_jws=compact,
            schema_version=record.schema_version,
            operational_key=key,
        )
    except ValueError as error:
        raise EvidenceAuthenticationError(
            f"signature authentication failed for {record.path}",
            check_name=_record_check_name(record),
        ) from error


def _record_check_name(record: SignedRecordReference) -> str:
    if record.path == MANIFEST_PATH:
        return "bundle_signature"
    if record.schema_version in {
        "rproof.attestation.v1",
        "rproof.attestation.v2",
        "rproof.attestation.v3",
    }:
        return "attestation_signature"
    return "lifecycle"


def _record_signing_time(authenticated: AuthenticatedRproof, record: SignedRecordReference) -> str:
    if record.path == MANIFEST_PATH:
        return cast(str, authenticated.parsed.manifest["created_at"])
    if record.schema_version in {
        "rproof.attestation.v1",
        "rproof.attestation.v2",
        "rproof.attestation.v3",
    }:
        return authenticated.timestamp.token_gen_time
    time_fields = {
        "rproof.lifecycle-event.v1": "recorded_at",
        "rproof.review-completion.v1": "satisfied_at",
        "rproof.status-snapshot.v1": "generated_at",
    }
    field = time_fields.get(record.schema_version)
    if field is None:
        raise BundleUnsupportedError(
            "signed record has no supported signing-time policy",
            check_name=_record_check_name(record),
        )
    try:
        payload = json.loads(authenticated.parsed.components[record.path])
        signing_time = payload[field]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise BundleValidationError("signed record lacks its required signing time") from error
    if type(signing_time) is not str:
        raise BundleValidationError("signed record lacks its required signing time")
    return signing_time


def _authenticate_timestamp(
    parsed: ParsedRproofBundle,
    evidence: dict[str, object],
    tsa_policy: dict[str, object],
    environment: str,
) -> TimestampResult:
    try:
        response = parsed.components["evidence/timestamp/attestation.tsr"]
        result = validate_archived_timestamp_response(
            response,
            message_digest=bytes.fromhex(cast(str, evidence["message_imprint_sha256"])),
            nonce=timestamp_response_nonce(response),
            policy_oid=cast(str, evidence["policy_oid"]),
            provider=cast(str, evidence["provider"]),
            trust_roots_pem=b"".join(
                item.encode("ascii")
                for item in cast(list[str], tsa_policy["certificate_roots_pem"])
            ),
            intermediate_certificates_pem=parsed.components["evidence/timestamp/tsa-chain.pem"],
            development_only=environment != "production",
        )
        wrapper_time_matches = portable_utc_times_equal(
            result.token_gen_time, cast(str, evidence["token_gen_time"])
        )
    except (UnicodeEncodeError, ValueError) as error:
        raise EvidenceAuthenticationError(
            "archived RFC 3161 evidence is invalid", check_name="timestamp"
        ) from error
    if (
        result.provider != evidence["provider"]
        or result.policy_oid != evidence["policy_oid"]
        or not wrapper_time_matches
        or result.nonce_sha256.hex() != evidence["nonce_sha256"]
    ):
        raise EvidenceAuthenticationError(
            "authenticated timestamp differs from its wrapper", check_name="timestamp"
        )
    return result


def _require_authenticated_record_time(
    root: dict[str, object],
    key: AuthenticatedOperationalKey,
    record: SignedRecordReference,
    signing_time_text: str,
    signing_time: datetime,
    distrust_events: tuple[dict[str, object], ...],
    verified_at: datetime,
    parsed: ParsedRproofBundle,
) -> None:
    try:
        require_operational_key_valid_at(key, signing_time)
        _require_root_valid_at(root, signing_time)
    except ValueError as error:
        raise EvidenceAuthenticationError(
            f"signing authority was not valid for {record.path}",
            check_name="operational_key_statements",
        ) from error
    stem = f"trust/operational-key-statements/{record.kid}.json"
    statement_digest = sha256(parsed.components[stem]).hexdigest()
    for event in distrust_events:
        effective_at = _policy_time(cast(str, event["effective_at"]), "distrust effective_at")
        if effective_at > _datetime_time(verified_at):
            continue
        time_range = cast(dict[str, object], event["affected_signing_time_range"])
        starts_at = _policy_time(cast(str, time_range["from"]), "distrust range start")
        through_text = cast(str | None, time_range["through"])
        through = None if through_text is None else _policy_time(through_text, "distrust range end")
        signing = _authority_time(
            signing_time_text, "record signing time", "operational_key_statements"
        )
        if (
            event["affected_kid"] == record.kid
            and event["affected_key_statement_sha256"] == statement_digest
            and starts_at <= signing
            and (through is None or signing <= through)
        ):
            raise EvidenceAuthenticationError(
                f"signing key is distrusted for {record.path} at its authenticated time",
                check_name="operational_key_statements",
            )


def _require_root_valid_at(root: dict[str, object], signing_time: datetime) -> None:
    not_before = _policy_datetime(cast(str, root["not_before"]), "root not_before")
    not_after_text = cast(str | None, root["not_after"])
    not_after = (
        None if not_after_text is None else _policy_datetime(not_after_text, "root not_after")
    )
    moment = signing_time.astimezone(UTC)
    if (
        (not_after is not None and not_before >= not_after)
        or moment < not_before
        or (not_after is not None and moment >= not_after)
    ):
        raise VerifierPolicyError("external root is not valid at authenticated record time")


def _require_attestation_chronology(
    attestation: dict[str, object], token_time: str, manifest_time: str
) -> None:
    identity = cast(dict[str, object], attestation["identity_assurance"])
    assessed = _authority_time(
        cast(str, identity["assessed_at"]), "identity assessed_at", "attestation"
    )
    completed = _authority_time(
        cast(str, attestation["completed_at"]), "attestation completed_at", "attestation"
    )
    token = _authority_time(token_time, "timestamp generation time", "timestamp")
    created = _authority_time(manifest_time, "bundle creation time", "bundle_signature")
    if not assessed <= completed <= token <= created:
        raise EvidenceAuthenticationError(
            "authenticated attestation chronology is invalid", check_name="timestamp"
        )


def _authority_datetime(value: str, label: str, check_name: str) -> datetime:
    instant = _authority_time(value, label, check_name)
    return instant[0].replace(microsecond=instant[1] // 1000)


def _authority_time(value: str, label: str, check_name: str) -> tuple[datetime, int]:
    try:
        return parse_portable_utc_time(value)
    except TimestampValidationError:
        raise EvidenceAuthenticationError(
            f"{label} must use portable UTC time", check_name=check_name
        ) from None


def _policy_datetime(value: str, label: str) -> datetime:
    instant = _policy_time(value, label)
    return instant[0].replace(microsecond=instant[1] // 1000)


def _policy_time(value: str, label: str) -> tuple[datetime, int]:
    try:
        return parse_portable_utc_time(value)
    except TimestampValidationError:
        raise VerifierPolicyError(f"{label} is not valid portable UTC time") from None


def _datetime_time(value: datetime) -> tuple[datetime, int]:
    utc = value.astimezone(UTC)
    return utc.replace(microsecond=0), utc.microsecond * 1000
