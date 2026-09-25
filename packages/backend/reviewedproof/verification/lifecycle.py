"""Historical lifecycle and review-completion semantics for authenticated records."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, cast

from reviewedproof.verification.kernel import canonical_json_bytes, sha256_hex

_ADR0010_POLICY = "adr0010-2026-09-09"
_PRIVATE_REASON = re.compile(r"^private_reason_sha256:[0-9a-f]{64}$")
_REPLACEMENT_PURPOSE = re.compile(
    r"^replacement_review:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12} private_reason_sha256:[0-9a-f]{64}$"
)
_ADR0010_REVOKE_AUTHORITIES = frozenset({"reviewer_self_revocation", "org_admin_review_withdrawal"})
_ADR0010_SUPERSEDE_AUTHORITIES = frozenset(
    {"requester_review_supersession", "org_admin_review_supersession"}
)
_ADR0010_AUTHORITIES = _ADR0010_REVOKE_AUTHORITIES | _ADR0010_SUPERSEDE_AUTHORITIES

type LifecycleStatus = Literal[
    "valid",
    "valid_but_revoked",
    "superseded",
    "expired",
    "incomplete_proof",
    "invalid",
]


class LifecycleValidationError(ValueError):
    """An authenticated lifecycle or completion claim is inconsistent."""


@dataclass(frozen=True, slots=True)
class CarriedLifecycleEvent:
    """A schema-validated event and the exact authenticated JSON bytes carrying it."""

    payload: Mapping[str, object]
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class LifecycleEvaluation:
    """Status carried by a signed snapshot at its historical generation horizon."""

    status: LifecycleStatus
    generated_at: datetime
    next_update_due_at: datetime


def evaluate_lifecycle(
    *,
    attestation: Mapping[str, object],
    bundle_manifest: Mapping[str, object],
    status_snapshot: Mapping[str, object],
    events: Sequence[CarriedLifecycleEvent],
) -> LifecycleEvaluation:
    """Validate and evaluate already schema- and signature-verified lifecycle records.

    The caller must first validate canonical schemas, JWS signatures, operational-key
    authority and validity. This helper evaluates only the signed snapshot horizon;
    it makes no claim about status at the verifier's wall clock. Display-correction
    events do not alter the authoritative attestation or the returned status.
    """
    receipt_id = cast(str, attestation["receipt_id"])
    if bundle_manifest["receipt_id"] != receipt_id:
        raise LifecycleValidationError("bundle and attestation receipt identifiers differ")
    if status_snapshot["receipt_id"] != receipt_id:
        raise LifecycleValidationError("status and attestation receipt identifiers differ")

    completed_at = _utc(attestation["completed_at"])
    generated_at = _utc(status_snapshot["generated_at"])
    next_update = _utc(status_snapshot["next_update_due_at"])
    bundle_created_at = _utc(bundle_manifest["created_at"])
    if completed_at > generated_at or generated_at > bundle_created_at:
        raise LifecycleValidationError("receipt lifecycle chronology is inconsistent")
    if next_update <= generated_at:
        raise LifecycleValidationError("status next update must follow its generation time")

    event_ids: set[str] = set()
    effective_types: set[str] = set()
    previous_digest: str | None = None
    previous_recorded_at: datetime | None = None
    for expected_sequence, carried in enumerate(events, start=1):
        event = carried.payload
        if canonical_json_bytes(dict(event)) != carried.canonical_bytes:
            raise LifecycleValidationError("lifecycle event mapping differs from its exact bytes")
        if event["receipt_id"] != receipt_id:
            raise LifecycleValidationError(
                "lifecycle event and attestation receipt identifiers differ"
            )
        if event["sequence"] != expected_sequence:
            raise LifecycleValidationError("lifecycle event sequence is not contiguous")
        if event.get("previous_event_sha256") != previous_digest:
            raise LifecycleValidationError("lifecycle event digest chain is invalid")

        event_id = cast(str, event["event_id"])
        if event_id in event_ids:
            raise LifecycleValidationError("lifecycle event identifiers must be unique")
        event_ids.add(event_id)

        recorded_at = _utc(event["recorded_at"])
        if recorded_at < completed_at or recorded_at > generated_at:
            raise LifecycleValidationError("lifecycle event falls outside the snapshot chronology")
        if previous_recorded_at is not None and recorded_at < previous_recorded_at:
            raise LifecycleValidationError("lifecycle event recorded times must not decrease")
        previous_recorded_at = recorded_at

        event_type = cast(str, event["event_type"])
        _validate_event_authority(attestation=attestation, event=event)
        if event_type == "supersede" and event["replacement_receipt_id"] == receipt_id:
            raise LifecycleValidationError("a receipt cannot supersede itself")
        if _utc(event["effective_at"]) <= generated_at:
            effective_types.add(event_type)
        previous_digest = sha256_hex(carried.canonical_bytes)

    if status_snapshot.get("event_chain_head_sha256") != previous_digest:
        raise LifecycleValidationError("status snapshot does not bind the lifecycle chain head")

    declared = cast(LifecycleStatus, status_snapshot["status"])
    expires_at = _predefined_expiry(attestation)
    projected = _project_status(
        declared,
        effective_types,
        predefined_expired=expires_at is not None and generated_at >= expires_at,
    )
    if declared != projected:
        raise LifecycleValidationError(
            "signed status is inconsistent with effective lifecycle events"
        )
    return LifecycleEvaluation(
        status=projected,
        generated_at=generated_at,
        next_update_due_at=next_update,
    )


def validate_completion(
    *,
    attestation: Mapping[str, object],
    bundle_manifest: Mapping[str, object],
    completion: Mapping[str, object],
) -> None:
    """Validate one already schema- and signature-verified historical completion claim.

    The caller must verify completion-key validity at ``satisfied_at`` before calling.
    Linked receipts not carried by the bundle remain unverified, and this result says
    nothing about quorum after ``satisfied_at``.
    """
    attestation_receipt = cast(str, attestation["receipt_id"])
    if bundle_manifest["receipt_id"] != attestation_receipt:
        raise LifecycleValidationError("bundle and attestation receipt identifiers differ")
    if completion["review_id"] != attestation["review_id"]:
        raise LifecycleValidationError("completion and attestation review identifiers differ")

    satisfied_at = _utc(completion["satisfied_at"])
    if _utc(attestation["completed_at"]) > satisfied_at:
        raise LifecycleValidationError("completion predates its included attestation")
    expires_at = _predefined_expiry(attestation)
    if expires_at is not None and satisfied_at >= expires_at:
        raise LifecycleValidationError("completion includes an expired attestation")
    if satisfied_at > _utc(bundle_manifest["created_at"]):
        raise LifecycleValidationError("completion postdates bundle creation")

    policy = cast(Mapping[str, object], completion["policy_snapshot"])
    eligible = cast(list[Mapping[str, object]], policy["eligible_reviewers"])
    assignment_ids = [cast(str, reviewer["assignment_id"]) for reviewer in eligible]
    if len(set(assignment_ids)) != len(assignment_ids):
        raise LifecycleValidationError("eligible assignment identifiers must be unique")
    if assignment_ids != sorted(assignment_ids):
        raise LifecycleValidationError("eligible reviewers must be sorted by assignment identifier")
    eligible_by_id = dict(zip(assignment_ids, eligible, strict=True))

    required_roles = cast(list[str], policy["required_roles"])
    if required_roles != sorted(required_roles) or len(set(required_roles)) != len(required_roles):
        raise LifecycleValidationError("required roles must be unique and sorted")

    links = cast(list[Mapping[str, object]], completion["receipt_links"])
    link_assignments = [cast(str, link["assignment_id"]) for link in links]
    link_receipts = [cast(str, link["receipt_id"]) for link in links]
    link_attestations = [cast(str, link["attestation_id"]) for link in links]
    for values, label in (
        (link_assignments, "assignment"),
        (link_receipts, "receipt"),
        (link_attestations, "attestation"),
    ):
        if len(set(values)) != len(values):
            raise LifecycleValidationError(f"completion link {label} identifiers must be unique")

    if completion["receipt_id"] in link_receipts:
        raise LifecycleValidationError("completion receipt must differ from contributing receipts")

    for link in links:
        assignment_id = cast(str, link["assignment_id"])
        eligible_reviewer = eligible_by_id.get(assignment_id)
        if eligible_reviewer is None:
            raise LifecycleValidationError("completion link assignment is not eligible")
        if link.get("role_code") != eligible_reviewer.get("role_code"):
            raise LifecycleValidationError(
                "completion link role differs from the frozen eligible role"
            )

    exact_links = [
        link
        for link in links
        if link["receipt_id"] == attestation_receipt
        and link["attestation_id"] == attestation["attestation_id"]
    ]
    if len(exact_links) != 1:
        raise LifecycleValidationError("bundle attestation lacks one exact completion link")

    linked_assignments = set(link_assignments)
    required_assignments = {
        assignment_id
        for assignment_id, reviewer in eligible_by_id.items()
        if reviewer.get("required") is True
    }
    if not required_assignments <= linked_assignments:
        raise LifecycleValidationError("completion omits a required assignment")
    _validate_policy_satisfaction(
        policy=policy,
        eligible_by_id=eligible_by_id,
        links=links,
        required_roles=required_roles,
        required_assignments=required_assignments,
    )


def apply_predefined_expiry(
    *,
    attestation: Mapping[str, object],
    status: LifecycleStatus,
    evaluated_at: datetime,
) -> LifecycleStatus:
    """Apply authenticated predefined expiry at one clock time without changing stronger states."""
    if type(evaluated_at) is not datetime or evaluated_at.utcoffset() is None:
        raise LifecycleValidationError("expiry evaluation time must be timezone-aware")
    expires_at = _predefined_expiry(attestation)
    if status in {"invalid", "incomplete_proof", "valid_but_revoked", "superseded", "expired"}:
        return status
    if expires_at is not None and evaluated_at.astimezone(UTC) >= expires_at:
        return "expired"
    return status


def _validate_event_authority(
    *, attestation: Mapping[str, object], event: Mapping[str, object]
) -> None:
    authority = event.get("actor_authority")
    if not isinstance(authority, Mapping):
        return
    authority_type = authority.get("authority_type")
    policy_version = authority.get("policy_version")
    if authority_type not in _ADR0010_AUTHORITIES and policy_version != _ADR0010_POLICY:
        return
    event_type = event.get("event_type")
    allowed = (
        _ADR0010_REVOKE_AUTHORITIES
        if event_type == "revoke"
        else _ADR0010_SUPERSEDE_AUTHORITIES
        if event_type == "supersede"
        else frozenset()
    )
    if policy_version != _ADR0010_POLICY or authority_type not in allowed:
        raise LifecycleValidationError("lifecycle event authority vocabulary is invalid")
    actor = event.get("actor")
    if not isinstance(actor, Mapping) or actor.get("display_name") is not None:
        raise LifecycleValidationError("ADR 0010 lifecycle actor display name must be null")
    if _utc(event["effective_at"]) > _utc(event["recorded_at"]):
        raise LifecycleValidationError("ADR 0010 lifecycle event cannot postdate its record")

    review_id = attestation.get("review_id")
    reference = authority.get("authority_reference")
    if event_type == "revoke":
        explanation = event.get("explanation")
        if type(explanation) is not str or _PRIVATE_REASON.fullmatch(explanation) is None:
            raise LifecycleValidationError("ADR 0010 revocation must commit its private reason")
        if authority_type == "reviewer_self_revocation":
            reviewer = attestation.get("reviewer")
            if (
                reference != f"attestation_id:{attestation.get('attestation_id')}"
                or not isinstance(reviewer, Mapping)
                or actor.get("subject_id") != reviewer.get("subject_id")
            ):
                raise LifecycleValidationError(
                    "reviewer self-revocation authority does not bind the attestation"
                )
            return
    if reference != f"review_id:{review_id}":
        raise LifecycleValidationError("review lifecycle authority does not bind the source review")
    if event_type == "supersede":
        purpose = event.get("purpose")
        if type(purpose) is not str or _REPLACEMENT_PURPOSE.fullmatch(purpose) is None:
            raise LifecycleValidationError(
                "ADR 0010 supersession must bind the replacement review and private reason"
            )


def _project_status(
    declared: LifecycleStatus,
    event_types: set[str],
    *,
    predefined_expired: bool = False,
) -> LifecycleStatus:
    if declared == "invalid":
        return "invalid"
    if declared == "incomplete_proof":
        return "incomplete_proof"
    if "revoke" in event_types:
        return "valid_but_revoked"
    if "supersede" in event_types:
        return "superseded"
    if "expire" in event_types or predefined_expired:
        return "expired"
    return "valid"


def _predefined_expiry(attestation: Mapping[str, object]) -> datetime | None:
    schema_version = attestation.get("schema_version")
    if schema_version == "rproof.attestation.v1":
        return None
    if schema_version not in {"rproof.attestation.v2", "rproof.attestation.v3"}:
        raise LifecycleValidationError("attestation schema version is unsupported")
    expires_at_value = attestation.get("expires_at")
    if expires_at_value is None:
        if "expires_at" not in attestation:
            raise LifecycleValidationError("attestation lacks predefined expiry")
        return None
    expires_at = _utc(expires_at_value)
    if expires_at <= _utc(attestation["completed_at"]):
        raise LifecycleValidationError("attestation expiry must follow completion")
    return expires_at


def _validate_policy_satisfaction(
    policy: Mapping[str, object],
    eligible_by_id: Mapping[str, Mapping[str, object]],
    links: Sequence[Mapping[str, object]],
    required_roles: list[str],
    required_assignments: set[str],
) -> None:
    policy_type = policy["type"]
    threshold = policy.get("threshold")
    if policy_type == "threshold":
        if type(threshold) is not int or not 1 <= threshold <= len(eligible_by_id):
            raise LifecycleValidationError("threshold policy has an invalid threshold")
        if required_roles or len(links) < threshold:
            raise LifecycleValidationError("threshold policy is not satisfied")
        return
    if threshold is not None:
        raise LifecycleValidationError("non-threshold policy must not carry a threshold")

    if policy_type == "all_required":
        if required_roles or not required_assignments:
            raise LifecycleValidationError("all-required policy shape is invalid")
        return
    if policy_type == "any_reviewer":
        if required_roles or required_assignments or not links:
            raise LifecycleValidationError("any-reviewer policy shape is invalid")
        return
    if policy_type == "role_quorum":
        if not required_roles:
            raise LifecycleValidationError("role-quorum policy must name required roles")
        eligible_roles = {reviewer.get("role_code") for reviewer in eligible_by_id.values()}
        linked_roles = {link.get("role_code") for link in links}
        if not set(required_roles) <= eligible_roles or not set(required_roles) <= linked_roles:
            raise LifecycleValidationError("role-quorum policy is not satisfied")
        return
    raise LifecycleValidationError("completion policy type is unsupported")


def _utc(value: object) -> datetime:
    """Parse a schema-validated exact-UTC whole-second timestamp."""
    return datetime.strptime(cast(str, value), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
