"""Optional local artefact matching against an authenticated package manifest."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, cast

from reviewedproof.verification.kernel import package_root, sha256_hex

_MAX_ARTEFACTS = 100
_MAX_TOTAL_BYTES = 200_000_000

type ArtefactCheck = dict[str, str]
type ArtefactMatchState = Literal["valid", "invalid", "not_checked"]


@dataclass(frozen=True, slots=True)
class ArtefactInput:
    """Exact local bytes with an optional explicit manifest entry assignment."""

    content: bytes
    entry_id: str | None = None


def match_artefacts(
    package: Mapping[str, object], artefacts: Sequence[ArtefactInput]
) -> tuple[ArtefactCheck, tuple[str, ...]]:
    """Match local bytes to an already authenticated, schema-validated package.

    Local file names and selection order have no meaning. The caller separately
    preserves receipt-integrity results even when this optional comparison fails.
    """
    entries = sorted(
        cast(list[Mapping[str, object]], package["entries"]),
        key=lambda entry: cast(int, entry["position"]),
    )
    if not artefacts:
        return _check("not_checked", "no_artefacts_selected"), ()
    if len(artefacts) > _MAX_ARTEFACTS:
        return _check("invalid", "too_many_artefacts_selected"), ()
    if sum(len(artefact.content) for artefact in artefacts) > _MAX_TOTAL_BYTES:
        return _check("invalid", "artefact_selection_too_large"), ()

    entries_by_id = {cast(str, entry["entry_id"]): entry for entry in entries}
    candidates_by_content: dict[tuple[str, int], list[Mapping[str, object]]] = {}
    for entry in entries:
        content_hash = cast(Mapping[str, object], entry["content_hash"])
        key = (cast(str, content_hash["value"]), cast(int, entry["byte_length"]))
        candidates_by_content.setdefault(key, []).append(entry)

    prepared = [
        (artefact, sha256_hex(artefact.content), len(artefact.content)) for artefact in artefacts
    ]
    assigned: dict[str, tuple[ArtefactInput, str]] = {}
    invalid_reasons: set[str] = set()
    ambiguous = False

    for artefact, digest, byte_length in prepared:
        if artefact.entry_id is None:
            continue
        explicit_entry = entries_by_id.get(artefact.entry_id)
        if explicit_entry is None:
            invalid_reasons.add("unknown_artefact_entry")
            continue
        if artefact.entry_id in assigned:
            invalid_reasons.add("duplicate_artefact_assignment")
            continue
        if not _matches(explicit_entry, digest, byte_length):
            invalid_reasons.add("artefact_content_mismatch")
            continue
        assigned[artefact.entry_id] = (artefact, digest)

    for artefact, digest, byte_length in prepared:
        if artefact.entry_id is not None:
            continue
        candidates = candidates_by_content.get((digest, byte_length), [])
        if not candidates:
            invalid_reasons.add("artefact_content_mismatch")
            continue
        candidate_ids = [
            cast(str, entry["entry_id"])
            for entry in candidates
            if cast(str, entry["entry_id"]) not in assigned
        ]
        if not candidate_ids:
            invalid_reasons.add("duplicate_artefact_assignment")
            continue
        if len(candidate_ids) > 1:
            ambiguous = True
            continue
        entry_id = candidate_ids[0]
        assigned[entry_id] = (artefact, digest)

    matched_ids = tuple(
        cast(str, entry["entry_id"])
        for entry in entries
        if cast(str, entry["entry_id"]) in assigned
    )
    if invalid_reasons:
        reason = next(
            reason
            for reason in (
                "unknown_artefact_entry",
                "duplicate_artefact_assignment",
                "artefact_content_mismatch",
            )
            if reason in invalid_reasons
        )
        return _check("invalid", reason), matched_ids
    if ambiguous:
        return _check("not_checked", "ambiguous_artefact_assignment"), matched_ids
    if len(assigned) != len(entries):
        return _check("not_checked", "partial_artefact_selection"), matched_ids

    rebuilt_entries: list[dict[str, object]] = []
    for entry in entries:
        entry_id = cast(str, entry["entry_id"])
        artefact, digest = assigned[entry_id]
        rebuilt_entries.append(
            {
                **entry,
                "byte_length": len(artefact.content),
                "content_hash": {"algorithm": "sha-256", "value": digest},
            }
        )
    if package_root(rebuilt_entries) != package["package_root"]:
        return _check("invalid", "artefact_package_root_mismatch"), matched_ids
    return _check("valid", "artefacts_match_package"), matched_ids


def _matches(entry: Mapping[str, object], digest: str, byte_length: int) -> bool:
    content_hash = cast(Mapping[str, object], entry["content_hash"])
    return entry["byte_length"] == byte_length and content_hash["value"] == digest


def _check(state: ArtefactMatchState, reason_code: str) -> ArtefactCheck:
    return {"reason_code": reason_code, "state": state}
