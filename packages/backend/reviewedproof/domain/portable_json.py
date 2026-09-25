"""Bounded semantic preflight for portable JSON objects."""

from __future__ import annotations

from typing import cast

from reviewedproof.verification.kernel import canonical_json_bytes

_MAX_DEPTH = 32
_MAX_NODES = 10_000
_MAX_CONTAINER_ITEMS = 100
_MAX_KEY_LENGTH = 200
_MAX_STRING_LENGTH = 10_000


def validate_portable_json_object(value: object) -> None:
    """Reject values outside the bounded CanonicalJsonObject contract."""
    if type(value) is not dict:
        raise ValueError("portable JSON root must be an object")

    stack: list[tuple[object, int]] = [(value, 1)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_NODES:
            raise ValueError("portable JSON exceeds 10000 nodes")
        if depth > _MAX_DEPTH:
            raise ValueError("portable JSON exceeds depth 32")

        current_type = type(current)
        if current is None or current_type in (bool, int):
            continue
        if current_type is str:
            if len(cast(str, current)) > _MAX_STRING_LENGTH:
                raise ValueError("portable JSON string exceeds 10000 characters")
            continue
        if current_type not in (list, dict):
            raise ValueError("portable JSON contains an unsupported value")

        if current_type is list:
            items = cast(list[object], current)
            if len(items) > _MAX_CONTAINER_ITEMS:
                raise ValueError("portable JSON array exceeds 100 items")
            stack.extend((item, depth + 1) for item in reversed(items))
            continue

        mapping = cast(dict[object, object], current)
        if len(mapping) > _MAX_CONTAINER_ITEMS:
            raise ValueError("portable JSON object exceeds 100 properties")
        for key in mapping:
            if type(key) is not str or not 1 <= len(key) <= _MAX_KEY_LENGTH:
                raise ValueError("portable JSON keys must contain 1 to 200 characters")
        stack.extend((item, depth + 1) for item in reversed(tuple(mapping.values())))

    # The shared kernel supplies the NFC, safe-integer and no-float rules.
    canonical_json_bytes(value)
