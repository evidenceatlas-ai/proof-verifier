"""Pure canonicalisation, hashing, package-tree, and fingerprint primitives."""

from __future__ import annotations

import base64
import hmac
import re
import unicodedata
from collections.abc import Mapping, Sequence
from hashlib import sha256 as _sha256
from typing import Literal, TypedDict, cast

import rfc8785

type JsonValue = None | bool | int | str | list["JsonValue"] | dict[str, "JsonValue"]
type JsonObject = dict[str, JsonValue]

_JSON_SAFE_INTEGER = 9_007_199_254_740_991
_MAX_PACKAGE_ENTRIES = 100
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_BASE64URL_P256_COORDINATE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_ENTRY_FIELDS = frozenset(
    {
        "byte_length",
        "content_hash",
        "entry_id",
        "media_type",
        "name",
        "position",
        "required",
    }
)


class AuditNode(TypedDict):
    """One sibling in a package inclusion path."""

    hash: str
    side: Literal["left", "right"]


class PackageInclusionProof(TypedDict):
    """Portable package inclusion-proof shape."""

    audit_path: list[AuditNode]
    leaf_index: int
    schema_version: Literal["rproof.package-inclusion-proof.v1"]
    tree_size: int


def canonical_json_bytes(value: object) -> bytes:
    """Return RFC 8785 UTF-8 bytes after ReviewedProof JSON input checks."""
    _validate_json_value(value, set())
    return rfc8785.dumps(cast(JsonValue, value))


def sha256_bytes(data: bytes) -> bytes:
    """Hash exact input bytes without decoding or normalisation."""
    if type(data) is not bytes:
        raise ValueError("SHA-256 input must be bytes")
    return _sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Hash exact input bytes as lowercase hexadecimal."""
    return sha256_bytes(data).hex()


def canonical_sha256_hex(value: object) -> str:
    """Hash the RFC 8785 bytes of a JSON value."""
    return sha256_hex(canonical_json_bytes(value))


def package_entry_leaf_hash(entry: Mapping[str, object]) -> str:
    """Hash one validated package entry with the RFC 6962 leaf prefix."""
    validated = _validate_entry(entry)
    return _leaf_hash(canonical_json_bytes(validated)).hex()


def package_root(entries: Sequence[Mapping[str, object]]) -> str:
    """Calculate a package root after ordering entries by explicit position."""
    canonical_entries = _ordered_canonical_entries(entries)
    return _merkle_tree_hash(canonical_entries).hex()


def package_manifest_digest(manifest: Mapping[str, object]) -> str:
    """Hash exact supplied JSON; caller validates manifest schema and bindings."""
    return canonical_sha256_hex(manifest)


def create_package_inclusion_proof(
    entries: Sequence[Mapping[str, object]], leaf_index: int
) -> PackageInclusionProof:
    """Create a bottom-up RFC 6962 proof for a position-ordered package."""
    canonical_entries = _ordered_canonical_entries(entries)
    if type(leaf_index) is not int or not 0 <= leaf_index < len(canonical_entries):
        raise ValueError("leaf_index must identify an entry")

    return {
        "audit_path": _inclusion_path(canonical_entries, leaf_index),
        "leaf_index": leaf_index,
        "schema_version": "rproof.package-inclusion-proof.v1",
        "tree_size": len(canonical_entries),
    }


def verify_package_inclusion_proof(
    entry: Mapping[str, object],
    proof: Mapping[str, object],
    expected_root: str,
    expected_tree_size: int,
) -> bool:
    """Verify against root and entry count supplied by a trusted manifest."""
    try:
        validated_entry = _validate_entry(entry)
        if set(proof) != {"audit_path", "leaf_index", "schema_version", "tree_size"}:
            return False
        if proof["schema_version"] != "rproof.package-inclusion-proof.v1":
            return False

        leaf_index = proof["leaf_index"]
        tree_size = proof["tree_size"]
        if type(leaf_index) is not int or type(tree_size) is not int:
            return False
        if not 1 <= tree_size <= _MAX_PACKAGE_ENTRIES or not 0 <= leaf_index < tree_size:
            return False
        if type(expected_tree_size) is not int or tree_size != expected_tree_size:
            return False
        if validated_entry["position"] != leaf_index:
            return False
        if type(expected_root) is not str or _SHA256_HEX.fullmatch(expected_root) is None:
            return False

        audit_path = proof["audit_path"]
        if type(audit_path) is not list:
            return False
        expected_sides = _inclusion_sides(leaf_index, tree_size)
        if len(audit_path) != len(expected_sides):
            return False

        current = _leaf_hash(canonical_json_bytes(validated_entry))
        for raw_node, expected_side in zip(audit_path, expected_sides, strict=True):
            if type(raw_node) is not dict or set(raw_node) != {"hash", "side"}:
                return False
            sibling_hex = raw_node["hash"]
            side = raw_node["side"]
            if (
                type(sibling_hex) is not str
                or _SHA256_HEX.fullmatch(sibling_hex) is None
                or side != expected_side
            ):
                return False
            sibling = bytes.fromhex(sibling_hex)
            current = (
                _node_hash(sibling, current) if side == "left" else _node_hash(current, sibling)
            )

        return hmac.compare_digest(current.hex(), expected_root)
    except (KeyError, TypeError, ValueError):
        return False


def p256_fingerprint_sha256(jwk: Mapping[str, object]) -> str:
    """Calculate ReviewedProof's RFC 7638-derived P-256 fingerprint."""
    projected: JsonObject = {}
    for field in ("crv", "kty", "x", "y"):
        value = jwk.get(field)
        if type(value) is not str:
            raise ValueError(f"P-256 JWK {field} must be a string")
        projected[field] = value

    if projected["crv"] != "P-256" or projected["kty"] != "EC":
        raise ValueError("unsupported JWK key type or curve")
    for field in ("x", "y"):
        value = cast(str, projected[field])
        if _BASE64URL_P256_COORDINATE.fullmatch(value) is None:
            raise ValueError(f"P-256 JWK {field} must be an unpadded 32-byte base64url value")
        decoded = base64.urlsafe_b64decode(value + "=")
        encoded = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
        if len(decoded) != 32 or encoded != value:
            raise ValueError(f"P-256 JWK {field} must use canonical base64url encoding")

    return canonical_sha256_hex(projected)


def _validate_json_value(value: object, active_containers: set[int]) -> None:
    value_type = type(value)
    if value is None or value_type is bool:
        return
    if value_type is int:
        integer = cast(int, value)
        if not -_JSON_SAFE_INTEGER <= integer <= _JSON_SAFE_INTEGER:
            raise ValueError("JSON integers must be exactly representable in both runtimes")
        return
    if value_type is str:
        if not unicodedata.is_normalized("NFC", cast(str, value)):
            raise ValueError("JSON strings and object keys must use Unicode NFC")
        return
    if value_type not in (list, dict):
        raise ValueError(
            "canonical JSON accepts only null, booleans, integers, strings, arrays, and objects"
        )

    identity = id(value)
    if identity in active_containers:
        raise ValueError("canonical JSON cannot contain cycles")
    active_containers.add(identity)
    try:
        if value_type is list:
            for child in cast(list[object], value):
                _validate_json_value(child, active_containers)
            return

        for key, child in cast(dict[object, object], value).items():
            if type(key) is not str:
                raise ValueError("JSON object keys must be strings")
            _validate_json_value(key, active_containers)
            _validate_json_value(child, active_containers)
    finally:
        active_containers.remove(identity)


def _validate_entry(entry: Mapping[str, object]) -> JsonObject:
    if type(entry) is not dict or set(entry) != _ENTRY_FIELDS:
        raise ValueError("package entry fields must match rproof.package-manifest.v1 exactly")
    _validate_json_value(entry, set())
    value = cast(dict[str, object], entry)

    byte_length = value["byte_length"]
    position = value["position"]
    required = value["required"]
    if type(byte_length) is not int or byte_length < 0:
        raise ValueError("package entry byte_length must be a non-negative integer")
    if type(position) is not int or position < 0:
        raise ValueError("package entry position must be a non-negative integer")
    if type(required) is not bool:
        raise ValueError("package entry required must be a boolean")

    for field in ("entry_id", "media_type"):
        scalar = value[field]
        if type(scalar) is not str or not scalar:
            raise ValueError(f"package entry {field} must be a non-empty string")
    name = value["name"]
    if name is not None and (type(name) is not str or not name):
        raise ValueError("package entry name must be a non-empty string or explicit null")

    content_hash = value["content_hash"]
    if type(content_hash) is not dict or set(content_hash) != {"algorithm", "value"}:
        raise ValueError("package entry content_hash fields are invalid")
    digest = cast(dict[str, object], content_hash)
    if digest["algorithm"] != "sha-256":
        raise ValueError("unsupported package content hash algorithm")
    digest_value = digest["value"]
    if type(digest_value) is not str or _SHA256_HEX.fullmatch(digest_value) is None:
        raise ValueError("package content hash must be 64 lowercase hexadecimal characters")

    return cast(JsonObject, value)


def _ordered_canonical_entries(entries: Sequence[Mapping[str, object]]) -> list[bytes]:
    if not 1 <= len(entries) <= _MAX_PACKAGE_ENTRIES:
        raise ValueError("package must contain between 1 and 100 entries")
    validated = [_validate_entry(entry) for entry in entries]
    ordered = sorted(validated, key=lambda entry: cast(int, entry["position"]))
    if [entry["position"] for entry in ordered] != list(range(len(ordered))):
        raise ValueError("package positions must be unique and consecutive from zero")
    return [canonical_json_bytes(entry) for entry in ordered]


def _leaf_hash(canonical_entry: bytes) -> bytes:
    return sha256_bytes(b"\x00" + canonical_entry)


def _node_hash(left: bytes, right: bytes) -> bytes:
    return sha256_bytes(b"\x01" + left + right)


def _largest_power_of_two_below(size: int) -> int:
    return 1 << ((size - 1).bit_length() - 1)


def _merkle_tree_hash(canonical_entries: Sequence[bytes]) -> bytes:
    if not canonical_entries:
        return sha256_bytes(b"")
    if len(canonical_entries) == 1:
        return _leaf_hash(canonical_entries[0])
    split = _largest_power_of_two_below(len(canonical_entries))
    return _node_hash(
        _merkle_tree_hash(canonical_entries[:split]),
        _merkle_tree_hash(canonical_entries[split:]),
    )


def _inclusion_path(canonical_entries: Sequence[bytes], leaf_index: int) -> list[AuditNode]:
    if len(canonical_entries) == 1:
        return []
    split = _largest_power_of_two_below(len(canonical_entries))
    if leaf_index < split:
        return _inclusion_path(canonical_entries[:split], leaf_index) + [
            {"hash": _merkle_tree_hash(canonical_entries[split:]).hex(), "side": "right"}
        ]
    return _inclusion_path(canonical_entries[split:], leaf_index - split) + [
        {"hash": _merkle_tree_hash(canonical_entries[:split]).hex(), "side": "left"}
    ]


def _inclusion_sides(leaf_index: int, tree_size: int) -> list[Literal["left", "right"]]:
    if tree_size == 1:
        return []
    split = _largest_power_of_two_below(tree_size)
    if leaf_index < split:
        return _inclusion_sides(leaf_index, split) + ["right"]
    return _inclusion_sides(leaf_index - split, tree_size - split) + ["left"]
