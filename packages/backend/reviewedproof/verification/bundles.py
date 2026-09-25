"""Bounded in-memory reader for supported ReviewedProof evidence bundles."""

from __future__ import annotations

import hmac
import io
import json
import re
import stat
import struct
import unicodedata
import zipfile
import zlib
from dataclasses import dataclass
from hashlib import sha256
from importlib import resources
from pathlib import Path
from typing import cast

from asn1crypto import cms, tsp  # type: ignore[import-untyped]
from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from jsonschema.exceptions import ValidationError  # type: ignore[import-untyped]
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012
from reviewedproof.verification.kernel import (
    canonical_json_bytes,
    p256_fingerprint_sha256,
    package_root,
)
from reviewedproof.verification.signing import decode_base64url
from reviewedproof.verification.timestamp import (
    format_generalized_time,
    portable_utc_times_equal,
)

MAX_ARCHIVE_BYTES = 20 * 1024 * 1024
MAX_COMPONENT_BYTES = 10 * 1024 * 1024
MAX_EXPANDED_BYTES = 50 * 1024 * 1024
MAX_COMPRESSION_RATIO = 100
MAX_ARCHIVE_MEMBERS = 502
MAX_PACKAGE_BYTES = 200_000_000
_READ_CHUNK = 1024 * 1024
_EOCD = b"PK\x05\x06"
_ZIP64_EXTRA = 0x0001
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_KID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_EVENT_JSON = re.compile(r"^evidence/lifecycle/events/([0-9]{4})\.json$")
_STATEMENT = re.compile(
    r"^trust/operational-key-statements/([A-Za-z0-9][A-Za-z0-9._-]{0,127})\.(json|jws)$"
)

MANIFEST_PATH = "META-INF/bundle-manifest.json"
MANIFEST_JWS_PATH = "META-INF/bundle-manifest.jws"
BUNDLE_README = (
    b"ReviewedProof portable evidence bundle.\n"
    b"Signed JSON is authoritative; the PDF is presentation only.\n"
    b"Reviewed artefact bytes are not included. Distribute them separately.\n"
)
_COMMON_BUNDLE_SCHEMA_NAMES = frozenset(
    {
        "common.v1.schema.json",
        "operational-key-statement.v1.schema.json",
        "package-manifest.v1.schema.json",
        "status-snapshot.v1.schema.json",
        "timestamp-evidence.v1.schema.json",
    }
)


@dataclass(frozen=True, slots=True)
class _BundleProfile:
    manifest_schema_name: str
    attestation_schema_version: str
    attestation_schema_name: str
    protected_header_schema_name: str


_BUNDLE_PROFILES = {
    "rproof.bundle-manifest.v1": _BundleProfile(
        manifest_schema_name="bundle-manifest.v1.schema.json",
        attestation_schema_version="rproof.attestation.v1",
        attestation_schema_name="attestation.v1.schema.json",
        protected_header_schema_name="jws-protected-header.v1.schema.json",
    ),
    "rproof.bundle-manifest.v2": _BundleProfile(
        manifest_schema_name="bundle-manifest.v2.schema.json",
        attestation_schema_version="rproof.attestation.v2",
        attestation_schema_name="attestation.v2.schema.json",
        protected_header_schema_name="jws-protected-header.v2.schema.json",
    ),
    "rproof.bundle-manifest.v3": _BundleProfile(
        manifest_schema_name="bundle-manifest.v3.schema.json",
        attestation_schema_version="rproof.attestation.v3",
        attestation_schema_name="attestation.v3.schema.json",
        protected_header_schema_name="jws-protected-header.v3.schema.json",
    ),
}
_SUPPORTED_ATTESTATION_SCHEMA_VERSIONS = frozenset(
    profile.attestation_schema_version for profile in _BUNDLE_PROFILES.values()
)
_BASE_PATHS = frozenset(
    {
        "README.txt",
        "evidence/lifecycle/status-snapshot.json",
        "evidence/lifecycle/status-snapshot.jws",
        "evidence/timestamp/attestation.tsr",
        "evidence/timestamp/evidence.json",
        "evidence/timestamp/tsa-chain.pem",
        "package/manifest.json",
        "receipt/attestation.json",
        "receipt/attestation.jws",
        "receipt/human-receipt.pdf",
        "trust/root-fingerprint.txt",
        "trust/root-public-key.jwk",
    }
)
_RECORD_PROFILES = {
    "evidence/lifecycle/status-snapshot.json": (
        "rproof.status-snapshot.v1",
        "lifecycle-status-signing",
    ),
    "review/completion.json": ("rproof.review-completion.v1", "lifecycle-status-signing"),
}
_SUPPORTED_SIGNED_SCHEMA_VERSIONS = frozenset(
    {
        *_BUNDLE_PROFILES,
        *_SUPPORTED_ATTESTATION_SCHEMA_VERSIONS,
        "rproof.lifecycle-event.v1",
        "rproof.operational-key-statement.v1",
        "rproof.review-completion.v1",
        "rproof.status-snapshot.v1",
    }
)
_MEDIA_TYPES = {
    "README.txt": "text/plain; charset=utf-8",
    "evidence/timestamp/attestation.tsr": "application/timestamp-reply",
    "evidence/timestamp/tsa-chain.pem": "application/pem-certificate-chain",
    "receipt/human-receipt.pdf": "application/pdf",
    "trust/root-fingerprint.txt": "text/plain; charset=utf-8",
}


def load_bundle_schemas(
    *,
    bundle_version: str | None = None,
    include_lifecycle_events: bool = False,
    include_review_completion: bool = False,
) -> dict[str, bytes]:
    """Load exact schemas for one bundle profile, or all profiles for verification."""
    if bundle_version is None:
        names = set().union(*(bundle_schema_names(version) for version in _BUNDLE_PROFILES))
    else:
        names = set(bundle_schema_names(bundle_version))
    if include_lifecycle_events:
        names.add("lifecycle-event.v1.schema.json")
    if include_review_completion:
        names.add("review-completion.v1.schema.json")
    return _load_schema_files(names)


def bundle_schema_names(bundle_version: str) -> frozenset[str]:
    """Return the exact base schema set carried by one supported bundle profile."""
    try:
        profile = _BUNDLE_PROFILES[bundle_version]
    except KeyError:
        raise ValueError("bundle manifest schema version is unsupported") from None
    return _COMMON_BUNDLE_SCHEMA_NAMES | frozenset(
        {
            profile.manifest_schema_name,
            profile.attestation_schema_name,
            profile.protected_header_schema_name,
        }
    )


def load_verifier_policy_schemas() -> dict[str, bytes]:
    """Load the schemas needed to validate external verifier trust policy."""
    return _load_schema_files(
        {"common.v1.schema.json", "key-distrust-event.v1.schema.json", "trust-store.v1.schema.json"}
    )


def load_verification_result_schemas() -> dict[str, bytes]:
    """Load the schemas needed to validate one exported verification result."""
    return _load_schema_files({"common.v1.schema.json", "verification-result.v1.schema.json"})


def _load_schema_files(names: set[str]) -> dict[str, bytes]:
    loaded: dict[str, bytes] = {}
    for name in sorted(names):
        packaged = resources.files("reviewedproof").joinpath("_schemas", name)
        try:
            loaded[name] = packaged.read_bytes()
        except FileNotFoundError:
            source = Path(__file__).resolve().parents[4] / "documentation" / "schemas" / name
            loaded[name] = source.read_bytes()
    return loaded


class BundleSafetyError(ValueError):
    """ZIP container is unsafe or exceeds the v1 resource limits."""

    check_name = "archive_safety"


class BundleValidationError(ValueError):
    """Safe ZIP bytes do not form one coherent ReviewedProof bundle."""

    check_name = "bundle_manifest"

    def __init__(self, message: str, *, check_name: str | None = None) -> None:
        super().__init__(message)
        if check_name is not None:
            self.check_name = check_name


class BundleIncompleteError(BundleValidationError):
    """Safe bundle lacks evidence required by its supported profile."""


class BundleUnsupportedError(BundleValidationError):
    """Safe bundle declares a critical version or component this verifier cannot process."""


@dataclass(frozen=True, slots=True)
class ParsedRproofBundle:
    """Exact bounded bytes selected from one validated archive."""

    manifest: dict[str, object]
    manifest_json: bytes
    manifest_jws: bytes
    components: dict[str, bytes]
    bundle_version: str = "rproof.bundle-manifest.v1"


@dataclass(frozen=True, slots=True)
class SignedRecordReference:
    """One carried signed record and its fixed signing purpose."""

    path: str
    jws_path: str
    schema_version: str
    purpose: str
    kid: str


@dataclass(frozen=True, slots=True)
class OperationalKeyLayout:
    """Untrusted bundle convenience material selected for later authentication."""

    root_jwk: dict[str, object]
    root_fingerprint_sha256: str
    root_kid: str
    environment: str


@dataclass(frozen=True, slots=True)
class CanonicalLifecycleRecords:
    """Canonical, schema-valid lifecycle mappings carried by one bundle."""

    status_snapshot: dict[str, object]
    events: tuple[dict[str, object], ...]
    completion: dict[str, object] | None


def parse_rproof_bundle(
    archive_bytes: bytes, *, canonical_schema_files: dict[str, bytes]
) -> ParsedRproofBundle:
    """Read and validate one supported archive without filesystem extraction."""
    if type(archive_bytes) is not bytes or not archive_bytes:
        raise BundleSafetyError("bundle must be non-empty bytes")
    if len(archive_bytes) > MAX_ARCHIVE_BYTES:
        raise BundleSafetyError("bundle exceeds 20 MiB compressed limit")
    expected_entries = _central_directory_entry_count(archive_bytes)
    if expected_entries > MAX_ARCHIVE_MEMBERS:
        raise BundleSafetyError("bundle contains too many members")

    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            if archive.comment:
                raise BundleSafetyError("bundle ZIP comment is not supported")
            infos = archive.infolist()
            if len(infos) != expected_entries:
                raise BundleSafetyError("bundle central-directory count is inconsistent")
            components = _read_members(archive, infos)
    except BundleSafetyError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile, zlib.error) as error:
        raise BundleSafetyError("bundle is not a readable single-disk ZIP") from error

    if MANIFEST_PATH not in components or MANIFEST_JWS_PATH not in components:
        raise BundleIncompleteError("bundle manifest JSON/JWS pair is required")
    manifest_json = components.pop(MANIFEST_PATH)
    manifest_jws = components.pop(MANIFEST_JWS_PATH)
    bundle_version = _manifest_bundle_version(manifest_json)
    profile = _BUNDLE_PROFILES[bundle_version]
    required_schema_names = bundle_schema_names(bundle_version)
    if not set(canonical_schema_files) >= required_schema_names:
        raise BundleValidationError("canonical schema input lacks required bundle schemas")
    schemas = _schema_validators(canonical_schema_files)
    manifest = _canonical_record(
        manifest_json, schemas[profile.manifest_schema_name], "bundle manifest"
    )
    descriptors = manifest.get("components")
    if type(descriptors) is not list:
        raise BundleValidationError("bundle manifest components must be an array")
    paths = [item.get("path") if type(item) is dict else None for item in descriptors]
    if paths != sorted(paths, key=lambda item: cast(str, item)) or any(
        type(path) is not str for path in paths
    ):
        raise BundleValidationError("bundle manifest components must be path-sorted")
    if len(paths) != len(set(paths)) or set(paths) != set(components):
        raise BundleValidationError("bundle manifest must declare every component exactly once")
    for descriptor in descriptors:
        item = cast(dict[str, object], descriptor)
        path = cast(str, item["path"])
        content = components[path]
        if item["byte_length"] != len(content) or item["sha256"] != sha256(content).hexdigest():
            raise BundleValidationError(f"bundle manifest binding failed for {path}")
        if item["media_type"] != bundle_component_media_type(path):
            raise BundleValidationError(f"bundle manifest media type failed for {path}")

    _validate_component_layout(components, canonical_schema_files, bundle_version=bundle_version)
    return ParsedRproofBundle(
        manifest=manifest,
        manifest_json=manifest_json,
        manifest_jws=manifest_jws,
        components=components,
        bundle_version=bundle_version,
    )


def _central_directory_entry_count(data: bytes) -> int:
    offset = data.rfind(_EOCD, max(0, len(data) - 65_557))
    if offset < 0 or offset + 22 > len(data):
        raise BundleSafetyError("bundle has no valid ZIP end record")
    end_record = struct.unpack_from("<HHHHIIH", data, offset + 4)
    disk, central_disk, disk_entries, total_entries, size, start, comment_length = end_record
    if offset + 22 + comment_length != len(data):
        raise BundleSafetyError("bundle ZIP end record is ambiguous")
    if disk != 0 or central_disk != 0 or disk_entries != total_entries:
        raise BundleSafetyError("split ZIP bundles are not supported")
    if 0xFFFF in (disk_entries, total_entries) or 0xFFFFFFFF in (size, start):
        raise BundleSafetyError("Zip64 bundles are not supported")
    if offset >= 20 and data[offset - 20 : offset - 16] == b"PK\x06\x07":
        raise BundleSafetyError("Zip64 bundles are not supported")
    central_end = start + size
    if central_end != offset or central_end > len(data):
        raise BundleSafetyError("bundle central-directory bounds are inconsistent")
    cursor = start
    scanned_entries = 0
    while cursor < central_end:
        if scanned_entries >= MAX_ARCHIVE_MEMBERS or cursor + 46 > central_end:
            raise BundleSafetyError("bundle contains too many or malformed members")
        if data[cursor : cursor + 4] != b"PK\x01\x02":
            raise BundleSafetyError("bundle central directory is malformed")
        name_length, extra_length, member_comment_length = struct.unpack_from(
            "<HHH", data, cursor + 28
        )
        cursor += 46 + name_length + extra_length + member_comment_length
        scanned_entries += 1
    if cursor != central_end or scanned_entries != total_entries:
        raise BundleSafetyError("bundle central-directory count is inconsistent")
    return scanned_entries


def _read_members(archive: zipfile.ZipFile, infos: list[zipfile.ZipInfo]) -> dict[str, bytes]:
    seen: set[str] = set()
    seen_casefolded: set[str] = set()
    declared_total = 0
    for info in infos:
        path = info.orig_filename
        _validate_path(path)
        folded = path.casefold()
        if path in seen:
            raise BundleSafetyError("bundle contains duplicate paths")
        if folded in seen_casefolded:
            raise BundleSafetyError("bundle contains case-colliding paths")
        seen.add(path)
        seen_casefolded.add(folded)
        if info.is_dir():
            raise BundleSafetyError("bundle directories are not members")
        if info.flag_bits & 1:
            raise BundleSafetyError("encrypted bundle members are not supported")
        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise BundleSafetyError("bundle member uses unsupported compression")
        if _has_zip64_extra(info.extra):
            raise BundleSafetyError("Zip64 bundle members are not supported")
        mode = info.external_attr >> 16
        file_type = stat.S_IFMT(mode)
        if file_type not in (0, stat.S_IFREG) or mode & 0o111:
            raise BundleSafetyError("bundle members must be non-executable regular files")
        if info.file_size > MAX_COMPONENT_BYTES:
            raise BundleSafetyError("bundle component exceeds 10 MiB limit")
        if info.file_size and (
            info.compress_size == 0 or info.file_size > info.compress_size * MAX_COMPRESSION_RATIO
        ):
            raise BundleSafetyError("bundle component exceeds 100:1 compression ratio")
        declared_total += info.file_size
        if declared_total > MAX_EXPANDED_BYTES:
            raise BundleSafetyError("bundle exceeds 50 MiB expanded limit")

    result: dict[str, bytes] = {}
    actual_total = 0
    for info in infos:
        chunks: list[bytes] = []
        actual_size = 0
        with archive.open(info) as stream:
            while True:
                chunk = stream.read(min(_READ_CHUNK, MAX_COMPONENT_BYTES - actual_size + 1))
                if not chunk:
                    break
                actual_size += len(chunk)
                actual_total += len(chunk)
                if actual_size > MAX_COMPONENT_BYTES or actual_total > MAX_EXPANDED_BYTES:
                    raise BundleSafetyError("bundle expansion exceeds declared limits")
                chunks.append(chunk)
        if actual_size != info.file_size:
            raise BundleSafetyError("bundle member size differs from central directory")
        result[info.orig_filename] = b"".join(chunks)
    return result


def _validate_path(path: str) -> None:
    if (
        not path
        or len(path) > 512
        or path.startswith("/")
        or "\\" in path
        or "\x00" in path
        or "//" in path
        or any(part in ("", ".", "..") for part in path.split("/"))
        or not unicodedata.is_normalized("NFC", path)
    ):
        raise BundleSafetyError("bundle member path is unsafe")


def _has_zip64_extra(extra: bytes) -> bool:
    offset = 0
    while offset < len(extra):
        if offset + 4 > len(extra):
            raise BundleSafetyError("bundle member extra field is malformed")
        field_id, size = struct.unpack_from("<HH", extra, offset)
        offset += 4
        if offset + size > len(extra):
            raise BundleSafetyError("bundle member extra field is malformed")
        if field_id == _ZIP64_EXTRA:
            return True
        offset += size
    return False


def _schema_validators(
    canonical_files: dict[str, bytes],
) -> dict[str, Draft202012Validator]:
    loaded: dict[str, dict[str, object]] = {}
    registry: Registry[dict[str, object]] = Registry()
    for name, content in canonical_files.items():
        try:
            value = json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise BundleValidationError(f"canonical schema {name} is invalid JSON") from error
        if type(value) is not dict or type(value.get("$id")) is not str:
            raise BundleValidationError(f"canonical schema {name} lacks an identifier")
        loaded[name] = cast(dict[str, object], value)
        registry = registry.with_resource(
            cast(str, value["$id"]),
            Resource.from_contents(value, default_specification=DRAFT202012),
        )
    supported = set().union(*(bundle_schema_names(version) for version in _BUNDLE_PROFILES)) | {
        "lifecycle-event.v1.schema.json",
        "review-completion.v1.schema.json",
    }
    return {
        name: Draft202012Validator(schema, registry=registry, format_checker=FormatChecker())
        for name, schema in loaded.items()
        if name in supported
    }


def _canonical_record(
    content: bytes, validator: Draft202012Validator, label: str
) -> dict[str, object]:
    try:
        value = json.loads(content)
        if type(value) is not dict or canonical_json_bytes(value) != content:
            raise BundleValidationError(f"{label} must use exact canonical JSON bytes")
        validator.validate(value)
    except BundleValidationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, ValueError) as error:
        raise BundleValidationError(f"{label} does not satisfy its schema") from error
    return cast(dict[str, object], value)


def _require_supported_schema(
    content: bytes,
    expected: str,
    label: str,
    *,
    check_name: str = "bundle_manifest",
    supported: frozenset[str] | None = None,
) -> None:
    try:
        value = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return
    schema_version = value.get("schema_version") if type(value) is dict else None
    if type(schema_version) is str and schema_version != expected:
        error_type = (
            BundleValidationError
            if supported and schema_version in supported
            else BundleUnsupportedError
        )
        raise error_type(f"{label} schema version is unsupported", check_name=check_name)


def _manifest_bundle_version(content: bytes) -> str:
    try:
        value = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise BundleValidationError("bundle manifest is not valid JSON") from None
    schema_version = value.get("schema_version") if type(value) is dict else None
    if type(schema_version) is not str:
        raise BundleValidationError("bundle manifest lacks a schema version")
    if schema_version not in _BUNDLE_PROFILES:
        raise BundleUnsupportedError("bundle manifest schema version is unsupported")
    return schema_version


def _require_supported_values(
    content: bytes,
    expected: dict[str, str],
    label: str,
    *,
    check_name: str,
) -> None:
    try:
        value = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return
    if type(value) is not dict:
        return
    if any(
        type(value.get(name)) is str and value[name] != wanted for name, wanted in expected.items()
    ):
        raise BundleUnsupportedError(f"{label} algorithm is unsupported", check_name=check_name)


def _validate_component_layout(
    components: dict[str, bytes],
    canonical_schemas: dict[str, bytes],
    *,
    bundle_version: str,
) -> None:
    paths = set(components)
    if not paths >= _BASE_PATHS:
        raise BundleIncompleteError("bundle lacks required components")
    event_paths = sorted(path for path in paths if _EVENT_JSON.fullmatch(path))
    expected_events = [
        f"evidence/lifecycle/events/{index:04d}.json" for index in range(1, len(event_paths) + 1)
    ]
    if event_paths != expected_events:
        raise BundleValidationError("lifecycle event names must be consecutive from 0001")
    completion_present = "review/completion.json" in paths or "review/completion.jws" in paths
    if completion_present and not {"review/completion.json", "review/completion.jws"} <= paths:
        raise BundleIncompleteError("review completion must be an exact JSON/JWS pair")

    statement_files: dict[str, set[str]] = {}
    for path in paths:
        match = _STATEMENT.fullmatch(path)
        if match:
            statement_files.setdefault(match.group(1), set()).add(match.group(2))
    if not statement_files or any(parts != {"json", "jws"} for parts in statement_files.values()):
        raise BundleIncompleteError("operational key statements must be exact JSON/JWS pairs")

    required_schemas = set(bundle_schema_names(bundle_version))
    if event_paths:
        required_schemas.add("lifecycle-event.v1.schema.json")
    if completion_present:
        required_schemas.add("review-completion.v1.schema.json")
    schema_paths = {path for path in paths if path.startswith("schemas/")}
    expected_schemas = {f"schemas/{name}" for name in required_schemas}
    all_profile_schema_names = set().union(
        *(bundle_schema_names(version) for version in _BUNDLE_PROFILES)
    )
    unexpected_schema_names = {
        path.removeprefix("schemas/") for path in schema_paths - expected_schemas
    }
    if unexpected_schema_names & all_profile_schema_names:
        raise BundleValidationError("bundle mixes supported schema profiles")
    if not schema_paths >= expected_schemas:
        raise BundleIncompleteError("bundle lacks a required schema")
    if schema_paths != expected_schemas:
        raise BundleUnsupportedError("bundle carries an unsupported schema")
    for name in required_schemas:
        if components[f"schemas/{name}"] != canonical_schemas.get(name):
            raise BundleValidationError(f"bundle schema {name} is not the canonical source")
    expected_paths = set(_BASE_PATHS) | schema_paths
    expected_paths.update(
        path for json_path in event_paths for path in (json_path, json_path[:-5] + ".jws")
    )
    expected_paths.update(
        f"trust/operational-key-statements/{kid}.{suffix}"
        for kid in statement_files
        for suffix in ("json", "jws")
    )
    if completion_present:
        expected_paths.update({"review/completion.json", "review/completion.jws"})
    if not paths >= expected_paths:
        raise BundleIncompleteError("bundle contains incomplete components")
    if paths != expected_paths:
        raise BundleUnsupportedError("bundle contains unsupported components")


def signed_record_references(parsed: ParsedRproofBundle) -> tuple[SignedRecordReference, ...]:
    """Discover exact signed-record pairs without interpreting their JSON payloads."""
    profile = _BUNDLE_PROFILES[parsed.bundle_version]
    records = {
        MANIFEST_PATH: (parsed.bundle_version, "bundle-signing"),
        "receipt/attestation.json": (
            profile.attestation_schema_version,
            "attestation-signing",
        ),
        **_RECORD_PROFILES,
    }
    records.update(
        (path, ("rproof.lifecycle-event.v1", "lifecycle-status-signing"))
        for path in sorted(parsed.components)
        if _EVENT_JSON.fullmatch(path)
    )
    references: list[SignedRecordReference] = []
    purposes: dict[str, str] = {}
    for path, (schema_version, purpose) in records.items():
        if path == MANIFEST_PATH:
            payload = parsed.manifest_json
            jws_path = MANIFEST_JWS_PATH
            jws = parsed.manifest_jws
        elif path in parsed.components:
            payload = parsed.components[path]
            jws_path = path[:-5] + ".jws"
            jws = parsed.components[jws_path]
        else:
            continue
        kid = _jws_kid(jws, payload, schema_version)
        previous = purposes.setdefault(kid, purpose)
        if previous != purpose:
            raise BundleValidationError("one operational key cannot cross record purposes")
        references.append(SignedRecordReference(path, jws_path, schema_version, purpose, kid))
    return tuple(references)


def validate_operational_key_bindings(
    parsed: ParsedRproofBundle,
    records: tuple[SignedRecordReference, ...],
    *,
    canonical_schema_files: dict[str, bytes],
) -> OperationalKeyLayout:
    """Validate untrusted root/statement layout before external authentication."""
    validators = _schema_validators(canonical_schema_files)
    components = parsed.components
    root_jwk = _canonical_public_jwk(components["trust/root-public-key.jwk"])
    fingerprint = p256_fingerprint_sha256(root_jwk)
    if components["trust/root-fingerprint.txt"] != f"sha256:{fingerprint}\n".encode():
        raise BundleValidationError("bundled root fingerprint does not match public JWK")

    purposes = {record.kid: record.purpose for record in records}
    statement_kids = {
        match.group(1) for path in components if (match := _STATEMENT.fullmatch(path)) is not None
    }
    if not statement_kids >= set(purposes):
        raise BundleIncompleteError("bundle lacks a signing-key statement")
    if statement_kids != set(purposes):
        raise BundleValidationError("bundle has an unrelated signing-key statement")
    root_kids: set[str] = set()
    environments: set[str] = set()
    for kid in statement_kids:
        stem = f"trust/operational-key-statements/{kid}"
        statement = _canonical_record(
            components[f"{stem}.json"],
            validators["operational-key-statement.v1.schema.json"],
            f"operational key statement {kid}",
        )
        if (
            statement["kid"] != kid
            or statement["purpose"] != purposes[kid]
            or statement["root_fingerprint_sha256"] != fingerprint
        ):
            raise BundleValidationError("operational key statement binding is invalid")
        environments.add(cast(str, statement["environment"]))
        root_kids.add(
            _jws_kid(
                components[f"{stem}.jws"],
                components[f"{stem}.json"],
                "rproof.operational-key-statement.v1",
            )
        )
    if len(root_kids) != 1 or len(environments) != 1:
        raise BundleValidationError("bundle key statements must share one root and environment")
    return OperationalKeyLayout(root_jwk, fingerprint, root_kids.pop(), environments.pop())


def validate_package_manifest(
    parsed: ParsedRproofBundle, *, canonical_schema_files: dict[str, bytes]
) -> dict[str, object]:
    """Validate canonical package bytes and recalculate their committed root."""
    validators = _schema_validators(canonical_schema_files)
    _require_supported_schema(
        parsed.components["package/manifest.json"],
        "rproof.package-manifest.v1",
        "package manifest",
        check_name="package_manifest",
    )
    _require_supported_values(
        parsed.components["package/manifest.json"],
        {"hash_algorithm": "sha-256", "tree_algorithm": "rproof-rfc6962-sha256-v1"},
        "package manifest",
        check_name="package_manifest",
    )
    package = _canonical_record(
        parsed.components["package/manifest.json"],
        validators["package-manifest.v1.schema.json"],
        "package manifest",
    )
    entries = cast(list[dict[str, object]], package["entries"])
    entry_ids = [entry["entry_id"] for entry in entries]
    if (
        package["entry_count"] != len(entries)
        or len(entry_ids) != len(set(entry_ids))
        or sum(cast(int, entry["byte_length"]) for entry in entries) > MAX_PACKAGE_BYTES
        or package["package_root"] != package_root(entries)
    ):
        raise BundleValidationError("package manifest root, entries or total size is invalid")
    return package


def validate_attestation_bindings(
    parsed: ParsedRproofBundle,
    package: dict[str, object],
    *,
    canonical_schema_files: dict[str, bytes],
) -> dict[str, object]:
    """Validate attestation schema and package/receipt digest bindings."""
    validators = _schema_validators(canonical_schema_files)
    profile = _BUNDLE_PROFILES[parsed.bundle_version]
    _require_supported_schema(
        parsed.components["receipt/attestation.json"],
        profile.attestation_schema_version,
        "attestation",
        check_name="attestation",
        supported=_SUPPORTED_ATTESTATION_SCHEMA_VERSIONS,
    )
    attestation = _canonical_record(
        parsed.components["receipt/attestation.json"],
        validators[profile.attestation_schema_name],
        "attestation",
    )
    if parsed.manifest["receipt_id"] != attestation["receipt_id"]:
        raise BundleValidationError("bundle manifest and attestation receipt identifiers differ")
    package_bytes = parsed.components["package/manifest.json"]
    if (
        cast(dict[str, object], attestation["manifest_digest"])["value"]
        != sha256(package_bytes).hexdigest()
    ):
        raise BundleValidationError("attestation does not bind package manifest bytes")
    if cast(dict[str, object], attestation["package_root"])["value"] != package["package_root"]:
        raise BundleValidationError("attestation does not bind package root")
    return attestation


def validate_timestamp_bindings(
    parsed: ParsedRproofBundle, *, canonical_schema_files: dict[str, bytes]
) -> dict[str, object]:
    """Validate wrapper/DER byte bindings; cryptographic TSA trust stays external."""
    validators = _schema_validators(canonical_schema_files)
    _require_supported_schema(
        parsed.components["evidence/timestamp/evidence.json"],
        "rproof.timestamp-evidence.v1",
        "timestamp evidence",
        check_name="timestamp",
    )
    _require_supported_values(
        parsed.components["evidence/timestamp/evidence.json"],
        {"algorithm": "rfc3161-sha256"},
        "timestamp evidence",
        check_name="timestamp",
    )
    evidence = _canonical_record(
        parsed.components["evidence/timestamp/evidence.json"],
        validators["timestamp-evidence.v1.schema.json"],
        "timestamp evidence",
    )
    _validate_timestamp(evidence, parsed.components, parsed.components["receipt/attestation.jws"])
    return evidence


def validate_lifecycle_bindings(
    parsed: ParsedRproofBundle, *, canonical_schema_files: dict[str, bytes]
) -> CanonicalLifecycleRecords:
    """Validate canonical lifecycle schemas before signature and semantic checks."""
    validators = _schema_validators(canonical_schema_files)
    components = parsed.components
    _require_supported_schema(
        components["evidence/lifecycle/status-snapshot.json"],
        "rproof.status-snapshot.v1",
        "status snapshot",
        check_name="lifecycle",
    )
    status = _canonical_record(
        components["evidence/lifecycle/status-snapshot.json"],
        validators["status-snapshot.v1.schema.json"],
        "status snapshot",
    )
    event_paths = sorted(path for path in components if _EVENT_JSON.fullmatch(path))
    events: list[dict[str, object]] = []
    for path in event_paths:
        _require_supported_schema(
            components[path],
            "rproof.lifecycle-event.v1",
            "lifecycle event",
            check_name="lifecycle",
        )
        event = _canonical_record(
            components[path], validators["lifecycle-event.v1.schema.json"], path
        )
        events.append(event)
    completion: dict[str, object] | None = None
    if "review/completion.json" in components:
        _require_supported_schema(
            components["review/completion.json"],
            "rproof.review-completion.v1",
            "review completion",
            check_name="lifecycle",
        )
        completion = _canonical_record(
            components["review/completion.json"],
            validators["review-completion.v1.schema.json"],
            "review completion",
        )
    return CanonicalLifecycleRecords(status, tuple(events), completion)


def _canonical_public_jwk(content: bytes) -> dict[str, object]:
    try:
        value = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BundleValidationError("root public key is invalid JSON") from error
    if (
        type(value) is not dict
        or set(value) != {"crv", "kty", "x", "y"}
        or canonical_json_bytes(value) != content
        or "d" in value
    ):
        raise BundleValidationError("root public key must be canonical public P-256 JWK")
    try:
        p256_fingerprint_sha256(value)
    except ValueError as error:
        raise BundleValidationError("root public key is not valid P-256 JWK") from error
    return cast(dict[str, object], value)


def _jws_kid(compact: bytes, expected_payload: bytes, schema_version: str) -> str:
    check_name = (
        "bundle_signature"
        if schema_version.startswith("rproof.bundle-manifest.")
        else "attestation_signature"
        if schema_version.startswith("rproof.attestation.")
        else "lifecycle"
    )
    try:
        text = compact.decode("ascii")
        encoded_header, encoded_payload, encoded_signature = text.split(".")
        header_bytes = decode_base64url(encoded_header)
        payload = decode_base64url(encoded_payload)
        signature = decode_base64url(encoded_signature)
        header = json.loads(header_bytes)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise BundleValidationError("compact JWS encoding is invalid") from error
    if type(header) is not dict or canonical_json_bytes(header) != header_bytes:
        raise BundleValidationError("compact JWS header is not canonical JSON")
    algorithm = header.get("alg")
    if type(algorithm) is str and algorithm != "ES256":
        raise BundleUnsupportedError("compact JWS algorithm is unsupported", check_name=check_name)
    declared_schema = header.get("rproof_schema")
    if type(declared_schema) is str and declared_schema != schema_version:
        error_type = (
            BundleValidationError
            if declared_schema in _SUPPORTED_SIGNED_SCHEMA_VERSIONS
            else BundleUnsupportedError
        )
        raise error_type("compact JWS schema version is unsupported", check_name=check_name)
    record_name = schema_version.removeprefix("rproof.").rsplit(".", 1)[0]
    cty = f"application/rproof-{record_name}+json"
    typ = f"application/rproof-{record_name}+jws"
    expected = {
        "alg": "ES256",
        "cty": cty,
        "kid": header.get("kid"),
        "rproof_schema": schema_version,
        "typ": typ,
    }
    kid = header.get("kid")
    if header != expected or type(kid) is not str or _KID.fullmatch(kid) is None:
        raise BundleValidationError("compact JWS protected header profile is invalid")
    if not hmac.compare_digest(payload, expected_payload) or len(signature) != 64:
        raise BundleValidationError("compact JWS does not bind exact record bytes")
    return kid


def _validate_timestamp(
    evidence: dict[str, object], components: dict[str, bytes], attestation_jws: bytes
) -> None:
    token = components["evidence/timestamp/attestation.tsr"]
    chain = components["evidence/timestamp/tsa-chain.pem"]
    for descriptor_name, content in (("token", token), ("certificate_chain", chain)):
        descriptor = cast(dict[str, object], evidence[descriptor_name])
        if (
            descriptor["byte_length"] != len(content)
            or descriptor["sha256"] != sha256(content).hexdigest()
        ):
            raise BundleValidationError(f"timestamp {descriptor_name} binding is invalid")
    if evidence["message_imprint_sha256"] != sha256(attestation_jws).hexdigest():
        raise BundleValidationError("timestamp wrapper does not bind attestation JWS")
    try:
        response = tsp.TimeStampResp.load(token, strict=True)
        signed_data = response["time_stamp_token"]["content"]
        if not isinstance(signed_data, cms.SignedData):
            raise ValueError
        info = signed_data["encap_content_info"]["content"].parsed
        if not isinstance(info, tsp.TSTInfo):
            raise ValueError
        nonce = info["nonce"].native
        if type(nonce) is not int or nonce <= 0:
            raise ValueError
        nonce_bytes = nonce.to_bytes((nonce.bit_length() + 7) // 8, "big")
        gen_time = format_generalized_time(info["gen_time"].contents)
        imprint = info["message_imprint"]
        if response["status"]["status"].native != "granted":
            raise ValueError
    except (KeyError, TypeError, ValueError) as error:
        raise BundleValidationError("timestamp reply is not usable RFC 3161 evidence") from error
    if (
        imprint["hash_algorithm"]["algorithm"].dotted != "2.16.840.1.101.3.4.2.1"
        or imprint["hashed_message"].native.hex() != evidence["message_imprint_sha256"]
        or info["policy"].dotted != evidence["policy_oid"]
        or sha256(nonce_bytes).hexdigest() != evidence["nonce_sha256"]
        or not portable_utc_times_equal(gen_time, cast(str, evidence["token_gen_time"]))
    ):
        raise BundleValidationError("timestamp reply fields do not match wrapper")


def bundle_component_media_type(path: str) -> str:
    """Return the fixed v1 media type for one supported component path."""
    if path in _MEDIA_TYPES:
        return _MEDIA_TYPES[path]
    if path.endswith(".schema.json"):
        return "application/schema+json"
    if path.endswith((".json", ".jwk")):
        return "application/json"
    if path.endswith(".jws"):
        return "application/jose"
    raise BundleUnsupportedError(f"bundle contains unsupported component path {path}")
