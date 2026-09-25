# SPDX-License-Identifier: MIT
"""Independent Python command-line verification boundary."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import cast

from reviewedproof.verification.bundles import (
    MAX_ARCHIVE_BYTES,
    BundleIncompleteError,
    BundleSafetyError,
    BundleUnsupportedError,
    BundleValidationError,
    load_bundle_schemas,
    parse_rproof_bundle,
)
from reviewedproof.verification.kernel import canonical_json_bytes
from reviewedproof.verification.result import ArtefactInput, VerificationOutcome, verify_rproof

_MAX_ARTEFACTS = 100
_MAX_ARTEFACT_BYTES = 200_000_000
_MAX_TRUST_STORE_BYTES = 2 * 1024 * 1024


class _CliInputError(ValueError):
    """A bounded CLI input could not be consumed safely."""

    def __init__(self, message: str, *, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def main(argv: Sequence[str] | None = None) -> int:
    """Run the ReviewedProof verifier CLI and return its process exit code."""
    parser = _parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "verify":
            return _verify(arguments)
        return _inspect(arguments)
    except _CliInputError as error:
        print(f"reviewedproof: {error}", file=sys.stderr)
        return error.exit_code


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reviewedproof",
        description="Verify portable ReviewedProof evidence without network access.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    verify = commands.add_parser(
        "verify", help="cryptographically verify a bundle and optionally match local artefacts"
    )
    verify.add_argument("bundle", help="portable .rproof bundle")
    verify.add_argument("--trust-store", required=True, help="external verifier trust-store JSON")
    verify.add_argument(
        "--allow-non-production",
        action="store_true",
        help="permit explicitly marked staging or development evidence",
    )
    verify.add_argument(
        "--artefact", action="append", default=[], help="local artefact to match automatically"
    )
    verify.add_argument(
        "--artefact-for",
        action="append",
        default=[],
        metavar="ENTRY_ID=PATH",
        help="local artefact explicitly assigned to one manifest entry",
    )
    verify.add_argument("--output", help="also write the exact JSON result to this file")

    inspect = commands.add_parser(
        "inspect", help="inspect safe bundle structure without verifying signatures or trust"
    )
    inspect.add_argument("bundle", help="portable .rproof bundle")
    inspect.add_argument("--json", action="store_true", required=True, help="emit unverified JSON")
    return parser


def _verify(arguments: argparse.Namespace) -> int:
    archive = _read_bounded(
        Path(cast(str, arguments.bundle)),
        MAX_ARCHIVE_BYTES,
        "bundle",
        too_large_exit_code=6,
    )
    trust_store = _read_bounded(
        Path(cast(str, arguments.trust_store)), _MAX_TRUST_STORE_BYTES, "trust store"
    )
    artefacts = _read_artefacts(
        cast(list[str], arguments.artefact), cast(list[str], arguments.artefact_for)
    )
    outcome = verify_rproof(
        archive,
        trust_store_bytes=trust_store,
        verified_at=datetime.now(UTC).replace(microsecond=0),
        artefacts=artefacts,
        allow_non_production=cast(bool, arguments.allow_non_production),
    )
    _emit_result(outcome, None if arguments.output is None else Path(arguments.output))
    return outcome.exit_code


def _inspect(arguments: argparse.Namespace) -> int:
    archive = _read_bounded(
        Path(cast(str, arguments.bundle)),
        MAX_ARCHIVE_BYTES,
        "bundle",
        too_large_exit_code=6,
    )
    try:
        parsed = parse_rproof_bundle(
            archive,
            canonical_schema_files=load_bundle_schemas(
                include_lifecycle_events=True,
                include_review_completion=True,
            ),
        )
    except BundleSafetyError:
        raise _CliInputError("bundle could not be safely inspected", exit_code=6) from None
    except BundleIncompleteError:
        raise _CliInputError("bundle evidence is incomplete", exit_code=4) from None
    except BundleUnsupportedError:
        raise _CliInputError("bundle uses an unsupported profile", exit_code=5) from None
    except BundleValidationError:
        raise _CliInputError("bundle evidence is invalid") from None
    result = {
        "bundle_sha256": sha256(archive).hexdigest(),
        "component_count": len(parsed.components),
        "inspection": "unverified",
        "receipt_id": parsed.manifest["receipt_id"],
        "warning": "Structure only; signatures, trust, timestamp and lifecycle were not verified.",
    }
    sys.stdout.write(canonical_json_bytes(result).decode("utf-8") + "\n")
    return 0


def _read_artefacts(automatic: list[str], explicit: list[str]) -> tuple[ArtefactInput, ...]:
    selected: list[tuple[str | None, Path]] = [(None, Path(path)) for path in automatic]
    for assignment in explicit:
        entry_id, separator, path_text = assignment.partition("=")
        if not separator or not entry_id or not path_text:
            raise _CliInputError("--artefact-for must use ENTRY_ID=PATH")
        selected.append((entry_id, Path(path_text)))
    if len(selected) > _MAX_ARTEFACTS:
        raise _CliInputError("no more than 100 artefacts may be selected")

    total = 0
    artefacts: list[ArtefactInput] = []
    for selected_entry_id, selected_path in selected:
        content = _read_bounded(selected_path, _MAX_ARTEFACT_BYTES - total, "selected artefact")
        total += len(content)
        artefacts.append(ArtefactInput(content=content, entry_id=selected_entry_id))
    return tuple(artefacts)


def _read_bounded(
    path: Path, maximum_bytes: int, label: str, *, too_large_exit_code: int = 2
) -> bytes:
    try:
        with path.open("rb") as source:
            content = source.read(maximum_bytes + 1)
    except OSError:
        raise _CliInputError(f"could not read {label}") from None
    if len(content) > maximum_bytes:
        raise _CliInputError(f"{label} exceeds its size limit", exit_code=too_large_exit_code)
    return content


def _emit_result(outcome: VerificationOutcome, output: Path | None) -> None:
    content = canonical_json_bytes(outcome.result) + b"\n"
    if output is not None:
        try:
            output.write_bytes(content)
        except OSError:
            raise _CliInputError("could not write verification result") from None
    sys.stdout.write(content.decode("utf-8"))
