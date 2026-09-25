"""Framework/vendor-neutral ports required by documented architecture."""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

Evidence = Mapping[str, object]


@dataclass(frozen=True, slots=True)
class TimestampResult:
    """Validated timestamp bytes and metadata needed for immutable storage."""

    response_bytes: bytes
    certificate_chain_pem: bytes
    provider: str
    policy_oid: str
    message_imprint_sha256: bytes
    nonce_sha256: bytes
    token_gen_time: str
    development_only: bool


class Signer(Protocol):
    @property
    def development_only(self) -> bool: ...

    def sign(self, key_id: str, algorithm: str, digest: bytes) -> bytes: ...


class TimestampAuthority(Protocol):
    development_only: bool

    def timestamp(self, message_digest: bytes, nonce: int) -> TimestampResult: ...


class ObjectStore(Protocol):
    development_only: bool

    def read_immutable(self, object_key: str, *, max_bytes: int) -> bytes: ...

    def put_immutable(
        self,
        content: bytes,
        media_type: str,
        retention: str,
        *,
        object_key: str | None = None,
    ) -> Evidence: ...


class EmailSender(Protocol):
    """Deliver data containing rendered subject/body plus caller-owned metadata."""

    development_only: bool

    def send(self, template: str, recipient_ref: str, data: Evidence) -> Evidence: ...


class Clock(Protocol):
    def now(self) -> datetime: ...


class IdGenerator(Protocol):
    def new_uuid7(self) -> UUID: ...


class IdentifierProtector(Protocol):
    development_only: bool

    def encrypt(self, plaintext: bytes, *, purpose: str, record_id: UUID) -> bytes: ...

    def decrypt(self, envelope: bytes, *, purpose: str, record_id: UUID) -> bytes: ...

    def lookup_hmac(self, plaintext: bytes, *, purpose: str) -> bytes: ...
