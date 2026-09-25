"""Typed runtime ports."""

from reviewedproof.ports.protocols import (
    Clock,
    EmailSender,
    IdentifierProtector,
    IdGenerator,
    ObjectStore,
    Signer,
    TimestampAuthority,
    TimestampResult,
)

__all__ = [
    "Clock",
    "EmailSender",
    "IdentifierProtector",
    "IdGenerator",
    "ObjectStore",
    "Signer",
    "TimestampAuthority",
    "TimestampResult",
]
