"""Small immutable models shared by CipherDesk's interface and services."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


class CipherDeskError(Exception):
    """An actionable, safe-to-display error without GnuPG's raw diagnostics."""

    def __init__(self, message: str, code: str = "operation_failed") -> None:
        super().__init__(message)
        self.code = code


class CryptoError(CipherDeskError):
    pass


class StoreError(CipherDeskError):
    pass


@dataclass(frozen=True)
class Key:
    fingerprint: str
    name: str = ""
    email: str = ""
    can_encrypt: bool = False
    can_sign: bool = False
    has_secret: bool = False
    validity: str = ""
    expires: int | None = None
    uid: str = ""
    reason: str = ""
    can_sign_secret: bool = False
    can_decrypt_secret: bool = False

    @property
    def trusted(self) -> bool:
        return self.validity in {"f", "u"}

    @property
    def display_name(self) -> str:
        return self.uid or self.name or self.email or self.fingerprint


@dataclass(frozen=True)
class ContactGroup:
    name: str
    fingerprints: tuple[str, ...]


@dataclass(frozen=True)
class SignatureStatus:
    status: str
    valid: bool
    fingerprint: str = ""
    signer: str = ""
    trust: str = "unknown"
    timestamp: int | None = None

    @property
    def name(self) -> str:
        return self.signer

    @property
    def trusted(self) -> bool:
        return self.trust in {"full", "fully", "ultimate"}


@dataclass(frozen=True)
class OperationReport:
    output_path: Path
    signatures: tuple[SignatureStatus, ...] = ()
    encrypted_for: tuple[str, ...] = ()
    signed: bool = False
    unsigned: bool = False

