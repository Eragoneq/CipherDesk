"""GnuPG orchestration: Kleopatra's keyring, explicit recipients, no trust bypass.

No private keys or passphrases are read by this module. GnuPG's agent and
Pinentry own passphrase prompts. Machine statuses, rather than localized log
messages, determine success. Decryption never trusts an embedded filename.
"""

from __future__ import annotations

from dataclasses import replace
from email.utils import parseaddr
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time
from collections.abc import Iterable
from typing import BinaryIO

from .models import CryptoError, Key, OperationReport, SignatureStatus, StoreError
from .store import normalize_fingerprint

GPGError = CryptoError
_BAD_VALIDITY = {"r", "e", "d", "i"}
_STATUS_PREFIX = b"[GNUPG:] "


def _find_executable(name: str, relative_paths: tuple[str, ...]) -> str | None:
    executable = shutil.which(name)
    if executable:
        return str(Path(executable).resolve())
    roots = [os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles")]
    if os.name == "nt":
        roots.extend([r"C:\Program Files (x86)", r"C:\Program Files"])
    for root in dict.fromkeys(filter(None, roots)):
        for relative in relative_paths:
            candidate = Path(root) / relative
            if candidate.is_file():
                return str(candidate.resolve())
    return None


def discover_gpg() -> str | None:
    return _find_executable("gpg", ("GnuPG/bin/gpg.exe", "Gpg4win/bin/gpg.exe", "Gpg4win/../GnuPG/bin/gpg.exe"))


def discover_kleopatra() -> str | None:
    return _find_executable("kleopatra", ("Gpg4win/bin/kleopatra.exe", "Gpg4win/kleopatra.exe", "Kleopatra/bin/kleopatra.exe"))


def open_kleopatra() -> None:
    executable = discover_kleopatra()
    if not executable:
        raise CryptoError("Kleopatra was not found. Install Gpg4win, then try again.", "kleopatra_missing")
    try:
        subprocess.Popen(
            [executable], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except OSError as exc:
        raise CryptoError("Kleopatra could not be opened. Check the Gpg4win installation.", "kleopatra_failed") from exc


def _decode_uid(value: str) -> str:
    """Decode GnuPG C escapes as bytes before interpreting the UTF-8 UID."""
    raw = value.encode("utf-8")
    escapes = {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b", b"f": b"\f", b"v": b"\v", b"0": b"\0", b"\\": b"\\"}

    def decode(match: re.Match[bytes]) -> bytes:
        piece = match.group(1)
        if piece.startswith(b"x"):
            return bytes([int(piece[1:], 16)])
        return escapes.get(piece, piece)

    decoded = re.sub(rb"\\(x[0-9a-fA-F]{2}|[nrtbfv0\\])", decode, raw).decode("utf-8", errors="replace")
    # Key user IDs are untrusted text; keep them on a single readable UI line.
    return "".join(c if ord(c) >= 32 and ord(c) != 127 else " " for c in decoded)


def _integer(value: str) -> int | None:
    try:
        number = int(value)
        return number or None
    except (ValueError, TypeError):
        return None


def _status_lines(stderr: bytes) -> list[tuple[str, str]]:
    result = []
    for line in stderr.splitlines():
        if line.startswith(_STATUS_PREFIX):
            keyword, _, value = line[len(_STATUS_PREFIX):].partition(b" ")
            result.append((keyword.decode("ascii", "replace"), value.decode("utf-8", "replace")))
    return result


def _packet_usable(fields: list[str], now: int) -> bool:
    expires = _integer(fields[6])
    return fields[1][:1] not in _BAD_VALIDITY and "D" not in fields[11] and (expires is None or expires > now)


def _parse_listing(output: bytes) -> list[dict]:
    groups: list[dict] = []
    current: dict | None = None
    packet: dict | None = None
    for line in output.decode("utf-8", "replace").splitlines():
        fields = line.split(":")
        fields.extend([""] * max(0, 20 - len(fields)))
        kind = fields[0]
        if kind in {"pub", "sec"}:
            packet = {"fields": fields, "fingerprint": ""}
            current = {"primary": packet, "packets": [packet], "uids": []}
            groups.append(current)
        elif kind in {"sub", "ssb"} and current is not None:
            packet = {"fields": fields, "fingerprint": ""}
            current["packets"].append(packet)
        elif kind == "fpr" and packet is not None and not packet["fingerprint"]:
            packet["fingerprint"] = fields[9].upper()
        elif kind == "uid" and current is not None:
            current["uids"].append((fields[1][:1], _decode_uid(fields[9])))
    return groups


def _check_not_link(path: Path) -> None:
    for part in (path, *path.parents):
        try:
            is_junction = getattr(part, "is_junction", lambda: False)()
            if part.is_symlink() or is_junction:
                raise CryptoError("Choose a regular file and folder; symbolic links and junctions are not supported.", "unsafe_path")
        except OSError as exc:
            raise CryptoError("The file or folder could not be inspected.", "unsafe_path") from exc


def _source_path(value: str | Path) -> Path:
    path = Path(value).expanduser().absolute()
    _check_not_link(path)
    try:
        path = path.resolve(strict=True)
        if not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
            raise CryptoError("Select a regular file to process.", "invalid_source")
        return path
    except OSError as exc:
        raise CryptoError("The input file is unavailable. Check that it exists and is downloaded locally.", "invalid_source") from exc


def _output_directory(value: str | Path) -> Path:
    path = Path(value).expanduser().absolute()
    _check_not_link(path)
    try:
        path.mkdir(parents=True, exist_ok=True)
        _check_not_link(path)
        path = path.resolve(strict=True)
        if not path.is_dir():
            raise CryptoError("Choose an existing output folder.", "invalid_output")
        return path
    except OSError as exc:
        raise CryptoError("The output folder is unavailable. Choose a writable folder.", "invalid_output") from exc


def _safe_name(name: str) -> str:
    # Only app-derived basenames reach here, never the literal-data packet name.
    if not name or name in {".", ".."} or Path(name).name != name or any(c in name for c in ("/", "\\", "\0", ":")):
        raise CryptoError("This filename cannot be used safely for the output.", "unsafe_path")
    return name


def _publish(staged: Path, directory: Path, name: str, source: Path, *, atomic: bool = False) -> Path:
    """Copy only checked output into a new, exclusively created destination."""
    name = _safe_name(name)
    stem, suffix = os.path.splitext(name)
    for number in range(10_000):
        candidate = directory / (name if number == 0 else f"{stem} ({number}){suffix}")
        if candidate.absolute() == source.absolute():
            continue
        if atomic:
            try:
                if os.name == "nt":
                    # Windows rename is an atomic move that fails if the target
                    # exists. Both encrypted paths are in this same directory.
                    os.rename(staged, candidate)
                else:
                    # POSIX rename would overwrite a target. Link creates a
                    # destination atomically and fails when it already exists.
                    os.link(staged, candidate)
                return candidate
            except FileExistsError:
                continue
            except OSError as exc:
                raise CryptoError("Cannot publish the encrypted output atomically. Check output-folder permissions and free space.", "output_failed") from exc
        try:
            # O_EXCL prevents replacement of an existing file or a link created
            # concurrently. Never follow a destination chosen by an attacker.
            fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        except FileExistsError:
            continue
        except OSError as exc:
            raise CryptoError("Cannot create the output file. Check the destination permissions and free space.", "output_failed") from exc
        try:
            with os.fdopen(fd, "wb") as destination, staged.open("rb") as original:
                shutil.copyfileobj(original, destination, length=1024 * 1024)
                destination.flush()
                os.fsync(destination.fileno())
            return candidate
        except OSError as exc:
            try:
                candidate.unlink()
            except OSError:
                pass
            raise CryptoError("The completed output could not be saved. Check free disk space and folder permissions.", "output_failed") from exc
    raise CryptoError("There are too many files with the same name in the output folder.", "output_collision")


def _raise_failure(statuses: list[tuple[str, str]], operation: str) -> None:
    keywords = {key for key, _ in statuses}
    error_numbers: set[int] = set()
    for keyword, value in statuses:
        if keyword in {"ERROR", "FAILURE"}:
            fields = value.split()
            if len(fields) >= 2 and fields[1].isdigit():
                error_numbers.add(int(fields[1]) & 0xFFFF)
    if keywords.intersection({"CANCELED_BY_USER", "CANCEL"}) or error_numbers.intersection({99, 198}):
        raise CryptoError("The operation was cancelled in the passphrase dialog.", "cancelled")
    if "BAD_PASSPHRASE" in keywords or error_numbers.intersection({11, 177}):
        raise CryptoError("The key could not be unlocked. Try again using the GnuPG passphrase dialog.", "bad_passphrase")
    if 85 in error_numbers:
        raise CryptoError("GnuPG could not open Pinentry. Check Gpg4win's passphrase-dialog setup.", "pinentry_failed")
    for keyword, value in statuses:
        if keyword == "INV_RECP":
            reason = value.split(" ", 1)[0]
            if reason == "10":
                raise CryptoError("A recipient key is not certified as valid. Verify its fingerprint and certify it in Kleopatra, then refresh.", "untrusted_key")
            raise CryptoError("A recipient key is missing, expired, revoked, disabled, or unsuitable for encryption. Review it in Kleopatra.", "unusable_key")
    if "NO_SECKEY" in keywords:
        raise CryptoError("No matching private decryption key is available in the current GnuPG keyring.", "no_secret_key")
    if keywords.intersection({"BADMDC", "ERRMDC"}):
        raise CryptoError("The encrypted file failed its integrity check. No decrypted file was saved.", "integrity_failed")
    if keywords.intersection({"BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY"}):
        raise CryptoError("The signature could not be verified with a current local public key. Review the sender's key in Kleopatra. No decrypted file was saved.", "signature_failed")
    if "NODATA" in keywords:
        raise CryptoError("This file does not contain a supported PGP encrypted message.", "invalid_message")
    if "INV_SGNR" in keywords:
        raise CryptoError("The selected signing key is unavailable or unsuitable. Review it in Kleopatra.", "unusable_signer")
    raise CryptoError(f"GnuPG could not complete {operation}. Check the selected keys in Kleopatra and try again.", "gpg_failed")


def _signatures(statuses: list[tuple[str, str]]) -> tuple[SignatureStatus, ...]:
    signatures: list[SignatureStatus] = []
    current: SignatureStatus | None = None
    bad = {"BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY"}
    now = int(time.time())
    for keyword, value in statuses:
        if keyword == "NEWSIG":
            if current is not None:
                signatures.append(current)
            current = SignatureStatus(status="unverified", valid=False)
        elif keyword in {"GOODSIG", "VALIDSIG"} | bad:
            if current is None:
                current = SignatureStatus(status="unverified", valid=False)
            fields = value.split()
            if keyword == "GOODSIG":
                current = replace(current, signer=_decode_uid(value.partition(" ")[2]))
            elif keyword == "VALIDSIG" and len(fields) >= 9:
                fingerprint = fields[9] if len(fields) > 9 else fields[0]
                expiration = _integer(fields[3])
                expired = expiration is not None and expiration <= now
                # A prior bad/expired/revoked status cannot be cured by VALIDSIG.
                valid = not expired and current.status not in {"bad", "error", "expired", "revoked", "unknown_key"}
                current = replace(current, fingerprint=fingerprint, timestamp=_integer(fields[2]), valid=valid, status="valid" if valid else ("expired" if expired else current.status))
            elif keyword in bad:
                state = {"BADSIG": "bad", "ERRSIG": "error", "EXPSIG": "expired", "EXPKEYSIG": "expired", "REVKEYSIG": "revoked", "NO_PUBKEY": "unknown_key"}[keyword]
                current = replace(current, status=state, valid=False, signer=current.signer or _decode_uid(value.partition(" ")[2]))
        elif keyword.startswith("TRUST_") and current is not None:
            trust = keyword[6:].lower()
            current = replace(current, trust="full" if trust == "fully" else trust)
    if current is not None:
        signatures.append(current)
    return tuple(signatures) if signatures else (SignatureStatus(status="unsigned", valid=False),)


class GPGBackend:
    def __init__(self, gpg_path: str | Path | None = None, homedir: str | Path | None = None, timeout: int = 300) -> None:
        self.gpg_path = str(gpg_path) if gpg_path else discover_gpg()
        self.homedir = Path(homedir) if homedir is not None else None
        self.timeout = timeout

    def open_kleopatra(self) -> None:
        open_kleopatra()

    def _command(self) -> list[str]:
        if not self.gpg_path:
            raise CryptoError("GnuPG was not found. Install Gpg4win, or start CipherDesk with --gpg-path followed by the full path to gpg.exe.", "gpg_missing")
        # Ignore gpg.conf so it cannot silently add encrypt-to recipients,
        # output files, auto imports, trust overrides, or dangerous debug logs.
        result = [self.gpg_path, "--no-options"]
        if self.homedir is not None:
            result.extend(["--homedir", str(self.homedir)])
        result.extend([
            "--batch", "--no-tty", "--status-fd", "2", "--display-charset", "utf-8",
            "--no-auto-key-retrieve", "--no-auto-key-import", "--auto-key-locate", "clear",
            "--trust-model", "pgp", "--pinentry-mode", "ask",
        ])
        return result

    def _run(self, arguments: list[str], output: BinaryIO | None = None) -> tuple[subprocess.CompletedProcess, list[tuple[str, str]]]:
        try:
            process = subprocess.run(
                self._command() + arguments, stdin=subprocess.DEVNULL,
                stdout=output if output is not None else subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=self.timeout, check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except subprocess.TimeoutExpired as exc:
            raise CryptoError("GnuPG timed out. Finish or cancel any open passphrase dialog and try again.", "timeout") from exc
        except (OSError, ValueError) as exc:
            raise CryptoError("GnuPG could not be started. Check the configured gpg.exe path and Gpg4win installation.", "gpg_missing") from exc
        return process, _status_lines(process.stderr)

    def list_keys(self) -> list[Key]:
        options = ["--with-colons", "--fixed-list-mode", "--with-fingerprint", "--with-fingerprint"]
        public, statuses = self._run(options + ["--list-keys"])
        if public.returncode:
            _raise_failure(statuses, "reading the keyring")
        secret, statuses = self._run(options + ["--list-secret-keys"])
        if secret.returncode:
            _raise_failure(statuses, "reading private-key availability")
        now = int(time.time())
        secrets: dict[str, tuple[bool, bool, bool]] = {}
        for group in _parse_listing(secret.stdout):
            primary = group["primary"]
            packets = [p for p in group["packets"] if p["fields"][14] != "#" and _packet_usable(p["fields"], now)]
            secrets[primary["fingerprint"]] = (
                bool(packets), any("s" in p["fields"][11] for p in packets),
                any("e" in p["fields"][11] for p in packets),
            )
        keys: list[Key] = []
        for group in _parse_listing(public.stdout):
            primary = group["primary"]
            fields = primary["fields"]
            fingerprint = primary["fingerprint"]
            if not fingerprint:
                continue
            usable = _packet_usable(fields, now)
            packets = [p for p in group["packets"] if usable and _packet_usable(p["fields"], now)]
            can_encrypt = any("e" in p["fields"][11] for p in packets)
            can_sign = any("s" in p["fields"][11] for p in packets)
            uids = group["uids"]
            uid = next((uid for validity, uid in uids if validity not in _BAD_VALIDITY), uids[0][1] if uids else "")
            name, email = parseaddr(uid)
            if not email or "@" not in email:
                name, email = uid, ""
            validity = fields[1][:1]
            if validity == "r":
                reason = "The key has been revoked."
            elif validity == "e" or (_integer(fields[6]) or now + 1) <= now:
                reason = "The key has expired."
            elif validity == "d" or "D" in fields[11]:
                reason = "The key is disabled."
            elif validity == "i":
                reason = "The key is invalid."
            elif not can_encrypt:
                reason = "No current usable encryption key or subkey is available."
            elif validity not in {"f", "u"}:
                reason = "Verify the fingerprint and certify this key in Kleopatra before encrypting."
            else:
                reason = ""
            has_secret, can_sign_secret, can_decrypt_secret = secrets.get(fingerprint, (False, False, False))
            keys.append(Key(
                fingerprint=fingerprint, name=name, email=email, can_encrypt=can_encrypt,
                can_sign=can_sign, has_secret=has_secret, validity=validity,
                expires=_integer(fields[6]), uid=uid, reason=reason,
                can_sign_secret=can_sign_secret and usable,
                can_decrypt_secret=can_decrypt_secret and usable,
            ))
        return sorted(keys, key=lambda key: (key.display_name.casefold(), key.fingerprint))

    @staticmethod
    def _fingerprint(value: str) -> str:
        try:
            return normalize_fingerprint(value)
        except StoreError as exc:
            raise CryptoError(str(exc), exc.code) from exc

    def encrypt_file(
        self, source: str | Path, output_dir: str | Path, recipient_fingerprints: Iterable[str],
        signer_fingerprint: str | None = None, include_self_fingerprint: str | None = None,
    ) -> OperationReport:
        source_path = _source_path(source)
        directory = _output_directory(output_dir)
        fingerprints = list(dict.fromkeys(self._fingerprint(f) for f in recipient_fingerprints))
        own_fingerprint = self._fingerprint(include_self_fingerprint) if include_self_fingerprint else None
        if own_fingerprint:
            fingerprints = list(dict.fromkeys(fingerprints + [own_fingerprint]))
        if not fingerprints:
            raise CryptoError("Choose at least one recipient or contact group.", "empty_recipients")
        keys = {key.fingerprint: key for key in self.list_keys()}
        for fingerprint in fingerprints:
            key = keys.get(fingerprint)
            if key is None:
                raise CryptoError(f"A selected recipient is missing from the keyring: {fingerprint}. Review the group in Kleopatra.", "missing_key")
            if not key.can_encrypt:
                raise CryptoError(f"Cannot encrypt for {key.display_name}. {key.reason}", "unusable_key")
            if not key.trusted:
                raise CryptoError(f"The key for {key.display_name} is not certified as valid. Verify its full fingerprint and certify it in Kleopatra, then refresh.", "untrusted_key")
        if own_fingerprint and not keys[own_fingerprint].can_decrypt_secret:
            raise CryptoError("The selected personal key has no current available private encryption key. Review its encryption subkey in Kleopatra.", "no_secret_key")
        signer: str | None = None
        if signer_fingerprint:
            signer = self._fingerprint(signer_fingerprint)
            key = keys.get(signer)
            if key is None or not key.can_sign or not key.can_sign_secret:
                raise CryptoError("Select a current signing key with an available private key in Kleopatra.", "unusable_signer")
        temporary: str | None = None
        try:
            fd, temporary = tempfile.mkstemp(prefix=".cipherdesk-encrypted-", suffix=".tmp", dir=directory)
            with os.fdopen(fd, "wb") as destination:
                arguments = ["--output", "-", "--set-filename", source_path.name]
                for fingerprint in fingerprints:
                    arguments.extend(["--recipient", fingerprint])
                if signer:
                    arguments.extend(["--local-user", signer, "--sign"])
                arguments.extend(["--encrypt", "--", str(source_path)])
                process, statuses = self._run(arguments, output=destination)
                destination.flush()
                os.fsync(destination.fileno())
            keywords = {key for key, _ in statuses}
            if process.returncode or "END_ENCRYPTION" not in keywords or (signer and "SIG_CREATED" not in keywords):
                _raise_failure(statuses, "encryption")
            if not Path(temporary).stat().st_size:
                raise CryptoError("GnuPG produced no encrypted output.", "empty_output")
            output = _publish(Path(temporary), directory, source_path.name + ".gpg", source_path, atomic=True)
            return OperationReport(output_path=output, encrypted_for=tuple(fingerprints), signed=bool(signer))
        except OSError as exc:
            raise CryptoError("Cannot write encrypted output. Check free disk space and output-folder permissions.", "output_failed") from exc
        finally:
            if temporary:
                try:
                    Path(temporary).unlink()
                except OSError:
                    pass

    def decrypt_file(self, source: str | Path, output_dir: str | Path, *, require_signature: bool = False) -> OperationReport:
        source_path = _source_path(source)
        directory = _output_directory(output_dir)
        name = source_path.name
        if source_path.suffix.lower() in {".gpg", ".pgp", ".asc"}:
            name = source_path.stem
        else:
            name += ".decrypted"
        _safe_name(name)
        temporary_root = Path(tempfile.gettempdir()).resolve()
        if temporary_root == directory or directory in temporary_root.parents:
            raise CryptoError("Choose a decrypted-output folder separate from the system temporary folder, so unverified plaintext can be staged privately.", "unsafe_output")
        # This deliberately uses the OS temporary directory, never the selected
        # output/sync folder. A failed operation cannot expose plaintext there.
        try:
            with tempfile.TemporaryDirectory(prefix="cipherdesk-private-") as scratch:
                staged = Path(scratch) / "decrypted.tmp"
                with staged.open("xb") as destination:
                    process, statuses = self._run(["--output", "-", "--decrypt", "--", str(source_path)], output=destination)
                    destination.flush()
                    os.fsync(destination.fileno())
                keywords = {key for key, _ in statuses}
                if process.returncode or "DECRYPTION_OKAY" not in keywords or keywords.intersection({"BADMDC", "ERRMDC", "DECRYPTION_FAILED"}):
                    _raise_failure(statuses, "decryption")
                aead = any(key == "DECRYPTION_INFO" and len(value.split()) >= 3 and value.split()[2].isdigit() and int(value.split()[2]) > 0 for key, value in statuses)
                if "GOODMDC" not in keywords and not aead:
                    raise CryptoError("This message has no verified integrity protection. No decrypted file was saved.", "integrity_failed")
                signatures = _signatures(statuses)
                unsigned = all(signature.status == "unsigned" for signature in signatures)
                if not unsigned and any(not signature.valid for signature in signatures):
                    raise CryptoError("The file contains a signature that could not be verified. Check the sender's public key in Kleopatra. No decrypted file was saved.", "signature_failed")
                if require_signature and (unsigned or any(not signature.trusted for signature in signatures)):
                    raise CryptoError("A valid signature from a trusted sender is required. Verify and certify the sender's public key in Kleopatra, then try again. No decrypted file was saved.", "signature_required")
                output = _publish(staged, directory, name, source_path)
                return OperationReport(output_path=output, signatures=signatures, signed=not unsigned, unsigned=unsigned)
        except OSError as exc:
            raise CryptoError("Cannot prepare or save the decrypted file. Check local temporary storage, output permissions and free disk space.", "output_failed") from exc
