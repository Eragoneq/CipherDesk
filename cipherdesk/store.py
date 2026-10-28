"""Local contact groups contain public fingerprints, never private key material."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import re
import tempfile
import threading
from collections.abc import Iterable

from .models import ContactGroup, Key, StoreError

_FINGERPRINT = re.compile(r"(?:[0-9A-F]{40}|[0-9A-F]{64})\Z")


def normalize_fingerprint(value: str) -> str:
    if not isinstance(value, str):
        raise StoreError("A contact needs a complete public-key fingerprint.", "invalid_fingerprint")
    value = value.replace(" ", "").upper()
    if not _FINGERPRINT.fullmatch(value):
        raise StoreError("Use the complete key fingerprint, rather than an email or short key ID.", "invalid_fingerprint")
    return value


def default_data_dir() -> Path:
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))) / "CipherDesk"
    return Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))) / "CipherDesk"


class GroupStore:
    """Atomic, reload-on-access JSON persistence with locking inside this process."""

    def __init__(self, data_dir: str | Path | None = None) -> None:
        self.data_dir = Path(data_dir) if data_dir is not None else default_data_dir()
        self.path = self.data_dir / "groups.json"
        self._lock = threading.RLock()

    def _read(self) -> dict:
        if not self.path.exists():
            return {"version": 1, "groups": [], "settings": {}}
        try:
            if self.path.is_symlink() or self.path.stat().st_size > 2_000_000:
                raise ValueError("Unsafe configuration file")
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict) or raw.get("version") != 1:
                raise ValueError("Unsupported configuration")
            if not isinstance(raw.get("groups"), list) or not isinstance(raw.get("settings"), dict):
                raise ValueError("Invalid configuration fields")
            seen: set[str] = set()
            for group in raw["groups"]:
                if not isinstance(group, dict) or not isinstance(group.get("fingerprints"), list):
                    raise ValueError("Invalid contact group")
                name = self._name(group.get("name"))
                if name.casefold() in seen or not group["fingerprints"]:
                    raise ValueError("Duplicate or empty contact group")
                seen.add(name.casefold())
                group["name"] = name
                group["fingerprints"] = list(dict.fromkeys(normalize_fingerprint(f) for f in group["fingerprints"]))
            return raw
        except (OSError, ValueError, TypeError, StoreError) as exc:
            raise StoreError(
                "Cannot read local groups. Restore groups.json from a backup or rename it to start again; it has not been replaced.",
                "invalid_config",
            ) from exc

    @staticmethod
    def _name(name: str) -> str:
        if not isinstance(name, str):
            raise StoreError("Enter a group name.", "invalid_group")
        name = name.strip()
        if not name or len(name) > 100 or any(ord(c) < 32 for c in name):
            raise StoreError("Use a group name of 1–100 characters, without control characters.", "invalid_group")
        return name

    def _write(self, data: dict) -> None:
        temporary: str | None = None
        try:
            serialized = json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
            if len(serialized.encode("utf-8")) > 2_000_000:
                raise StoreError("Local groups and settings exceed the size limit.", "invalid_config")
            self.data_dir.mkdir(parents=True, exist_ok=True)
            if self.path.is_symlink() or self.data_dir.is_symlink():
                raise StoreError("The groups location must not be a symbolic link.", "unsafe_path")
            fd, temporary = tempfile.mkstemp(prefix=".groups-", suffix=".tmp", dir=self.data_dir)
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(serialized)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            temporary = None
        except (OSError, TypeError, ValueError) as exc:
            raise StoreError("Cannot save local groups and settings. Check the folder permissions.", "save_failed") from exc
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    def list_groups(self) -> list[ContactGroup]:
        with self._lock:
            return sorted(
                (ContactGroup(g["name"], tuple(g["fingerprints"])) for g in self._read()["groups"]),
                key=lambda group: group.name.casefold(),
            )

    def get_group(self, name: str) -> ContactGroup:
        for group in self.list_groups():
            if group.name.casefold() == name.casefold():
                return group
        raise StoreError("This contact group no longer exists. Refresh the group list.", "missing_group")

    def save_group(self, name: str, fingerprints: Iterable[str], original_name: str | None = None) -> ContactGroup:
        name = self._name(name)
        normalized = tuple(dict.fromkeys(normalize_fingerprint(f) for f in fingerprints))
        if not normalized:
            raise StoreError("Select at least one contact for the group.", "empty_group")
        with self._lock:
            data = self._read()
            existing = next((g for g in data["groups"] if g["name"].casefold() == name.casefold()), None)
            if original_name is None:
                if existing:
                    raise StoreError("A group with that name already exists.", "duplicate_group")
            else:
                original = next((g for g in data["groups"] if g["name"].casefold() == original_name.casefold()), None)
                if original is None:
                    raise StoreError("The group being edited no longer exists.", "missing_group")
                if existing is not None and existing is not original:
                    raise StoreError("A group with that name already exists.", "duplicate_group")
                data["groups"].remove(original)
            data["groups"].append({"name": name, "fingerprints": list(normalized)})
            self._write(data)
        return ContactGroup(name, normalized)

    def delete_group(self, name: str) -> None:
        with self._lock:
            data = self._read()
            remaining = [g for g in data["groups"] if g["name"].casefold() != name.casefold()]
            if len(remaining) == len(data["groups"]):
                raise StoreError("This contact group no longer exists.", "missing_group")
            data["groups"] = remaining
            self._write(data)

    def get_settings(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._read()["settings"])

    def update_settings(self, **values) -> dict:
        with self._lock:
            data = self._read()
            data["settings"].update(copy.deepcopy(values))
            self._write(data)
            return copy.deepcopy(data["settings"])

    def resolve_group(self, name: str, keys: Iterable[Key]) -> list[Key]:
        group = self.get_group(name)
        available = {key.fingerprint: key for key in keys}
        result: list[Key] = []
        for fingerprint in group.fingerprints:
            key = available.get(fingerprint)
            if key is None:
                raise StoreError(
                    f"A saved group member is missing: {fingerprint}. Import that public key in Kleopatra or edit the group.",
                    "missing_key",
                )
            if not key.can_encrypt:
                raise StoreError(f"A group member cannot receive encrypted files: {key.display_name}. {key.reason}", "unusable_key")
            if not key.trusted:
                raise StoreError(f"A group member's key is not certified as valid: {key.display_name}. Verify its fingerprint and certify it in Kleopatra.", "untrusted_key")
            result.append(key)
        return result
