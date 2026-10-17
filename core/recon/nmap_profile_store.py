"""Bounded, versioned storage for offline Nmap configuration only.

No target, scope, executable or runtime capability is part of this format.
Loading never creates a directory or repairs a damaged document.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from PySide6.QtCore import QLockFile, QStandardPaths

from core.recon.nmap_profiles import (
    BUILTIN_PROFILES, NmapScanProfile, ProfileValidationError,
    profile_from_dict, profile_to_dict,
)
from core.session_persistence import save_session as _atomic_write_json


PROFILE_SCHEMA = "websecsuite.nmap.profiles"
PROFILE_VERSION = 1
MAX_PROFILE_DOCUMENT_BYTES = 256 * 1024
MAX_CUSTOM_PROFILES = 64


class ProfileStorageError(ValueError):
    """The complete profile collection could not be safely read or saved."""


def default_profile_path() -> Path:
    """Use the OS user configuration directory, independent of Qt app naming."""
    location = QStandardPaths.writableLocation(QStandardPaths.GenericConfigLocation)
    root = Path(location) if location else Path.home() / ".config"
    return root / "WebSecSuite" / "nmap_profiles.json"


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProfileStorageError("Profile JSON contains a duplicate field.")
        result[key] = value
    return result


def _validate_document(data) -> tuple[NmapScanProfile, ...]:
    if not isinstance(data, dict) or set(data) != {"schema", "version", "profiles"}:
        raise ProfileStorageError("Expected only schema, version and profiles in the profile document.")
    if data["schema"] != PROFILE_SCHEMA:
        raise ProfileStorageError("Unrecognized Nmap profile schema.")
    if type(data["version"]) is not int or data["version"] != PROFILE_VERSION:
        raise ProfileStorageError("Unsupported Nmap profile version; expected version 1.")
    entries = data["profiles"]
    if not isinstance(entries, list) or len(entries) > MAX_CUSTOM_PROFILES:
        raise ProfileStorageError(f"Profiles must be a list of at most {MAX_CUSTOM_PROFILES} custom profiles.")
    profiles, identities = [], set()
    for entry in entries:
        try:
            profile = profile_from_dict(entry)
        except ProfileValidationError as exc:
            raise ProfileStorageError(f"Invalid custom profile: {exc}") from exc
        if profile.is_builtin:
            raise ProfileStorageError("Built-in profiles cannot be stored in the custom profile file.")
        if profile.profile_id in identities:
            raise ProfileStorageError("Duplicate custom profile ID.")
        identities.add(profile.profile_id)
        profiles.append(profile)
    return tuple(profiles)


def _parse_document(raw: bytes) -> tuple[NmapScanProfile, ...]:
    if len(raw) > MAX_PROFILE_DOCUMENT_BYTES:
        raise ProfileStorageError("Nmap profile document exceeds the 256 KiB limit.")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ProfileStorageError("Invalid Nmap profile JSON; the original file has been preserved.") from exc
    return _validate_document(data)


class NmapProfileStore:
    """Own saved custom profiles; built-ins are always supplied by the catalog.

    A load error blocks mutations for this instance, preserving the original
    file for manual recovery. External changes also require reopening the app.
    """

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path is not None else default_profile_path()
        self._profiles: tuple[NmapScanProfile, ...] = ()
        self._loaded_bytes: bytes | None = None
        self.load_error = ""
        try:
            raw = self._read_bytes()
            profiles = _parse_document(raw) if raw is not None else ()
        except (OSError, ProfileStorageError) as exc:
            self.load_error = f"Could not load custom profiles: {exc} Saving is disabled; the file is preserved."
        else:
            self._loaded_bytes, self._profiles = raw, profiles

    @property
    def profiles(self) -> tuple[NmapScanProfile, ...]:
        return self._profiles

    @property
    def all_profiles(self) -> tuple[NmapScanProfile, ...]:
        return BUILTIN_PROFILES + self._profiles

    @property
    def writable(self) -> bool:
        return not self.load_error

    def _read_bytes(self) -> bytes | None:
        try:
            with self.path.open("rb") as handle:
                raw = handle.read(MAX_PROFILE_DOCUMENT_BYTES + 1)
        except FileNotFoundError:
            return None
        if len(raw) > MAX_PROFILE_DOCUMENT_BYTES:
            raise ProfileStorageError("Nmap profile document exceeds the 256 KiB limit.")
        return raw

    def save(self, profile: NmapScanProfile) -> None:
        """Create or replace one validated custom profile, retaining its ID."""
        if not isinstance(profile, NmapScanProfile) or profile.is_builtin:
            raise ProfileStorageError("Only validated custom profiles can be saved.")
        candidate = tuple(profile if existing.profile_id == profile.profile_id else existing
                          for existing in self._profiles)
        if not any(existing.profile_id == profile.profile_id for existing in self._profiles):
            candidate += (profile,)
        self._commit(candidate)

    def delete(self, profile_id: str) -> None:
        """Delete only a saved custom profile, never a built-in or unsaved ID."""
        if not any(profile.profile_id == profile_id for profile in self._profiles):
            raise ProfileStorageError("Select a saved custom profile to delete.")
        self._commit(tuple(profile for profile in self._profiles if profile.profile_id != profile_id))

    def _commit(self, profiles: tuple[NmapScanProfile, ...]) -> None:
        if not self.writable:
            raise ProfileStorageError(self.load_error)
        document = {"schema": PROFILE_SCHEMA, "version": PROFILE_VERSION,
                    "profiles": [profile_to_dict(profile) for profile in profiles]}
        validated = _validate_document(document)
        # Match the shared writer's native text-mode newline translation.
        serialized = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
        encoded = serialized.replace("\n", os.linesep).encode("utf-8")
        if len(encoded) > MAX_PROFILE_DOCUMENT_BYTES:
            raise ProfileStorageError("Nmap profile document exceeds the 256 KiB limit.")
        lock = QLockFile(str(self.path) + ".lock")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if not lock.tryLock(0):
                raise ProfileStorageError("Another profile manager is saving, or the profile directory is not writable. Try again.")
            if self._read_bytes() != self._loaded_bytes:
                raise ProfileStorageError("Profile file changed outside this manager. Reopen the application before saving.")
            # This existing helper accepts any JSON mapping and already flushes,
            # fsyncs, closes, replaces, and cleans up same-directory temp files.
            # Its Scraper session schema and serialization remain unchanged.
            _atomic_write_json(self.path, document)
            self._profiles, self._loaded_bytes = validated, encoded
        except OSError as exc:
            raise ProfileStorageError(f"Could not save custom profiles: {exc}") from exc
        finally:
            if lock.isLocked():
                lock.unlock()
