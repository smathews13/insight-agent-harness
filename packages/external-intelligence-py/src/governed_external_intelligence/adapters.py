"""Local filesystem test adapters.

No Databricks SDK or cloud client is provided here. Production code must
implement the governed UC Volume and managed-table ports from ``core``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .core import NormalizedClaim, QuarantineRecord, RawSnapshot


class ImmutableSnapshotError(RuntimeError):
    """Raised when a caller attempts to replace an existing snapshot."""


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")


_PATH_COMPONENT = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,95}$")


def _validate_component(value: str) -> str:
    if not _PATH_COMPONENT.fullmatch(value):
        raise ValueError("storage path component is invalid")
    return value


@contextmanager
def _open_directory(root: Path, components: Sequence[str]) -> Iterator[int]:
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(root, flags)
    try:
        for raw_component in components:
            component = _validate_component(raw_component)
            try:
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                os.mkdir(component, mode=0o700, dir_fd=descriptor)
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        yield descriptor
    finally:
        os.close(descriptor)


def _read_file(directory_descriptor: int, filename: str) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(_validate_component(filename), flags, dir_fd=directory_descriptor)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError("storage entry is not a regular file")
        chunks = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, content: bytes) -> None:
    remaining = memoryview(content)
    while remaining:
        written = os.write(descriptor, remaining)
        remaining = remaining[written:]


def _write_once(
    root: Path, directory_components: Sequence[str], filename: str, content: bytes
) -> None:
    with _open_directory(root, directory_components) as directory_descriptor:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(
                _validate_component(filename),
                flags,
                mode=0o400,
                dir_fd=directory_descriptor,
            )
        except FileExistsError as exc:
            if _read_file(directory_descriptor, filename) == content:
                return
            raise ImmutableSnapshotError(
                f"refusing to replace immutable snapshot file: {filename}"
            ) from exc
        try:
            _write_all(descriptor, content)
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o400)
        finally:
            os.close(descriptor)


def _append(
    root: Path, directory_components: Sequence[str], filename: str, content: bytes
) -> None:
    with _open_directory(root, directory_components) as directory_descriptor:
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(
            _validate_component(filename),
            flags,
            mode=0o600,
            dir_fd=directory_descriptor,
        )
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise OSError("storage entry is not a regular file")
            _write_all(descriptor, content)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _read_optional(
    root: Path, directory_components: Sequence[str], filename: str
) -> bytes | None:
    try:
        with _open_directory(root, directory_components) as directory_descriptor:
            return _read_file(directory_descriptor, filename)
    except FileNotFoundError:
        return None


class LocalFilesystemAdapter:
    """Deterministic local adapter for tests and offline development only."""

    def __init__(self, root: Path) -> None:
        candidate = Path(root)
        candidate.mkdir(parents=True, exist_ok=True)
        self.root = candidate.resolve(strict=True)

    def put_once(self, snapshot: RawSnapshot, body: bytes) -> None:
        if len(body) != snapshot.byte_count:
            raise ValueError("snapshot byte_count does not match body")
        if hashlib.sha256(body).hexdigest() != snapshot.content_hash:
            raise ValueError("snapshot content_hash does not match body")
        directory = ("raw", snapshot.source_id)
        _write_once(self.root, directory, snapshot.snapshot_id + ".body", body)
        try:
            _write_once(
                self.root,
                directory,
                snapshot.snapshot_id + ".metadata.json",
                _canonical_bytes(snapshot.to_metadata()),
            )
        except Exception:
            # A body is never removed or rewritten after it has been admitted.
            # An operator can repair missing metadata, but cannot mutate bytes.
            raise

    def read_snapshot(self, snapshot: RawSnapshot) -> bytes:
        content = _read_optional(
            self.root,
            ("raw", snapshot.source_id),
            snapshot.snapshot_id + ".body",
        )
        if content is None:
            raise FileNotFoundError(snapshot.snapshot_id)
        return content

    def append(self, claims: Sequence[NormalizedClaim]) -> None:
        if not claims:
            return
        _append(
            self.root,
            ("managed",),
            "claims.jsonl",
            b"".join(_canonical_bytes(claim.to_record()) for claim in claims),
        )

    def put_quarantined(
        self, snapshot: RawSnapshot, body: bytes, record: QuarantineRecord
    ) -> None:
        if len(body) != snapshot.byte_count:
            raise ValueError("quarantined snapshot byte_count does not match body")
        if hashlib.sha256(body).hexdigest() != snapshot.content_hash:
            raise ValueError("quarantined snapshot content_hash does not match body")
        directory = ("quarantine", "raw", snapshot.source_id)
        _write_once(self.root, directory, snapshot.snapshot_id + ".body", body)
        _write_once(
            self.root,
            directory,
            snapshot.snapshot_id + ".metadata.json",
            _canonical_bytes(snapshot.to_metadata()),
        )
        value = {
            "snapshot_ref": record.snapshot_ref,
            "source_id": record.source_id,
            "retrieved_at": record.retrieved_at,
            "finding_codes": list(record.finding_codes),
            "content_hash": record.content_hash,
        }
        _append(
            self.root,
            ("quarantine",),
            "records.jsonl",
            _canonical_bytes(value),
        )

    def claim_records(self) -> tuple[Mapping[str, Any], ...]:
        content = _read_optional(self.root, ("managed",), "claims.jsonl")
        if content is None:
            return ()
        return tuple(json.loads(line) for line in content.decode("utf-8").splitlines())

    def quarantine_records(self) -> tuple[Mapping[str, Any], ...]:
        content = _read_optional(self.root, ("quarantine",), "records.jsonl")
        if content is None:
            return ()
        return tuple(json.loads(line) for line in content.decode("utf-8").splitlines())
