from __future__ import annotations

import abc
import os
import shutil
import uuid
from pathlib import Path

from backend.app.core.config import get_settings


class StorageBackend(abc.ABC):
    @abc.abstractmethod
    async def save(self, data: bytes, filename: str, analysis_id: str) -> str:
        ...

    @abc.abstractmethod
    async def load(self, path: str) -> bytes:
        ...

    @abc.abstractmethod
    async def delete(self, path: str) -> None:
        ...

    @abc.abstractmethod
    async def exists(self, path: str) -> bool:
        ...


class LocalStorageBackend(StorageBackend):
    def __init__(self, base_path: str | None = None) -> None:
        settings = get_settings()
        self.base_path = Path(base_path or settings.STORAGE_LOCAL_PATH)
        self.base_path.mkdir(parents=True, exist_ok=True)

    def _resolve(self, path: str) -> Path:
        resolved = (self.base_path / path).resolve()
        if not str(resolved).startswith(str(self.base_path.resolve())):
            raise ValueError("Path traversal detected")
        return resolved

    async def save(self, data: bytes, filename: str, analysis_id: str) -> str:
        safe_name = f"{uuid.uuid4().hex}_{_sanitize_filename(filename)}"
        rel_path = f"{analysis_id}/{safe_name}"
        full_path = self._resolve(rel_path)
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_bytes(data)
        return rel_path

    async def load(self, path: str) -> bytes:
        return self._resolve(path).read_bytes()

    async def delete(self, path: str) -> None:
        resolved = self._resolve(path)
        if resolved.is_file():
            resolved.unlink()
        elif resolved.is_dir():
            shutil.rmtree(resolved)

    async def exists(self, path: str) -> bool:
        return self._resolve(path).exists()


def _sanitize_filename(filename: str) -> str:
    name = os.path.basename(filename)
    name = "".join(c for c in name if c.isalnum() or c in "._-")
    if not name:
        name = "upload"
    return name[:200]


def get_storage_backend() -> StorageBackend:
    settings = get_settings()
    if settings.STORAGE_BACKEND == "local":
        return LocalStorageBackend()
    raise ValueError(f"Unknown storage backend: {settings.STORAGE_BACKEND}")
