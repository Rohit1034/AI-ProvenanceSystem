from __future__ import annotations

import os
from pathlib import Path
from functools import lru_cache

from pydantic_settings import BaseSettings
from pydantic import field_validator


class Settings(BaseSettings):
    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}

    PROJECT_NAME: str = "Image Provenance System"
    VERSION: str = "0.1.0"
    API_V1_PREFIX: str = "/api/v1"
    DEBUG: bool = False

    DATABASE_URL: str = "postgresql+asyncpg://provenance:provenance@localhost:5432/provenance"
    DATABASE_ECHO: bool = False

    REDIS_URL: str = "redis://localhost:6379/0"

    STORAGE_BACKEND: str = "local"
    STORAGE_LOCAL_PATH: str = "./storage"
    STORAGE_S3_BUCKET: str = ""
    STORAGE_S3_ENDPOINT: str = ""
    STORAGE_S3_ACCESS_KEY: str = ""
    STORAGE_S3_SECRET_KEY: str = ""

    MAX_UPLOAD_SIZE_MB: int = 100
    ALLOWED_MIME_TYPES: list[str] = [
        "image/jpeg",
        "image/png",
        "image/webp",
        "image/tiff",
        "image/bmp",
    ]
    ALLOWED_EXTENSIONS: list[str] = [
        ".jpg", ".jpeg", ".png", ".webp", ".tiff", ".tif", ".bmp",
    ]

    ANALYSIS_TIMEOUT_SECONDS: int = 300
    TEMP_DIR: str = "./tmp"

    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"

    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    RETENTION_HOURS: int = 24

    @field_validator("STORAGE_LOCAL_PATH", "TEMP_DIR")
    @classmethod
    def ensure_path_exists(cls, v: str) -> str:
        Path(v).mkdir(parents=True, exist_ok=True)
        return v

    @property
    def max_upload_bytes(self) -> int:
        return self.MAX_UPLOAD_SIZE_MB * 1024 * 1024


@lru_cache
def get_settings() -> Settings:
    return Settings()
