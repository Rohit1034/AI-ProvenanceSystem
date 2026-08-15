from __future__ import annotations

import asyncio
import logging
import os
from uuid import UUID

from backend.app.analyzers.base import BaseAnalyzer, AnalyzerResult
from backend.app.core.config import get_settings

logger = logging.getLogger("provenance.analyzers.file_validator")

MAGIC_BYTES = {
    b"\xff\xd8\xff": "jpeg",
    b"\x89PNG\r\n\x1a\n": "png",
    b"RIFF": "webp",
    b"II\x2a\x00": "tiff_le",
    b"MM\x00\x2a": "tiff_be",
    b"BM": "bmp",
}

MIME_TO_FORMAT = {
    "image/jpeg": "jpeg",
    "image/png": "png",
    "image/webp": "webp",
    "image/tiff": "tiff",
    "image/bmp": "bmp",
}


class FileValidator(BaseAnalyzer):
    name = "file_validator"
    version = "0.1.0"

    async def analyze(self, image_path: str, analysis_id: UUID) -> AnalyzerResult:
        findings: list[dict] = []
        limitations: list[str] = []
        valid = True

        if not os.path.isfile(image_path):
            return self._make_result(
                status="error",
                findings=[{"error": "File not found", "path": image_path}],
            )

        file_size = os.path.getsize(image_path)
        settings = get_settings()

        if file_size > settings.max_upload_bytes:
            findings.append({
                "type": "validation_error",
                "issue": "file_too_large",
                "file_size": file_size,
                "max_size": settings.max_upload_bytes,
            })
            valid = False

        if file_size == 0:
            findings.append({
                "type": "validation_error",
                "issue": "empty_file",
            })
            valid = False
            return self._make_result(
                status="completed",
                confidence=None,
                findings=findings,
            )

        with open(image_path, "rb") as f:
            header = f.read(16)

        detected_format = self._detect_format(header)
        if detected_format:
            findings.append({
                "type": "format_detection",
                "detected_format": detected_format,
                "method": "magic_bytes",
            })
        else:
            findings.append({
                "type": "validation_warning",
                "issue": "unknown_magic_bytes",
                "header_hex": header[:8].hex(),
            })
            valid = False

        if detected_format == "webp" and header[:4] == b"RIFF":
            if len(header) >= 12 and header[8:12] != b"WEBP":
                findings.append({
                    "type": "validation_error",
                    "issue": "riff_not_webp",
                })
                valid = False

        mime_result = await self._check_mime(image_path)
        if mime_result:
            findings.append(mime_result)
            mime_format = MIME_TO_FORMAT.get(mime_result.get("mime_type", ""))
            if mime_format and detected_format and mime_format != detected_format:
                if not (detected_format.startswith("tiff") and mime_format == "tiff"):
                    findings.append({
                        "type": "validation_warning",
                        "issue": "mime_magic_mismatch",
                        "mime_format": mime_format,
                        "magic_format": detected_format,
                    })

        ext = os.path.splitext(image_path)[1].lower()
        ext_format = self._ext_to_format(ext)
        if ext_format and detected_format and ext_format != detected_format:
            if not (detected_format.startswith("tiff") and ext_format == "tiff"):
                findings.append({
                    "type": "validation_warning",
                    "issue": "extension_mismatch",
                    "extension": ext,
                    "expected_format": ext_format,
                    "actual_format": detected_format,
                })

        bomb_check = await self._check_decompression_bomb(image_path)
        if bomb_check:
            findings.append(bomb_check)
            if bomb_check.get("issue") == "decompression_bomb":
                valid = False

        return self._make_result(
            status="completed",
            confidence=1.0 if valid else None,
            findings=findings,
            raw_output={
                "valid": valid,
                "file_size": file_size,
                "detected_format": detected_format,
            },
        )

    def _detect_format(self, header: bytes) -> str | None:
        for magic, fmt in MAGIC_BYTES.items():
            if header[:len(magic)] == magic:
                return fmt
        return None

    def _ext_to_format(self, ext: str) -> str | None:
        mapping = {
            ".jpg": "jpeg", ".jpeg": "jpeg",
            ".png": "png",
            ".webp": "webp",
            ".tiff": "tiff", ".tif": "tiff",
            ".bmp": "bmp",
        }
        return mapping.get(ext)

    async def _check_mime(self, path: str) -> dict | None:
        try:
            import magic
            mime = await asyncio.to_thread(magic.from_file, path, mime=True)
            return {"type": "mime_detection", "mime_type": mime}
        except ImportError:
            return {"type": "mime_detection", "status": "python-magic not available"}
        except Exception as e:
            return {"type": "mime_detection", "status": "error", "error": str(e)}

    async def _check_decompression_bomb(self, path: str) -> dict | None:
        try:
            from PIL import Image
            Image.MAX_IMAGE_PIXELS = 178_956_970  # ~13k x 13k

            def _check():
                try:
                    with Image.open(path) as img:
                        w, h = img.size
                        pixels = w * h
                        if pixels > Image.MAX_IMAGE_PIXELS:
                            return {
                                "type": "security_check",
                                "issue": "decompression_bomb",
                                "pixels": pixels,
                                "max_pixels": Image.MAX_IMAGE_PIXELS,
                            }
                        return {
                            "type": "security_check",
                            "issue": None,
                            "pixels": pixels,
                        }
                except Image.DecompressionBombError:
                    return {
                        "type": "security_check",
                        "issue": "decompression_bomb",
                    }
                except Exception as e:
                    return {
                        "type": "security_check",
                        "issue": "cannot_open",
                        "error": str(e),
                    }

            return await asyncio.to_thread(_check)
        except ImportError:
            return None
