from __future__ import annotations

import asyncio
import hashlib
import logging
from uuid import UUID

from backend.app.analyzers.base import BaseAnalyzer, AnalyzerResult

logger = logging.getLogger("provenance.analyzers.hash_generator")


class HashGenerator(BaseAnalyzer):
    name = "hash_generator"
    version = "0.1.0"

    async def analyze(self, image_path: str, analysis_id: UUID) -> AnalyzerResult:
        findings: list[dict] = []

        sha256 = await asyncio.to_thread(self._compute_sha256, image_path)
        findings.append({
            "type": "cryptographic_hash",
            "algorithm": "sha256",
            "value": sha256,
        })

        perceptual_hashes = await self._compute_perceptual_hashes(image_path)
        for algo, value in perceptual_hashes.items():
            findings.append({
                "type": "perceptual_hash",
                "algorithm": algo,
                "value": str(value),
            })

        return self._make_result(
            status="completed",
            confidence=1.0,
            findings=findings,
            raw_output={
                "sha256": sha256,
                "perceptual_hashes": {k: str(v) for k, v in perceptual_hashes.items()},
            },
        )

    def _compute_sha256(self, path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    async def _compute_perceptual_hashes(self, path: str) -> dict:
        try:
            import imagehash
            from PIL import Image

            def _compute():
                hashes = {}
                with Image.open(path) as img:
                    hashes["average_hash"] = imagehash.average_hash(img)
                    hashes["phash"] = imagehash.phash(img)
                    hashes["dhash"] = imagehash.dhash(img)
                    hashes["whash"] = imagehash.whash(img)
                return hashes

            return await asyncio.to_thread(_compute)
        except ImportError:
            logger.warning("imagehash not available, skipping perceptual hashes")
            return {}
        except Exception as e:
            logger.warning("Perceptual hash computation failed: %s", e)
            return {}
