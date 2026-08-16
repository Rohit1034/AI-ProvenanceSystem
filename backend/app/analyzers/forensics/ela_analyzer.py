from __future__ import annotations

import asyncio
import io
import logging
import math
from uuid import UUID

import numpy as np
from PIL import Image

from backend.app.analyzers.base import BaseAnalyzer, AnalyzerResult

logger = logging.getLogger("provenance.analyzers.ela")

ELA_QUALITY = 95
GRID_SIZE = 64


class ELAAnalyzer(BaseAnalyzer):
    name = "ela_analyzer"
    version = "0.1.0"

    async def analyze(self, image_path: str, analysis_id: UUID) -> AnalyzerResult:
        try:
            result = await asyncio.to_thread(self._run_ela, image_path)
            return self._make_result(
                status="completed",
                confidence=result.get("confidence", 0.5),
                findings=result["findings"],
                raw_output=result["raw_output"],
            )
        except Exception as e:
            logger.warning("ELA analysis failed: %s", e)
            return self._make_result(
                status="error",
                findings=[{"error": str(e)}],
            )

    def _run_ela(self, path: str) -> dict:
        original = Image.open(path).convert("RGB")
        orig_array = np.array(original, dtype=np.float64)

        buf = io.BytesIO()
        original.save(buf, format="JPEG", quality=ELA_QUALITY)
        buf.seek(0)
        resaved = Image.open(buf).convert("RGB")
        resaved_array = np.array(resaved, dtype=np.float64)

        if orig_array.shape != resaved_array.shape:
            resaved = resaved.resize(
                (original.width, original.height), Image.LANCZOS
            )
            resaved_array = np.array(resaved, dtype=np.float64)

        diff = np.abs(orig_array - resaved_array)
        ela_gray = np.mean(diff, axis=2)

        global_stats = {
            "mean_error": float(np.mean(ela_gray)),
            "max_error": float(np.max(ela_gray)),
            "std_error": float(np.std(ela_gray)),
            "median_error": float(np.median(ela_gray)),
            "quality_used": ELA_QUALITY,
        }

        h, w = ela_gray.shape
        grid_h = max(1, h // GRID_SIZE)
        grid_w = max(1, w // GRID_SIZE)
        grid_means = []
        grid_stds = []

        for gy in range(grid_h):
            for gx in range(grid_w):
                y0 = gy * GRID_SIZE
                y1 = min(y0 + GRID_SIZE, h)
                x0 = gx * GRID_SIZE
                x1 = min(x0 + GRID_SIZE, w)
                block = ela_gray[y0:y1, x0:x1]
                grid_means.append(float(np.mean(block)))
                grid_stds.append(float(np.std(block)))

        grid_means_arr = np.array(grid_means)
        grid_stds_arr = np.array(grid_stds)

        global_mean = float(np.mean(grid_means_arr))
        global_std = float(np.std(grid_means_arr))

        suspicious_blocks = 0
        total_blocks = len(grid_means)
        threshold = global_mean + 2.5 * global_std if global_std > 0 else global_mean * 2

        for m in grid_means:
            if m > threshold and threshold > 0:
                suspicious_blocks += 1

        suspicious_ratio = suspicious_blocks / total_blocks if total_blocks > 0 else 0

        variance_ratio = float(grid_stds_arr.std() / grid_stds_arr.mean()) if grid_stds_arr.mean() > 0 else 0

        findings = []
        confidence = 0.5

        if global_stats["mean_error"] < 0.5 and global_stats["std_error"] < 1.0:
            findings.append({
                "type": "ela_uniform_low_error",
                "category": "forensics",
                "description": "Very low and uniform ELA error — consistent with uncompressed or lossless source",
                "mean_error": global_stats["mean_error"],
            })
            confidence = 0.6

        elif suspicious_ratio > 0.05 and global_std > 1.0:
            findings.append({
                "type": "ela_suspicious_regions",
                "category": "forensics",
                "description": f"ELA detected {suspicious_blocks}/{total_blocks} blocks with anomalous error levels",
                "suspicious_blocks": suspicious_blocks,
                "total_blocks": total_blocks,
                "suspicious_ratio": round(suspicious_ratio, 4),
                "threshold": round(threshold, 2),
            })
            confidence = min(0.5 + suspicious_ratio * 2, 0.85)

        elif variance_ratio > 1.5:
            findings.append({
                "type": "ela_high_variance",
                "category": "forensics",
                "description": "High variance in ELA error distribution across image regions",
                "variance_ratio": round(variance_ratio, 3),
            })
            confidence = 0.6

        else:
            findings.append({
                "type": "ela_normal",
                "category": "forensics",
                "description": "ELA error distribution appears consistent across the image",
            })
            confidence = 0.5

        raw_output = {
            "global_stats": global_stats,
            "grid_analysis": {
                "grid_size": GRID_SIZE,
                "total_blocks": total_blocks,
                "suspicious_blocks": suspicious_blocks,
                "suspicious_ratio": round(suspicious_ratio, 4),
                "mean_of_means": round(global_mean, 3),
                "std_of_means": round(global_std, 3),
                "variance_ratio": round(variance_ratio, 3),
            },
        }

        return {
            "findings": findings,
            "raw_output": raw_output,
            "confidence": confidence,
        }
