from __future__ import annotations

import asyncio
import logging
from uuid import UUID

import numpy as np
from PIL import Image

from backend.app.analyzers.base import BaseAnalyzer, AnalyzerResult

logger = logging.getLogger("provenance.analyzers.statistics")


class StatisticsAnalyzer(BaseAnalyzer):
    name = "statistics_analyzer"
    version = "0.1.0"

    async def analyze(self, image_path: str, analysis_id: UUID) -> AnalyzerResult:
        try:
            result = await asyncio.to_thread(self._compute_stats, image_path)
            return self._make_result(
                status="completed",
                confidence=result.get("confidence", 0.5),
                findings=result["findings"],
                raw_output=result["raw_output"],
            )
        except Exception as e:
            logger.warning("Statistics analysis failed: %s", e)
            return self._make_result(
                status="error",
                findings=[{"error": str(e)}],
            )

    def _compute_stats(self, path: str) -> dict:
        img = Image.open(path).convert("RGB")
        arr = np.array(img, dtype=np.float64)

        channels = {"red": arr[:, :, 0], "green": arr[:, :, 1], "blue": arr[:, :, 2]}

        channel_stats = {}
        for name, ch in channels.items():
            channel_stats[name] = {
                "mean": round(float(np.mean(ch)), 2),
                "std": round(float(np.std(ch)), 2),
                "min": int(np.min(ch)),
                "max": int(np.max(ch)),
                "median": round(float(np.median(ch)), 2),
                "skewness": round(float(self._skewness(ch)), 4),
                "kurtosis": round(float(self._kurtosis(ch)), 4),
            }

            hist, _ = np.histogram(ch.ravel(), bins=256, range=(0, 255))
            unique_values = int(np.count_nonzero(hist))
            channel_stats[name]["unique_values"] = unique_values
            channel_stats[name]["value_coverage"] = round(unique_values / 256, 4)

        gray = np.mean(arr, axis=2)
        noise_level = self._estimate_noise(gray)
        laplacian_var = self._laplacian_variance(gray)

        saturation = self._compute_saturation(arr)
        sat_stats = {
            "mean": round(float(np.mean(saturation)), 4),
            "std": round(float(np.std(saturation)), 4),
            "low_sat_ratio": round(float(np.mean(saturation < 0.1)), 4),
            "high_sat_ratio": round(float(np.mean(saturation > 0.8)), 4),
        }

        findings = []
        confidence = 0.5

        avg_coverage = np.mean([cs["value_coverage"] for cs in channel_stats.values()])
        avg_std = np.mean([cs["std"] for cs in channel_stats.values()])

        if noise_level < 0.3 and laplacian_var < 10:
            findings.append({
                "type": "low_noise_smooth",
                "category": "forensics",
                "description": "Unusually low noise level and smooth texture — may indicate synthetic/AI-generated content",
                "noise_level": round(noise_level, 3),
                "laplacian_variance": round(laplacian_var, 2),
            })
            confidence = 0.65

        elif noise_level > 15.0:
            findings.append({
                "type": "high_noise",
                "category": "forensics",
                "description": "High noise level — consistent with high-ISO camera capture or heavy processing",
                "noise_level": round(noise_level, 3),
            })
            confidence = 0.55

        if avg_coverage < 0.5:
            findings.append({
                "type": "limited_color_range",
                "category": "forensics",
                "description": "Limited color value range — may indicate synthetic origin or heavy quantization",
                "average_coverage": round(avg_coverage, 4),
            })
            confidence = max(confidence, 0.6)

        if sat_stats["low_sat_ratio"] > 0.8:
            findings.append({
                "type": "mostly_desaturated",
                "category": "forensics",
                "description": "Image is predominantly desaturated",
                "low_saturation_ratio": sat_stats["low_sat_ratio"],
            })

        if not findings:
            findings.append({
                "type": "statistics_normal",
                "category": "forensics",
                "description": "Image statistics within normal parameters",
            })

        raw_output = {
            "channel_stats": channel_stats,
            "noise_level": round(noise_level, 3),
            "laplacian_variance": round(laplacian_var, 2),
            "saturation": sat_stats,
            "dimensions": {"width": img.width, "height": img.height},
        }

        return {
            "findings": findings,
            "raw_output": raw_output,
            "confidence": confidence,
        }

    def _skewness(self, data: np.ndarray) -> float:
        flat = data.ravel()
        m = np.mean(flat)
        s = np.std(flat)
        if s == 0:
            return 0.0
        return float(np.mean(((flat - m) / s) ** 3))

    def _kurtosis(self, data: np.ndarray) -> float:
        flat = data.ravel()
        m = np.mean(flat)
        s = np.std(flat)
        if s == 0:
            return 0.0
        return float(np.mean(((flat - m) / s) ** 4) - 3)

    def _estimate_noise(self, gray: np.ndarray) -> float:
        h, w = gray.shape
        if h < 3 or w < 3:
            return 0.0
        kernel = np.array([
            [1, -2, 1],
            [-2, 4, -2],
            [1, -2, 1],
        ], dtype=np.float64)

        from scipy.signal import convolve2d
        convolved = convolve2d(gray, kernel, mode="valid")
        sigma = np.sum(np.abs(convolved))
        sigma = sigma * (1.4826 / 6.0) / ((h - 2) * (w - 2))
        return float(sigma)

    def _laplacian_variance(self, gray: np.ndarray) -> float:
        kernel = np.array([[0, 1, 0], [1, -4, 1], [0, 1, 0]], dtype=np.float64)
        from scipy.signal import convolve2d
        lap = convolve2d(gray, kernel, mode="valid")
        return float(np.var(lap))

    def _compute_saturation(self, rgb: np.ndarray) -> np.ndarray:
        r, g, b = rgb[:, :, 0], rgb[:, :, 1], rgb[:, :, 2]
        max_c = np.maximum(np.maximum(r, g), b)
        min_c = np.minimum(np.minimum(r, g), b)
        denom = max_c.copy()
        denom[denom == 0] = 1
        return (max_c - min_c) / denom
