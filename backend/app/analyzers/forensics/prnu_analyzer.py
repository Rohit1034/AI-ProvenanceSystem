from __future__ import annotations

import asyncio
import logging
from uuid import UUID

import numpy as np
from PIL import Image

from backend.app.analyzers.base import BaseAnalyzer, AnalyzerResult

logger = logging.getLogger("provenance.analyzers.prnu")


class PRNUAnalyzer(BaseAnalyzer):
    name = "prnu_analyzer"
    version = "0.1.0"

    async def analyze(self, image_path: str, analysis_id: UUID) -> AnalyzerResult:
        try:
            result = await asyncio.to_thread(self._analyze_prnu, image_path)
            return self._make_result(
                status="completed",
                confidence=result["confidence"],
                findings=result["findings"],
                raw_output=result["raw_output"],
            )
        except Exception as e:
            logger.warning("PRNU analysis failed: %s", e)
            return self._make_result(
                status="error",
                findings=[{"error": str(e)}],
            )

    def _analyze_prnu(self, path: str) -> dict:
        img = Image.open(path).convert("RGB")
        arr = np.array(img, dtype=np.float64)

        noise_residual = self._extract_noise_residual(arr)
        noise_stats = self._compute_noise_statistics(noise_residual)
        cross_channel = self._cross_channel_correlation(noise_residual)
        spatial_consistency = self._spatial_noise_consistency(noise_residual)

        findings = []
        confidence = 0.5

        if noise_stats["variance"] < 0.5 and noise_stats["kurtosis"] < 1.0:
            findings.append({
                "type": "synthetic_noise_profile",
                "category": "forensics",
                "description": (
                    "Noise residual has unusually low variance and near-Gaussian distribution — "
                    "inconsistent with physical sensor PRNU"
                ),
                "noise_variance": round(noise_stats["variance"], 4),
                "noise_kurtosis": round(noise_stats["kurtosis"], 4),
            })
            confidence = 0.7

        elif noise_stats["variance"] > 50:
            findings.append({
                "type": "high_noise_residual",
                "category": "forensics",
                "description": "High noise residual — consistent with heavy processing or high-ISO capture",
                "noise_variance": round(noise_stats["variance"], 4),
            })
            confidence = 0.55

        if cross_channel["max_correlation"] > 0.85:
            findings.append({
                "type": "correlated_channel_noise",
                "category": "forensics",
                "description": (
                    "Highly correlated noise across color channels — "
                    "atypical of independent sensor noise, possible synthetic origin"
                ),
                "max_correlation": round(cross_channel["max_correlation"], 4),
                "channel_pair": cross_channel["most_correlated_pair"],
            })
            confidence = max(confidence, 0.65)

        if spatial_consistency["consistency_ratio"] < 0.3:
            findings.append({
                "type": "inconsistent_spatial_noise",
                "category": "forensics",
                "description": "Spatially inconsistent noise — possible local manipulation or compositing",
                "consistency_ratio": round(spatial_consistency["consistency_ratio"], 4),
            })
            confidence = max(confidence, 0.6)

        if not findings:
            findings.append({
                "type": "prnu_consistent_camera",
                "category": "forensics",
                "description": "Noise profile is consistent with authentic camera sensor capture",
            })
            confidence = 0.6

        raw_output = {
            "noise_stats": {
                k: round(v, 4) if isinstance(v, float) else v
                for k, v in noise_stats.items()
            },
            "cross_channel": {
                k: round(v, 4) if isinstance(v, float) else v
                for k, v in cross_channel.items()
            },
            "spatial_consistency": {
                k: round(v, 4) if isinstance(v, float) else v
                for k, v in spatial_consistency.items()
            },
        }

        return {
            "findings": findings,
            "raw_output": raw_output,
            "confidence": confidence,
        }

    def _extract_noise_residual(self, arr: np.ndarray) -> np.ndarray:
        from scipy.ndimage import median_filter
        denoised = np.zeros_like(arr)
        for c in range(3):
            denoised[:, :, c] = median_filter(arr[:, :, c], size=3)
        return arr - denoised

    def _compute_noise_statistics(self, residual: np.ndarray) -> dict:
        per_channel = {}
        for c, name in enumerate(["red", "green", "blue"]):
            ch = residual[:, :, c].ravel()
            per_channel[name] = {
                "mean": float(np.mean(ch)),
                "std": float(np.std(ch)),
                "variance": float(np.var(ch)),
            }

        flat = residual.ravel()
        m = np.mean(flat)
        s = np.std(flat)
        if s > 0:
            kurtosis = float(np.mean(((flat - m) / s) ** 4) - 3)
            skewness = float(np.mean(((flat - m) / s) ** 3))
        else:
            kurtosis = 0.0
            skewness = 0.0

        return {
            "variance": float(np.var(flat)),
            "std": float(np.std(flat)),
            "kurtosis": kurtosis,
            "skewness": skewness,
            "per_channel": per_channel,
        }

    def _cross_channel_correlation(self, residual: np.ndarray) -> dict:
        r = residual[:, :, 0].ravel()
        g = residual[:, :, 1].ravel()
        b = residual[:, :, 2].ravel()

        def _corr(a: np.ndarray, b: np.ndarray) -> float:
            a_m = a - np.mean(a)
            b_m = b - np.mean(b)
            denom = np.sqrt(np.sum(a_m ** 2) * np.sum(b_m ** 2))
            if denom == 0:
                return 0.0
            return float(np.sum(a_m * b_m) / denom)

        rg = _corr(r, g)
        rb = _corr(r, b)
        gb = _corr(g, b)

        pairs = {"R-G": rg, "R-B": rb, "G-B": gb}
        max_pair = max(pairs, key=lambda k: abs(pairs[k]))

        return {
            "rg_correlation": rg,
            "rb_correlation": rb,
            "gb_correlation": gb,
            "max_correlation": abs(pairs[max_pair]),
            "most_correlated_pair": max_pair,
        }

    def _spatial_noise_consistency(self, residual: np.ndarray) -> dict:
        gray_residual = np.mean(np.abs(residual), axis=2)
        h, w = gray_residual.shape

        grid_size = 64
        block_variances = []
        for y in range(0, h - grid_size, grid_size):
            for x in range(0, w - grid_size, grid_size):
                block = gray_residual[y:y + grid_size, x:x + grid_size]
                block_variances.append(float(np.var(block)))

        if len(block_variances) < 4:
            return {"consistency_ratio": 0.5, "block_count": len(block_variances)}

        bv = np.array(block_variances)
        mean_var = float(np.mean(bv))
        std_var = float(np.std(bv))

        consistency = 1.0 - (std_var / (mean_var + 1e-10))
        consistency = max(0, min(1, consistency))

        return {
            "consistency_ratio": consistency,
            "mean_block_variance": mean_var,
            "std_block_variance": std_var,
            "block_count": len(block_variances),
        }
