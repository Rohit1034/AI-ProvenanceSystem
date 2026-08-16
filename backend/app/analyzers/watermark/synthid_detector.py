from __future__ import annotations

import asyncio
import logging
from uuid import UUID

import numpy as np
from PIL import Image

from backend.app.analyzers.base import BaseAnalyzer, AnalyzerResult

logger = logging.getLogger("provenance.analyzers.synthid")


class SynthIDDetector(BaseAnalyzer):
    name = "synthid_detector"
    version = "0.1.0"

    async def analyze(self, image_path: str, analysis_id: UUID) -> AnalyzerResult:
        try:
            result = await asyncio.to_thread(self._detect, image_path)
            return self._make_result(
                status="completed",
                confidence=result["confidence"],
                findings=result["findings"],
                raw_output=result["raw_output"],
                limitations=result["limitations"],
            )
        except Exception as e:
            logger.warning("SynthID detection failed: %s", e)
            return self._make_result(
                status="error",
                findings=[{"error": str(e)}],
            )

    def _detect(self, path: str) -> dict:
        img = Image.open(path).convert("RGB")
        arr = np.array(img, dtype=np.float64)

        freq_features = self._analyze_frequency_domain(arr)
        spatial_features = self._analyze_spatial_patterns(arr)

        score = self._compute_synthid_score(freq_features, spatial_features)

        findings = []
        limitations = [
            "SynthID detection uses heuristic frequency analysis. "
            "Full verification requires Google Cloud SynthID API credentials.",
            "This detector identifies patterns consistent with SynthID embedding "
            "but cannot cryptographically verify the watermark.",
        ]

        if score > 0.7:
            findings.append({
                "type": "synthid_likely_present",
                "category": "watermark",
                "description": "Frequency domain patterns consistent with SynthID watermark embedding detected",
                "score": round(score, 4),
                "spectral_anomaly_score": round(freq_features["spectral_anomaly"], 4),
                "mid_freq_energy_ratio": round(freq_features["mid_freq_ratio"], 4),
            })
        elif score > 0.4:
            findings.append({
                "type": "synthid_inconclusive",
                "category": "watermark",
                "description": "Weak frequency domain patterns — possible SynthID presence but inconclusive",
                "score": round(score, 4),
            })
        else:
            findings.append({
                "type": "synthid_not_detected",
                "category": "watermark",
                "description": "No frequency domain patterns consistent with SynthID detected",
                "score": round(score, 4),
            })

        raw_output = {
            "synthid_score": round(score, 4),
            "frequency_features": {
                k: round(v, 4) if isinstance(v, float) else v
                for k, v in freq_features.items()
            },
            "spatial_features": {
                k: round(v, 4) if isinstance(v, float) else v
                for k, v in spatial_features.items()
            },
        }

        return {
            "findings": findings,
            "raw_output": raw_output,
            "confidence": round(min(score, 0.85), 2),
            "limitations": limitations,
        }

    def _analyze_frequency_domain(self, arr: np.ndarray) -> dict:
        gray = np.mean(arr, axis=2)
        f_transform = np.fft.fft2(gray)
        f_shift = np.fft.fftshift(f_transform)
        magnitude = np.abs(f_shift)
        log_magnitude = np.log1p(magnitude)

        h, w = gray.shape
        cy, cx = h // 2, w // 2

        radius_max = min(cy, cx)
        low_r = int(radius_max * 0.05)
        mid_r_start = int(radius_max * 0.15)
        mid_r_end = int(radius_max * 0.45)
        high_r = int(radius_max * 0.7)

        y_grid, x_grid = np.ogrid[:h, :w]
        dist = np.sqrt((y_grid - cy) ** 2 + (x_grid - cx) ** 2)

        low_mask = dist <= low_r
        mid_mask = (dist >= mid_r_start) & (dist <= mid_r_end)
        high_mask = dist >= high_r

        low_energy = float(np.mean(log_magnitude[low_mask])) if np.any(low_mask) else 0
        mid_energy = float(np.mean(log_magnitude[mid_mask])) if np.any(mid_mask) else 0
        high_energy = float(np.mean(log_magnitude[high_mask])) if np.any(high_mask) else 0

        total_energy = low_energy + mid_energy + high_energy
        mid_freq_ratio = mid_energy / total_energy if total_energy > 0 else 0

        radial_profile = self._radial_profile(log_magnitude, (cy, cx))
        if len(radial_profile) > 10:
            profile_diff = np.diff(radial_profile)
            spectral_anomaly = float(np.std(profile_diff))
        else:
            spectral_anomaly = 0.0

        per_channel_ratios = []
        for c in range(3):
            ch_fft = np.fft.fftshift(np.fft.fft2(arr[:, :, c]))
            ch_mag = np.log1p(np.abs(ch_fft))
            ch_mid = float(np.mean(ch_mag[mid_mask])) if np.any(mid_mask) else 0
            ch_total = float(np.mean(ch_mag))
            if ch_total > 0:
                per_channel_ratios.append(ch_mid / ch_total)

        channel_consistency = float(np.std(per_channel_ratios)) if per_channel_ratios else 0

        return {
            "low_energy": low_energy,
            "mid_energy": mid_energy,
            "high_energy": high_energy,
            "mid_freq_ratio": mid_freq_ratio,
            "spectral_anomaly": spectral_anomaly,
            "channel_consistency": channel_consistency,
        }

    def _analyze_spatial_patterns(self, arr: np.ndarray) -> dict:
        gray = np.mean(arr, axis=2)
        h, w = gray.shape

        block_size = 8
        block_vars = []
        for y in range(0, h - block_size, block_size):
            for x in range(0, w - block_size, block_size):
                block = gray[y:y + block_size, x:x + block_size]
                block_vars.append(float(np.var(block)))

        if block_vars:
            block_var_array = np.array(block_vars)
            uniformity = float(np.std(block_vars) / (np.mean(block_vars) + 1e-10))
            low_var_ratio = float(np.mean(block_var_array < np.median(block_var_array) * 0.1))
        else:
            uniformity = 0
            low_var_ratio = 0

        lsb_planes = []
        for c in range(3):
            channel = arr[:, :, c].astype(np.uint8)
            lsb = channel & 1
            lsb_entropy = self._binary_entropy(lsb)
            lsb_planes.append(lsb_entropy)

        lsb_uniformity = float(np.std(lsb_planes)) if lsb_planes else 0

        return {
            "block_uniformity": uniformity,
            "low_variance_ratio": low_var_ratio,
            "lsb_entropies": [round(e, 4) for e in lsb_planes],
            "lsb_uniformity": lsb_uniformity,
        }

    def _compute_synthid_score(self, freq: dict, spatial: dict) -> float:
        score = 0.0

        if 0.30 < freq["mid_freq_ratio"] < 0.42:
            score += 0.25
        elif 0.25 < freq["mid_freq_ratio"] < 0.50:
            score += 0.10

        if freq["spectral_anomaly"] > 0.5:
            score += 0.15
        elif freq["spectral_anomaly"] > 0.3:
            score += 0.08

        if freq["channel_consistency"] < 0.05:
            score += 0.2
        elif freq["channel_consistency"] < 0.1:
            score += 0.1

        lsb_entropies = spatial.get("lsb_entropies", [])
        if lsb_entropies:
            avg_entropy = np.mean(lsb_entropies)
            if 0.95 < avg_entropy < 1.0:
                score += 0.2
            elif 0.90 < avg_entropy:
                score += 0.1

        if spatial["block_uniformity"] < 0.5:
            score += 0.1

        return min(score, 1.0)

    def _radial_profile(self, data: np.ndarray, center: tuple[int, int]) -> np.ndarray:
        y, x = np.indices(data.shape)
        r = np.sqrt((y - center[0]) ** 2 + (x - center[1]) ** 2).astype(int)
        max_r = min(center[0], center[1], data.shape[0] - center[0], data.shape[1] - center[1])
        r_clipped = np.clip(r, 0, max_r - 1)
        profile = np.bincount(r_clipped.ravel(), weights=data.ravel())
        counts = np.bincount(r_clipped.ravel())
        counts[counts == 0] = 1
        return profile / counts

    def _binary_entropy(self, binary_plane: np.ndarray) -> float:
        p1 = np.mean(binary_plane)
        p0 = 1 - p1
        if p0 <= 0 or p1 <= 0:
            return 0.0
        return float(-p0 * np.log2(p0) - p1 * np.log2(p1))
