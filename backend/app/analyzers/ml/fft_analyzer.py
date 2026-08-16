from __future__ import annotations

import asyncio
import logging
from uuid import UUID

import numpy as np
from PIL import Image

from backend.app.analyzers.base import BaseAnalyzer, AnalyzerResult

logger = logging.getLogger("provenance.analyzers.fft")


class FFTSpectrumAnalyzer(BaseAnalyzer):
    name = "fft_spectrum_analyzer"
    version = "0.1.0"

    async def analyze(self, image_path: str, analysis_id: UUID) -> AnalyzerResult:
        try:
            result = await asyncio.to_thread(self._analyze, image_path)
            return self._make_result(
                status="completed",
                confidence=result["confidence"],
                findings=result["findings"],
                raw_output=result["raw_output"],
            )
        except Exception as e:
            logger.warning("FFT spectrum analysis failed: %s", e)
            return self._make_result(
                status="error",
                findings=[{"error": str(e)}],
            )

    def _analyze(self, path: str) -> dict:
        img = Image.open(path).convert("RGB")
        arr = np.array(img, dtype=np.float64)
        gray = np.mean(arr, axis=2)

        radial = self._radial_power_spectrum(gray)
        spectral_features = self._extract_spectral_features(radial)
        grid_artifacts = self._detect_grid_artifacts(gray)
        channel_spectra = self._per_channel_spectral_analysis(arr)

        ai_score = self._compute_ai_score(spectral_features, grid_artifacts, channel_spectra)

        findings = []
        confidence = 0.5

        if ai_score > 0.7:
            findings.append({
                "type": "fft_ai_pattern",
                "category": "ml",
                "description": (
                    "Frequency spectrum exhibits patterns consistent with AI-generated imagery: "
                    "abnormal high-frequency rolloff and spectral regularity"
                ),
                "ai_score": round(ai_score, 4),
                "spectral_slope": round(spectral_features["slope"], 4),
                "high_freq_rolloff": round(spectral_features["high_freq_rolloff"], 4),
            })
            confidence = min(0.5 + ai_score * 0.4, 0.85)

        elif ai_score > 0.4:
            findings.append({
                "type": "fft_mixed_signals",
                "category": "ml",
                "description": "Frequency spectrum shows some atypical patterns but is not definitively AI-characteristic",
                "ai_score": round(ai_score, 4),
            })
            confidence = 0.5

        else:
            findings.append({
                "type": "fft_natural_spectrum",
                "category": "ml",
                "description": "Frequency spectrum is consistent with natural photographic imagery",
                "ai_score": round(ai_score, 4),
            })
            confidence = 0.5

        if grid_artifacts["detected"]:
            findings.append({
                "type": "fft_grid_artifacts",
                "category": "ml",
                "description": (
                    f"Periodic grid artifacts detected at {grid_artifacts['period']:.1f}px spacing — "
                    "possible GAN checkerboard artifacts or upsampling patterns"
                ),
                "period": round(grid_artifacts["period"], 2),
                "strength": round(grid_artifacts["strength"], 4),
            })
            confidence = max(confidence, 0.65)

        raw_output = {
            "spectral_features": {
                k: round(v, 4) if isinstance(v, (float, np.floating)) else v
                for k, v in spectral_features.items()
            },
            "grid_artifacts": {
                k: round(v, 4) if isinstance(v, (float, np.floating)) else v
                for k, v in grid_artifacts.items()
            },
            "channel_spectra": channel_spectra,
            "ai_score": round(ai_score, 4),
        }

        return {
            "findings": findings,
            "raw_output": raw_output,
            "confidence": confidence,
        }

    def _radial_power_spectrum(self, gray: np.ndarray) -> np.ndarray:
        f_transform = np.fft.fft2(gray)
        f_shift = np.fft.fftshift(f_transform)
        power = np.abs(f_shift) ** 2

        h, w = gray.shape
        cy, cx = h // 2, w // 2
        y, x = np.ogrid[:h, :w]
        r = np.sqrt((y - cy) ** 2 + (x - cx) ** 2).astype(int)

        max_r = min(cy, cx)
        r_clipped = np.clip(r, 0, max_r - 1)

        radial_sum = np.bincount(r_clipped.ravel(), weights=power.ravel())
        radial_count = np.bincount(r_clipped.ravel())
        radial_count[radial_count == 0] = 1

        return radial_sum / radial_count

    def _extract_spectral_features(self, radial: np.ndarray) -> dict:
        n = len(radial)
        if n < 10:
            return {"slope": 0, "high_freq_rolloff": 0, "spectral_centroid": 0, "flatness": 0}

        log_radial = np.log1p(radial)

        freqs = np.arange(1, n)
        log_freqs = np.log(freqs)
        log_power = log_radial[1:n]

        valid = np.isfinite(log_freqs) & np.isfinite(log_power)
        if np.sum(valid) < 5:
            slope = 0.0
        else:
            coeffs = np.polyfit(log_freqs[valid], log_power[valid], 1)
            slope = float(coeffs[0])

        low_third = n // 3
        mid_start = n // 3
        mid_end = 2 * n // 3
        high_start = 2 * n // 3

        low_energy = float(np.mean(radial[1:low_third])) if low_third > 1 else 0
        mid_energy = float(np.mean(radial[mid_start:mid_end])) if mid_end > mid_start else 0
        high_energy = float(np.mean(radial[high_start:])) if high_start < n else 0

        high_freq_rolloff = 0.0
        if mid_energy > 0:
            high_freq_rolloff = high_energy / mid_energy

        total_energy = float(np.sum(radial[1:]))
        if total_energy > 0:
            spectral_centroid = float(np.sum(np.arange(1, n) * radial[1:]) / total_energy)
        else:
            spectral_centroid = 0.0

        geometric_mean = float(np.exp(np.mean(np.log(radial[1:] + 1e-10))))
        arithmetic_mean = float(np.mean(radial[1:]))
        flatness = geometric_mean / arithmetic_mean if arithmetic_mean > 0 else 0

        return {
            "slope": slope,
            "high_freq_rolloff": high_freq_rolloff,
            "spectral_centroid": spectral_centroid,
            "flatness": flatness,
            "low_energy": low_energy,
            "mid_energy": mid_energy,
            "high_energy": high_energy,
        }

    def _detect_grid_artifacts(self, gray: np.ndarray) -> dict:
        f_transform = np.fft.fft2(gray)
        f_shift = np.fft.fftshift(f_transform)
        magnitude = np.abs(f_shift)
        log_mag = np.log1p(magnitude)

        h, w = gray.shape
        cy, cx = h // 2, w // 2

        horiz_slice = log_mag[cy, cx + 1:]
        vert_slice = log_mag[cy + 1:, cx]

        h_peaks = self._find_spectral_peaks(horiz_slice)
        v_peaks = self._find_spectral_peaks(vert_slice)

        detected = False
        period = 0.0
        strength = 0.0

        for pos, s in h_peaks:
            if pos > 0:
                p = w / (2 * pos) if pos > 0 else 0
                if 2 < p < 32 and s > 0.5:
                    detected = True
                    period = p
                    strength = s
                    break

        if not detected:
            for pos, s in v_peaks:
                if pos > 0:
                    p = h / (2 * pos) if pos > 0 else 0
                    if 2 < p < 32 and s > 0.5:
                        detected = True
                        period = p
                        strength = s
                        break

        return {
            "detected": detected,
            "period": period,
            "strength": strength,
        }

    def _per_channel_spectral_analysis(self, arr: np.ndarray) -> dict:
        slopes: list[float] = []
        rolloffs: list[float] = []

        for c in range(3):
            channel = arr[:, :, c]
            radial = self._radial_power_spectrum(channel)
            features = self._extract_spectral_features(radial)
            slopes.append(features["slope"])
            rolloffs.append(features["high_freq_rolloff"])

        return {
            "slope_consistency": round(float(np.std(slopes)), 4),
            "rolloff_consistency": round(float(np.std(rolloffs)), 4),
            "slopes": [round(s, 4) for s in slopes],
            "rolloffs": [round(r, 4) for r in rolloffs],
        }

    def _compute_ai_score(
        self, spectral: dict, grid: dict, channel: dict
    ) -> float:
        score = 0.0

        slope = spectral["slope"]
        if slope > -1.5:
            score += 0.25
        elif slope > -2.0:
            score += 0.15

        rolloff = spectral["high_freq_rolloff"]
        if rolloff < 0.05:
            score += 0.2
        elif rolloff < 0.15:
            score += 0.1

        if spectral["flatness"] > 0.1:
            score += 0.15

        if grid["detected"]:
            score += 0.2

        if channel["slope_consistency"] < 0.1:
            score += 0.1

        if channel["rolloff_consistency"] < 0.01:
            score += 0.1

        return min(score, 1.0)

    def _find_spectral_peaks(self, signal: np.ndarray) -> list[tuple[int, float]]:
        if len(signal) < 5:
            return []

        mean = float(np.mean(signal))
        std = float(np.std(signal))
        if std == 0:
            return []

        threshold = mean + 3 * std
        peaks: list[tuple[int, float]] = []

        for i in range(2, len(signal) - 1):
            if signal[i] > signal[i - 1] and signal[i] > signal[i + 1]:
                if signal[i] > threshold:
                    normalized_strength = float((signal[i] - mean) / std)
                    peaks.append((i, normalized_strength))

        peaks.sort(key=lambda p: p[1], reverse=True)
        return peaks[:5]
