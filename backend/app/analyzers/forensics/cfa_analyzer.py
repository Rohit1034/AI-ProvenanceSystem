from __future__ import annotations

import asyncio
import logging
from uuid import UUID

import numpy as np
from PIL import Image

from backend.app.analyzers.base import BaseAnalyzer, AnalyzerResult

logger = logging.getLogger("provenance.analyzers.cfa")


class CFAAnalyzer(BaseAnalyzer):
    name = "cfa_analyzer"
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
            logger.warning("CFA analysis failed: %s", e)
            return self._make_result(
                status="error",
                findings=[{"error": str(e)}],
            )

    def _analyze(self, path: str) -> dict:
        img = Image.open(path).convert("RGB")
        arr = np.array(img, dtype=np.float64)

        cfa_result = self._detect_cfa_artifacts(arr)
        resample_result = self._detect_resampling(arr)

        findings = []
        confidence = 0.5

        if cfa_result["cfa_score"] > 0.6:
            findings.append({
                "type": "cfa_artifacts_present",
                "category": "forensics",
                "description": (
                    "CFA demosaicing artifacts detected — consistent with real camera sensor capture. "
                    "Bayer pattern interpolation traces found."
                ),
                "cfa_score": round(cfa_result["cfa_score"], 4),
                "dominant_pattern": cfa_result["dominant_pattern"],
            })
            confidence = 0.7
        elif cfa_result["cfa_score"] < 0.2:
            findings.append({
                "type": "cfa_artifacts_absent",
                "category": "forensics",
                "description": (
                    "No CFA demosaicing artifacts detected — image was not captured by a "
                    "Bayer-pattern sensor (synthetic, screenshot, or heavily processed)"
                ),
                "cfa_score": round(cfa_result["cfa_score"], 4),
            })
            confidence = 0.65

        if resample_result["resampling_detected"]:
            findings.append({
                "type": "resampling_detected",
                "category": "forensics",
                "description": (
                    f"Periodic resampling artifacts detected (period ~{resample_result['period']:.1f}px) — "
                    "indicates geometric transformation (rotation, scaling, or warping)"
                ),
                "resampling_score": round(resample_result["score"], 4),
                "period": round(resample_result["period"], 2),
            })
            confidence = max(confidence, 0.6)

        if not findings:
            findings.append({
                "type": "cfa_inconclusive",
                "category": "forensics",
                "description": "CFA and resampling analysis inconclusive",
            })

        raw_output = {
            "cfa": {
                k: round(v, 4) if isinstance(v, float) else v
                for k, v in cfa_result.items()
            },
            "resampling": {
                k: round(v, 4) if isinstance(v, (float, np.floating)) else v
                for k, v in resample_result.items()
            },
        }

        return {
            "findings": findings,
            "raw_output": raw_output,
            "confidence": confidence,
        }

    def _detect_cfa_artifacts(self, arr: np.ndarray) -> dict:
        h, w, _ = arr.shape

        patterns = {
            "RGGB": [(0, 0, 0), (0, 1, 1), (1, 0, 1), (1, 1, 2)],
            "BGGR": [(0, 0, 2), (0, 1, 1), (1, 0, 1), (1, 1, 0)],
            "GRBG": [(0, 0, 1), (0, 1, 0), (1, 0, 2), (1, 1, 1)],
            "GBRG": [(0, 0, 1), (0, 1, 2), (1, 0, 0), (1, 1, 1)],
        }

        best_score = 0.0
        best_pattern = "none"

        for pattern_name, positions in patterns.items():
            score = self._evaluate_bayer_pattern(arr, positions)
            if score > best_score:
                best_score = score
                best_pattern = pattern_name

        inter_pixel_corr = self._inter_pixel_correlation(arr)

        combined_score = best_score * 0.6 + inter_pixel_corr * 0.4

        return {
            "cfa_score": combined_score,
            "dominant_pattern": best_pattern,
            "pattern_score": best_score,
            "inter_pixel_correlation": inter_pixel_corr,
        }

    def _evaluate_bayer_pattern(
        self, arr: np.ndarray, positions: list[tuple[int, int, int]]
    ) -> float:
        h, w, _ = arr.shape
        scores: list[float] = []

        sample_h = min(h, 512)
        sample_w = min(w, 512)
        region = arr[:sample_h, :sample_w]

        for dy, dx, ch in positions:
            sampled = region[dy::2, dx::2, ch]
            if sampled.size < 4:
                continue

            neighbors_h = (region[dy::2, max(0, dx - 1)::2, ch][:sampled.shape[0], :sampled.shape[1]]
                           if dx > 0 else sampled)
            diff = np.abs(sampled - neighbors_h)
            pred_error = float(np.mean(diff))

            other_channels = [c for c in range(3) if c != ch]
            cross_diff = 0.0
            for oc in other_channels:
                oc_sampled = region[dy::2, dx::2, oc][:sampled.shape[0], :sampled.shape[1]]
                cross_diff += float(np.mean(np.abs(sampled - oc_sampled)))
            cross_diff /= len(other_channels) if other_channels else 1

            if cross_diff > 0:
                ratio = pred_error / cross_diff
                scores.append(1.0 - min(ratio, 1.0))

        return float(np.mean(scores)) if scores else 0.0

    def _inter_pixel_correlation(self, arr: np.ndarray) -> float:
        gray = np.mean(arr, axis=2)
        h, w = gray.shape
        if h < 4 or w < 4:
            return 0.0

        even_rows = gray[0::2, :]
        odd_rows = gray[1::2, :]
        min_rows = min(even_rows.shape[0], odd_rows.shape[0])

        if min_rows < 2:
            return 0.0

        diff_even = np.abs(np.diff(even_rows[:min_rows], axis=1))
        diff_odd = np.abs(np.diff(odd_rows[:min_rows], axis=1))

        even_energy = float(np.mean(diff_even))
        odd_energy = float(np.mean(diff_odd))

        if even_energy + odd_energy == 0:
            return 0.0

        asymmetry = abs(even_energy - odd_energy) / (even_energy + odd_energy)

        return min(asymmetry * 5, 1.0)

    def _detect_resampling(self, arr: np.ndarray) -> dict:
        gray = np.mean(arr, axis=2)
        h, w = gray.shape

        row_derivatives = np.diff(gray, axis=1)
        col_derivatives = np.diff(gray, axis=0)

        row_autocorr = self._periodic_autocorrelation(row_derivatives)
        col_autocorr = self._periodic_autocorrelation(col_derivatives)

        row_peaks = self._find_periodic_peaks(row_autocorr)
        col_peaks = self._find_periodic_peaks(col_autocorr)

        detected = False
        score = 0.0
        period = 0.0

        if row_peaks:
            best = max(row_peaks, key=lambda p: p[1])
            if best[1] > 0.15:
                detected = True
                score = best[1]
                period = best[0]

        if col_peaks:
            best = max(col_peaks, key=lambda p: p[1])
            if best[1] > score:
                detected = True
                score = best[1]
                period = best[0]

        return {
            "resampling_detected": detected,
            "score": score,
            "period": period,
            "row_peaks": [(p, round(s, 4)) for p, s in row_peaks[:3]],
            "col_peaks": [(p, round(s, 4)) for p, s in col_peaks[:3]],
        }

    def _periodic_autocorrelation(self, signal_2d: np.ndarray) -> np.ndarray:
        avg_row = np.mean(np.abs(signal_2d), axis=0)
        n = len(avg_row)
        if n < 10:
            return np.array([])

        avg_row = avg_row - np.mean(avg_row)
        result = np.correlate(avg_row, avg_row, mode="full")
        result = result[n - 1:]
        if result[0] != 0:
            result = result / result[0]
        return result

    def _find_periodic_peaks(
        self, autocorr: np.ndarray
    ) -> list[tuple[float, float]]:
        if len(autocorr) < 5:
            return []

        peaks: list[tuple[float, float]] = []
        for i in range(2, len(autocorr) - 1):
            if autocorr[i] > autocorr[i - 1] and autocorr[i] > autocorr[i + 1]:
                if autocorr[i] > 0.1:
                    peaks.append((float(i), float(autocorr[i])))

        peaks.sort(key=lambda p: p[1], reverse=True)
        return peaks[:5]
