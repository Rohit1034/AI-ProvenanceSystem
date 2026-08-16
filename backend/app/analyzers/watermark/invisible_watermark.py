from __future__ import annotations

import asyncio
import logging
from uuid import UUID

import numpy as np
from PIL import Image

from backend.app.analyzers.base import BaseAnalyzer, AnalyzerResult

logger = logging.getLogger("provenance.analyzers.invisible_watermark")


class InvisibleWatermarkDetector(BaseAnalyzer):
    name = "invisible_watermark_detector"
    version = "0.1.0"

    async def analyze(self, image_path: str, analysis_id: UUID) -> AnalyzerResult:
        try:
            result = await asyncio.to_thread(self._detect, image_path)
            return self._make_result(
                status="completed",
                confidence=result["confidence"],
                findings=result["findings"],
                raw_output=result["raw_output"],
            )
        except Exception as e:
            logger.warning("Invisible watermark detection failed: %s", e)
            return self._make_result(
                status="error",
                findings=[{"error": str(e)}],
            )

    def _detect(self, path: str) -> dict:
        img = Image.open(path).convert("RGB")
        arr = np.array(img, dtype=np.float64)

        dwt_result = self._detect_dwt_watermark(arr)
        lsb_result = self._detect_lsb_steganography(arr)
        dct_result = self._detect_dct_watermark(arr)

        findings = []
        combined_score = 0.0
        weights = {"dwt": 0.4, "lsb": 0.3, "dct": 0.3}

        if dwt_result["detected"]:
            findings.append({
                "type": "dwt_watermark_detected",
                "category": "watermark",
                "description": (
                    "DWT-domain watermark patterns detected — consistent with "
                    "Stable Diffusion invisible-watermark library embedding"
                ),
                "score": round(dwt_result["score"], 4),
                "subband_anomalies": dwt_result["anomalous_subbands"],
            })
            combined_score += dwt_result["score"] * weights["dwt"]
        else:
            combined_score += dwt_result["score"] * weights["dwt"] * 0.3

        if lsb_result["detected"]:
            findings.append({
                "type": "lsb_steganography_detected",
                "category": "watermark",
                "description": "LSB plane entropy anomaly detected — possible spatial steganographic content",
                "score": round(lsb_result["score"], 4),
                "anomalous_channels": lsb_result["anomalous_channels"],
            })
            combined_score += lsb_result["score"] * weights["lsb"]
        else:
            combined_score += lsb_result["score"] * weights["lsb"] * 0.3

        if dct_result["detected"]:
            findings.append({
                "type": "dct_watermark_detected",
                "category": "watermark",
                "description": "DCT coefficient watermark pattern detected in frequency domain",
                "score": round(dct_result["score"], 4),
            })
            combined_score += dct_result["score"] * weights["dct"]
        else:
            combined_score += dct_result["score"] * weights["dct"] * 0.3

        if not findings:
            findings.append({
                "type": "no_watermark_detected",
                "category": "watermark",
                "description": "No invisible watermark patterns detected",
            })

        raw_output = {
            "dwt": dwt_result,
            "lsb": lsb_result,
            "dct": dct_result,
            "combined_score": round(combined_score, 4),
        }

        return {
            "findings": findings,
            "raw_output": raw_output,
            "confidence": round(combined_score, 2),
        }

    def _detect_dwt_watermark(self, arr: np.ndarray) -> dict:
        anomalous_subbands: list[str] = []
        scores: list[float] = []

        for c, cname in enumerate(["R", "G", "B"]):
            channel = arr[:, :, c]
            coeffs = self._haar_dwt2(channel)
            ll, (lh, hl, hh) = coeffs

            for subband, sname in [(lh, "LH"), (hl, "HL"), (hh, "HH")]:
                energy = float(np.mean(np.abs(subband)))
                std = float(np.std(subband))
                kurtosis = self._kurtosis(subband)

                if abs(kurtosis) < 1.5 and energy > 0.5:
                    anomalous_subbands.append(f"{cname}_{sname}")
                    scores.append(0.7)
                elif std > 0 and energy / std > 0.8:
                    scores.append(0.4)
                else:
                    scores.append(0.1)

        avg_score = float(np.mean(scores)) if scores else 0
        detected = len(anomalous_subbands) >= 2

        return {
            "detected": detected,
            "score": avg_score,
            "anomalous_subbands": anomalous_subbands,
        }

    def _detect_lsb_steganography(self, arr: np.ndarray) -> dict:
        anomalous_channels: list[str] = []
        scores: list[float] = []

        for c, cname in enumerate(["R", "G", "B"]):
            channel = arr[:, :, c].astype(np.uint8)

            lsb = channel & 1
            p1 = np.mean(lsb)
            entropy = self._binary_entropy(p1)

            bit1 = (channel >> 1) & 1
            chi2_stat = self._chi_square_lsb(channel)

            if entropy > 0.998 and chi2_stat > 0.9:
                anomalous_channels.append(cname)
                scores.append(0.8)
            elif entropy > 0.995:
                scores.append(0.5)
            else:
                scores.append(0.15)

        avg_score = float(np.mean(scores)) if scores else 0
        detected = len(anomalous_channels) >= 2

        return {
            "detected": detected,
            "score": avg_score,
            "anomalous_channels": anomalous_channels,
        }

    def _detect_dct_watermark(self, arr: np.ndarray) -> dict:
        gray = np.mean(arr, axis=2)
        h, w = gray.shape

        block_size = 8
        ac_coeffs: list[float] = []

        for y in range(0, h - block_size, block_size):
            for x in range(0, w - block_size, block_size):
                block = gray[y:y + block_size, x:x + block_size]
                dct_block = self._dct2(block)
                mid_coeffs = []
                for i in range(block_size):
                    for j in range(block_size):
                        if 2 <= i + j <= 5:
                            mid_coeffs.append(abs(dct_block[i, j]))
                ac_coeffs.extend(mid_coeffs)

        if not ac_coeffs:
            return {"detected": False, "score": 0.0}

        ac_array = np.array(ac_coeffs)
        kurtosis = self._kurtosis(ac_array)
        skewness = self._skewness(ac_array)
        std = float(np.std(ac_array))

        score = 0.0
        if abs(kurtosis) < 2.0:
            score += 0.3
        if abs(skewness) < 0.5:
            score += 0.2
        if std > 0 and float(np.mean(ac_array)) / std > 0.5:
            score += 0.2

        detected = score > 0.5

        return {
            "detected": detected,
            "score": score,
            "kurtosis": round(kurtosis, 4),
            "skewness": round(skewness, 4),
            "ac_std": round(std, 4),
        }

    def _haar_dwt2(self, data: np.ndarray) -> tuple:
        h, w = data.shape
        h2, w2 = h // 2, w // 2
        if h2 == 0 or w2 == 0:
            return data, (np.zeros((1, 1)), np.zeros((1, 1)), np.zeros((1, 1)))

        rows = data[:h2 * 2, :w2 * 2]
        low = (rows[0::2, :] + rows[1::2, :]) / 2.0
        high = (rows[0::2, :] - rows[1::2, :]) / 2.0

        ll = (low[:, 0::2] + low[:, 1::2]) / 2.0
        lh = (low[:, 0::2] - low[:, 1::2]) / 2.0
        hl = (high[:, 0::2] + high[:, 1::2]) / 2.0
        hh = (high[:, 0::2] - high[:, 1::2]) / 2.0

        return ll, (lh, hl, hh)

    def _dct2(self, block: np.ndarray) -> np.ndarray:
        from scipy.fft import dctn
        return dctn(block, type=2, norm="ortho")

    def _kurtosis(self, data: np.ndarray) -> float:
        flat = data.ravel()
        m = np.mean(flat)
        s = np.std(flat)
        if s == 0:
            return 0.0
        return float(np.mean(((flat - m) / s) ** 4) - 3)

    def _skewness(self, data: np.ndarray) -> float:
        flat = data.ravel()
        m = np.mean(flat)
        s = np.std(flat)
        if s == 0:
            return 0.0
        return float(np.mean(((flat - m) / s) ** 3))

    def _binary_entropy(self, p1: float) -> float:
        p0 = 1 - p1
        if p0 <= 0 or p1 <= 0:
            return 0.0
        return float(-p0 * np.log2(p0) - p1 * np.log2(p1))

    def _chi_square_lsb(self, channel: np.ndarray) -> float:
        flat = channel.ravel()
        hist, _ = np.histogram(flat, bins=256, range=(0, 255))
        chi2 = 0.0
        n_pairs = 0
        for i in range(0, 256, 2):
            expected = (hist[i] + hist[i + 1]) / 2.0
            if expected > 0:
                chi2 += (hist[i] - expected) ** 2 / expected
                chi2 += (hist[i + 1] - expected) ** 2 / expected
                n_pairs += 1
        if n_pairs == 0:
            return 0.0
        return 1.0 - chi2 / (n_pairs * 10)
