from __future__ import annotations

import asyncio
import logging
from uuid import UUID

import numpy as np
from PIL import Image

from backend.app.analyzers.base import BaseAnalyzer, AnalyzerResult

logger = logging.getLogger("provenance.analyzers.ai_classifier")


class AIClassifier(BaseAnalyzer):
    """
    Multi-signal AI image classifier that combines frequency domain,
    texture, and statistical features to distinguish AI-generated images
    from authentic photographs.

    Uses a hand-tuned feature extraction pipeline rather than a deep
    learning model, producing calibrated probability estimates.
    """

    name = "ai_classifier"
    version = "0.1.0"

    async def analyze(self, image_path: str, analysis_id: UUID) -> AnalyzerResult:
        try:
            result = await asyncio.to_thread(self._classify, image_path)
            return self._make_result(
                status="completed",
                confidence=result["confidence"],
                findings=result["findings"],
                raw_output=result["raw_output"],
            )
        except Exception as e:
            logger.warning("AI classification failed: %s", e)
            return self._make_result(
                status="error",
                findings=[{"error": str(e)}],
            )

    def _classify(self, path: str) -> dict:
        img = Image.open(path).convert("RGB")

        max_dim = 1024
        w, h = img.size
        if max(w, h) > max_dim:
            scale = max_dim / max(w, h)
            img = img.resize((int(w * scale), int(h * scale)), Image.LANCZOS)

        arr = np.array(img, dtype=np.float64)
        gray = np.mean(arr, axis=2)

        texture_features = self._extract_texture_features(gray)
        noise_features = self._extract_noise_features(arr)
        color_features = self._extract_color_features(arr)
        frequency_features = self._extract_frequency_features(gray)
        edge_features = self._extract_edge_features(gray)

        ai_prob = self._fuse_features(
            texture_features, noise_features, color_features,
            frequency_features, edge_features,
        )

        edited_prob = self._estimate_edited_probability(
            texture_features, noise_features, edge_features,
        )

        findings = []
        status = "completed"

        if ai_prob > 0.7:
            findings.append({
                "type": "ai_generated_high",
                "category": "ml",
                "description": (
                    f"Statistical features strongly suggest AI-generated content "
                    f"(score: {ai_prob:.2f})"
                ),
                "ai_probability": round(ai_prob, 4),
                "key_indicators": self._get_key_indicators(
                    texture_features, noise_features, frequency_features,
                ),
            })
        elif ai_prob > 0.4:
            findings.append({
                "type": "ai_generated_moderate",
                "category": "ml",
                "description": (
                    f"Some statistical features suggest possible AI generation "
                    f"(score: {ai_prob:.2f})"
                ),
                "ai_probability": round(ai_prob, 4),
            })
        else:
            findings.append({
                "type": "ai_generated_low",
                "category": "ml",
                "description": (
                    f"Statistical features consistent with natural photography "
                    f"(AI score: {ai_prob:.2f})"
                ),
                "ai_probability": round(ai_prob, 4),
            })

        raw_output = {
            "ai_generated_probability": round(ai_prob, 4),
            "ai_edited_probability": round(edited_prob, 4),
            "conventional_edit_probability": round(max(0, edited_prob - ai_prob * 0.3), 4),
            "features": {
                "texture": {k: round(v, 4) for k, v in texture_features.items()},
                "noise": {k: round(v, 4) for k, v in noise_features.items()},
                "color": {k: round(v, 4) for k, v in color_features.items()},
                "frequency": {k: round(v, 4) for k, v in frequency_features.items()},
                "edge": {k: round(v, 4) for k, v in edge_features.items()},
            },
        }

        return {
            "findings": findings,
            "raw_output": raw_output,
            "confidence": round(abs(ai_prob - 0.5) * 2, 2),
        }

    def _extract_texture_features(self, gray: np.ndarray) -> dict:
        h, w = gray.shape
        block_size = 32
        local_stds: list[float] = []
        local_entropies: list[float] = []

        for y in range(0, h - block_size, block_size):
            for x in range(0, w - block_size, block_size):
                block = gray[y:y + block_size, x:x + block_size]
                local_stds.append(float(np.std(block)))
                hist, _ = np.histogram(block.ravel(), bins=32, range=(0, 255))
                hist = hist / hist.sum()
                hist = hist[hist > 0]
                local_entropies.append(float(-np.sum(hist * np.log2(hist))))

        if not local_stds:
            return {"std_uniformity": 0, "entropy_uniformity": 0, "avg_entropy": 0, "avg_std": 0}

        std_arr = np.array(local_stds)
        ent_arr = np.array(local_entropies)

        return {
            "avg_std": float(np.mean(std_arr)),
            "std_uniformity": float(np.std(std_arr) / (np.mean(std_arr) + 1e-10)),
            "avg_entropy": float(np.mean(ent_arr)),
            "entropy_uniformity": float(np.std(ent_arr) / (np.mean(ent_arr) + 1e-10)),
        }

    def _extract_noise_features(self, arr: np.ndarray) -> dict:
        from scipy.ndimage import median_filter

        noise_levels: list[float] = []
        noise_kurtoses: list[float] = []

        for c in range(3):
            channel = arr[:, :, c]
            denoised = median_filter(channel, size=3)
            residual = channel - denoised
            noise_levels.append(float(np.std(residual)))

            flat = residual.ravel()
            m = np.mean(flat)
            s = np.std(flat)
            if s > 0:
                k = float(np.mean(((flat - m) / s) ** 4) - 3)
            else:
                k = 0.0
            noise_kurtoses.append(k)

        cross_corr = self._noise_cross_correlation(arr)

        return {
            "avg_noise_level": float(np.mean(noise_levels)),
            "noise_consistency": float(np.std(noise_levels) / (np.mean(noise_levels) + 1e-10)),
            "avg_kurtosis": float(np.mean(noise_kurtoses)),
            "cross_channel_correlation": cross_corr,
        }

    def _extract_color_features(self, arr: np.ndarray) -> dict:
        r, g, b = arr[:, :, 0], arr[:, :, 1], arr[:, :, 2]

        max_c = np.maximum(np.maximum(r, g), b)
        min_c = np.minimum(np.minimum(r, g), b)
        denom = max_c.copy()
        denom[denom == 0] = 1
        saturation = (max_c - min_c) / denom

        rg_diff = np.abs(r - g)
        rb_diff = np.abs(r - b)
        gb_diff = np.abs(g - b)

        return {
            "saturation_mean": float(np.mean(saturation)),
            "saturation_std": float(np.std(saturation)),
            "color_variance": float(np.mean([np.std(r), np.std(g), np.std(b)])),
            "channel_independence": float(np.mean([np.std(rg_diff), np.std(rb_diff), np.std(gb_diff)])),
        }

    def _extract_frequency_features(self, gray: np.ndarray) -> dict:
        f_transform = np.fft.fft2(gray)
        f_shift = np.fft.fftshift(f_transform)
        power = np.abs(f_shift) ** 2
        log_power = np.log1p(power)

        h, w = gray.shape
        cy, cx = h // 2, w // 2
        y, x = np.ogrid[:h, :w]
        dist = np.sqrt((y - cy) ** 2 + (x - cx) ** 2)

        max_r = min(cy, cx)
        third = max_r // 3

        low = dist <= third
        mid = (dist > third) & (dist <= 2 * third)
        high = dist > 2 * third

        low_e = float(np.mean(log_power[low])) if np.any(low) else 0
        mid_e = float(np.mean(log_power[mid])) if np.any(mid) else 0
        high_e = float(np.mean(log_power[high])) if np.any(high) else 0

        total = low_e + mid_e + high_e
        if total > 0:
            high_ratio = high_e / total
            mid_ratio = mid_e / total
        else:
            high_ratio = 0
            mid_ratio = 0

        return {
            "high_freq_ratio": high_ratio,
            "mid_freq_ratio": mid_ratio,
            "energy_concentration": low_e / (total + 1e-10) if total > 0 else 0,
        }

    def _extract_edge_features(self, gray: np.ndarray) -> dict:
        sobel_x = np.array([[-1, 0, 1], [-2, 0, 2], [-1, 0, 1]], dtype=np.float64)
        sobel_y = np.array([[-1, -2, -1], [0, 0, 0], [1, 2, 1]], dtype=np.float64)

        from scipy.signal import convolve2d
        gx = convolve2d(gray, sobel_x, mode="valid")
        gy = convolve2d(gray, sobel_y, mode="valid")
        magnitude = np.sqrt(gx ** 2 + gy ** 2)

        mean_edge = float(np.mean(magnitude))
        std_edge = float(np.std(magnitude))

        threshold = mean_edge + std_edge
        edge_density = float(np.mean(magnitude > threshold))

        h, w = magnitude.shape
        block_size = 32
        local_densities: list[float] = []
        for y in range(0, h - block_size, block_size):
            for x in range(0, w - block_size, block_size):
                block = magnitude[y:y + block_size, x:x + block_size]
                local_densities.append(float(np.mean(block > threshold)))

        edge_uniformity = float(np.std(local_densities) / (np.mean(local_densities) + 1e-10)) if local_densities else 0

        return {
            "mean_edge_strength": mean_edge,
            "edge_density": edge_density,
            "edge_uniformity": edge_uniformity,
        }

    def _noise_cross_correlation(self, arr: np.ndarray) -> float:
        from scipy.ndimage import median_filter
        residuals = []
        for c in range(3):
            denoised = median_filter(arr[:, :, c], size=3)
            residuals.append((arr[:, :, c] - denoised).ravel())

        corrs = []
        for i in range(3):
            for j in range(i + 1, 3):
                a = residuals[i] - np.mean(residuals[i])
                b = residuals[j] - np.mean(residuals[j])
                denom = np.sqrt(np.sum(a ** 2) * np.sum(b ** 2))
                if denom > 0:
                    corrs.append(float(np.sum(a * b) / denom))

        return float(np.mean(corrs)) if corrs else 0

    def _fuse_features(
        self,
        texture: dict,
        noise: dict,
        color: dict,
        frequency: dict,
        edge: dict,
    ) -> float:
        score = 0.0
        weights_used = 0.0

        if noise["avg_noise_level"] < 1.0:
            score += 0.15
            weights_used += 0.15
        elif noise["avg_noise_level"] > 5.0:
            weights_used += 0.15

        if noise["cross_channel_correlation"] > 0.7:
            score += 0.12
            weights_used += 0.12
        else:
            weights_used += 0.12

        if abs(noise["avg_kurtosis"]) < 1.5:
            score += 0.08
            weights_used += 0.08
        else:
            weights_used += 0.08

        if texture["std_uniformity"] < 0.3:
            score += 0.1
            weights_used += 0.1
        else:
            weights_used += 0.1

        if texture["entropy_uniformity"] < 0.15:
            score += 0.08
            weights_used += 0.08
        else:
            weights_used += 0.08

        if frequency["high_freq_ratio"] < 0.15:
            score += 0.15
            weights_used += 0.15
        elif frequency["high_freq_ratio"] < 0.25:
            score += 0.08
            weights_used += 0.15
        else:
            weights_used += 0.15

        if edge["edge_uniformity"] < 0.5:
            score += 0.1
            weights_used += 0.1
        else:
            weights_used += 0.1

        if color["saturation_std"] < 0.1:
            score += 0.08
            weights_used += 0.08
        else:
            weights_used += 0.08

        if frequency["energy_concentration"] > 0.6:
            score += 0.1
            weights_used += 0.1
        else:
            weights_used += 0.1

        if noise["noise_consistency"] < 0.2:
            score += 0.04
            weights_used += 0.04
        else:
            weights_used += 0.04

        return min(score / (weights_used if weights_used > 0 else 1.0), 1.0) * weights_used / 1.0

    def _estimate_edited_probability(
        self, texture: dict, noise: dict, edge: dict,
    ) -> float:
        score = 0.0

        if noise["noise_consistency"] > 0.5:
            score += 0.3

        if texture["std_uniformity"] > 0.8:
            score += 0.2

        if edge["edge_uniformity"] > 1.5:
            score += 0.2

        return min(score, 0.9)

    def _get_key_indicators(
        self, texture: dict, noise: dict, frequency: dict,
    ) -> list[str]:
        indicators: list[str] = []

        if noise["avg_noise_level"] < 1.0:
            indicators.append("very_low_noise")
        if noise["cross_channel_correlation"] > 0.7:
            indicators.append("correlated_channel_noise")
        if texture["std_uniformity"] < 0.3:
            indicators.append("uniform_texture")
        if frequency["high_freq_ratio"] < 0.15:
            indicators.append("suppressed_high_frequencies")
        if texture["entropy_uniformity"] < 0.15:
            indicators.append("uniform_entropy")

        return indicators
