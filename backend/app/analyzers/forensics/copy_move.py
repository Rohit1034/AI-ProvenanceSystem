from __future__ import annotations

import asyncio
import logging
from uuid import UUID

import numpy as np
from PIL import Image

from backend.app.analyzers.base import BaseAnalyzer, AnalyzerResult

logger = logging.getLogger("provenance.analyzers.copy_move")

BLOCK_SIZE = 16
DCT_TRUNC = 6
MATCH_THRESHOLD = 0.95
MIN_DISTANCE = 32
MIN_CLUSTER_SIZE = 4


class CopyMoveDetector(BaseAnalyzer):
    name = "copy_move_detector"
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
            logger.warning("Copy-move detection failed: %s", e)
            return self._make_result(
                status="error",
                findings=[{"error": str(e)}],
            )

    def _detect(self, path: str) -> dict:
        img = Image.open(path).convert("RGB")

        max_dim = 1024
        w, h = img.size
        if max(w, h) > max_dim:
            scale = max_dim / max(w, h)
            img = img.resize((int(w * scale), int(h * scale)), Image.LANCZOS)

        gray = np.array(img.convert("L"), dtype=np.float64)

        dct_matches = self._block_dct_matching(gray)

        keypoint_matches = self._keypoint_matching(gray)

        findings = []
        confidence = 0.5

        total_matches = len(dct_matches) + len(keypoint_matches)

        if total_matches > 20:
            regions = self._cluster_matches(dct_matches + keypoint_matches, gray.shape)
            findings.append({
                "type": "copy_move_detected",
                "category": "forensics",
                "description": (
                    f"Copy-move forgery detected: {len(regions)} duplicated region(s) "
                    f"identified with {total_matches} matching features"
                ),
                "match_count": total_matches,
                "region_count": len(regions),
                "regions": regions[:10],
            })
            confidence = min(0.5 + total_matches * 0.01, 0.9)

        elif total_matches > 5:
            findings.append({
                "type": "copy_move_suspicious",
                "category": "forensics",
                "description": (
                    f"Possible copy-move: {total_matches} similar regions detected, "
                    "but below high-confidence threshold"
                ),
                "match_count": total_matches,
            })
            confidence = 0.55

        else:
            findings.append({
                "type": "copy_move_not_detected",
                "category": "forensics",
                "description": "No significant copy-move forgery detected",
                "match_count": total_matches,
            })

        raw_output = {
            "dct_matches": len(dct_matches),
            "keypoint_matches": len(keypoint_matches),
            "total_matches": total_matches,
            "image_size": {"width": gray.shape[1], "height": gray.shape[0]},
            "block_size": BLOCK_SIZE,
        }

        return {
            "findings": findings,
            "raw_output": raw_output,
            "confidence": confidence,
        }

    def _block_dct_matching(self, gray: np.ndarray) -> list[tuple[int, int, int, int]]:
        from scipy.fft import dctn

        h, w = gray.shape
        step = BLOCK_SIZE // 2
        features: list[tuple[np.ndarray, int, int]] = []

        for y in range(0, h - BLOCK_SIZE, step):
            for x in range(0, w - BLOCK_SIZE, step):
                block = gray[y:y + BLOCK_SIZE, x:x + BLOCK_SIZE]
                dct_block = dctn(block, type=2, norm="ortho")
                feature = dct_block[:DCT_TRUNC, :DCT_TRUNC].ravel()
                norm = np.linalg.norm(feature)
                if norm > 0:
                    feature = feature / norm
                features.append((feature, y, x))

        if len(features) < 2:
            return []

        feature_matrix = np.array([f[0] for f in features])
        positions = [(f[1], f[2]) for f in features]

        sorted_indices = np.lexsort(feature_matrix.T)

        matches: list[tuple[int, int, int, int]] = []
        for i in range(len(sorted_indices) - 1):
            idx1 = sorted_indices[i]
            idx2 = sorted_indices[i + 1]

            similarity = float(np.dot(feature_matrix[idx1], feature_matrix[idx2]))
            if similarity > MATCH_THRESHOLD:
                y1, x1 = positions[idx1]
                y2, x2 = positions[idx2]
                dist = np.sqrt((y2 - y1) ** 2 + (x2 - x1) ** 2)
                if dist > MIN_DISTANCE:
                    matches.append((y1, x1, y2, x2))

        return matches

    def _keypoint_matching(self, gray: np.ndarray) -> list[tuple[int, int, int, int]]:
        h, w = gray.shape
        matches: list[tuple[int, int, int, int]] = []

        block_size = 32
        step = 16
        keypoints: list[tuple[float, int, int]] = []

        for y in range(0, h - block_size, step):
            for x in range(0, w - block_size, step):
                block = gray[y:y + block_size, x:x + block_size]
                response = self._harris_response(block)
                if response > 1000:
                    keypoints.append((response, y + block_size // 2, x + block_size // 2))

        keypoints.sort(reverse=True)
        keypoints = keypoints[:500]

        if len(keypoints) < 2:
            return []

        descriptors = []
        for _, ky, kx in keypoints:
            patch_size = 16
            y0 = max(0, ky - patch_size // 2)
            y1 = min(h, ky + patch_size // 2)
            x0 = max(0, kx - patch_size // 2)
            x1 = min(w, kx + patch_size // 2)
            patch = gray[y0:y1, x0:x1]
            if patch.size == 0:
                descriptors.append(np.zeros(64))
                continue
            resized = np.array(
                Image.fromarray(patch.astype(np.uint8)).resize((8, 8), Image.LANCZOS),
                dtype=np.float64,
            )
            desc = resized.ravel()
            norm = np.linalg.norm(desc)
            if norm > 0:
                desc = desc / norm
            descriptors.append(desc)

        desc_matrix = np.array(descriptors)
        for i in range(len(keypoints)):
            for j in range(i + 1, min(i + 50, len(keypoints))):
                sim = float(np.dot(desc_matrix[i], desc_matrix[j]))
                if sim > MATCH_THRESHOLD:
                    _, y1, x1 = keypoints[i]
                    _, y2, x2 = keypoints[j]
                    dist = np.sqrt((y2 - y1) ** 2 + (x2 - x1) ** 2)
                    if dist > MIN_DISTANCE:
                        matches.append((y1, x1, y2, x2))

        return matches

    def _harris_response(self, block: np.ndarray) -> float:
        if block.shape[0] < 3 or block.shape[1] < 3:
            return 0.0
        iy = np.diff(block, axis=0)[:, :-1] if block.shape[1] > 1 else np.diff(block, axis=0)
        ix = np.diff(block, axis=1)[:-1, :] if block.shape[0] > 1 else np.diff(block, axis=1)
        min_h = min(ix.shape[0], iy.shape[0])
        min_w = min(ix.shape[1], iy.shape[1])
        ix = ix[:min_h, :min_w]
        iy = iy[:min_h, :min_w]

        sxx = float(np.sum(ix ** 2))
        syy = float(np.sum(iy ** 2))
        sxy = float(np.sum(ix * iy))

        det = sxx * syy - sxy ** 2
        trace = sxx + syy
        k = 0.04
        return det - k * trace ** 2

    def _cluster_matches(
        self,
        matches: list[tuple[int, int, int, int]],
        img_shape: tuple[int, ...],
    ) -> list[dict]:
        if not matches:
            return []

        regions: list[dict] = []
        source_points = [(m[0], m[1]) for m in matches]
        target_points = [(m[2], m[3]) for m in matches]

        cluster_radius = 50
        used = set()
        for i, (sy, sx) in enumerate(source_points):
            if i in used:
                continue
            cluster_src = [(sy, sx)]
            cluster_tgt = [target_points[i]]
            used.add(i)
            for j in range(i + 1, len(source_points)):
                if j in used:
                    continue
                ty, tx = source_points[j]
                if abs(ty - sy) < cluster_radius and abs(tx - sx) < cluster_radius:
                    cluster_src.append((ty, tx))
                    cluster_tgt.append(target_points[j])
                    used.add(j)

            if len(cluster_src) >= MIN_CLUSTER_SIZE:
                src_ys = [p[0] for p in cluster_src]
                src_xs = [p[1] for p in cluster_src]
                tgt_ys = [p[0] for p in cluster_tgt]
                tgt_xs = [p[1] for p in cluster_tgt]
                regions.append({
                    "source": {
                        "y_min": min(src_ys),
                        "x_min": min(src_xs),
                        "y_max": max(src_ys) + BLOCK_SIZE,
                        "x_max": max(src_xs) + BLOCK_SIZE,
                    },
                    "target": {
                        "y_min": min(tgt_ys),
                        "x_min": min(tgt_xs),
                        "y_max": max(tgt_ys) + BLOCK_SIZE,
                        "x_max": max(tgt_xs) + BLOCK_SIZE,
                    },
                    "match_count": len(cluster_src),
                })

        return regions
