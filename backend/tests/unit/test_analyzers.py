import pytest
import os
import tempfile
from pathlib import Path

from backend.app.analyzers.file_validator import FileValidator
from backend.app.analyzers.hash_generator import HashGenerator
from backend.app.analyzers.format_analyzer import FormatAnalyzer
from backend.app.analyzers.forensics.ela_analyzer import ELAAnalyzer
from backend.app.analyzers.forensics.statistics_analyzer import StatisticsAnalyzer
from backend.app.analyzers.forensics.prnu_analyzer import PRNUAnalyzer
from backend.app.analyzers.forensics.copy_move import CopyMoveDetector
from backend.app.analyzers.forensics.cfa_analyzer import CFAAnalyzer
from backend.app.analyzers.watermark.synthid_detector import SynthIDDetector
from backend.app.analyzers.watermark.invisible_watermark import InvisibleWatermarkDetector
from backend.app.analyzers.ml.fft_analyzer import FFTSpectrumAnalyzer
from backend.app.analyzers.ml.ai_classifier import AIClassifier
from backend.app.analyzers.provenance.provider_registry import ProviderRegistry
from backend.app.analyzers.base import AnalyzerResult
from backend.app.fusion.engine import EvidenceFusionEngine, FusionInput

import uuid

TEST_ANALYSIS_ID = uuid.uuid4()


def create_minimal_jpeg(path: str) -> None:
    """Create a minimal valid JPEG file for testing."""
    from PIL import Image
    img = Image.new("RGB", (100, 100), color="red")
    img.save(path, format="JPEG")


def create_minimal_png(path: str) -> None:
    """Create a minimal valid PNG file for testing."""
    from PIL import Image
    img = Image.new("RGBA", (50, 50), color=(0, 128, 255, 255))
    img.save(path, format="PNG")


def create_larger_jpeg(path: str, width: int = 256, height: int = 256) -> None:
    from PIL import Image
    import numpy as np
    arr = np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)
    img = Image.fromarray(arr)
    img.save(path, format="JPEG", quality=85)


@pytest.fixture
def jpeg_path(tmp_path: Path) -> str:
    path = str(tmp_path / "test.jpg")
    create_minimal_jpeg(path)
    return path


@pytest.fixture
def png_path(tmp_path: Path) -> str:
    path = str(tmp_path / "test.png")
    create_minimal_png(path)
    return path


@pytest.fixture
def large_jpeg_path(tmp_path: Path) -> str:
    path = str(tmp_path / "large.jpg")
    create_larger_jpeg(path, 256, 256)
    return path


@pytest.fixture
def empty_file(tmp_path: Path) -> str:
    path = str(tmp_path / "empty.jpg")
    Path(path).touch()
    return path


@pytest.fixture
def non_image_file(tmp_path: Path) -> str:
    path = str(tmp_path / "notimage.jpg")
    Path(path).write_text("this is not an image")
    return path


class TestFileValidator:
    @pytest.mark.asyncio
    async def test_valid_jpeg(self, jpeg_path: str):
        validator = FileValidator()
        result = await validator.analyze(jpeg_path, TEST_ANALYSIS_ID)
        assert result.status == "completed"
        assert result.raw_output["valid"] is True
        assert result.raw_output["detected_format"] == "jpeg"

    @pytest.mark.asyncio
    async def test_valid_png(self, png_path: str):
        validator = FileValidator()
        result = await validator.analyze(png_path, TEST_ANALYSIS_ID)
        assert result.status == "completed"
        assert result.raw_output["valid"] is True
        assert result.raw_output["detected_format"] == "png"

    @pytest.mark.asyncio
    async def test_empty_file(self, empty_file: str):
        validator = FileValidator()
        result = await validator.analyze(empty_file, TEST_ANALYSIS_ID)
        assert result.status == "completed"
        assert any(
            f.get("issue") == "empty_file" for f in result.findings
        )

    @pytest.mark.asyncio
    async def test_missing_file(self):
        validator = FileValidator()
        result = await validator.analyze("/nonexistent/file.jpg", TEST_ANALYSIS_ID)
        assert result.status == "error"

    @pytest.mark.asyncio
    async def test_extension_mismatch(self, tmp_path: Path):
        path = str(tmp_path / "test.png")
        create_minimal_jpeg(path)  # JPEG content with .png extension
        validator = FileValidator()
        result = await validator.analyze(path, TEST_ANALYSIS_ID)
        assert result.status == "completed"
        assert any(
            f.get("issue") == "extension_mismatch" for f in result.findings
        )


class TestHashGenerator:
    @pytest.mark.asyncio
    async def test_sha256(self, jpeg_path: str):
        gen = HashGenerator()
        result = await gen.analyze(jpeg_path, TEST_ANALYSIS_ID)
        assert result.status == "completed"
        assert result.confidence == 1.0
        assert "sha256" in result.raw_output
        assert len(result.raw_output["sha256"]) == 64

    @pytest.mark.asyncio
    async def test_perceptual_hashes(self, jpeg_path: str):
        gen = HashGenerator()
        result = await gen.analyze(jpeg_path, TEST_ANALYSIS_ID)
        phashes = result.raw_output.get("perceptual_hashes", {})
        assert "average_hash" in phashes
        assert "phash" in phashes
        assert "dhash" in phashes

    @pytest.mark.asyncio
    async def test_deterministic(self, jpeg_path: str):
        gen = HashGenerator()
        r1 = await gen.analyze(jpeg_path, TEST_ANALYSIS_ID)
        r2 = await gen.analyze(jpeg_path, TEST_ANALYSIS_ID)
        assert r1.raw_output["sha256"] == r2.raw_output["sha256"]


class TestFormatAnalyzer:
    @pytest.mark.asyncio
    async def test_jpeg_analysis(self, jpeg_path: str):
        analyzer = FormatAnalyzer()
        result = await analyzer.analyze(jpeg_path, TEST_ANALYSIS_ID)
        assert result.status == "completed"
        assert result.raw_output["format"] == "JPEG"
        assert result.raw_output["width"] == 100
        assert result.raw_output["height"] == 100

    @pytest.mark.asyncio
    async def test_png_analysis(self, png_path: str):
        analyzer = FormatAnalyzer()
        result = await analyzer.analyze(png_path, TEST_ANALYSIS_ID)
        assert result.status == "completed"
        assert result.raw_output["format"] == "PNG"
        assert result.raw_output["width"] == 50
        assert result.raw_output["height"] == 50

    @pytest.mark.asyncio
    async def test_no_false_double_compression(self, jpeg_path: str):
        analyzer = FormatAnalyzer()
        result = await analyzer.analyze(jpeg_path, TEST_ANALYSIS_ID)
        assert result.raw_output.get("double_compression_indicator") is not True

    @pytest.mark.asyncio
    async def test_double_compression_quality_100(self, tmp_path: Path):
        from PIL import Image
        path = str(tmp_path / "q100.jpg")
        img = Image.new("RGB", (200, 200), color="blue")
        img.save(path, format="JPEG", quality=100)
        analyzer = FormatAnalyzer()
        result = await analyzer.analyze(path, TEST_ANALYSIS_ID)
        compression = result.raw_output.get("compression", {})
        assert compression.get("soi_count", 0) == 1


class TestELAAnalyzer:
    @pytest.mark.asyncio
    async def test_jpeg_ela(self, jpeg_path: str):
        analyzer = ELAAnalyzer()
        result = await analyzer.analyze(jpeg_path, TEST_ANALYSIS_ID)
        assert result.status == "completed"
        assert result.raw_output.get("global_stats") is not None
        assert "mean_error" in result.raw_output["global_stats"]

    @pytest.mark.asyncio
    async def test_png_ela(self, png_path: str):
        analyzer = ELAAnalyzer()
        result = await analyzer.analyze(png_path, TEST_ANALYSIS_ID)
        assert result.status == "completed"

    @pytest.mark.asyncio
    async def test_ela_grid_analysis(self, jpeg_path: str):
        analyzer = ELAAnalyzer()
        result = await analyzer.analyze(jpeg_path, TEST_ANALYSIS_ID)
        grid = result.raw_output.get("grid_analysis", {})
        assert grid.get("total_blocks", 0) > 0


class TestStatisticsAnalyzer:
    @pytest.mark.asyncio
    async def test_jpeg_statistics(self, jpeg_path: str):
        analyzer = StatisticsAnalyzer()
        result = await analyzer.analyze(jpeg_path, TEST_ANALYSIS_ID)
        assert result.status == "completed"
        assert "channel_stats" in result.raw_output
        assert "red" in result.raw_output["channel_stats"]
        assert "noise_level" in result.raw_output

    @pytest.mark.asyncio
    async def test_png_statistics(self, png_path: str):
        analyzer = StatisticsAnalyzer()
        result = await analyzer.analyze(png_path, TEST_ANALYSIS_ID)
        assert result.status == "completed"
        assert "channel_stats" in result.raw_output

    @pytest.mark.asyncio
    async def test_solid_color_statistics(self, tmp_path: Path):
        from PIL import Image
        path = str(tmp_path / "solid.png")
        img = Image.new("RGB", (100, 100), color=(128, 128, 128))
        img.save(path, format="PNG")
        analyzer = StatisticsAnalyzer()
        result = await analyzer.analyze(path, TEST_ANALYSIS_ID)
        assert result.status == "completed"
        stats = result.raw_output["channel_stats"]["red"]
        assert stats["std"] == 0.0
        assert stats["unique_values"] == 1


class TestPRNUAnalyzer:
    @pytest.mark.asyncio
    async def test_jpeg_prnu(self, jpeg_path: str):
        analyzer = PRNUAnalyzer()
        result = await analyzer.analyze(jpeg_path, TEST_ANALYSIS_ID)
        assert result.status == "completed"
        assert "noise_stats" in result.raw_output
        assert "cross_channel" in result.raw_output

    @pytest.mark.asyncio
    async def test_larger_image_prnu(self, large_jpeg_path: str):
        analyzer = PRNUAnalyzer()
        result = await analyzer.analyze(large_jpeg_path, TEST_ANALYSIS_ID)
        assert result.status == "completed"
        assert result.raw_output["noise_stats"]["variance"] > 0

    @pytest.mark.asyncio
    async def test_solid_prnu(self, tmp_path: Path):
        from PIL import Image
        path = str(tmp_path / "solid.png")
        img = Image.new("RGB", (100, 100), color=(128, 128, 128))
        img.save(path, format="PNG")
        analyzer = PRNUAnalyzer()
        result = await analyzer.analyze(path, TEST_ANALYSIS_ID)
        assert result.status == "completed"
        assert result.raw_output["noise_stats"]["variance"] < 1.0


class TestCopyMoveDetector:
    @pytest.mark.asyncio
    async def test_no_copy_move_in_simple(self, jpeg_path: str):
        detector = CopyMoveDetector()
        result = await detector.analyze(jpeg_path, TEST_ANALYSIS_ID)
        assert result.status == "completed"
        assert "total_matches" in result.raw_output
        assert any(
            f.get("type") in ("copy_move_not_detected", "copy_move_suspicious")
            for f in result.findings
        )

    @pytest.mark.asyncio
    async def test_larger_image(self, large_jpeg_path: str):
        detector = CopyMoveDetector()
        result = await detector.analyze(large_jpeg_path, TEST_ANALYSIS_ID)
        assert result.status == "completed"
        assert "dct_matches" in result.raw_output
        assert "keypoint_matches" in result.raw_output


class TestCFAAnalyzer:
    @pytest.mark.asyncio
    async def test_jpeg_cfa(self, jpeg_path: str):
        analyzer = CFAAnalyzer()
        result = await analyzer.analyze(jpeg_path, TEST_ANALYSIS_ID)
        assert result.status == "completed"
        assert "cfa" in result.raw_output
        assert "resampling" in result.raw_output

    @pytest.mark.asyncio
    async def test_cfa_has_pattern(self, large_jpeg_path: str):
        analyzer = CFAAnalyzer()
        result = await analyzer.analyze(large_jpeg_path, TEST_ANALYSIS_ID)
        assert result.status == "completed"
        cfa = result.raw_output["cfa"]
        assert "cfa_score" in cfa
        assert "dominant_pattern" in cfa

    @pytest.mark.asyncio
    async def test_synthetic_image_no_cfa(self, tmp_path: Path):
        from PIL import Image
        import numpy as np
        path = str(tmp_path / "gradient.png")
        arr = np.zeros((100, 100, 3), dtype=np.uint8)
        for i in range(100):
            arr[i, :, :] = [i * 2, i, 255 - i * 2]
        Image.fromarray(arr).save(path, format="PNG")
        analyzer = CFAAnalyzer()
        result = await analyzer.analyze(path, TEST_ANALYSIS_ID)
        assert result.status == "completed"


class TestSynthIDDetector:
    @pytest.mark.asyncio
    async def test_jpeg_synthid(self, jpeg_path: str):
        detector = SynthIDDetector()
        result = await detector.analyze(jpeg_path, TEST_ANALYSIS_ID)
        assert result.status == "completed"
        assert "synthid_score" in result.raw_output
        assert "frequency_features" in result.raw_output

    @pytest.mark.asyncio
    async def test_larger_image_synthid(self, large_jpeg_path: str):
        detector = SynthIDDetector()
        result = await detector.analyze(large_jpeg_path, TEST_ANALYSIS_ID)
        assert result.status == "completed"
        assert len(result.findings) > 0

    @pytest.mark.asyncio
    async def test_has_limitations(self, jpeg_path: str):
        detector = SynthIDDetector()
        result = await detector.analyze(jpeg_path, TEST_ANALYSIS_ID)
        assert len(result.limitations) > 0


class TestInvisibleWatermarkDetector:
    @pytest.mark.asyncio
    async def test_jpeg_watermark(self, jpeg_path: str):
        detector = InvisibleWatermarkDetector()
        result = await detector.analyze(jpeg_path, TEST_ANALYSIS_ID)
        assert result.status == "completed"
        assert "dwt" in result.raw_output
        assert "lsb" in result.raw_output
        assert "dct" in result.raw_output

    @pytest.mark.asyncio
    async def test_larger_image_watermark(self, large_jpeg_path: str):
        detector = InvisibleWatermarkDetector()
        result = await detector.analyze(large_jpeg_path, TEST_ANALYSIS_ID)
        assert result.status == "completed"
        assert "combined_score" in result.raw_output


class TestFFTSpectrumAnalyzer:
    @pytest.mark.asyncio
    async def test_jpeg_fft(self, jpeg_path: str):
        analyzer = FFTSpectrumAnalyzer()
        result = await analyzer.analyze(jpeg_path, TEST_ANALYSIS_ID)
        assert result.status == "completed"
        assert "spectral_features" in result.raw_output
        assert "ai_score" in result.raw_output

    @pytest.mark.asyncio
    async def test_larger_image_fft(self, large_jpeg_path: str):
        analyzer = FFTSpectrumAnalyzer()
        result = await analyzer.analyze(large_jpeg_path, TEST_ANALYSIS_ID)
        assert result.status == "completed"
        features = result.raw_output["spectral_features"]
        assert "slope" in features
        assert "high_freq_rolloff" in features

    @pytest.mark.asyncio
    async def test_fft_grid_detection(self, jpeg_path: str):
        analyzer = FFTSpectrumAnalyzer()
        result = await analyzer.analyze(jpeg_path, TEST_ANALYSIS_ID)
        assert "grid_artifacts" in result.raw_output


class TestAIClassifier:
    @pytest.mark.asyncio
    async def test_jpeg_classify(self, jpeg_path: str):
        classifier = AIClassifier()
        result = await classifier.analyze(jpeg_path, TEST_ANALYSIS_ID)
        assert result.status == "completed"
        assert "ai_generated_probability" in result.raw_output
        assert "ai_edited_probability" in result.raw_output
        assert 0 <= result.raw_output["ai_generated_probability"] <= 1

    @pytest.mark.asyncio
    async def test_larger_image_classify(self, large_jpeg_path: str):
        classifier = AIClassifier()
        result = await classifier.analyze(large_jpeg_path, TEST_ANALYSIS_ID)
        assert result.status == "completed"
        assert "features" in result.raw_output
        features = result.raw_output["features"]
        assert "texture" in features
        assert "noise" in features
        assert "color" in features
        assert "frequency" in features
        assert "edge" in features

    @pytest.mark.asyncio
    async def test_solid_color_classify(self, tmp_path: Path):
        from PIL import Image
        path = str(tmp_path / "solid.png")
        img = Image.new("RGB", (100, 100), color=(128, 128, 128))
        img.save(path, format="PNG")
        classifier = AIClassifier()
        result = await classifier.analyze(path, TEST_ANALYSIS_ID)
        assert result.status == "completed"


class TestProviderRegistry:
    def test_openai_metadata(self):
        registry = ProviderRegistry()
        findings = [
            {"category": "software", "software_name": "DALL-E 3", "description": "AI generator"}
        ]
        matches = registry.identify_from_metadata(findings)
        assert len(matches) > 0
        assert matches[0].provider_name == "OpenAI"

    def test_stable_diffusion_png_text(self):
        registry = ProviderRegistry()
        findings = [
            {"category": "ai_parameters", "type": "sd_parameters",
             "raw_value": "Steps: 20, Sampler: Euler, CFG scale: 7, Model: sd_xl_base_1.0"}
        ]
        matches = registry.identify_from_metadata(findings)
        assert len(matches) > 0
        provider_names = [m.provider_name for m in matches]
        assert "Stability AI" in provider_names

    def test_c2pa_openai(self):
        registry = ProviderRegistry()
        matches = registry.identify_from_c2pa(
            signer="OpenAI",
            claim_generator="dall-e-3",
            actions=[],
        )
        assert len(matches) > 0
        assert matches[0].provider_name == "OpenAI"

    def test_no_match(self):
        registry = ProviderRegistry()
        findings = [
            {"category": "camera", "make": "Canon", "model": "EOS R5"}
        ]
        matches = registry.identify_from_metadata(findings)
        assert len(matches) == 0


class TestFusionEngine:
    def test_empty_input(self):
        engine = EvidenceFusionEngine()
        output = engine.fuse(FusionInput())
        assert output.classification == "inconclusive"
        assert output.overall_confidence <= 0.4

    def test_ai_classifier_high(self):
        engine = EvidenceFusionEngine()
        fusion_input = FusionInput(
            ai_classifier_result={
                "findings": [
                    {"type": "ai_generated_high", "category": "ml",
                     "description": "high", "ai_probability": 0.85}
                ],
                "raw_output": {
                    "ai_generated_probability": 0.85,
                    "ai_edited_probability": 0.1,
                    "conventional_edit_probability": 0.05,
                },
            },
            statistics_result={
                "findings": [
                    {"type": "low_noise_smooth", "category": "forensics"}
                ],
                "raw_output": {"noise_level": 0.1},
            },
        )
        output = engine.fuse(fusion_input)
        assert output.ml.ai_generated == 0.85
        assert output.ml.status == "completed"

    def test_watermark_detected(self):
        engine = EvidenceFusionEngine()
        fusion_input = FusionInput(
            synthid_result={
                "findings": [
                    {"type": "synthid_likely_present", "category": "watermark",
                     "score": 0.8}
                ],
                "raw_output": {"synthid_score": 0.8},
            },
        )
        output = engine.fuse(fusion_input)
        assert len(output.provenance.watermarks) > 0
        assert output.provenance.watermarks[0].detected is True

    def test_camera_with_cfa_confirmation(self):
        engine = EvidenceFusionEngine()
        fusion_input = FusionInput(
            metadata_result={
                "findings": [
                    {"category": "camera", "make": "Canon", "model": "EOS R5"},
                    {"category": "timestamps", "type": "exif_timestamps"},
                ],
            },
            cfa_result={
                "findings": [
                    {"type": "cfa_artifacts_present", "category": "forensics",
                     "cfa_score": 0.8, "dominant_pattern": "RGGB"}
                ],
                "raw_output": {"cfa": {"cfa_score": 0.8}, "resampling": {}},
            },
        )
        output = engine.fuse(fusion_input)
        assert output.classification == "likely_original"
        assert output.overall_confidence >= 0.85
