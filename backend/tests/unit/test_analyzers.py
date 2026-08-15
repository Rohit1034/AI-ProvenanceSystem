import pytest
import os
import tempfile
from pathlib import Path

from backend.app.analyzers.file_validator import FileValidator
from backend.app.analyzers.hash_generator import HashGenerator
from backend.app.analyzers.format_analyzer import FormatAnalyzer
from backend.app.analyzers.base import AnalyzerResult

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
