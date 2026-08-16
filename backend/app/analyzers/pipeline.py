from __future__ import annotations

import logging
from uuid import UUID

from backend.app.analyzers.base import AnalyzerResult
from backend.app.analyzers.file_validator import FileValidator
from backend.app.analyzers.hash_generator import HashGenerator
from backend.app.analyzers.format_analyzer import FormatAnalyzer
from backend.app.analyzers.metadata.extractor import MetadataExtractor
from backend.app.analyzers.provenance.c2pa_analyzer import C2PAAnalyzer
from backend.app.analyzers.forensics.ela_analyzer import ELAAnalyzer
from backend.app.analyzers.forensics.statistics_analyzer import StatisticsAnalyzer
from backend.app.analyzers.forensics.prnu_analyzer import PRNUAnalyzer
from backend.app.analyzers.forensics.copy_move import CopyMoveDetector
from backend.app.analyzers.forensics.cfa_analyzer import CFAAnalyzer
from backend.app.analyzers.watermark.synthid_detector import SynthIDDetector
from backend.app.analyzers.watermark.invisible_watermark import InvisibleWatermarkDetector
from backend.app.analyzers.ml.fft_analyzer import FFTSpectrumAnalyzer
from backend.app.analyzers.ml.ai_classifier import AIClassifier

logger = logging.getLogger("provenance.analyzers.pipeline")


class AnalysisPipeline:
    def __init__(self) -> None:
        self.file_validator = FileValidator()
        self.hash_generator = HashGenerator()
        self.format_analyzer = FormatAnalyzer()
        self.metadata_extractor = MetadataExtractor()
        self.c2pa_analyzer = C2PAAnalyzer()
        self.ela_analyzer = ELAAnalyzer()
        self.statistics_analyzer = StatisticsAnalyzer()
        self.prnu_analyzer = PRNUAnalyzer()
        self.copy_move_detector = CopyMoveDetector()
        self.cfa_analyzer = CFAAnalyzer()
        self.synthid_detector = SynthIDDetector()
        self.invisible_watermark_detector = InvisibleWatermarkDetector()
        self.fft_analyzer = FFTSpectrumAnalyzer()
        self.ai_classifier = AIClassifier()

    async def run(self, image_path: str, analysis_id: UUID) -> list[AnalyzerResult]:
        results: list[AnalyzerResult] = []

        validation = await self.file_validator.safe_analyze(image_path, analysis_id)
        results.append(validation)

        if validation.status == "error" or (
            validation.raw_output
            and not validation.raw_output.get("valid", True)
        ):
            logger.warning(
                "File validation failed for %s, skipping remaining analyzers",
                analysis_id,
            )
            return results

        hash_result = await self.hash_generator.safe_analyze(image_path, analysis_id)
        results.append(hash_result)

        format_result = await self.format_analyzer.safe_analyze(image_path, analysis_id)
        results.append(format_result)

        metadata_result = await self.metadata_extractor.safe_analyze(image_path, analysis_id)
        results.append(metadata_result)

        c2pa_result = await self.c2pa_analyzer.safe_analyze(image_path, analysis_id)
        results.append(c2pa_result)

        ela_result = await self.ela_analyzer.safe_analyze(image_path, analysis_id)
        results.append(ela_result)

        statistics_result = await self.statistics_analyzer.safe_analyze(image_path, analysis_id)
        results.append(statistics_result)

        prnu_result = await self.prnu_analyzer.safe_analyze(image_path, analysis_id)
        results.append(prnu_result)

        copy_move_result = await self.copy_move_detector.safe_analyze(image_path, analysis_id)
        results.append(copy_move_result)

        cfa_result = await self.cfa_analyzer.safe_analyze(image_path, analysis_id)
        results.append(cfa_result)

        synthid_result = await self.synthid_detector.safe_analyze(image_path, analysis_id)
        results.append(synthid_result)

        watermark_result = await self.invisible_watermark_detector.safe_analyze(image_path, analysis_id)
        results.append(watermark_result)

        fft_result = await self.fft_analyzer.safe_analyze(image_path, analysis_id)
        results.append(fft_result)

        ai_result = await self.ai_classifier.safe_analyze(image_path, analysis_id)
        results.append(ai_result)

        return results
