from __future__ import annotations

import logging
from uuid import UUID

from backend.app.analyzers.base import AnalyzerResult
from backend.app.analyzers.file_validator import FileValidator
from backend.app.analyzers.hash_generator import HashGenerator
from backend.app.analyzers.format_analyzer import FormatAnalyzer
from backend.app.analyzers.metadata.extractor import MetadataExtractor
from backend.app.analyzers.provenance.c2pa_analyzer import C2PAAnalyzer

logger = logging.getLogger("provenance.analyzers.pipeline")


class AnalysisPipeline:
    def __init__(self) -> None:
        self.file_validator = FileValidator()
        self.hash_generator = HashGenerator()
        self.format_analyzer = FormatAnalyzer()
        self.metadata_extractor = MetadataExtractor()
        self.c2pa_analyzer = C2PAAnalyzer()

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

        return results
