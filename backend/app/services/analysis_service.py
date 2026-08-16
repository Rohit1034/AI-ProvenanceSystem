from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.models.analysis import (
    AnalysisRecord,
    AnalysisStatus,
    EvidenceResult,
    PerceptualHash,
)
from backend.app.storage.backend import StorageBackend
from backend.app.fusion.engine import EvidenceFusionEngine, FusionInput
from backend.app.schemas.analysis import (
    AnalysisDetail,
    AnalysisSummary,
    EvidenceResultOut,
    ForensicReport,
    ImageInfo,
    PerceptualHashOut,
)

logger = logging.getLogger("provenance.services.analysis")


class AnalysisService:
    def __init__(self, db: AsyncSession, storage: StorageBackend) -> None:
        self.db = db
        self.storage = storage
        self.fusion = EvidenceFusionEngine()

    async def create_analysis(
        self,
        file_data: bytes,
        filename: str,
        mime_type: str,
    ) -> AnalysisRecord:
        import hashlib

        analysis_id = uuid.uuid4()
        sha256 = hashlib.sha256(file_data).hexdigest()

        storage_path = await self.storage.save(
            file_data, filename, str(analysis_id)
        )

        record = AnalysisRecord(
            id=analysis_id,
            original_sha256=sha256,
            file_size=len(file_data),
            original_filename=filename,
            mime_type=mime_type,
            detected_format="unknown",
            status=AnalysisStatus.PENDING,
            storage_path=storage_path,
        )
        self.db.add(record)
        await self.db.commit()
        await self.db.refresh(record)

        return record

    async def run_analysis(self, analysis_id: uuid.UUID) -> AnalysisRecord:
        record = await self._get_record(analysis_id)
        if not record:
            raise ValueError(f"Analysis {analysis_id} not found")

        record.status = AnalysisStatus.PROCESSING
        await self.db.commit()

        try:
            image_path = await self._get_image_path(record)
            results = await self._run_pipeline(image_path, analysis_id)

            for result in results:
                evidence = EvidenceResult(
                    analysis_id=analysis_id,
                    analyzer_name=result.analyzer_name,
                    analyzer_version=result.analyzer_version,
                    status=result.status,
                    confidence=result.confidence,
                    findings=result.findings,
                    limitations=result.limitations,
                    raw_output=result.raw_output,
                    duration_ms=result.duration_ms,
                )
                self.db.add(evidence)

            self._apply_image_info(record, results)
            self._apply_hash_results(record, results)
            fusion_output = self._run_fusion(results)

            record.classification = fusion_output.classification
            record.overall_confidence = fusion_output.overall_confidence
            record.status = AnalysisStatus.COMPLETED
            record.completed_at = datetime.now(timezone.utc)

            await self.db.commit()
            await self.db.refresh(record)

        except Exception as exc:
            logger.exception("Analysis %s failed", analysis_id)
            record.status = AnalysisStatus.FAILED
            record.error_message = str(exc)
            await self.db.commit()
            raise

        return record

    async def get_analysis(self, analysis_id: uuid.UUID) -> AnalysisRecord | None:
        return await self._get_record(analysis_id, load_evidence=True)

    async def get_report(self, analysis_id: uuid.UUID) -> ForensicReport | None:
        record = await self._get_record(analysis_id, load_evidence=True)
        if not record:
            return None

        hashes = await self._get_hashes(analysis_id)

        evidence_map: dict[str, Any] = {}
        for er in record.evidence_results:
            evidence_map[er.analyzer_name] = {
                "findings": er.findings or [],
                "raw_output": er.raw_output or {},
                "confidence": er.confidence,
                "status": er.status,
            }

        fusion_input = FusionInput(
            metadata_result=evidence_map.get("metadata_extractor"),
            c2pa_result=evidence_map.get("c2pa_analyzer"),
            format_result=evidence_map.get("format_analyzer"),
            ela_result=evidence_map.get("ela_analyzer"),
            statistics_result=evidence_map.get("statistics_analyzer"),
            prnu_result=evidence_map.get("prnu_analyzer"),
            copy_move_result=evidence_map.get("copy_move_detector"),
            cfa_result=evidence_map.get("cfa_analyzer"),
            synthid_result=evidence_map.get("synthid_detector"),
            invisible_watermark_result=evidence_map.get("invisible_watermark_detector"),
            fft_result=evidence_map.get("fft_spectrum_analyzer"),
            ai_classifier_result=evidence_map.get("ai_classifier"),
        )
        fusion_output = self.fusion.fuse(fusion_input)

        return ForensicReport(
            analysis_id=record.id,
            classification=record.classification.value if record.classification else None,
            overall_confidence=record.overall_confidence,
            image_info=ImageInfo(
                sha256=record.original_sha256,
                file_size=record.file_size,
                mime_type=record.mime_type,
                format=record.detected_format,
                width=record.width,
                height=record.height,
                bit_depth=record.bit_depth,
                color_mode=record.color_mode,
                color_profile=record.color_profile,
                compression_info=record.compression_info,
                perceptual_hashes=[
                    PerceptualHashOut(
                        hash_algorithm=h.hash_algorithm,
                        hash_value=h.hash_value,
                    )
                    for h in hashes
                ],
            ),
            provenance=fusion_output.provenance,
            forensics=fusion_output.forensics,
            ml=fusion_output.ml,
            evidence_chain=fusion_output.evidence_chain,
            limitations=fusion_output.limitations,
        )

    async def _get_record(
        self, analysis_id: uuid.UUID, load_evidence: bool = False
    ) -> AnalysisRecord | None:
        stmt = select(AnalysisRecord).where(AnalysisRecord.id == analysis_id)
        if load_evidence:
            stmt = stmt.options(selectinload(AnalysisRecord.evidence_results))
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def _get_hashes(self, analysis_id: uuid.UUID) -> list[PerceptualHash]:
        stmt = select(PerceptualHash).where(
            PerceptualHash.analysis_id == analysis_id
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def _get_image_path(self, record: AnalysisRecord) -> str:
        from backend.app.core.config import get_settings
        from pathlib import Path

        settings = get_settings()
        if settings.STORAGE_BACKEND == "local":
            return str(Path(settings.STORAGE_LOCAL_PATH) / record.storage_path)
        raise NotImplementedError("Only local storage supported currently")

    async def _run_pipeline(
        self, image_path: str, analysis_id: uuid.UUID
    ) -> list:
        from backend.app.analyzers.pipeline import AnalysisPipeline

        pipeline = AnalysisPipeline()
        return await pipeline.run(image_path, analysis_id)

    def _apply_image_info(self, record: AnalysisRecord, results: list) -> None:
        for r in results:
            if r.analyzer_name == "format_analyzer" and r.raw_output:
                raw = r.raw_output
                record.detected_format = raw.get("format", record.detected_format)
                record.width = raw.get("width", record.width)
                record.height = raw.get("height", record.height)
                record.bit_depth = raw.get("bit_depth", record.bit_depth)
                record.color_mode = raw.get("color_mode", record.color_mode)
                record.color_profile = raw.get("color_profile", record.color_profile)
                record.compression_info = raw.get("compression")

    def _apply_hash_results(self, record: AnalysisRecord, results: list) -> None:
        for r in results:
            if r.analyzer_name == "hash_generator" and r.raw_output:
                phashes = r.raw_output.get("perceptual_hashes", {})
                for algo, value in phashes.items():
                    ph = PerceptualHash(
                        analysis_id=record.id,
                        hash_algorithm=algo,
                        hash_value=str(value),
                    )
                    self.db.add(ph)

    def _run_fusion(self, results: list) -> Any:
        evidence_map: dict[str, Any] = {}
        for r in results:
            evidence_map[r.analyzer_name] = {
                "findings": r.findings,
                "raw_output": r.raw_output,
                "confidence": r.confidence,
                "status": r.status,
            }

        fusion_input = FusionInput(
            metadata_result=evidence_map.get("metadata_extractor"),
            c2pa_result=evidence_map.get("c2pa_analyzer"),
            format_result=evidence_map.get("format_analyzer"),
            ela_result=evidence_map.get("ela_analyzer"),
            statistics_result=evidence_map.get("statistics_analyzer"),
            prnu_result=evidence_map.get("prnu_analyzer"),
            copy_move_result=evidence_map.get("copy_move_detector"),
            cfa_result=evidence_map.get("cfa_analyzer"),
            synthid_result=evidence_map.get("synthid_detector"),
            invisible_watermark_result=evidence_map.get("invisible_watermark_detector"),
            fft_result=evidence_map.get("fft_spectrum_analyzer"),
            ai_classifier_result=evidence_map.get("ai_classifier"),
        )
        return self.fusion.fuse(fusion_input)
