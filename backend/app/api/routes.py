from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import get_settings
from backend.app.core.database import get_db
from backend.app.schemas.analysis import (
    AnalysisDetail,
    AnalysisSummary,
    ForensicReport,
    HealthResponse,
    VersionResponse,
)
from backend.app.services.analysis_service import AnalysisService
from backend.app.storage.backend import get_storage_backend

logger = logging.getLogger("provenance.api")

router = APIRouter()


def _get_service(db: AsyncSession = Depends(get_db)) -> AnalysisService:
    return AnalysisService(db, get_storage_backend())


@router.post("/analyze", response_model=AnalysisSummary, status_code=201)
async def analyze_image(
    file: UploadFile = File(...),
    service: AnalysisService = Depends(_get_service),
):
    settings = get_settings()

    if not file.filename:
        raise HTTPException(400, "No filename provided")

    content_type = file.content_type or "application/octet-stream"

    data = await file.read()

    if len(data) > settings.max_upload_bytes:
        raise HTTPException(
            413,
            f"File exceeds maximum size of {settings.MAX_UPLOAD_SIZE_MB}MB",
        )

    if len(data) == 0:
        raise HTTPException(400, "Empty file")

    record = await service.create_analysis(data, file.filename, content_type)

    try:
        record = await service.run_analysis(record.id)
    except Exception:
        logger.exception("Analysis failed for %s", record.id)

    return AnalysisSummary(
        analysis_id=record.id,
        status=record.status.value,
        classification=record.classification.value if record.classification else None,
        overall_confidence=record.overall_confidence,
        original_sha256=record.original_sha256,
        file_size=record.file_size,
        mime_type=record.mime_type,
        detected_format=record.detected_format,
        width=record.width,
        height=record.height,
        created_at=record.created_at,
        completed_at=record.completed_at,
    )


@router.get("/analysis/{analysis_id}", response_model=AnalysisDetail)
async def get_analysis(
    analysis_id: uuid.UUID,
    service: AnalysisService = Depends(_get_service),
):
    record = await service.get_analysis(analysis_id)
    if not record:
        raise HTTPException(404, "Analysis not found")

    return AnalysisDetail(
        analysis_id=record.id,
        status=record.status.value,
        classification=record.classification.value if record.classification else None,
        overall_confidence=record.overall_confidence,
        original_sha256=record.original_sha256,
        file_size=record.file_size,
        mime_type=record.mime_type,
        detected_format=record.detected_format,
        width=record.width,
        height=record.height,
        bit_depth=record.bit_depth,
        color_mode=record.color_mode,
        color_profile=record.color_profile,
        compression_info=record.compression_info,
        analysis_version=record.analysis_version,
        software_version=record.software_version,
        model_versions=record.model_versions,
        error_message=record.error_message,
        created_at=record.created_at,
        completed_at=record.completed_at,
        evidence_results=[
            {
                "analyzer_name": er.analyzer_name,
                "analyzer_version": er.analyzer_version,
                "status": er.status,
                "confidence": er.confidence,
                "findings": er.findings,
                "limitations": er.limitations,
                "duration_ms": er.duration_ms,
                "created_at": er.created_at,
            }
            for er in record.evidence_results
        ],
    )


@router.get("/analysis/{analysis_id}/report", response_model=ForensicReport)
async def get_report(
    analysis_id: uuid.UUID,
    service: AnalysisService = Depends(_get_service),
):
    report = await service.get_report(analysis_id)
    if not report:
        raise HTTPException(404, "Analysis not found")
    return report


@router.get("/health", response_model=HealthResponse)
async def health_check():
    settings = get_settings()
    return HealthResponse(
        status="ok",
        version=settings.VERSION,
        analyzers={
            "file_validator": "0.1.0",
            "hash_generator": "0.1.0",
            "format_analyzer": "0.1.0",
            "metadata_extractor": "0.1.0",
            "c2pa_analyzer": "0.1.0",
        },
    )


@router.get("/version", response_model=VersionResponse)
async def version():
    settings = get_settings()
    return VersionResponse(
        version=settings.VERSION,
        api_version="v1",
        analyzers={
            "file_validator": "0.1.0",
            "hash_generator": "0.1.0",
            "format_analyzer": "0.1.0",
            "metadata_extractor": "0.1.0",
            "c2pa_analyzer": "0.1.0",
        },
        ml_models={},
    )
