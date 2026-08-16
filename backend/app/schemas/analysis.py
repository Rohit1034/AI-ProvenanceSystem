from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class EvidenceResultOut(BaseModel):
    analyzer_name: str
    analyzer_version: str
    status: str
    confidence: float | None = None
    findings: list[dict[str, Any]] | None = None
    limitations: list[str] | None = None
    duration_ms: int | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class PerceptualHashOut(BaseModel):
    hash_algorithm: str
    hash_value: str

    model_config = {"from_attributes": True}


class AnalysisSummary(BaseModel):
    analysis_id: UUID
    status: str
    classification: str | None = None
    overall_confidence: float | None = None
    original_sha256: str
    file_size: int
    mime_type: str
    detected_format: str
    width: int | None = None
    height: int | None = None
    created_at: datetime
    completed_at: datetime | None = None

    model_config = {"from_attributes": True}


class AnalysisDetail(AnalysisSummary):
    bit_depth: int | None = None
    color_mode: str | None = None
    color_profile: str | None = None
    compression_info: dict[str, Any] | None = None
    analysis_version: str
    software_version: str
    model_versions: dict[str, str] | None = None
    error_message: str | None = None
    evidence_results: list[EvidenceResultOut] = Field(default_factory=list)


class ForensicReport(BaseModel):
    analysis_id: UUID
    classification: str | None
    overall_confidence: float | None

    image_info: ImageInfo
    provenance: ProvenanceSection
    forensics: ForensicsSection
    ml: MLSection
    regions: list[dict[str, Any]] = Field(default_factory=list)
    evidence_chain: list[EvidenceItem] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class ImageInfo(BaseModel):
    sha256: str
    file_size: int
    mime_type: str
    format: str
    width: int | None = None
    height: int | None = None
    bit_depth: int | None = None
    color_mode: str | None = None
    color_profile: str | None = None
    compression_info: dict[str, Any] | None = None
    perceptual_hashes: list[PerceptualHashOut] = Field(default_factory=list)


class C2PAInfo(BaseModel):
    present: bool = False
    valid: bool | None = None
    trusted: bool | None = None
    signer: str | None = None
    claim_generator: str | None = None
    actions: list[dict[str, Any]] = Field(default_factory=list)
    ingredients: list[dict[str, Any]] = Field(default_factory=list)
    validation_errors: list[str] = Field(default_factory=list)
    trust_signals: list[str] = Field(default_factory=list)


class WatermarkResult(BaseModel):
    provider: str
    watermark_type: str
    detected: bool
    confidence: float
    detector_version: str
    limitations: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)


class ProvenanceSection(BaseModel):
    c2pa: C2PAInfo = Field(default_factory=C2PAInfo)
    metadata: dict[str, Any] = Field(default_factory=dict)
    watermarks: list[WatermarkResult] = Field(default_factory=list)


class ForensicsSection(BaseModel):
    compression: dict[str, Any] = Field(default_factory=dict)
    ela: dict[str, Any] = Field(default_factory=dict)
    noise: dict[str, Any] = Field(default_factory=dict)
    resampling: dict[str, Any] = Field(default_factory=dict)
    copy_move: dict[str, Any] = Field(default_factory=dict)
    statistics: dict[str, Any] = Field(default_factory=dict)


class MLSection(BaseModel):
    ai_generated: float | None = None
    ai_edited: float | None = None
    conventional_edit: float | None = None
    provider_prediction: str | None = None
    provider_confidence: float | None = None
    model_name: str | None = None
    model_version: str | None = None
    status: str = "not_implemented"


class EvidenceItem(BaseModel):
    source: str
    category: str
    description: str
    confidence: float | None = None
    supports: str | None = None


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    analyzers: dict[str, str] = Field(default_factory=dict)


class VersionResponse(BaseModel):
    version: str
    api_version: str
    analyzers: dict[str, str] = Field(default_factory=dict)
    ml_models: dict[str, str] = Field(default_factory=dict)


ForensicReport.model_rebuild()
