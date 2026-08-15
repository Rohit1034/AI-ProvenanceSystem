from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from backend.app.core.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AnalysisStatus(str, enum.Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class ClassificationCategory(str, enum.Enum):
    VERIFIED_AI_PROVENANCE = "verified_ai_provenance"
    LIKELY_AI_GENERATED = "likely_ai_generated"
    LIKELY_AI_EDITED = "likely_ai_edited"
    CONVENTIONALLY_EDITED = "conventionally_edited"
    LIKELY_ORIGINAL = "likely_original"
    MIXED_PROVENANCE = "mixed_provenance"
    INCONCLUSIVE = "inconclusive"


class AnalysisRecord(Base):
    __tablename__ = "analysis_records"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    original_sha256 = Column(String(64), nullable=False, index=True)
    file_size = Column(Integer, nullable=False)
    original_filename = Column(String(255), nullable=True)
    mime_type = Column(String(127), nullable=False)
    detected_format = Column(String(31), nullable=False)
    width = Column(Integer, nullable=True)
    height = Column(Integer, nullable=True)
    bit_depth = Column(Integer, nullable=True)
    color_mode = Column(String(31), nullable=True)
    color_profile = Column(String(255), nullable=True)
    compression_info = Column(JSONB, nullable=True)

    status = Column(
        Enum(AnalysisStatus), nullable=False, default=AnalysisStatus.PENDING
    )
    classification = Column(Enum(ClassificationCategory), nullable=True)
    overall_confidence = Column(Float, nullable=True)

    storage_path = Column(String(1024), nullable=False)

    analysis_version = Column(String(31), nullable=False, default="0.1.0")
    software_version = Column(String(31), nullable=False, default="0.1.0")
    model_versions = Column(JSONB, nullable=True)

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )
    completed_at = Column(DateTime(timezone=True), nullable=True)

    error_message = Column(Text, nullable=True)

    evidence_results = relationship(
        "EvidenceResult", back_populates="analysis", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_analysis_created", "created_at"),
        Index("ix_analysis_status", "status"),
    )


class EvidenceResult(Base):
    __tablename__ = "evidence_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    analysis_id = Column(
        UUID(as_uuid=True),
        ForeignKey("analysis_records.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    analyzer_name = Column(String(63), nullable=False)
    analyzer_version = Column(String(31), nullable=False)
    status = Column(String(31), nullable=False, default="pending")
    confidence = Column(Float, nullable=True)
    findings = Column(JSONB, nullable=True)
    limitations = Column(JSONB, nullable=True)
    raw_output = Column(JSONB, nullable=True)
    duration_ms = Column(Integer, nullable=True)

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    analysis = relationship("AnalysisRecord", back_populates="evidence_results")

    __table_args__ = (
        Index("ix_evidence_analyzer", "analysis_id", "analyzer_name"),
    )


class PerceptualHash(Base):
    __tablename__ = "perceptual_hashes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    analysis_id = Column(
        UUID(as_uuid=True),
        ForeignKey("analysis_records.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    hash_algorithm = Column(String(31), nullable=False)
    hash_value = Column(String(255), nullable=False, index=True)

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
