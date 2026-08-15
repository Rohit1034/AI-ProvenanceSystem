from __future__ import annotations

import logging
from typing import Any
from dataclasses import dataclass, field

from backend.app.schemas.analysis import (
    C2PAInfo,
    EvidenceItem,
    ForensicsSection,
    MLSection,
    ProvenanceSection,
    WatermarkResult,
)

logger = logging.getLogger("provenance.fusion")


@dataclass
class FusionInput:
    metadata_result: dict[str, Any] | None = None
    c2pa_result: dict[str, Any] | None = None
    watermark_results: list[dict[str, Any]] = field(default_factory=list)
    forensics_results: list[dict[str, Any]] = field(default_factory=list)
    ml_results: dict[str, Any] | None = None
    format_result: dict[str, Any] | None = None


@dataclass
class FusionOutput:
    classification: str
    overall_confidence: float
    provenance: ProvenanceSection
    forensics: ForensicsSection
    ml: MLSection
    evidence_chain: list[EvidenceItem]
    limitations: list[str]


class EvidenceFusionEngine:
    """Phase 1 evidence fusion — metadata and provenance based.

    ML-based fusion will be added in Phase 6. Currently combines:
    - C2PA provenance signals
    - Metadata software signatures
    - Format analysis indicators
    """

    version = "0.1.0"

    def fuse(self, inputs: FusionInput) -> FusionOutput:
        evidence_chain: list[EvidenceItem] = []
        limitations: list[str] = []

        provenance = self._build_provenance(inputs, evidence_chain)
        forensics = self._build_forensics(inputs, evidence_chain)
        ml = self._build_ml(inputs, evidence_chain, limitations)

        classification, confidence = self._classify(
            evidence_chain, provenance, forensics, ml
        )

        limitations.extend(self._global_limitations(inputs))

        return FusionOutput(
            classification=classification,
            overall_confidence=confidence,
            provenance=provenance,
            forensics=forensics,
            ml=ml,
            evidence_chain=evidence_chain,
            limitations=limitations,
        )

    def _build_provenance(
        self, inputs: FusionInput, evidence: list[EvidenceItem]
    ) -> ProvenanceSection:
        c2pa = C2PAInfo()
        metadata: dict[str, Any] = {}
        watermarks: list[WatermarkResult] = []

        if inputs.c2pa_result and inputs.c2pa_result.get("findings"):
            for f in inputs.c2pa_result["findings"]:
                if f.get("type") == "c2pa_manifest":
                    c2pa = C2PAInfo(
                        present=True,
                        valid=f.get("valid"),
                        trusted=f.get("trusted"),
                        signer=f.get("signer"),
                        claim_generator=f.get("claim_generator"),
                        actions=f.get("actions", []),
                        ingredients=f.get("ingredients", []),
                        validation_errors=f.get("validation_errors", []),
                        trust_signals=f.get("trust_signals", []),
                    )
                    evidence.append(EvidenceItem(
                        source="c2pa",
                        category="provenance",
                        description=f"C2PA manifest found. Signer: {c2pa.signer or 'unknown'}",
                        confidence=1.0 if c2pa.valid else 0.5,
                        supports=self._c2pa_supports(c2pa),
                    ))

        if inputs.metadata_result and inputs.metadata_result.get("findings"):
            for f in inputs.metadata_result["findings"]:
                category = f.get("category", "unknown")
                metadata.setdefault(category, []).append(f)

                if category == "software" and f.get("software_name"):
                    sw = f["software_name"]
                    evidence.append(EvidenceItem(
                        source="metadata",
                        category="software_signature",
                        description=f"Software signature detected: {sw}",
                        confidence=f.get("confidence", 0.8),
                        supports=self._software_supports(sw),
                    ))

                if category == "camera" and f.get("make"):
                    evidence.append(EvidenceItem(
                        source="metadata",
                        category="camera_signature",
                        description=f"Camera: {f.get('make')} {f.get('model', '')}",
                        confidence=0.85,
                        supports="likely_original",
                    ))

        return ProvenanceSection(c2pa=c2pa, metadata=metadata, watermarks=watermarks)

    def _build_forensics(
        self, inputs: FusionInput, evidence: list[EvidenceItem]
    ) -> ForensicsSection:
        section = ForensicsSection()

        if inputs.format_result and inputs.format_result.get("raw_output"):
            raw = inputs.format_result["raw_output"]
            if "compression" in raw:
                section.compression = raw["compression"]
            if raw.get("double_compression_indicator"):
                evidence.append(EvidenceItem(
                    source="format_analysis",
                    category="compression",
                    description="Double JPEG compression indicators detected",
                    confidence=0.7,
                    supports="conventionally_edited",
                ))

        return section

    def _build_ml(
        self,
        inputs: FusionInput,
        evidence: list[EvidenceItem],
        limitations: list[str],
    ) -> MLSection:
        limitations.append(
            "ML-based AI detection is not yet implemented. "
            "Classification is based on metadata and provenance signals only."
        )
        return MLSection(status="not_implemented")

    def _classify(
        self,
        evidence: list[EvidenceItem],
        provenance: ProvenanceSection,
        forensics: ForensicsSection,
        ml: MLSection,
    ) -> tuple[str, float]:
        if provenance.c2pa.present and provenance.c2pa.valid:
            for action in provenance.c2pa.actions:
                action_type = action.get("action", "").lower()
                if any(kw in action_type for kw in ("ai", "generat", "created")):
                    return "verified_ai_provenance", 0.95

        ai_software = any(
            e.supports and "ai" in e.supports.lower()
            for e in evidence
            if e.category == "software_signature"
        )
        if ai_software:
            return "likely_ai_generated", 0.7

        has_camera = any(e.category == "camera_signature" for e in evidence)
        has_editing = any(
            e.supports == "conventionally_edited" for e in evidence
        )

        if has_camera and not has_editing:
            return "likely_original", 0.75

        if has_camera and has_editing:
            return "conventionally_edited", 0.65

        if has_editing:
            return "conventionally_edited", 0.6

        return "inconclusive", 0.3

    def _c2pa_supports(self, c2pa: C2PAInfo) -> str:
        for action in c2pa.actions:
            a = action.get("action", "").lower()
            if any(kw in a for kw in ("ai", "generat")):
                return "verified_ai_provenance"
        if c2pa.claim_generator and any(
            kw in c2pa.claim_generator.lower()
            for kw in ("openai", "dall-e", "midjourney", "stable diffusion", "firefly")
        ):
            return "verified_ai_provenance"
        return "has_provenance"

    def _software_supports(self, software: str) -> str:
        sw_lower = software.lower()
        ai_indicators = [
            "dall-e", "midjourney", "stable diffusion", "openai",
            "firefly", "flux", "ideogram", "runway",
        ]
        if any(kw in sw_lower for kw in ai_indicators):
            return "likely_ai_generated"

        edit_indicators = [
            "photoshop", "lightroom", "gimp", "canva", "affinity",
            "imagemagick", "paint", "pixlr", "snapseed",
        ]
        if any(kw in sw_lower for kw in edit_indicators):
            return "conventionally_edited"

        return "unknown_software"

    def _global_limitations(self, inputs: FusionInput) -> list[str]:
        lims: list[str] = []
        if not inputs.c2pa_result or not any(
            f.get("type") == "c2pa_manifest"
            for f in (inputs.c2pa_result or {}).get("findings", [])
        ):
            lims.append(
                "No cryptographically verified provenance (C2PA) was found. "
                "Classification is based on heuristic evidence."
            )
        if not inputs.watermark_results:
            lims.append(
                "No AI watermark detection was performed. "
                "Watermark analyzers are not yet implemented."
            )
        return lims
