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
    ela_result: dict[str, Any] | None = None
    statistics_result: dict[str, Any] | None = None
    prnu_result: dict[str, Any] | None = None
    copy_move_result: dict[str, Any] | None = None
    cfa_result: dict[str, Any] | None = None
    synthid_result: dict[str, Any] | None = None
    invisible_watermark_result: dict[str, Any] | None = None
    fft_result: dict[str, Any] | None = None
    ai_classifier_result: dict[str, Any] | None = None


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

    version = "0.3.0"

    def fuse(self, inputs: FusionInput) -> FusionOutput:
        evidence_chain: list[EvidenceItem] = []
        limitations: list[str] = []

        provenance = self._build_provenance(inputs, evidence_chain)
        forensics = self._build_forensics(inputs, evidence_chain)
        ml = self._build_ml(inputs, evidence_chain, limitations)

        self._assess_metadata_absence(inputs, evidence_chain)

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
                    c2pa_support = self._c2pa_supports(c2pa)
                    evidence.append(EvidenceItem(
                        source="c2pa",
                        category="provenance",
                        description=f"C2PA Content Credentials found. Signer: {c2pa.signer or c2pa.claim_generator or 'unknown'}",
                        confidence=1.0 if c2pa.valid else 0.85,
                        supports=c2pa_support,
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

                if category == "camera" and (f.get("make") or f.get("model")):
                    evidence.append(EvidenceItem(
                        source="metadata",
                        category="camera_signature",
                        description=f"Camera hardware: {f.get('make', '')} {f.get('model', '')}".strip(),
                        confidence=0.9,
                        supports="likely_original",
                    ))

                if category == "timestamps" and f.get("type") == "exif_timestamps":
                    evidence.append(EvidenceItem(
                        source="metadata",
                        category="camera_capture_timestamp",
                        description="Hardware/OS EXIF timestamp found",
                        confidence=0.8,
                        supports="likely_original",
                    ))

                if category == "location" and f.get("type") == "gps_present":
                    evidence.append(EvidenceItem(
                        source="metadata",
                        category="camera_capture_location",
                        description="GPS capture coordinates present",
                        confidence=0.85,
                        supports="likely_original",
                    ))

        self._process_watermarks(inputs, evidence, watermarks)

        return ProvenanceSection(c2pa=c2pa, metadata=metadata, watermarks=watermarks)

    def _process_watermarks(
        self,
        inputs: FusionInput,
        evidence: list[EvidenceItem],
        watermarks: list[WatermarkResult],
    ) -> None:
        if inputs.synthid_result and inputs.synthid_result.get("findings"):
            for f in inputs.synthid_result["findings"]:
                ftype = f.get("type", "")
                if ftype == "synthid_likely_present":
                    watermarks.append(WatermarkResult(
                        provider="Google DeepMind",
                        watermark_type="SynthID",
                        detected=True,
                        confidence=f.get("score", 0.7),
                        detector_version="0.1.0",
                        limitations=["Heuristic detection — requires Google API for verification"],
                    ))
                    evidence.append(EvidenceItem(
                        source="watermark",
                        category="synthid",
                        description="SynthID watermark patterns detected — likely Google AI-generated",
                        confidence=f.get("score", 0.7),
                        supports="likely_ai_generated",
                    ))
                elif ftype == "synthid_inconclusive":
                    watermarks.append(WatermarkResult(
                        provider="Google DeepMind",
                        watermark_type="SynthID",
                        detected=False,
                        confidence=f.get("score", 0.4),
                        detector_version="0.1.0",
                        limitations=["Inconclusive heuristic result"],
                    ))

        if inputs.invisible_watermark_result and inputs.invisible_watermark_result.get("findings"):
            for f in inputs.invisible_watermark_result["findings"]:
                ftype = f.get("type", "")
                if ftype == "dwt_watermark_detected":
                    watermarks.append(WatermarkResult(
                        provider="Stable Diffusion",
                        watermark_type="DWT (invisible-watermark)",
                        detected=True,
                        confidence=f.get("score", 0.6),
                        detector_version="0.1.0",
                    ))
                    evidence.append(EvidenceItem(
                        source="watermark",
                        category="dwt_watermark",
                        description="DWT invisible watermark detected — consistent with Stable Diffusion",
                        confidence=f.get("score", 0.6),
                        supports="likely_ai_generated",
                    ))
                elif ftype == "lsb_steganography_detected":
                    watermarks.append(WatermarkResult(
                        provider="Unknown",
                        watermark_type="LSB Steganography",
                        detected=True,
                        confidence=f.get("score", 0.6),
                        detector_version="0.1.0",
                    ))
                    evidence.append(EvidenceItem(
                        source="watermark",
                        category="lsb_steganography",
                        description="LSB steganographic content detected",
                        confidence=f.get("score", 0.6),
                        supports="conventionally_edited",
                    ))
                elif ftype == "dct_watermark_detected":
                    watermarks.append(WatermarkResult(
                        provider="Unknown",
                        watermark_type="DCT Frequency",
                        detected=True,
                        confidence=f.get("score", 0.5),
                        detector_version="0.1.0",
                    ))

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
                    description="Multiple JPEG stream markers detected",
                    confidence=0.6,
                    supports="conventionally_edited",
                ))

        if inputs.ela_result and inputs.ela_result.get("raw_output"):
            raw = inputs.ela_result["raw_output"]
            section.ela = raw
            findings = inputs.ela_result.get("findings", [])
            for f in findings:
                ftype = f.get("type", "")
                if ftype == "ela_suspicious_regions":
                    ratio = f.get("suspicious_ratio", 0)
                    evidence.append(EvidenceItem(
                        source="ela",
                        category="manipulation_indicator",
                        description=f"ELA detected anomalous error levels in {f.get('suspicious_blocks', 0)} regions",
                        confidence=min(0.5 + ratio * 2, 0.85),
                        supports="conventionally_edited",
                    ))
                elif ftype == "ela_high_variance":
                    evidence.append(EvidenceItem(
                        source="ela",
                        category="manipulation_indicator",
                        description="High ELA variance across image regions",
                        confidence=0.55,
                        supports="conventionally_edited",
                    ))
                elif ftype == "ela_uniform_low_error":
                    evidence.append(EvidenceItem(
                        source="ela",
                        category="compression_analysis",
                        description="Uniform low ELA error — consistent with lossless or synthetic source",
                        confidence=0.6,
                        supports="synthetic_indicator",
                    ))

        if inputs.statistics_result and inputs.statistics_result.get("raw_output"):
            raw = inputs.statistics_result["raw_output"]
            section.statistics = raw
            findings = inputs.statistics_result.get("findings", [])
            for f in findings:
                ftype = f.get("type", "")
                if ftype == "low_noise_smooth":
                    evidence.append(EvidenceItem(
                        source="statistics",
                        category="noise_analysis",
                        description="Unusually smooth noise profile — possible synthetic/AI origin",
                        confidence=0.6,
                        supports="synthetic_indicator",
                    ))
                elif ftype == "limited_color_range":
                    evidence.append(EvidenceItem(
                        source="statistics",
                        category="color_analysis",
                        description="Limited color value range",
                        confidence=0.5,
                        supports="synthetic_indicator",
                    ))

        self._process_prnu(inputs, evidence, section)
        self._process_copy_move(inputs, evidence, section)
        self._process_cfa(inputs, evidence, section)

        return section

    def _process_prnu(
        self, inputs: FusionInput, evidence: list[EvidenceItem], section: ForensicsSection
    ) -> None:
        if not inputs.prnu_result or not inputs.prnu_result.get("raw_output"):
            return

        section.noise = inputs.prnu_result["raw_output"]
        findings = inputs.prnu_result.get("findings", [])

        for f in findings:
            ftype = f.get("type", "")
            if ftype == "synthetic_noise_profile":
                evidence.append(EvidenceItem(
                    source="prnu",
                    category="sensor_noise",
                    description="Noise profile inconsistent with physical camera sensor — possible synthetic origin",
                    confidence=0.7,
                    supports="synthetic_indicator",
                ))
            elif ftype == "correlated_channel_noise":
                evidence.append(EvidenceItem(
                    source="prnu",
                    category="sensor_noise",
                    description="Highly correlated cross-channel noise — atypical of camera sensors",
                    confidence=0.65,
                    supports="synthetic_indicator",
                ))
            elif ftype == "inconsistent_spatial_noise":
                evidence.append(EvidenceItem(
                    source="prnu",
                    category="sensor_noise",
                    description="Spatially inconsistent noise distribution — possible local manipulation",
                    confidence=0.6,
                    supports="conventionally_edited",
                ))
            elif ftype == "prnu_consistent_camera":
                evidence.append(EvidenceItem(
                    source="prnu",
                    category="sensor_noise",
                    description="Sensor noise consistent with authentic camera capture",
                    confidence=0.6,
                    supports="likely_original",
                ))

    def _process_copy_move(
        self, inputs: FusionInput, evidence: list[EvidenceItem], section: ForensicsSection
    ) -> None:
        if not inputs.copy_move_result or not inputs.copy_move_result.get("raw_output"):
            return

        section.copy_move = inputs.copy_move_result["raw_output"]
        findings = inputs.copy_move_result.get("findings", [])

        for f in findings:
            ftype = f.get("type", "")
            if ftype == "copy_move_detected":
                evidence.append(EvidenceItem(
                    source="copy_move",
                    category="forgery_detection",
                    description=f"Copy-move forgery: {f.get('region_count', 0)} duplicated region(s) detected",
                    confidence=min(0.6 + f.get("match_count", 0) * 0.005, 0.9),
                    supports="conventionally_edited",
                ))
            elif ftype == "copy_move_suspicious":
                evidence.append(EvidenceItem(
                    source="copy_move",
                    category="forgery_detection",
                    description="Possible copy-move regions detected (below high-confidence threshold)",
                    confidence=0.5,
                    supports="conventionally_edited",
                ))

    def _process_cfa(
        self, inputs: FusionInput, evidence: list[EvidenceItem], section: ForensicsSection
    ) -> None:
        if not inputs.cfa_result or not inputs.cfa_result.get("raw_output"):
            return

        section.resampling = inputs.cfa_result["raw_output"]
        findings = inputs.cfa_result.get("findings", [])

        for f in findings:
            ftype = f.get("type", "")
            if ftype == "cfa_artifacts_present":
                evidence.append(EvidenceItem(
                    source="cfa",
                    category="sensor_analysis",
                    description="CFA demosaicing artifacts confirm real camera sensor capture",
                    confidence=0.7,
                    supports="likely_original",
                ))
            elif ftype == "cfa_artifacts_absent":
                evidence.append(EvidenceItem(
                    source="cfa",
                    category="sensor_analysis",
                    description="No CFA artifacts — image not from a Bayer-pattern sensor",
                    confidence=0.65,
                    supports="synthetic_indicator",
                ))
            elif ftype == "resampling_detected":
                evidence.append(EvidenceItem(
                    source="cfa",
                    category="resampling",
                    description=f"Resampling artifacts detected (period ~{f.get('period', 0):.1f}px)",
                    confidence=0.6,
                    supports="conventionally_edited",
                ))

    def _build_ml(
        self,
        inputs: FusionInput,
        evidence: list[EvidenceItem],
        limitations: list[str],
    ) -> MLSection:
        ai_generated = None
        ai_edited = None
        conventional_edit = None
        model_name = None
        model_version = None
        status = "completed"

        has_fft = inputs.fft_result and inputs.fft_result.get("raw_output")
        has_classifier = inputs.ai_classifier_result and inputs.ai_classifier_result.get("raw_output")

        if not has_fft and not has_classifier:
            limitations.append(
                "ML-based AI detection did not produce results. "
                "Classification is based on metadata and provenance signals only."
            )
            return MLSection(status="error")

        if has_classifier:
            raw = inputs.ai_classifier_result["raw_output"]
            ai_generated = raw.get("ai_generated_probability")
            ai_edited = raw.get("ai_edited_probability")
            conventional_edit = raw.get("conventional_edit_probability")
            model_name = "statistical_classifier"
            model_version = "0.1.0"

            findings = inputs.ai_classifier_result.get("findings", [])
            for f in findings:
                ftype = f.get("type", "")
                if ftype == "ai_generated_high":
                    evidence.append(EvidenceItem(
                        source="ml_classifier",
                        category="ai_detection",
                        description=f"ML classifier: high AI-generation probability ({ai_generated:.2f})",
                        confidence=min(ai_generated or 0, 0.85),
                        supports="likely_ai_generated",
                    ))
                elif ftype == "ai_generated_moderate":
                    evidence.append(EvidenceItem(
                        source="ml_classifier",
                        category="ai_detection",
                        description=f"ML classifier: moderate AI-generation signal ({ai_generated:.2f})",
                        confidence=ai_generated or 0.4,
                        supports="synthetic_indicator",
                    ))

        if has_fft:
            fft_raw = inputs.fft_result["raw_output"]
            fft_findings = inputs.fft_result.get("findings", [])
            for f in fft_findings:
                ftype = f.get("type", "")
                if ftype == "fft_ai_pattern":
                    fft_score = f.get("ai_score", 0.5)
                    evidence.append(EvidenceItem(
                        source="fft_analysis",
                        category="frequency_analysis",
                        description=f"FFT spectrum shows AI-characteristic patterns (score: {fft_score:.2f})",
                        confidence=min(fft_score, 0.8),
                        supports="likely_ai_generated",
                    ))
                elif ftype == "fft_grid_artifacts":
                    evidence.append(EvidenceItem(
                        source="fft_analysis",
                        category="frequency_analysis",
                        description="FFT detected periodic grid artifacts (possible GAN/upsampling)",
                        confidence=0.65,
                        supports="likely_ai_generated",
                    ))

        limitations.append(
            "ML classification uses statistical feature analysis (not a deep learning model). "
            "Results should be interpreted alongside provenance and forensic evidence."
        )

        return MLSection(
            ai_generated=ai_generated,
            ai_edited=ai_edited,
            conventional_edit=conventional_edit,
            model_name=model_name,
            model_version=model_version,
            status=status,
        )

    def _assess_metadata_absence(
        self, inputs: FusionInput, evidence: list[EvidenceItem]
    ) -> None:
        if not inputs.metadata_result:
            return

        findings = inputs.metadata_result.get("findings", [])
        has_exif = not any(f.get("type") == "no_exif" for f in findings)
        has_camera = any(f.get("category") in ("camera", "timestamps", "location") for f in findings)
        has_software = any(f.get("category") == "software" for f in findings)

        if has_exif or has_camera or has_software:
            return

        width = None
        height = None
        if inputs.format_result and inputs.format_result.get("raw_output"):
            raw = inputs.format_result["raw_output"]
            width = raw.get("width")
            height = raw.get("height")

        if width and height and (width * height) > 500_000:
            evidence.append(EvidenceItem(
                source="metadata",
                category="metadata_absence",
                description=f"High-resolution image ({width}x{height}) with no metadata — stripped or synthetic origin",
                confidence=0.5,
                supports="metadata_stripped",
            ))

    def _classify(
        self,
        evidence: list[EvidenceItem],
        provenance: ProvenanceSection,
        forensics: ForensicsSection,
        ml: MLSection,
    ) -> tuple[str, float]:
        if provenance.c2pa.present:
            c2pa_support = self._c2pa_supports(provenance.c2pa)
            if c2pa_support == "verified_ai_provenance":
                return "verified_ai_provenance", 0.98
            elif c2pa_support == "likely_original":
                return "likely_original", 0.95

        ai_software = any(
            e.supports and "ai" in e.supports.lower()
            for e in evidence
            if e.category == "software_signature"
        )
        if ai_software:
            return "likely_ai_generated", 0.85

        has_camera = any(
            e.category in ("camera_signature", "camera_capture_timestamp", "camera_capture_location")
            for e in evidence
        )
        has_editing = any(
            e.supports == "conventionally_edited" for e in evidence
        )
        has_synthetic = any(
            e.supports == "synthetic_indicator" for e in evidence
        )
        has_metadata_stripped = any(
            e.supports == "metadata_stripped" for e in evidence
        )
        synthetic_count = sum(
            1 for e in evidence if e.supports == "synthetic_indicator"
        )
        ai_watermark = any(
            e.category in ("synthid", "dwt_watermark") and e.supports == "likely_ai_generated"
            for e in evidence
        )
        has_cfa_camera = any(
            e.source == "cfa" and e.supports == "likely_original"
            for e in evidence
        )
        has_prnu_camera = any(
            e.source == "prnu" and e.supports == "likely_original"
            for e in evidence
        )
        has_copy_move = any(
            e.source == "copy_move" and e.supports == "conventionally_edited"
            for e in evidence
        )

        ml_ai_prob = ml.ai_generated or 0.0
        ml_strong_ai = ml_ai_prob > 0.7
        ml_moderate_ai = ml_ai_prob > 0.4

        fft_ai = any(
            e.source == "fft_analysis" and e.supports == "likely_ai_generated"
            for e in evidence
        )

        if ai_watermark:
            base_conf = max(0.8, min(0.92, 0.75 + ml_ai_prob * 0.2))
            return "likely_ai_generated", base_conf

        if ml_strong_ai and (synthetic_count >= 2 or fft_ai):
            return "likely_ai_generated", min(0.5 + ml_ai_prob * 0.4 + synthetic_count * 0.03, 0.9)

        if ml_strong_ai and has_metadata_stripped:
            return "likely_ai_generated", min(0.5 + ml_ai_prob * 0.35, 0.85)

        camera_signals = sum([has_camera, has_cfa_camera, has_prnu_camera])
        if camera_signals >= 2 and not has_editing and not ml_strong_ai:
            return "likely_original", 0.9

        if has_camera and not has_editing and not ml_strong_ai:
            return "likely_original", 0.85

        if has_camera and has_editing:
            if has_copy_move:
                return "conventionally_edited", 0.75
            return "conventionally_edited", 0.65

        if has_editing:
            return "conventionally_edited", 0.6

        if ml_strong_ai and not has_camera:
            return "likely_ai_generated", min(0.5 + ml_ai_prob * 0.3, 0.8)

        if synthetic_count >= 3 and has_metadata_stripped:
            return "likely_ai_generated", 0.6

        if synthetic_count >= 2 and has_metadata_stripped:
            return "likely_ai_generated", 0.55

        if has_metadata_stripped and synthetic_count >= 1:
            return "likely_ai_generated", 0.5

        if synthetic_count >= 2:
            return "likely_ai_generated", 0.45

        if ml_moderate_ai and synthetic_count >= 1:
            return "likely_ai_generated", 0.45

        if has_metadata_stripped:
            return "inconclusive", 0.4

        return "inconclusive", 0.3

    def _c2pa_supports(self, c2pa: C2PAInfo) -> str:
        claim_str = f"{c2pa.claim_generator or ''} {c2pa.signer or ''}".lower()
        ai_entities = (
            "openai", "dall-e", "chatgpt", "midjourney", "stable diffusion", "stability",
            "firefly", "adobe firefly", "bing", "copilot", "elevenlabs", "eleven labs",
            "runway", "pika", "kling", "luma", "sora", "ideogram", "flux", "leonardo",
            "civitai", "meta ai", "grok", "xai", "synthesia", "heygen", "canva ai",
            "recraft", "deepai", "craiyon", "nightcafe", "replicate", "fal.ai", "gemini",
            "google", "anthropic", "claude", "black forest labs", "bfl", "cohere",
        )
        if any(kw in claim_str for kw in ai_entities):
            return "verified_ai_provenance"

        for action in c2pa.actions:
            a_type = str(action.get("action", "")).lower()
            agent = str(action.get("softwareAgent", "")).lower()
            source_type = str(action.get("digitalSourceType", "")).lower()
            params = str(action.get("parameters", {})).lower()
            desc = str(action.get("description", "")).lower()

            combined = f"{a_type} {agent} {source_type} {params} {desc}"
            if any(kw in combined for kw in (
                "algorithmic", "trainedalgorithmicmedia", "openai", "dall-e", "generat",
                "synthid", "elevenlabs", "eleven labs", "ai", "synthetic", "text-to-image",
            )):
                return "verified_ai_provenance"

        camera_entities = ("leica", "sony", "nikon", "canon", "truepic", "fujifilm", "panasonic", "apple", "samsung")
        if any(kw in claim_str for kw in camera_entities):
            return "likely_original"

        return "has_provenance"

    def _software_supports(self, software: str) -> str:
        sw_lower = software.lower()
        ai_indicators = [
            "dall-e", "midjourney", "stable diffusion", "stability", "openai",
            "firefly", "flux", "ideogram", "runway", "elevenlabs", "eleven labs",
            "pika", "kling", "luma", "sora", "leonardo", "civitai", "meta ai",
            "grok", "xai", "recraft", "comfyui", "automatic1111", "fooocus", "invokeai",
        ]
        if any(kw in sw_lower for kw in ai_indicators):
            return "likely_ai_generated"

        edit_indicators = [
            "photoshop", "lightroom", "gimp", "canva", "affinity",
            "imagemagick", "paint", "pixlr", "snapseed", "vsco", "capture one",
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
        has_watermarks = (
            any(w.detected for w in (inputs.watermark_results or []))
            or (inputs.synthid_result and any(
                f.get("type") == "synthid_likely_present"
                for f in inputs.synthid_result.get("findings", [])
            ))
            or (inputs.invisible_watermark_result and any(
                f.get("type") in ("dwt_watermark_detected", "lsb_steganography_detected", "dct_watermark_detected")
                for f in inputs.invisible_watermark_result.get("findings", [])
            ))
        )
        if not has_watermarks:
            lims.append(
                "No AI watermarks (SynthID, DWT, LSB, DCT) were detected in this image."
            )
        return lims
