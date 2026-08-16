from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from backend.app.analyzers.base import BaseAnalyzer, AnalyzerResult

logger = logging.getLogger("provenance.analyzers.provider_registry")


@dataclass
class ProviderMatch:
    provider_name: str
    model_name: str | None
    confidence: float
    evidence_fields: list[str]
    category: str  # "ai_generator", "ai_editor", "camera", "editing_software"


_AI_PROVIDERS: list[dict[str, Any]] = [
    {
        "provider": "OpenAI",
        "category": "ai_generator",
        "patterns": {
            "software": [r"openai", r"dall[\-\s]?e", r"chatgpt", r"gpt-4o"],
            "c2pa_signer": [r"openai"],
            "c2pa_generator": [r"openai"],
        },
        "models": {
            r"dall[\-\s]?e[\-\s]?3": "DALL-E 3",
            r"dall[\-\s]?e[\-\s]?2": "DALL-E 2",
            r"gpt[\-\s]?4o": "GPT-4o",
            r"gpt[\-\s]?image": "GPT Image Generation",
        },
        "confidence": 0.95,
    },
    {
        "provider": "Google DeepMind",
        "category": "ai_generator",
        "patterns": {
            "software": [r"imagen", r"google\s+gemini", r"gemini", r"synthid"],
            "metadata": [r"synthid", r"google.*imagen"],
        },
        "models": {
            r"imagen\s*3": "Imagen 3",
            r"imagen\s*2": "Imagen 2",
            r"gemini": "Gemini",
        },
        "confidence": 0.9,
    },
    {
        "provider": "Midjourney",
        "category": "ai_generator",
        "patterns": {
            "software": [r"midjourney"],
            "metadata": [r"midjourney", r"mj_job_id", r"discord.*midjourney"],
            "png_text": [r"midjourney"],
        },
        "models": {
            r"v6": "Midjourney v6",
            r"v5": "Midjourney v5",
            r"niji": "Niji",
        },
        "confidence": 0.92,
    },
    {
        "provider": "Stability AI",
        "category": "ai_generator",
        "patterns": {
            "software": [
                r"stable\s*diffusion", r"stability", r"sdxl", r"sd\s*3",
                r"stable\s*cascade", r"stabilityai",
            ],
            "png_text": [
                r"stable\s*diffusion", r"automatic1111", r"a1111",
                r"comfyui", r"fooocus", r"invokeai", r"forge",
                r"sd[\s_]?model", r"sampler", r"cfg[\s_]?scale",
            ],
        },
        "models": {
            r"sdxl": "SDXL",
            r"sd\s*3\.5": "SD 3.5",
            r"sd\s*3": "SD 3",
            r"stable[\s_]cascade": "Stable Cascade",
            r"sd[\s_]?1\.5": "SD 1.5",
            r"sd[\s_]?2\.1": "SD 2.1",
        },
        "confidence": 0.9,
    },
    {
        "provider": "Black Forest Labs",
        "category": "ai_generator",
        "patterns": {
            "software": [r"flux", r"bfl", r"black\s*forest"],
            "png_text": [r"flux\.1", r"flux_dev", r"flux_schnell", r"flux_pro"],
        },
        "models": {
            r"flux[\.\s_]?1[\.\s_]?dev": "FLUX.1 Dev",
            r"flux[\.\s_]?1[\.\s_]?schnell": "FLUX.1 Schnell",
            r"flux[\.\s_]?1[\.\s_]?pro": "FLUX.1 Pro",
            r"flux": "FLUX",
        },
        "confidence": 0.9,
    },
    {
        "provider": "ElevenLabs",
        "category": "ai_generator",
        "patterns": {
            "software": [r"elevenlabs", r"eleven\s*labs"],
            "c2pa_signer": [r"eleven\s*labs"],
            "c2pa_generator": [r"elevenlabs"],
        },
        "models": {},
        "confidence": 0.95,
    },
    {
        "provider": "Adobe Firefly",
        "category": "ai_generator",
        "patterns": {
            "software": [r"firefly", r"adobe\s*firefly"],
            "c2pa_signer": [r"adobe"],
            "c2pa_generator": [r"firefly"],
        },
        "models": {
            r"firefly\s*3": "Firefly 3",
            r"firefly\s*2": "Firefly 2",
        },
        "confidence": 0.95,
    },
    {
        "provider": "Ideogram",
        "category": "ai_generator",
        "patterns": {"software": [r"ideogram"]},
        "models": {r"ideogram\s*2": "Ideogram 2"},
        "confidence": 0.9,
    },
    {
        "provider": "Runway",
        "category": "ai_generator",
        "patterns": {"software": [r"runway"]},
        "models": {r"gen[\-\s]?3": "Gen-3"},
        "confidence": 0.9,
    },
    {
        "provider": "Pika",
        "category": "ai_generator",
        "patterns": {"software": [r"pika"]},
        "models": {},
        "confidence": 0.9,
    },
    {
        "provider": "Kling AI",
        "category": "ai_generator",
        "patterns": {"software": [r"kling"]},
        "models": {},
        "confidence": 0.9,
    },
    {
        "provider": "Luma",
        "category": "ai_generator",
        "patterns": {"software": [r"luma", r"dream\s*machine"]},
        "models": {},
        "confidence": 0.9,
    },
    {
        "provider": "Leonardo.Ai",
        "category": "ai_generator",
        "patterns": {"software": [r"leonardo"], "png_text": [r"leonardo"]},
        "models": {},
        "confidence": 0.9,
    },
    {
        "provider": "Recraft",
        "category": "ai_generator",
        "patterns": {"software": [r"recraft"]},
        "models": {},
        "confidence": 0.9,
    },
    {
        "provider": "Civitai",
        "category": "ai_generator",
        "patterns": {"software": [r"civitai"], "png_text": [r"civitai"]},
        "models": {},
        "confidence": 0.88,
    },
    {
        "provider": "Meta AI",
        "category": "ai_generator",
        "patterns": {"software": [r"meta\s*ai", r"imagine.*meta"]},
        "models": {},
        "confidence": 0.9,
    },
    {
        "provider": "xAI / Grok",
        "category": "ai_generator",
        "patterns": {"software": [r"grok", r"xai"]},
        "models": {},
        "confidence": 0.88,
    },
]


class ProviderRegistry(BaseAnalyzer):
    name = "provider_registry"
    version = "0.1.0"

    async def analyze(self, image_path: str, analysis_id: UUID) -> AnalyzerResult:
        return self._not_implemented_result()

    def identify_from_metadata(
        self, metadata_findings: list[dict[str, Any]]
    ) -> list[ProviderMatch]:
        matches: list[ProviderMatch] = []
        searchable = self._build_searchable_text(metadata_findings)

        for provider_def in _AI_PROVIDERS:
            match = self._check_provider(provider_def, searchable, metadata_findings)
            if match:
                matches.append(match)

        matches.sort(key=lambda m: m.confidence, reverse=True)
        return matches

    def identify_from_c2pa(
        self,
        signer: str | None,
        claim_generator: str | None,
        actions: list[dict[str, Any]],
    ) -> list[ProviderMatch]:
        matches: list[ProviderMatch] = []
        combined = f"{signer or ''} {claim_generator or ''}"
        for action in actions:
            combined += f" {action.get('softwareAgent', '')} {action.get('description', '')}"

        for provider_def in _AI_PROVIDERS:
            patterns = provider_def.get("patterns", {})
            evidence: list[str] = []

            for field_key in ("c2pa_signer", "c2pa_generator", "software"):
                for pat in patterns.get(field_key, []):
                    if re.search(pat, combined, re.IGNORECASE):
                        evidence.append(f"c2pa:{field_key}")
                        break

            if evidence:
                model_name = self._detect_model(provider_def, combined)
                matches.append(ProviderMatch(
                    provider_name=provider_def["provider"],
                    model_name=model_name,
                    confidence=provider_def["confidence"],
                    evidence_fields=evidence,
                    category=provider_def["category"],
                ))

        matches.sort(key=lambda m: m.confidence, reverse=True)
        return matches

    def _build_searchable_text(
        self, findings: list[dict[str, Any]]
    ) -> dict[str, str]:
        texts: dict[str, str] = {}
        for f in findings:
            cat = f.get("category", "")
            ftype = f.get("type", "")

            if cat == "software" or ftype == "software_detected":
                texts.setdefault("software", "")
                texts["software"] += f" {f.get('software_name', '')} {f.get('description', '')}"

            if cat == "ai_parameters" or ftype in ("png_text_chunk", "sd_parameters", "comfyui_workflow"):
                texts.setdefault("png_text", "")
                raw_text = f.get("raw_value", "") or f.get("text", "") or f.get("description", "")
                texts["png_text"] += f" {raw_text}"

            texts.setdefault("metadata", "")
            texts["metadata"] += f" {f.get('description', '')} {f.get('software_name', '')}"

        return texts

    def _check_provider(
        self,
        provider_def: dict[str, Any],
        searchable: dict[str, str],
        findings: list[dict[str, Any]],
    ) -> ProviderMatch | None:
        patterns = provider_def.get("patterns", {})
        evidence: list[str] = []

        for field_key, field_patterns in patterns.items():
            text = searchable.get(field_key, "")
            if not text:
                continue
            for pat in field_patterns:
                if re.search(pat, text, re.IGNORECASE):
                    evidence.append(field_key)
                    break

        if not evidence:
            return None

        all_text = " ".join(searchable.values())
        model_name = self._detect_model(provider_def, all_text)

        return ProviderMatch(
            provider_name=provider_def["provider"],
            model_name=model_name,
            confidence=provider_def["confidence"],
            evidence_fields=evidence,
            category=provider_def["category"],
        )

    def _detect_model(self, provider_def: dict[str, Any], text: str) -> str | None:
        for pattern, model_name in provider_def.get("models", {}).items():
            if re.search(pattern, text, re.IGNORECASE):
                return model_name
        return None
