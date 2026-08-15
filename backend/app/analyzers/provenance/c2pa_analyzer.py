from __future__ import annotations

import asyncio
import logging
from uuid import UUID

from backend.app.analyzers.base import BaseAnalyzer, AnalyzerResult

logger = logging.getLogger("provenance.analyzers.c2pa")


class C2PAAnalyzer(BaseAnalyzer):
    name = "c2pa_analyzer"
    version = "0.1.0"

    async def analyze(self, image_path: str, analysis_id: UUID) -> AnalyzerResult:
        try:
            import c2pa
        except ImportError:
            return self._make_result(
                status="not_implemented",
                limitations=[
                    "c2pa-python library is not installed. "
                    "Install with: pip install c2pa-python"
                ],
            )

        try:
            reader = await asyncio.to_thread(self._read_c2pa, image_path, c2pa)
            if reader is None:
                return self._make_result(
                    status="completed",
                    confidence=1.0,
                    findings=[{
                        "type": "c2pa_absent",
                        "description": "No C2PA manifest found in this image",
                    }],
                    limitations=[
                        "Absence of C2PA does not prove the image is unmodified or human-created"
                    ],
                )

            return self._process_manifest(reader)

        except Exception as e:
            logger.warning("C2PA analysis error: %s", e)
            return self._make_result(
                status="completed",
                confidence=0.5,
                findings=[{
                    "type": "c2pa_error",
                    "description": f"Error reading C2PA data: {e}",
                }],
                limitations=["C2PA parsing encountered an error"],
            )

    def _read_c2pa(self, path: str, c2pa_module):
        try:
            reader = c2pa_module.Reader.from_file(path)
            return reader
        except Exception as e:
            err_str = str(e).lower()
            if "not found" in err_str or "no manifest" in err_str or "jumbf" in err_str:
                return None
            raise

    def _process_manifest(self, reader) -> AnalyzerResult:
        findings: list[dict] = []

        try:
            manifest_json = reader.json()
            if isinstance(manifest_json, str):
                import json
                manifest_data = json.loads(manifest_json)
            else:
                manifest_data = manifest_json
        except Exception as e:
            return self._make_result(
                status="completed",
                confidence=0.5,
                findings=[{
                    "type": "c2pa_parse_error",
                    "description": f"Could not parse C2PA manifest JSON: {e}",
                }],
            )

        active_manifest = None
        manifests = manifest_data.get("manifests", {})
        active_label = manifest_data.get("active_manifest", "")

        if active_label and active_label in manifests:
            active_manifest = manifests[active_label]
        elif manifests:
            active_manifest = next(iter(manifests.values()))

        if not active_manifest:
            findings.append({
                "type": "c2pa_manifest",
                "present": True,
                "valid": None,
                "description": "C2PA structure found but no active manifest",
            })
            return self._make_result(
                status="completed",
                confidence=0.6,
                findings=findings,
            )

        signer = None
        claim_generator = active_manifest.get("claim_generator", "")
        signature_info = active_manifest.get("signature_info", {})
        if signature_info:
            signer = signature_info.get("issuer", "")

        actions = []
        assertions = active_manifest.get("assertions", [])
        for assertion in assertions:
            label = assertion.get("label", "")
            data = assertion.get("data", {})

            if label == "c2pa.actions":
                action_list = data.get("actions", [])
                for a in action_list:
                    actions.append({
                        "action": a.get("action", ""),
                        "softwareAgent": a.get("softwareAgent", ""),
                        "parameters": a.get("parameters", {}),
                    })

        ingredients = []
        for assertion in assertions:
            label = assertion.get("label", "")
            if label == "c2pa.ingredient":
                data = assertion.get("data", {})
                ingredients.append({
                    "title": data.get("title", ""),
                    "format": data.get("format", ""),
                    "relationship": data.get("relationship", ""),
                })

        validation_errors = []
        validation_status = manifest_data.get("validation_status", [])
        for vs in validation_status:
            if vs.get("code"):
                validation_errors.append(vs.get("code", "") + ": " + vs.get("explanation", ""))

        is_valid = len(validation_errors) == 0
        trusted = is_valid and bool(signer)

        trust_signals = []
        if signer:
            trust_signals.append(f"Signed by: {signer}")
        if claim_generator:
            trust_signals.append(f"Generated by: {claim_generator}")
        if is_valid:
            trust_signals.append("Manifest validation passed")

        findings.append({
            "type": "c2pa_manifest",
            "present": True,
            "valid": is_valid,
            "trusted": trusted,
            "signer": signer,
            "claim_generator": claim_generator,
            "actions": actions,
            "ingredients": ingredients,
            "validation_errors": validation_errors,
            "trust_signals": trust_signals,
        })

        return self._make_result(
            status="completed",
            confidence=0.95 if is_valid else 0.5,
            findings=findings,
            raw_output=manifest_data,
        )
