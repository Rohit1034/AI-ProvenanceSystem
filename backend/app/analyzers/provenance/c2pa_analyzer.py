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
        manifest_data = await asyncio.to_thread(self._read_c2pa_multi, image_path)

        if manifest_data is None:
            return self._make_result(
                status="completed",
                confidence=1.0,
                findings=[{
                    "type": "c2pa_absent",
                    "description": "No C2PA manifest found in this image",
                }],
                limitations=[
                    "Absence of C2PA does not prove the image is unmodified or human-created (most social networks strip C2PA metadata)"
                ],
            )

        if isinstance(manifest_data, dict) and "error" in manifest_data:
            return self._make_result(
                status="completed",
                confidence=0.5,
                findings=[{
                    "type": "c2pa_error",
                    "description": f"C2PA parsing error: {manifest_data['error']}",
                }],
                limitations=["C2PA parsing encountered an error"],
            )

        return self._process_manifest(manifest_data)

    def _read_c2pa_multi(self, path: str) -> dict | None:
        # Method 1: c2pa-python SDK (c2pa.read_file or c2pa.Reader)
        try:
            import c2pa
            import json

            # Try c2pa.read_file
            if hasattr(c2pa, "read_file"):
                try:
                    res = c2pa.read_file(path)
                    if res:
                        return json.loads(res) if isinstance(res, str) else res
                except Exception as e:
                    err_str = str(e).lower()
                    if not any(kw in err_str for kw in ("not found", "no manifest", "jumbf", "empty")):
                        logger.debug("c2pa.read_file non-fatal: %s", e)

            # Try c2pa.Reader.from_file or c2pa.Reader
            if hasattr(c2pa, "Reader"):
                try:
                    if hasattr(c2pa.Reader, "from_file"):
                        reader = c2pa.Reader.from_file(path)
                    else:
                        reader = c2pa.Reader(path)
                    if reader:
                        res = reader.json() if hasattr(reader, "json") else str(reader)
                        return json.loads(res) if isinstance(res, str) else res
                except Exception as e:
                    err_str = str(e).lower()
                    if not any(kw in err_str for kw in ("not found", "no manifest", "jumbf", "empty")):
                        logger.debug("c2pa.Reader non-fatal: %s", e)
        except ImportError:
            logger.debug("c2pa-python library not available in runtime")
        except Exception as e:
            logger.debug("c2pa python extraction error: %s", e)

        # Method 2: Official c2patool CLI (if installed in container or host system)
        try:
            import shutil
            import subprocess
            import json

            if shutil.which("c2patool"):
                proc = subprocess.run(
                    ["c2patool", path, "--detailed"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    return json.loads(proc.stdout)
        except Exception as e:
            logger.debug("c2patool CLI error: %s", e)

        return None

    def _process_manifest(self, manifest_data: dict) -> AnalyzerResult:
        findings: list[dict] = []
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
        if not claim_generator:
            gen_info = active_manifest.get("claim_generator_info", [])
            if gen_info and isinstance(gen_info, list) and len(gen_info) > 0:
                claim_generator = gen_info[0].get("name", "")

        signature_info = active_manifest.get("signature_info", {})
        if signature_info:
            signer = (
                signature_info.get("issuer")
                or signature_info.get("common_name")
                or signature_info.get("organization")
                or signature_info.get("cert_serial_number")
            )

        actions = []
        assertions = active_manifest.get("assertions", [])
        for assertion in assertions:
            label = assertion.get("label", "")
            data = assertion.get("data", {})

            if label.startswith("c2pa.actions"):
                action_list = data.get("actions", [])
                for a in action_list:
                    actions.append({
                        "action": a.get("action", ""),
                        "softwareAgent": a.get("softwareAgent", ""),
                        "digitalSourceType": a.get("digitalSourceType", ""),
                        "parameters": a.get("parameters", {}),
                        "description": a.get("description", ""),
                    })

        ingredients = []
        for assertion in assertions:
            label = assertion.get("label", "")
            if label.startswith("c2pa.ingredient"):
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
