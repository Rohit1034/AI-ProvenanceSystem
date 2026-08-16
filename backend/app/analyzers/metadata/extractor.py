from __future__ import annotations

import asyncio
import logging
import re
from uuid import UUID

from backend.app.analyzers.base import BaseAnalyzer, AnalyzerResult

logger = logging.getLogger("provenance.analyzers.metadata")

AI_SOFTWARE_PATTERNS = [
    (r"dall[\-\s]?e", "DALL-E (OpenAI)"),
    (r"openai", "OpenAI"),
    (r"midjourney", "Midjourney"),
    (r"stable[\s\-]?diffusion", "Stable Diffusion"),
    (r"stability[\s\-]?ai", "Stability AI"),
    (r"firefly", "Adobe Firefly"),
    (r"flux", "FLUX"),
    (r"ideogram", "Ideogram"),
    (r"runway", "Runway"),
    (r"eleven[\s\-]?labs", "ElevenLabs"),
    (r"pika", "Pika"),
    (r"kling", "Kling AI"),
    (r"luma", "Luma Dream Machine"),
    (r"leonardo", "Leonardo.Ai"),
    (r"civitai", "Civitai"),
    (r"recraft", "Recraft"),
    (r"comfyui", "ComfyUI (Stable Diffusion)"),
    (r"automatic1111", "Automatic1111 (Stable Diffusion)"),
    (r"fooocus", "Fooocus"),
    (r"synthid", "Google SynthID"),
]

EDITING_SOFTWARE_PATTERNS = [
    (r"photoshop", "Adobe Photoshop"),
    (r"lightroom", "Adobe Lightroom"),
    (r"gimp", "GIMP"),
    (r"canva", "Canva"),
    (r"affinity[\s\-]?photo", "Affinity Photo"),
    (r"imagemagick", "ImageMagick"),
    (r"paint\.net", "Paint.NET"),
    (r"pixlr", "Pixlr"),
    (r"snapseed", "Snapseed"),
    (r"vsco", "VSCO"),
    (r"adobe[\s\-]?premiere", "Adobe Premiere"),
    (r"capture[\s\-]?one", "Capture One"),
    (r"darktable", "Darktable"),
    (r"rawtherapee", "RawTherapee"),
    (r"photos\s", "Photos App"),
    (r"samsung\s.*editor", "Samsung Photo Editor"),
    (r"google\s.*photos", "Google Photos"),
]


class MetadataExtractor(BaseAnalyzer):
    name = "metadata_extractor"
    version = "0.1.0"

    async def analyze(self, image_path: str, analysis_id: UUID) -> AnalyzerResult:
        findings: list[dict] = []
        limitations: list[str] = []
        raw: dict = {}

        # 1. Multi-source EXIF extraction (Pillow IFDs + piexif + exifread + exiftool)
        exif_data = await self._extract_exif_multi(image_path)
        if exif_data:
            raw["exif"] = exif_data
            findings.extend(self._process_exif(exif_data))
        else:
            findings.append({
                "category": "exif",
                "type": "no_exif",
                "description": "No EXIF data found",
            })

        # 2. XMP Packet extraction
        xmp_data = await self._extract_xmp(image_path)
        if xmp_data:
            raw["xmp"] = xmp_data
            findings.extend(self._process_xmp(xmp_data))

        # 3. Image Container / PIL info & text chunk extraction (PNG prompts, WebP, etc.)
        pil_info = await self._extract_pil_info(image_path)
        if pil_info:
            raw["pil_info"] = pil_info
            findings.extend(self._process_pil_info(pil_info))

        # 4. Software signatures (AI models & editing apps)
        software_findings = self._detect_software(raw)
        findings.extend(software_findings)

        # 5. Cross-field inconsistency checks
        inconsistencies = self._detect_inconsistencies(findings)
        findings.extend(inconsistencies)

        confidence = self._compute_confidence(findings)

        limitations.append("Metadata can be easily added, modified, or stripped")
        limitations.append("Presence of camera metadata does not prove the image is unedited")
        limitations.append("Absence of metadata does not prove manipulation")

        return self._make_result(
            status="completed",
            confidence=confidence,
            findings=findings,
            limitations=limitations,
            raw_output=raw,
        )

    async def _extract_exif_multi(self, path: str) -> dict | None:
        def _read():
            result: dict[str, Any] = {}

            # Engine 1: Pillow getexif() with sub-IFDs (Exif, GPS, Makernote) & _getexif()
            try:
                from PIL import Image, ExifTags
                with Image.open(path) as img:
                    # Top-level IFD
                    exif = img.getexif()
                    if exif:
                        for tag_id, val in exif.items():
                            tag_name = ExifTags.TAGS.get(tag_id, f"Tag_{tag_id}")
                            result[f"Image {tag_name}"] = str(val)[:500]

                        # Sub-IFDs
                        if hasattr(ExifTags, "IFD"):
                            for ifd_name, ifd_id in (
                                ("EXIF", ExifTags.IFD.Exif),
                                ("GPS", ExifTags.IFD.GPSInfo),
                                ("MakerNote", ExifTags.IFD.MakerNote),
                                ("Interop", ExifTags.IFD.Interop),
                            ):
                                try:
                                    sub_ifd = exif.get_ifd(ifd_id)
                                    if sub_ifd:
                                        tag_dict = (
                                            ExifTags.GPSTAGS if ifd_name == "GPS" else ExifTags.TAGS
                                        )
                                        for k, v in sub_ifd.items():
                                            name = tag_dict.get(k, f"{ifd_name}_{k}")
                                            result[f"{ifd_name} {name}"] = str(v)[:500]
                                except Exception:
                                    pass

                    # Pillow legacy _getexif() fallback
                    if hasattr(img, "_getexif"):
                        raw_exif = img._getexif()
                        if raw_exif:
                            for k, v in raw_exif.items():
                                name = ExifTags.TAGS.get(k, f"Tag_{k}")
                                if f"EXIF {name}" not in result and f"Image {name}" not in result:
                                    result[f"EXIF {name}"] = str(v)[:500]
            except Exception as e:
                logger.debug("Pillow EXIF extraction error: %s", e)

            # Engine 2: piexif fallback
            try:
                import piexif
                exif_dict = piexif.load(path)
                for ifd in ("0th", "Exif", "GPS", "1st"):
                    if ifd in exif_dict and isinstance(exif_dict[ifd], dict):
                        for tag_id, val in exif_dict[ifd].items():
                            tag_str = str(val)
                            if isinstance(val, bytes):
                                try:
                                    tag_str = val.decode("utf-8", errors="ignore")
                                except Exception:
                                    tag_str = str(val)
                            key_name = f"piexif_{ifd}_{tag_id}"
                            if key_name not in result:
                                result[key_name] = tag_str[:500]
            except Exception:
                pass

            # Engine 3: exifread fallback
            try:
                import exifread
                with open(path, "rb") as f:
                    tags = exifread.process_file(f, details=False)
                for key, value in tags.items():
                    if key not in result:
                        str_val = str(value)
                        result[key] = str_val[:500] + ("..." if len(str_val) > 500 else "")
            except Exception:
                pass

            # Engine 4: System exiftool CLI fallback (if installed on machine / container)
            try:
                import shutil
                import subprocess
                import json
                if shutil.which("exiftool"):
                    proc = subprocess.run(
                        ["exiftool", "-j", "-all", path],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if proc.returncode == 0 and proc.stdout.strip():
                        parsed = json.loads(proc.stdout)
                        if parsed and isinstance(parsed, list):
                            for k, v in parsed[0].items():
                                if k not in ("SourceFile", "Directory", "FilePermissions"):
                                    result[f"exiftool_{k}"] = str(v)[:500]
            except Exception as e:
                logger.debug("exiftool CLI fallback error: %s", e)

            return result if result else None

        return await asyncio.to_thread(_read)

    async def _extract_xmp(self, path: str) -> dict | None:
        try:
            def _read():
                with open(path, "rb") as f:
                    data = f.read()

                xmp_start = data.find(b"<x:xmpmeta")
                if xmp_start == -1:
                    xmp_start = data.find(b"<rdf:RDF")
                if xmp_start == -1:
                    return None

                xmp_end = data.find(b"</x:xmpmeta>", xmp_start)
                if xmp_end == -1:
                    xmp_end = data.find(b"</rdf:RDF>", xmp_start)
                if xmp_end == -1:
                    return None

                xmp_end += len(b"</x:xmpmeta>") if b"</x:xmpmeta>" in data[xmp_start:xmp_end + 20] else len(b"</rdf:RDF>")
                xmp_raw = data[xmp_start:xmp_end]

                from defusedxml import ElementTree as ET
                root = ET.fromstring(xmp_raw)

                result = {"raw_length": len(xmp_raw)}
                namespaces = set()
                for elem in root.iter():
                    tag = elem.tag
                    if "}" in tag:
                        ns = tag.split("}")[0].strip("{")
                        namespaces.add(ns)

                    if elem.text and elem.text.strip():
                        short_tag = tag.split("}")[-1] if "}" in tag else tag
                        text = elem.text.strip()
                        if len(text) > 500:
                            text = text[:500] + "..."
                        result[short_tag] = text

                    for attr_key, attr_val in elem.attrib.items():
                        short_key = attr_key.split("}")[-1] if "}" in attr_key else attr_key
                        if short_key not in ("about", "parseType"):
                            result[f"attr_{short_key}"] = attr_val[:500]

                result["namespaces"] = list(namespaces)
                return result

            return await asyncio.to_thread(_read)
        except ImportError:
            logger.warning("defusedxml not available for XMP parsing")
            return None
        except Exception as e:
            logger.debug("XMP extraction failed: %s", e)
            return None

    async def _extract_pil_info(self, path: str) -> dict | None:
        try:
            from PIL import Image

            def _read():
                result = {}
                with Image.open(path) as img:
                    # PNG Text chunks / metadata (parameters, prompt, workflow, etc.)
                    if hasattr(img, "text") and img.text:
                        for k, v in img.text.items():
                            result[f"png_text_{k}"] = str(v)[:2000]

                    # Pillow img.info dictionary
                    for key, val in img.info.items():
                        if key != "exif":  # already parsed
                            result[f"info_{key}"] = str(val)[:2000]

                return result if result else None

            return await asyncio.to_thread(_read)
        except Exception as e:
            logger.debug("PIL info extraction failed: %s", e)
            return None

    def _process_exif(self, exif: dict) -> list[dict]:
        findings = []

        make = exif.get("Image Make", "")
        model = exif.get("Image Model", "")
        if make or model:
            findings.append({
                "category": "camera",
                "type": "camera_info",
                "make": make,
                "model": model,
                "lens": exif.get("EXIF LensModel", ""),
            })

        exposure_keys = [
            "EXIF ExposureTime", "EXIF FNumber", "EXIF ISOSpeedRatings",
            "EXIF FocalLength", "EXIF ExposureProgram", "EXIF MeteringMode",
        ]
        exposure = {k: exif[k] for k in exposure_keys if k in exif}
        if exposure:
            findings.append({
                "category": "camera",
                "type": "exposure_settings",
                **exposure,
            })

        sw = exif.get("Image Software", "")
        if sw:
            findings.append({
                "category": "software",
                "type": "exif_software",
                "software_tag": sw,
            })

        date_keys = [
            "Image DateTime", "EXIF DateTimeOriginal", "EXIF DateTimeDigitized",
        ]
        dates = {k: exif[k] for k in date_keys if k in exif}
        if dates:
            findings.append({
                "category": "timestamps",
                "type": "exif_timestamps",
                **dates,
            })

        if "GPS GPSLatitude" in exif or "GPS GPSLongitude" in exif:
            findings.append({
                "category": "location",
                "type": "gps_present",
                "description": "GPS coordinates found in EXIF (not displayed for privacy)",
            })

        orientation = exif.get("Image Orientation")
        if orientation:
            findings.append({
                "category": "image",
                "type": "orientation",
                "value": orientation,
            })

        return findings

    def _process_xmp(self, xmp: dict) -> list[dict]:
        findings = []

        creator_tool = xmp.get("CreatorTool", "")
        if creator_tool:
            findings.append({
                "category": "software",
                "type": "xmp_creator_tool",
                "software_tag": creator_tool,
            })

        history_action = xmp.get("action", "")
        if history_action:
            findings.append({
                "category": "editing",
                "type": "xmp_history",
                "action": history_action,
                "software_agent": xmp.get("softwareAgent", ""),
            })

        for key in ("ModifyDate", "CreateDate", "MetadataDate"):
            if key in xmp:
                findings.append({
                    "category": "timestamps",
                    "type": f"xmp_{key}",
                    "value": xmp[key],
                })

        return findings

    def _process_pil_info(self, info: dict) -> list[dict]:
        findings = []

        sw = info.get("Software", "")
        if sw and not any(
            f.get("software_tag") == sw
            for f in findings
            if f.get("type") in ("exif_software", "xmp_creator_tool")
        ):
            findings.append({
                "category": "software",
                "type": "pil_software",
                "software_tag": sw,
            })

        comment = info.get("info_comment", "")
        if comment:
            findings.append({
                "category": "metadata",
                "type": "comment",
                "value": comment[:200],
            })

        return findings

    def _detect_software(self, raw: dict) -> list[dict]:
        findings = []
        all_text = " ".join(str(v) for d in raw.values() if isinstance(d, dict) for v in d.values())

        for pattern, name in AI_SOFTWARE_PATTERNS:
            if re.search(pattern, all_text, re.IGNORECASE):
                findings.append({
                    "category": "software",
                    "type": "ai_software_detected",
                    "software_name": name,
                    "confidence": 0.9,
                    "description": f"AI generation/editing software signature detected: {name}",
                })

        for pattern, name in EDITING_SOFTWARE_PATTERNS:
            if re.search(pattern, all_text, re.IGNORECASE):
                findings.append({
                    "category": "software",
                    "type": "editing_software_detected",
                    "software_name": name,
                    "confidence": 0.85,
                    "description": f"Editing software signature detected: {name}",
                })

        return findings

    def _detect_inconsistencies(self, findings: list[dict]) -> list[dict]:
        inconsistencies = []

        has_camera = any(f.get("category") == "camera" and f.get("make") for f in findings)
        has_ai_sw = any(f.get("type") == "ai_software_detected" for f in findings)
        has_edit_sw = any(f.get("type") == "editing_software_detected" for f in findings)

        if has_camera and has_ai_sw:
            inconsistencies.append({
                "category": "inconsistency",
                "type": "camera_with_ai_software",
                "description": (
                    "Camera EXIF data present alongside AI software signatures. "
                    "This may indicate an AI-edited photograph."
                ),
                "severity": "medium",
            })

        if has_camera and has_edit_sw:
            inconsistencies.append({
                "category": "consistency",
                "type": "camera_with_editing_software",
                "description": "Camera EXIF and editing software both present. Consistent with edited photograph.",
                "severity": "low",
            })

        return inconsistencies

    def _compute_confidence(self, findings: list[dict]) -> float:
        if any(f.get("type") == "no_exif" for f in findings):
            return 0.4

        has_camera = any(f.get("category") == "camera" and f.get("make") for f in findings)
        has_software = any(f.get("category") == "software" for f in findings)

        if has_camera and has_software:
            return 0.85
        if has_camera:
            return 0.8
        if has_software:
            return 0.7
        return 0.5
