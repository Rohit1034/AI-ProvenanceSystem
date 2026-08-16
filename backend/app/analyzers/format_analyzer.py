from __future__ import annotations

import asyncio
import logging
import struct
from uuid import UUID

from backend.app.analyzers.base import BaseAnalyzer, AnalyzerResult

logger = logging.getLogger("provenance.analyzers.format_analyzer")

JPEG_MARKERS = {
    0xD8: "SOI",
    0xC0: "SOF0", 0xC1: "SOF1", 0xC2: "SOF2", 0xC3: "SOF3",
    0xC4: "DHT",
    0xDB: "DQT",
    0xDA: "SOS",
    0xD9: "EOI",
    0xDD: "DRI",
    0xE0: "APP0", 0xE1: "APP1", 0xE2: "APP2", 0xE3: "APP3",
    0xE4: "APP4", 0xE5: "APP5", 0xE6: "APP6", 0xE7: "APP7",
    0xE8: "APP8", 0xE9: "APP9", 0xEA: "APP10", 0xEB: "APP11",
    0xEC: "APP12", 0xED: "APP13", 0xEE: "APP14", 0xEF: "APP15",
    0xFE: "COM",
}


class FormatAnalyzer(BaseAnalyzer):
    name = "format_analyzer"
    version = "0.1.0"

    async def analyze(self, image_path: str, analysis_id: UUID) -> AnalyzerResult:
        findings: list[dict] = []

        img_info = await self._get_image_info(image_path)
        if not img_info:
            return self._make_result(
                status="error",
                findings=[{"error": "Cannot open image"}],
            )

        findings.append({
            "type": "image_info",
            **img_info,
        })

        fmt = img_info.get("format", "").upper()
        format_details: dict = {}

        if fmt in ("JPEG", "MPO"):
            format_details = await asyncio.to_thread(
                self._analyze_jpeg, image_path
            )
        elif fmt == "PNG":
            format_details = await asyncio.to_thread(
                self._analyze_png, image_path
            )
        elif fmt == "WEBP":
            format_details = await asyncio.to_thread(
                self._analyze_webp, image_path
            )

        if format_details:
            findings.append({"type": "format_details", **format_details})

        raw_output = {
            "format": img_info.get("format", "unknown"),
            "width": img_info.get("width"),
            "height": img_info.get("height"),
            "bit_depth": img_info.get("bit_depth"),
            "color_mode": img_info.get("mode"),
            "color_profile": img_info.get("icc_profile"),
            "compression": format_details.get("compression", {}),
            "double_compression_indicator": format_details.get(
                "double_compression_indicator", False
            ),
        }

        return self._make_result(
            status="completed",
            confidence=1.0,
            findings=findings,
            raw_output=raw_output,
        )

    async def _get_image_info(self, path: str) -> dict | None:
        try:
            from PIL import Image

            def _info():
                with Image.open(path) as img:
                    info: dict = {
                        "format": img.format,
                        "width": img.width,
                        "height": img.height,
                        "mode": img.mode,
                    }
                    if img.mode in ("L", "P"):
                        info["bit_depth"] = 8
                    elif img.mode == "1":
                        info["bit_depth"] = 1
                    elif img.mode in ("RGB", "YCbCr"):
                        info["bit_depth"] = 24
                    elif img.mode == "RGBA":
                        info["bit_depth"] = 32
                    elif img.mode == "I;16":
                        info["bit_depth"] = 16
                    else:
                        info["bit_depth"] = None

                    icc = img.info.get("icc_profile")
                    info["icc_profile"] = "present" if icc else None

                    return info

            return await asyncio.to_thread(_info)
        except Exception as e:
            logger.error("Cannot open image: %s", e)
            return None

    def _analyze_jpeg(self, path: str) -> dict:
        result: dict = {"format_type": "jpeg", "segments": [], "compression": {}}
        quantization_tables: list[dict] = []
        dqt_count = 0
        soi_count = 0
        has_jfif = False
        has_exif = False

        try:
            with open(path, "rb") as f:
                data = f.read()

            i = 0
            while i < len(data) - 1:
                if data[i] != 0xFF:
                    i += 1
                    continue

                marker = data[i + 1]
                if marker == 0x00 or marker == 0xFF:
                    i += 1
                    continue

                marker_name = JPEG_MARKERS.get(marker, f"0x{marker:02X}")
                segment_info = {"marker": marker_name, "offset": i}

                if marker == 0xD8:
                    soi_count += 1
                    result["segments"].append(segment_info)
                    i += 2
                    continue
                if marker == 0xD9:
                    result["segments"].append(segment_info)
                    break

                if i + 3 < len(data):
                    length = struct.unpack(">H", data[i + 2 : i + 4])[0]
                    segment_info["length"] = length
                else:
                    break

                if marker == 0xE0 and length >= 14:
                    seg_data = data[i + 4 : i + 2 + length]
                    if seg_data[:5] == b"JFIF\x00":
                        has_jfif = True
                        segment_info["identifier"] = "JFIF"

                if marker == 0xE1 and length >= 8:
                    seg_data = data[i + 4 : i + 2 + length]
                    if seg_data[:6] == b"Exif\x00\x00":
                        has_exif = True
                        segment_info["identifier"] = "Exif"
                    elif seg_data[:29] == b"http://ns.adobe.com/xap/1.0/\x00":
                        segment_info["identifier"] = "XMP"

                if marker == 0xED:
                    segment_info["identifier"] = "Photoshop/IPTC"

                if marker == 0xDB:
                    dqt_count += 1
                    seg_data = data[i + 4 : i + 2 + length]
                    qt = self._parse_quantization_table(seg_data)
                    if qt:
                        quantization_tables.extend(qt)

                result["segments"].append(segment_info)
                i += 2 + length

            result["compression"] = {
                "has_jfif": has_jfif,
                "has_exif": has_exif,
                "dqt_count": dqt_count,
                "soi_count": soi_count,
                "quantization_tables": quantization_tables,
            }

            is_double = self._detect_double_compression(
                soi_count, quantization_tables, has_jfif, has_exif
            )
            if is_double:
                result["double_compression_indicator"] = True

        except Exception as e:
            logger.warning("JPEG analysis error: %s", e)
            result["error"] = str(e)

        return result

    def _detect_double_compression(
        self,
        soi_count: int,
        quantization_tables: list[dict],
        has_jfif: bool,
        has_exif: bool,
    ) -> bool:
        # Multiple SOI (Start of Image) markers indicate embedded/concatenated JPEG streams
        if soi_count > 1:
            return True

        # Conflicting/all-flat unity quantization tables (non-standard compression artifact)
        if has_jfif and has_exif and len(quantization_tables) >= 2:
            all_ones = all(
                t.get("values_summary", {}).get("max", 0) == 1
                for t in quantization_tables
            )
            if all_ones:
                return True

        return False

    def _parse_quantization_table(self, data: bytes) -> list[dict]:
        tables = []
        i = 0
        while i < len(data):
            if i >= len(data):
                break
            precision_id = data[i]
            precision = (precision_id >> 4) & 0x0F
            table_id = precision_id & 0x0F
            i += 1

            element_size = 2 if precision else 1
            table_size = 64 * element_size

            if i + table_size > len(data):
                break

            values = list(data[i : i + table_size])
            tables.append({
                "table_id": table_id,
                "precision": precision,
                "values_summary": {
                    "min": min(values),
                    "max": max(values),
                    "mean": sum(values) / len(values) if values else 0,
                },
            })
            i += table_size
        return tables

    def _analyze_png(self, path: str) -> dict:
        result: dict = {"format_type": "png", "chunks": []}

        try:
            with open(path, "rb") as f:
                sig = f.read(8)
                if sig != b"\x89PNG\r\n\x1a\n":
                    result["error"] = "Invalid PNG signature"
                    return result

                while True:
                    length_bytes = f.read(4)
                    if len(length_bytes) < 4:
                        break

                    length = struct.unpack(">I", length_bytes)[0]
                    chunk_type = f.read(4)
                    if len(chunk_type) < 4:
                        break

                    chunk_name = chunk_type.decode("ascii", errors="replace")
                    chunk_info: dict = {
                        "type": chunk_name,
                        "length": length,
                    }

                    if chunk_name == "IHDR" and length >= 13:
                        ihdr_data = f.read(length)
                        w, h = struct.unpack(">II", ihdr_data[:8])
                        bit_depth = ihdr_data[8]
                        color_type = ihdr_data[9]
                        compression = ihdr_data[10]
                        filter_method = ihdr_data[11]
                        interlace = ihdr_data[12]
                        chunk_info.update({
                            "width": w, "height": h,
                            "bit_depth": bit_depth,
                            "color_type": color_type,
                            "compression": compression,
                            "filter": filter_method,
                            "interlace": interlace,
                        })
                        f.read(4)  # CRC
                    elif chunk_name in ("tEXt", "iTXt", "zTXt") and length < 65536:
                        chunk_data = f.read(length)
                        if chunk_name == "tEXt":
                            parts = chunk_data.split(b"\x00", 1)
                            if len(parts) == 2:
                                chunk_info["key"] = parts[0].decode(
                                    "ascii", errors="replace"
                                )
                                chunk_info["value_preview"] = parts[1][:200].decode(
                                    "utf-8", errors="replace"
                                )
                        f.read(4)  # CRC
                    else:
                        f.seek(length + 4, 1)  # skip data + CRC

                    result["chunks"].append(chunk_info)

                    if chunk_name == "IEND":
                        break

        except Exception as e:
            logger.warning("PNG analysis error: %s", e)
            result["error"] = str(e)

        return result

    def _analyze_webp(self, path: str) -> dict:
        result: dict = {"format_type": "webp", "riff_chunks": []}

        try:
            with open(path, "rb") as f:
                header = f.read(12)
                if len(header) < 12:
                    result["error"] = "File too short"
                    return result

                if header[:4] != b"RIFF" or header[8:12] != b"WEBP":
                    result["error"] = "Not a WebP file"
                    return result

                file_size = struct.unpack("<I", header[4:8])[0]
                result["file_size_declared"] = file_size

                while f.tell() < file_size + 8:
                    chunk_header = f.read(8)
                    if len(chunk_header) < 8:
                        break

                    chunk_id = chunk_header[:4].decode("ascii", errors="replace")
                    chunk_size = struct.unpack("<I", chunk_header[4:8])[0]

                    result["riff_chunks"].append({
                        "id": chunk_id,
                        "size": chunk_size,
                    })

                    if chunk_id == "VP8 ":
                        result["encoding"] = "lossy"
                    elif chunk_id == "VP8L":
                        result["encoding"] = "lossless"
                    elif chunk_id == "VP8X":
                        result["encoding"] = "extended"
                    elif chunk_id == "EXIF":
                        result["has_exif"] = True
                    elif chunk_id == "XMP ":
                        result["has_xmp"] = True
                    elif chunk_id == "ICCP":
                        result["has_icc"] = True

                    padded = chunk_size + (chunk_size % 2)
                    f.seek(padded, 1)

        except Exception as e:
            logger.warning("WebP analysis error: %s", e)
            result["error"] = str(e)

        return result
