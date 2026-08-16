"""Quick validation of analyzers against the 4 test images."""
import asyncio
import json
import uuid
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.app.analyzers.format_analyzer import FormatAnalyzer
from backend.app.analyzers.metadata.extractor import MetadataExtractor
from backend.app.analyzers.forensics.ela_analyzer import ELAAnalyzer
from backend.app.analyzers.forensics.statistics_analyzer import StatisticsAnalyzer
from backend.app.fusion.engine import EvidenceFusionEngine, FusionInput


IMAGES = [
    ("respose/image/1.png", "AI-generated"),
    ("respose/image/2.JPG", "Modified photo"),
    ("respose/image/3.jpg", "Excel-generated"),
    ("respose/image/4.JPG", "Original iPhone"),
]


async def test_image(path: str, label: str):
    aid = uuid.uuid4()
    fmt = FormatAnalyzer()
    meta = MetadataExtractor()
    ela = ELAAnalyzer()
    stats = StatisticsAnalyzer()

    fmt_result = await fmt.safe_analyze(path, aid)
    meta_result = await meta.safe_analyze(path, aid)
    ela_result = await ela.safe_analyze(path, aid)
    stats_result = await stats.safe_analyze(path, aid)

    fusion_input = FusionInput(
        metadata_result={"findings": meta_result.findings, "raw_output": meta_result.raw_output},
        format_result={"findings": fmt_result.findings, "raw_output": fmt_result.raw_output},
        ela_result={"findings": ela_result.findings, "raw_output": ela_result.raw_output},
        statistics_result={"findings": stats_result.findings, "raw_output": stats_result.raw_output},
    )

    engine = EvidenceFusionEngine()
    output = engine.fuse(fusion_input)

    print(f"\n{'='*60}")
    print(f"Image: {path} ({label})")
    print(f"Classification: {output.classification}")
    print(f"Confidence: {output.overall_confidence}")
    print(f"Evidence chain ({len(output.evidence_chain)} items):")
    for e in output.evidence_chain:
        print(f"  - [{e.source}] {e.description} (supports: {e.supports}, conf: {e.confidence})")

    if ela_result.raw_output.get("global_stats"):
        gs = ela_result.raw_output["global_stats"]
        print(f"ELA: mean_error={gs['mean_error']:.2f}, std={gs['std_error']:.2f}")

    if stats_result.raw_output.get("noise_level") is not None:
        print(f"Stats: noise={stats_result.raw_output['noise_level']:.3f}, laplacian_var={stats_result.raw_output['laplacian_variance']:.2f}")

    dc = fmt_result.raw_output.get("double_compression_indicator", False)
    soi = fmt_result.raw_output.get("compression", {}).get("soi_count", "N/A")
    print(f"Format: double_compression={dc}, soi_count={soi}")


async def main():
    for path, label in IMAGES:
        full = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), path)
        if os.path.exists(full):
            await test_image(full, label)
        else:
            print(f"MISSING: {full}")


if __name__ == "__main__":
    asyncio.run(main())
