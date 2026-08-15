from __future__ import annotations

import abc
import time
import logging
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID


logger = logging.getLogger("provenance.analyzers")


@dataclass
class AnalyzerResult:
    analyzer_name: str
    analyzer_version: str
    status: str = "completed"
    confidence: float | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    raw_output: dict[str, Any] = field(default_factory=dict)
    duration_ms: int = 0


class BaseAnalyzer(abc.ABC):
    name: str = "base"
    version: str = "0.1.0"

    @abc.abstractmethod
    async def analyze(self, image_path: str, analysis_id: UUID) -> AnalyzerResult:
        ...

    def _make_result(self, **kwargs: Any) -> AnalyzerResult:
        return AnalyzerResult(
            analyzer_name=self.name,
            analyzer_version=self.version,
            **kwargs,
        )

    def _not_implemented_result(self) -> AnalyzerResult:
        return self._make_result(
            status="not_implemented",
            limitations=[f"{self.name} analyzer is not yet implemented"],
        )

    async def safe_analyze(self, image_path: str, analysis_id: UUID) -> AnalyzerResult:
        start = time.monotonic()
        try:
            result = await self.analyze(image_path, analysis_id)
            result.duration_ms = int((time.monotonic() - start) * 1000)
            return result
        except Exception as exc:
            duration = int((time.monotonic() - start) * 1000)
            logger.exception(
                "Analyzer %s failed for analysis %s", self.name, analysis_id
            )
            return self._make_result(
                status="error",
                findings=[{"error": str(exc)}],
                limitations=[f"Analyzer crashed: {type(exc).__name__}"],
                duration_ms=duration,
            )
