from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from .evidence import EvidenceExtractor
from .ingest import SkillIngestor
from .models import AnalysisResult
from .primitive import PrimitiveCompiler
from .reasoning.reasoner import FormalReasoner
from .report import ResultWriter
from .utils import ensure_dir


@dataclass
class AnalyzerConfig:
    enable_llm_evidence: bool = True
    export_souffle: bool = True
    enable_semgrep: bool = True
    enable_yasa: bool = True
    enable_cross_artifact_resolution: bool = True
    reasoning_mode: str = "hybrid"
    max_artifacts: int | None = None
    max_total_text_bytes: int | None = None


class SkillAnalyzer:
    def __init__(self) -> None:
        self.ingestor = SkillIngestor()
        self.evidence_extractor = EvidenceExtractor()
        self.primitive_compiler = PrimitiveCompiler()
        self.reasoner = FormalReasoner()
        self.writer = ResultWriter()

    def analyze(self, skill_path: str | Path, output_dir: str | Path | None = None, config: AnalyzerConfig | None = None) -> AnalysisResult:
        cfg = config or AnalyzerConfig()
        started_at = time.perf_counter()
        artifacts = self.ingestor.ingest(
            skill_path,
            max_artifacts=cfg.max_artifacts,
            max_total_text_bytes=cfg.max_total_text_bytes,
        )
        evidence = self.evidence_extractor.extract(
            str(Path(skill_path).resolve()),
            artifacts,
            enable_semgrep=cfg.enable_semgrep,
            enable_llm_evidence=cfg.enable_llm_evidence,
        ).evidence
        primitives, graph, derived_evidence, combined_evidence = self.primitive_compiler.synthesize(
            artifacts,
            evidence,
            skill_root=skill_path,
            enable_yasa=cfg.enable_yasa,
            enable_cross_artifact_resolution=cfg.enable_cross_artifact_resolution,
        )
        runtime_sec = time.perf_counter() - started_at
        patterns, verdict, facts = self.reasoner.reason(
            str(Path(skill_path).resolve()),
            primitives,
            artifacts=artifacts,
            evidence=combined_evidence,
            graph=graph,
            mode=cfg.reasoning_mode,
            runtime_sec=runtime_sec,
        )
        result = AnalysisResult(
            skill_path=str(Path(skill_path).resolve()),
            artifacts=artifacts,
            evidence=evidence,
            derived_evidence=derived_evidence,
            combined_evidence=combined_evidence,
            primitives=primitives,
            patterns=patterns,
            verdict=verdict,
            graph=graph,
            facts=facts,
        )
        if output_dir is not None:
            destination = Path(output_dir)
            ensure_dir(destination)
            self.writer.write(result, destination)
            if cfg.export_souffle:
                self.reasoner.export_souffle(facts, destination / "souffle")
        return result
