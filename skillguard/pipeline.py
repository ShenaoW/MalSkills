from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from .formal.reasoner import FormalReasoner
from .ingest import SkillIngestor
from .intent.extractor import build_intent_extractor
from .models import AnalysisResult
from .primitives.synthesizer import PrimitiveSynthesizer
from .report import ResultWriter
from .static.extractor import StaticExtractor
from .utils import ensure_dir


@dataclass
class AnalyzerConfig:
    enable_static: bool = True
    enable_intent: bool = True
    export_souffle: bool = True
    enable_semgrep: bool = True
    enable_yasa: bool = True
    enable_cross_artifact_resolution: bool = True
    enable_capability_mismatch: bool = True
    reasoning_mode: str = "formal"


class SkillAnalyzer:
    def __init__(self) -> None:
        self.ingestor = SkillIngestor()
        self.static_extractor = StaticExtractor()
        self.intent_extractor = build_intent_extractor()
        self.synthesizer = PrimitiveSynthesizer()
        self.reasoner = FormalReasoner()
        self.writer = ResultWriter()

    def analyze(self, skill_path: str | Path, output_dir: str | Path | None = None, config: AnalyzerConfig | None = None) -> AnalysisResult:
        cfg = config or AnalyzerConfig()
        started_at = time.perf_counter()
        artifacts = self.ingestor.ingest(skill_path)
        static_evidence = []
        if cfg.enable_static:
            static_evidence = self.static_extractor.extract(
                str(Path(skill_path).resolve()),
                artifacts,
                enable_semgrep=cfg.enable_semgrep,
                enable_yasa=cfg.enable_yasa,
            ).evidence
        intent_evidence = self.intent_extractor.extract(artifacts).evidence if cfg.enable_intent else []
        evidence = static_evidence + intent_evidence
        primitives, graph = self.synthesizer.synthesize(
            artifacts,
            evidence,
            enable_cross_artifact_resolution=cfg.enable_cross_artifact_resolution,
        )
        runtime_sec = time.perf_counter() - started_at
        patterns, verdict, facts = self.reasoner.reason(
            str(Path(skill_path).resolve()),
            primitives,
            artifacts=artifacts,
            evidence=evidence,
            graph=graph,
            enable_capability_mismatch=cfg.enable_capability_mismatch,
            mode=cfg.reasoning_mode,
            runtime_sec=runtime_sec,
        )
        result = AnalysisResult(
            skill_path=str(Path(skill_path).resolve()),
            artifacts=artifacts,
            evidence=evidence,
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
