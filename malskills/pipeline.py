from __future__ import annotations

import time
from dataclasses import dataclass, replace
from pathlib import Path

from .findings import SSOFindingExtractor
from .ingest import SkillIngestor
from .llm_runtime import resolve_llm_stage_enabled
from .models import AnalysisResult
from .sdg import SDGCompiler
from .reasoning.reasoner import PatternReasoner
from .report import ResultWriter
from .rule_learning.registry import RuleRegistry, RuleSnapshot
from .utils import ensure_dir


@dataclass
class AnalyzerConfig:
    enable_llm_sso_extraction: bool | None = None
    enable_llm_object_analysis: bool | None = None
    export_souffle: bool = True
    enable_semgrep: bool = True
    enable_yasa: bool = True
    enable_cross_artifact_resolution: bool = True
    reasoning_mode: str | None = None
    max_artifacts: int | None = None
    max_total_text_bytes: int | None = None
    rule_store_dir: str | Path | None = None
    collect_rule_candidates: bool | None = None
    rule_learning_group_id: str | None = None


class SkillAnalyzer:
    def __init__(self) -> None:
        self.ingestor = SkillIngestor()
        self.findings_extractor = SSOFindingExtractor()
        self.sdg_compiler = SDGCompiler()
        self.reasoner = PatternReasoner()
        self.writer = ResultWriter()

    def analyze(self, skill_path: str | Path, output_dir: str | Path | None = None, config: AnalyzerConfig | None = None) -> AnalysisResult:
        cfg = self._resolve_config(config or AnalyzerConfig())
        started_at = time.perf_counter()
        skill_root = Path(skill_path).resolve()
        rule_registry: RuleRegistry | None = None
        rule_snapshot = RuleSnapshot(
            digest="none",
            root=None,
            semgrep_dir=None,
            workflows_dir=None,
            manifest={"entries": []},
        )
        if cfg.rule_store_dir is not None:
            rule_store_root = Path(cfg.rule_store_dir).resolve()
            if rule_store_root == skill_root or rule_store_root in skill_root.parents:
                raise ValueError(
                    "rule_store_dir must not be the skill directory itself or an ancestor"
                )
            rule_registry = RuleRegistry(rule_store_root)
            rule_snapshot = rule_registry.snapshot()
        if cfg.collect_rule_candidates and rule_registry is None:
            raise ValueError("collect_rule_candidates requires rule_store_dir")
        artifacts = self.ingestor.ingest(
            skill_root,
            max_artifacts=cfg.max_artifacts,
            max_total_text_bytes=cfg.max_total_text_bytes,
            exclude_roots=[rule_registry.root] if rule_registry is not None else None,
        )
        extraction = self.findings_extractor.extract(
            str(skill_root),
            artifacts,
            enable_semgrep=cfg.enable_semgrep,
            enable_llm_sso_extraction=cfg.enable_llm_sso_extraction,
            enable_llm_object_analysis=cfg.enable_llm_object_analysis,
            additional_semgrep_rules_dirs=(
                [rule_snapshot.semgrep_dir] if rule_snapshot.semgrep_dir is not None else []
            ),
            ruleset_digest=rule_snapshot.digest,
        )
        findings = extraction.findings
        compilation = self.sdg_compiler.synthesize(
            artifacts,
            findings,
            skill_root=skill_root,
            enable_llm_object_analysis=cfg.enable_llm_object_analysis,
            enable_yasa=cfg.enable_yasa,
            enable_cross_artifact_resolution=cfg.enable_cross_artifact_resolution,
            precomputed_llm_bindings=(
                extraction.llm_operand_bindings
                if extraction.semantic_analysis_performed
                else None
            ),
        )
        runtime_sec = time.perf_counter() - started_at
        patterns, verdict, facts, workflow_discoveries = self.reasoner.reason(
            str(skill_root),
            compilation.ssos,
            artifacts=artifacts,
            findings=compilation.findings,
            graph=compilation.graph,
            mode=cfg.reasoning_mode,
            runtime_sec=runtime_sec,
            learned_workflow_rules_dir=rule_snapshot.workflows_dir,
        )
        result = AnalysisResult(
            skill_path=str(skill_root),
            artifacts=artifacts,
            findings=findings,
            ssos=compilation.ssos,
            operands=compilation.operands,
            values=compilation.values,
            operand_resolutions=compilation.resolutions,
            patterns=patterns,
            verdict=verdict,
            graph=compilation.graph,
            facts=facts,
            workflow_discoveries=workflow_discoveries,
            findings_by_producer={
                "semgrep": extraction.semgrep_findings,
                "llm": extraction.llm_findings,
            },
            analysis_metadata={
                **extraction.metadata,
                "ruleset_digest": rule_snapshot.digest,
                "rule_candidate_collection": cfg.collect_rule_candidates,
            },
        )
        feedback_payload: dict[str, object] | None = None
        if cfg.collect_rule_candidates:
            assert rule_registry is not None
            feedback_payload = self.writer.build_feedback_payload(result)
            feedback_payload["rule_learning"] = rule_registry.observe_analysis(
                result,
                feedback_payload,
                dedupe_group_id=cfg.rule_learning_group_id,
            )
        if output_dir is not None:
            destination = Path(output_dir)
            ensure_dir(destination)
            self.writer.write(
                result,
                destination,
                feedback_payload=feedback_payload,
            )
            if cfg.export_souffle:
                self.reasoner.export_souffle(facts, destination / "souffle")
        return result

    def _resolve_config(self, config: AnalyzerConfig) -> AnalyzerConfig:
        sso_extraction = resolve_llm_stage_enabled("sso_extraction")
        object_analysis = resolve_llm_stage_enabled("object_analysis")
        pattern_reasoning = resolve_llm_stage_enabled("pattern_reasoning")
        rule_feedback = resolve_llm_stage_enabled("rule_feedback")
        return replace(
            config,
            enable_llm_sso_extraction=(
                sso_extraction
                if config.enable_llm_sso_extraction is None
                else config.enable_llm_sso_extraction
            ),
            enable_llm_object_analysis=(
                object_analysis
                if config.enable_llm_object_analysis is None
                else config.enable_llm_object_analysis
            ),
            reasoning_mode=(
                config.reasoning_mode
                if config.reasoning_mode is not None
                else ("hybrid" if pattern_reasoning else "formal")
            ),
            collect_rule_candidates=(
                rule_feedback
                if config.collect_rule_candidates is None
                else config.collect_rule_candidates
            ),
        )
