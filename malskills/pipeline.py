from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable

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
    enable_semgrep: bool = True
    enable_yasa: bool = True
    enable_cross_artifact_resolution: bool = True
    reasoning_mode: str | None = None
    max_artifacts: int | None = None
    max_total_text_bytes: int | None = None
    rule_store_dir: str | Path | None = None
    collect_rule_candidates: bool | None = None
    rule_learning_group_id: str | None = None


AnalysisProgress = Callable[[str, dict[str, object]], None]


class SkillAnalyzer:
    def __init__(self) -> None:
        self.ingestor = SkillIngestor()
        self.findings_extractor = SSOFindingExtractor()
        self.sdg_compiler = SDGCompiler()
        self.reasoner = PatternReasoner()
        self.writer = ResultWriter()

    def analyze(
        self,
        skill_path: str | Path,
        output_dir: str | Path | None = None,
        config: AnalyzerConfig | None = None,
        progress: AnalysisProgress | None = None,
    ) -> AnalysisResult:
        cfg = self._resolve_config(config or AnalyzerConfig())
        started_at = time.perf_counter()
        skill_root = Path(skill_path).resolve()
        self._progress(
            progress,
            "analysis.start",
            skill_path=str(skill_root),
            reasoning_mode=cfg.reasoning_mode,
        )
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
        stage_started_at = time.perf_counter()
        self._progress(progress, "ingest.start")
        artifacts = self.ingestor.ingest(
            skill_root,
            max_artifacts=cfg.max_artifacts,
            max_total_text_bytes=cfg.max_total_text_bytes,
            exclude_roots=[rule_registry.root] if rule_registry is not None else None,
        )
        artifact_types = Counter(item.artifact_type for item in artifacts)
        self._progress(
            progress,
            "ingest.done",
            elapsed_sec=round(time.perf_counter() - stage_started_at, 3),
            artifacts=len(artifacts),
            text_artifacts=sum(1 for item in artifacts if item.is_text),
            text_bytes=sum(item.size_bytes for item in artifacts if item.is_text),
            artifact_types=dict(sorted(artifact_types.items())),
        )
        stage_started_at = time.perf_counter()
        self._progress(
            progress,
            "sso_extract.start",
            semgrep=cfg.enable_semgrep,
            llm=cfg.enable_llm_sso_extraction,
            object_analysis=cfg.enable_llm_object_analysis,
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
        finding_subtypes = Counter(item.subtype for item in findings)
        llm_metadata = extraction.metadata.get("llm_semantic", {})
        if not isinstance(llm_metadata, dict):
            llm_metadata = {}
        self._progress(
            progress,
            "sso_extract.done",
            elapsed_sec=round(time.perf_counter() - stage_started_at, 3),
            findings=len(findings),
            semgrep_findings=len(extraction.semgrep_findings),
            static_findings=len(extraction.static_findings),
            llm_findings=len(extraction.llm_findings),
            llm_bindings=len(extraction.llm_operand_bindings),
            finding_subtypes=dict(sorted(finding_subtypes.items())),
            semgrep_status=extraction.metadata.get("semgrep", {}).get("status", "unknown"),
            llm_artifacts=llm_metadata.get("artifact_count", 0),
            llm_backend=llm_metadata.get("backend", "disabled"),
            llm_model=llm_metadata.get("model", "disabled"),
        )
        stage_started_at = time.perf_counter()
        self._progress(
            progress,
            "sdg_compile.start",
            yasa=cfg.enable_yasa,
            cross_artifact=cfg.enable_cross_artifact_resolution,
        )
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
        value_flow_kinds = Counter(
            str(edge.get("flow_kind", "propagation"))
            for edge in compilation.graph.get("edges", [])
            if edge.get("type") == "value_flow"
        )
        sso_subtypes = Counter(item.subtype for item in compilation.ssos)
        self._progress(
            progress,
            "sdg_compile.done",
            elapsed_sec=round(time.perf_counter() - stage_started_at, 3),
            ssos=len(compilation.ssos),
            operands=len(compilation.operands),
            resolutions=len(compilation.resolutions),
            nodes=len(compilation.graph.get("nodes", [])),
            edges=len(compilation.graph.get("edges", [])),
            sso_subtypes=dict(sorted(sso_subtypes.items())),
            value_flows=dict(sorted(value_flow_kinds.items())),
        )
        stage_started_at = time.perf_counter()
        self._progress(progress, "reason.start", mode=cfg.reasoning_mode)
        patterns, verdict, workflow_discoveries = self.reasoner.reason(
            str(skill_root),
            compilation.ssos,
            artifacts=artifacts,
            findings=compilation.findings,
            graph=compilation.graph,
            mode=cfg.reasoning_mode,
            learned_workflow_rules_dir=rule_snapshot.workflows_dir,
        )
        self._progress(
            progress,
            "reason.done",
            elapsed_sec=round(time.perf_counter() - stage_started_at, 3),
            patterns=[item.name for item in patterns],
            workflow_discoveries=len(workflow_discoveries),
            verdict=verdict.label,
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
            workflow_discoveries=workflow_discoveries,
            findings_by_producer={
                "semgrep": extraction.semgrep_findings,
                "static_shell_semantics": extraction.static_findings,
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
            result.feedback_payload = feedback_payload
            result.analysis_metadata["rule_feedback_summary"] = feedback_payload.get(
                "summary", {}
            )
            result.analysis_metadata["rule_learning"] = feedback_payload.get(
                "rule_learning", {}
            )
        if output_dir is not None:
            destination = Path(output_dir)
            ensure_dir(destination)
            stage_started_at = time.perf_counter()
            self._progress(
                progress,
                "write.start",
                output_dir=str(destination),
            )
            self.writer.write(
                result,
                destination,
                feedback_payload=feedback_payload,
            )
            self._progress(
                progress,
                "write.done",
                elapsed_sec=round(time.perf_counter() - stage_started_at, 3),
                output_dir=str(destination),
            )
        self._progress(
            progress,
            "analysis.done",
            elapsed_sec=round(time.perf_counter() - started_at, 3),
            verdict=verdict.label,
        )
        return result

    def _progress(
        self,
        callback: AnalysisProgress | None,
        event: str,
        **fields: object,
    ) -> None:
        if callback is not None:
            callback(event, fields)

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
