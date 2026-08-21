from __future__ import annotations

from pathlib import Path
from typing import Any

from ..models import (
    ArtifactRecord,
    PatternMatch,
    SSOFinding,
    SSORecord,
    SkillVerdict,
    WorkflowDiscovery,
)
from ..rule_learning.workflow import WorkflowRuleMatcher
from .llm import LlmPatternReasoner
from .verdict import PatternVerdictBuilder


class PatternReasoner:
    def __init__(self) -> None:
        self._verdicts = PatternVerdictBuilder()
        self._llm_reasoner = LlmPatternReasoner()
        self._workflow_rules = WorkflowRuleMatcher()
        builtin_dir = Path(__file__).resolve().parents[1] / "rules" / "workflows" / "builtin"
        self._builtin_rules = self._workflow_rules.load_rules(builtin_dir)
        for rule in self._builtin_rules:
            self._workflow_rules.validate_rule(rule, expected_source="formal")

    def reason(
        self,
        skill_path: str,
        ssos: list[SSORecord],
        *,
        artifacts: list[ArtifactRecord] | None = None,
        findings: list[SSOFinding] | None = None,
        graph: dict[str, Any] | None = None,
        mode: str = "formal",
        learned_workflow_rules_dir: str | Path | None = None,
    ) -> tuple[
        list[PatternMatch],
        SkillVerdict,
        list[WorkflowDiscovery],
    ]:
        workflow_discoveries: list[WorkflowDiscovery] = []
        if mode == "llm":
            patterns, workflow_discoveries = self._llm_reasoner.reason(
                skill_path=skill_path,
                artifacts=artifacts or [],
                findings=findings or [],
                ssos=ssos,
                graph=graph or {},
            )
            symbolic_patterns, _ = self._formal_reason(
                skill_path,
                ssos,
                graph=graph or {},
                learned_workflow_rules_dir=learned_workflow_rules_dir,
            )
            workflow_discoveries = [
                discovery
                for discovery in workflow_discoveries
                if not self._workflow_discovery_covered(discovery, symbolic_patterns)
            ]
            patterns = self._finalize_patterns(patterns)
            verdict = self._verdicts.patterns_to_verdict(skill_path, patterns)
        elif mode == "hybrid":
            patterns, verdict, workflow_discoveries = self._hybrid_reason(
                skill_path,
                ssos,
                artifacts=artifacts or [],
                findings=findings or [],
                graph=graph or {},
                learned_workflow_rules_dir=learned_workflow_rules_dir,
            )
        else:
            patterns, verdict = self._formal_reason(
                skill_path,
                ssos,
                graph=graph or {},
                learned_workflow_rules_dir=learned_workflow_rules_dir,
            )
        return patterns, verdict, workflow_discoveries

    def _hybrid_reason(
        self,
        skill_path: str,
        ssos: list[SSORecord],
        *,
        artifacts: list[ArtifactRecord],
        findings: list[SSOFinding],
        graph: dict[str, Any],
        learned_workflow_rules_dir: str | Path | None,
    ) -> tuple[list[PatternMatch], SkillVerdict, list[WorkflowDiscovery]]:
        formal_patterns, formal_verdict = self._formal_reason(
            skill_path,
            ssos,
            graph=graph,
            learned_workflow_rules_dir=learned_workflow_rules_dir,
        )
        if not self._should_run_llm_reasoning(ssos, graph, formal_patterns):
            return formal_patterns, formal_verdict, []
        llm_patterns, discoveries = self._llm_reasoner.reason(
            skill_path=skill_path,
            artifacts=artifacts,
            findings=findings,
            ssos=ssos,
            graph=graph,
            symbolic_patterns=formal_patterns,
        )
        discoveries = [
            discovery
            for discovery in discoveries
            if not self._workflow_discovery_covered(discovery, formal_patterns)
        ]
        merged = self._finalize_patterns([*formal_patterns, *llm_patterns])
        verdict = self._verdicts.patterns_to_verdict(skill_path, merged)
        return merged, verdict, discoveries

    def _should_run_llm_reasoning(
        self,
        ssos: list[SSORecord],
        graph: dict[str, Any],
        formal_patterns: list[PatternMatch],
    ) -> bool:
        if formal_patterns or len(ssos) < 2:
            return False
        for index, left in enumerate(ssos):
            for right in ssos[index + 1 :]:
                if left.subtype != right.subtype and self._workflow_rules.connected(left, right, graph):
                    return True
        return False

    def _workflow_discovery_covered(
        self,
        discovery: WorkflowDiscovery,
        symbolic_patterns: list[PatternMatch],
    ) -> bool:
        discovery_ssos = set(discovery.sso_ids)
        return any(
            pattern.name == discovery.pattern_name
            and discovery_ssos
            and discovery_ssos <= set(pattern.sso_ids)
            for pattern in symbolic_patterns
        )

    def _formal_reason(
        self,
        skill_path: str,
        ssos: list[SSORecord],
        *,
        graph: dict[str, Any] | None = None,
        learned_workflow_rules_dir: str | Path | None = None,
    ) -> tuple[list[PatternMatch], SkillVerdict]:
        active_graph = graph or {}
        patterns = self._workflow_rules.match(ssos, active_graph, self._builtin_rules)
        learned_rules = self._workflow_rules.load_rules(learned_workflow_rules_dir)
        patterns.extend(self._workflow_rules.match(ssos, active_graph, learned_rules))
        deduped = self._finalize_patterns(patterns)
        verdict = self._verdicts.patterns_to_verdict(skill_path, deduped)
        return deduped, verdict

    def _finalize_patterns(self, patterns: list[PatternMatch]) -> list[PatternMatch]:
        deduped = self._verdicts.dedupe_patterns(patterns)
        for pattern in deduped:
            if not pattern.explanation_chain:
                pattern.explanation_chain = self._build_pattern_chain(
                    pattern_id=pattern.pattern_id,
                    name=pattern.name,
                    severity=pattern.severity,
                    rule_ids=pattern.rule_ids,
                    sso_ids=pattern.sso_ids,
                    finding_ids=pattern.finding_ids,
                    source=pattern.source,
                )
        return deduped

    def _build_pattern_chain(
        self,
        *,
        pattern_id: str,
        name: str,
        severity: str,
        rule_ids: list[str],
        sso_ids: list[str],
        finding_ids: list[str],
        source: str,
    ) -> list[dict[str, object]]:
        return [
            {"stage": "sso_finding", "finding_ids": finding_ids},
            {"stage": "sso", "sso_ids": sso_ids},
            {"stage": "rule", "rule_ids": rule_ids},
            {"stage": "reasoning_source", "source": source},
            {
                "stage": "pattern",
                "pattern_id": pattern_id,
                "pattern_name": name,
                "severity": severity,
            },
        ]
