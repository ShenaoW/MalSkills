from __future__ import annotations

import json
from pathlib import Path

from .findings.feedback import SSOFindingFeedbackAnalyzer
from .models import AnalysisResult, to_jsonable
from .utils import ensure_dir


class ResultWriter:
    def write(
        self,
        result: AnalysisResult,
        output_dir: str | Path,
        *,
        feedback_payload: dict[str, object] | None = None,
    ) -> None:
        destination = Path(output_dir)
        ensure_dir(destination)
        graph_payload = self._build_graph_payload(result)
        feedback_payload = (
            feedback_payload
            or result.feedback_payload
            or self.disabled_feedback_payload()
        )
        self._write_json(destination / "verdict.json", self._build_verdict_payload(result))
        self._write_json(destination / "artifacts.json", result.artifacts)
        self._write_json(
            destination / "sso_findings.json",
            [self._finding_payload(item) for item in result.findings],
        )
        self._write_json(
            destination / "ssos.json",
            [self._sso_payload(item) for item in result.ssos],
        )
        self._write_json(destination / "operands.json", result.operands)
        self._write_json(destination / "values.json", result.values)
        self._write_json(
            destination / "operand_resolutions.json", result.operand_resolutions
        )
        self._write_json(destination / "feedback_loop.json", feedback_payload)
        self._write_json(destination / "workflow_discoveries.json", result.workflow_discoveries)
        self._write_json(destination / "analysis_metadata.json", result.analysis_metadata)
        self._write_json(destination / "sdg.json", graph_payload)
        self._write_text(destination / "sdg.dot", self._render_graph_dot(graph_payload))
        self._write_json(destination / "proofs.json", self._build_pattern_proofs(result))
        self._write_json(destination / "pattern_summary.json", self._summarize_patterns(result))
        self._write_markdown(destination / "human_report.md", result)
        self.write_output_manifest(destination)

    def write_output_manifest(self, output_dir: str | Path) -> None:
        destination = Path(output_dir)
        self._write_json(destination / "output_manifest.json", self.build_output_manifest())

    def build_output_manifest(self) -> dict[str, object]:
        path_map = {
            "verdict": "verdict.json",
            "artifacts": "artifacts.json",
            "sso_findings": "sso_findings.json",
            "ssos": "ssos.json",
            "operands": "operands.json",
            "values": "values.json",
            "operand_resolutions": "operand_resolutions.json",
            "feedback_loop": "feedback_loop.json",
            "workflow_discoveries": "workflow_discoveries.json",
            "analysis_metadata": "analysis_metadata.json",
            "sdg_json": "sdg.json",
            "sdg_dot": "sdg.dot",
            "proofs": "proofs.json",
            "pattern_summary": "pattern_summary.json",
            "human_report": "human_report.md",
        }
        return {
            "schema_version": 6,
            "root": ".",
            "files": path_map,
            "directories": {},
            "available": {},
        }

    def _write_json(self, path: Path, payload: object) -> None:
        path.write_text(json.dumps(to_jsonable(payload), indent=2, sort_keys=True), encoding="utf-8")

    def _write_text(self, path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")

    def _finding_payload(self, finding: object) -> dict[str, object]:
        payload = to_jsonable(finding)
        if payload.get("confidence") is None:
            payload.pop("confidence", None)
        return payload

    def _sso_payload(self, sso: object) -> dict[str, object]:
        payload = to_jsonable(sso)
        if payload.get("confidence") is None:
            payload.pop("confidence", None)
        return payload

    def build_feedback_payload(self, result: AnalysisResult) -> dict[str, object]:
        return SSOFindingFeedbackAnalyzer().analyze(
            result.artifacts,
            result.findings,
            semgrep_findings=result.findings_by_producer.get("semgrep"),
            llm_findings=result.findings_by_producer.get("llm"),
        )

    def disabled_feedback_payload(self) -> dict[str, object]:
        return {
            "status": "disabled",
            "llm_only_hits": [],
            "llm_rule_feedback": [],
            "semgrep_rule_candidates": [],
            "summary": {
                "llm_only_hit_count": 0,
                "reviewed_hit_count": 0,
                "semgrep_candidate_count": 0,
                "proposed_rule_count": 0,
                "rejected_rule_count": 0,
            },
        }

    def _summarize_patterns(self, result: AnalysisResult) -> list[dict[str, object]]:
        grouped: dict[str, list[object]] = {}
        for pattern in result.patterns:
            grouped.setdefault(f"{pattern.source}::{pattern.name}", []).append(pattern)
        summaries: list[dict[str, object]] = []
        for _, matches in sorted(grouped.items()):
            first = matches[0]
            sso_ids = sorted({sso_id for match in matches for sso_id in match.sso_ids})
            finding_ids = sorted({finding_id for match in matches for finding_id in match.finding_ids})
            summaries.append(
                {
                    "name": first.name,
                    "source": first.source,
                    "severity": first.severity,
                    "match_count": len(matches),
                    "rule_ids": first.rule_ids,
                    "sso_ids": sso_ids,
                    "finding_ids": finding_ids,
                    "explanation": first.explanation,
                    "explanation_chain": getattr(first, "explanation_chain", []),
                }
            )
        return summaries

    def _build_pattern_proofs(self, result: AnalysisResult) -> list[dict[str, object]]:
        proofs: list[dict[str, object]] = []
        for pattern in result.patterns:
            proofs.append(
                {
                    "pattern_id": pattern.pattern_id,
                    "name": pattern.name,
                    "severity": pattern.severity,
                    "rule_ids": pattern.rule_ids,
                    "sso_ids": pattern.sso_ids,
                    "finding_ids": pattern.finding_ids,
                    "explanation": pattern.explanation,
                    "source": pattern.source,
                    "explanation_chain": getattr(pattern, "explanation_chain", []),
                }
            )
        return proofs

    def _build_verdict_payload(self, result: AnalysisResult) -> dict[str, object]:
        payload = to_jsonable(result.verdict)
        payload["decision_chain"] = getattr(result.verdict, "decision_chain", [])
        payload["supporting_patterns"] = self._build_pattern_proofs(result)
        return payload

    def _build_graph_payload(self, result: AnalysisResult) -> dict[str, object]:
        nodes = [dict(node) for node in result.graph.get("nodes", [])]
        edges = [dict(edge) for edge in result.graph.get("edges", [])]
        existing_node_ids = {str(node.get("id", "")) for node in nodes}
        existing_edge_keys = {
            (str(edge.get("source", "")), str(edge.get("target", "")), str(edge.get("type", "")))
            for edge in edges
        }
        focus_artifact_ids: set[str] = set()
        focus_finding_ids: set[str] = set()
        focus_sso_ids: set[str] = set()
        focus_pattern_ids: list[str] = []

        for pattern in result.patterns:
            focus_pattern_ids.append(pattern.pattern_id)
            focus_finding_ids.update(pattern.finding_ids)
            focus_sso_ids.update(pattern.sso_ids)
            if pattern.pattern_id not in existing_node_ids:
                nodes.append(
                    {
                        "id": pattern.pattern_id,
                        "kind": "pattern",
                        "type": pattern.severity,
                        "name": pattern.name,
                        "source": pattern.source,
                    }
                )
                existing_node_ids.add(pattern.pattern_id)
            for sso_id in pattern.sso_ids:
                edge_key = (sso_id, pattern.pattern_id, "triggers")
                if edge_key not in existing_edge_keys:
                    edges.append({"source": sso_id, "target": pattern.pattern_id, "type": "triggers"})
                    existing_edge_keys.add(edge_key)
        verdict_node_id = "verdict"
        if verdict_node_id not in existing_node_ids:
            nodes.append(
                {
                    "id": verdict_node_id,
                    "kind": "verdict",
                    "type": result.verdict.label,
                }
            )
        for pattern in result.patterns:
            edge_key = (pattern.pattern_id, verdict_node_id, "decides")
            if edge_key not in existing_edge_keys:
                edges.append({"source": pattern.pattern_id, "target": verdict_node_id, "type": "decides"})
                existing_edge_keys.add(edge_key)

        artifact_ids_by_finding = {
            item.finding_id: item.artifact_id for item in result.findings
        }
        focus_artifact_ids.update(
            artifact_id
            for finding_id, artifact_id in artifact_ids_by_finding.items()
            if finding_id in focus_finding_ids
        )
        focus_logical_object_ids = {
            str(edge.get("target", ""))
            for edge in edges
            if str(edge.get("source", "")) in focus_sso_ids
            and str(edge.get("type", "")) == "has_operand"
        }
        payload = {
            "nodes": nodes,
            "edges": edges,
            "artifacts": list(result.graph.get("artifacts", [])),
            "focus": {
                "artifact_ids": sorted(focus_artifact_ids),
                "finding_ids": sorted(focus_finding_ids),
                "sso_ids": sorted(focus_sso_ids),
                "logical_object_ids": sorted(focus_logical_object_ids),
                "pattern_ids": sorted(focus_pattern_ids),
                "verdict_node_id": verdict_node_id,
            },
        }
        return payload

    def _write_markdown(self, path: Path, result: AnalysisResult) -> None:
        pattern_summaries = self._summarize_patterns(result)
        lines = [
            f"# Analysis Report: {result.skill_path}",
            "",
            f"- Verdict: `{result.verdict.label}`",
            f"- Malicious patterns: {', '.join(result.verdict.malicious_patterns) or 'none'}",
            "",
            "## Artifact Inventory",
            "",
            f"- Artifacts: {len(result.artifacts)}",
            f"- SSO findings: {len(result.findings)}",
            f"- Operand resolutions: {len(result.operand_resolutions)}",
            f"- SSO facts: {len(result.ssos)}",
            f"- Operand facts: {len(result.operands)}",
            f"- Value facts: {len(result.values)}",
            "",
            "## Triggered Patterns",
        ]
        if not result.patterns:
            lines.append("- None")
        for summary in pattern_summaries:
            lines.append(f"- `{summary['name']}` [{summary['source']}] ({summary['severity']}, matches={summary['match_count']}): {summary['explanation']}")
            lines.append(f"  - Rules: {', '.join(summary['rule_ids'])}")
            lines.append(f"  - SSO IDs: {', '.join(summary['sso_ids'][:5])}")
        lines.extend(["", "## SSO Counts", ""])
        counts: dict[str, int] = {}
        for sso in result.ssos:
            counts[sso.subtype] = counts.get(sso.subtype, 0) + 1
        if not counts:
            lines.append("- None")
        else:
            for name, count in sorted(counts.items()):
                lines.append(f"- `{name}`: {count}")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _render_graph_dot(self, graph: dict[str, object]) -> str:
        lines = [
            "digraph sdg {",
            "  rankdir=LR;",
            '  graph [label="MalSkills Skill Dependency Graph", labelloc=t];',
            '  node [shape=box, style="rounded"];',
        ]
        for node in sorted(graph.get("nodes", []), key=lambda item: str(item.get("id", ""))):
            node_id = str(node.get("id", ""))
            label_parts = [node_id]
            kind = str(node.get("kind", "")).strip()
            node_type = str(node.get("type", "")).strip()
            subtype = str(node.get("subtype", "")).strip()
            name = str(node.get("name", "")).strip()
            path = str(node.get("path", "")).strip()
            if kind:
                label_parts.append(f"kind={kind}")
            if node_type:
                label_parts.append(f"type={node_type}")
            if subtype:
                label_parts.append(f"subtype={subtype}")
            if name:
                label_parts.append(f"name={name}")
            if path:
                label_parts.append(f"path={path}")
            node_label = self._escape_dot("\n".join(label_parts))
            lines.append(f'  "{self._escape_dot(node_id)}" [label="{node_label}"];')
        for edge in sorted(
            graph.get("edges", []),
            key=lambda item: (str(item.get("source", "")), str(item.get("target", "")), str(item.get("type", ""))),
        ):
            source = self._escape_dot(str(edge.get("source", "")))
            target = self._escape_dot(str(edge.get("target", "")))
            edge_type = self._escape_dot(str(edge.get("type", "")))
            lines.append(f'  "{source}" -> "{target}" [label="{edge_type}"];')
        lines.append("}")
        return "\n".join(lines) + "\n"

    def _escape_dot(self, value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
