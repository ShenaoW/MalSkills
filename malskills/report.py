from __future__ import annotations

import json
from pathlib import Path

from .evidence.feedback import EvidenceFeedbackAnalyzer
from .models import AnalysisResult, to_jsonable
from .utils import ensure_dir


class ResultWriter:
    def write(self, result: AnalysisResult, output_dir: str | Path) -> None:
        destination = Path(output_dir)
        ensure_dir(destination)
        graph_payload = self._build_graph_payload(result)
        feedback_payload = self._build_feedback_payload(result)
        self._write_json(destination / "verdict.json", self._build_verdict_payload(result))
        self._write_json(destination / "artifacts.json", result.artifacts)
        self._write_json(destination / "evidence.json", result.evidence)
        self._write_json(destination / "primitive_support_evidence.json", result.derived_evidence)
        self._write_json(destination / "all_evidence.json", result.combined_evidence)
        self._write_json(destination / "feedback_loop.json", feedback_payload)
        self._write_json(destination / "facts.json", self._build_facts_payload(result))
        self._write_json(destination / "evidence_graph.json", graph_payload)
        self._write_text(destination / "evidence_graph.dot", self._render_graph_dot(graph_payload))
        self._write_json(destination / "primitives.json", result.primitives)
        self._write_json(destination / "proofs.json", self._build_pattern_proofs(result))
        self._write_json(destination / "pattern_summary.json", self._summarize_patterns(result))
        self._write_markdown(destination / "human_report.md", result)
        self.write_output_manifest(destination)

    def write_output_manifest(self, output_dir: str | Path, *, include_souffle: bool | None = None) -> None:
        destination = Path(output_dir)
        self._write_json(destination / "output_manifest.json", self.build_output_manifest(destination, include_souffle=include_souffle))

    def build_output_manifest(self, output_dir: str | Path, *, include_souffle: bool | None = None) -> dict[str, object]:
        destination = Path(output_dir)
        path_map = {
            "verdict": "verdict.json",
            "artifacts": "artifacts.json",
            "evidence": "evidence.json",
            "primitive_support_evidence": "primitive_support_evidence.json",
            "all_evidence": "all_evidence.json",
            "feedback_loop": "feedback_loop.json",
            "facts": "facts.json",
            "graph_json": "evidence_graph.json",
            "graph_dot": "evidence_graph.dot",
            "primitives": "primitives.json",
            "proofs": "proofs.json",
            "pattern_summary": "pattern_summary.json",
            "human_report": "human_report.md",
        }
        if include_souffle is None:
            include_souffle = (destination / "souffle").exists()
        return {
            "schema_version": 1,
            "root": ".",
            "files": path_map,
            "directories": {
                "souffle": "souffle",
            },
            "available": {
                "souffle": bool(include_souffle),
            },
        }

    def _write_json(self, path: Path, payload: object) -> None:
        path.write_text(json.dumps(to_jsonable(payload), indent=2, sort_keys=True), encoding="utf-8")

    def _write_text(self, path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")

    def _build_feedback_payload(self, result: AnalysisResult) -> dict[str, object]:
        return EvidenceFeedbackAnalyzer().analyze(result.artifacts, result.evidence)

    def _summarize_patterns(self, result: AnalysisResult) -> list[dict[str, object]]:
        grouped: dict[str, list[object]] = {}
        for pattern in result.patterns:
            grouped.setdefault(f"{pattern.source}::{pattern.name}", []).append(pattern)
        summaries: list[dict[str, object]] = []
        for _, matches in sorted(grouped.items()):
            first = matches[0]
            primitive_ids = sorted({primitive_id for match in matches for primitive_id in match.primitive_ids})
            evidence_ids = sorted({evidence_id for match in matches for evidence_id in match.evidence_ids})
            summaries.append(
                {
                    "name": first.name,
                    "source": first.source,
                    "severity": first.severity,
                    "match_count": len(matches),
                    "rule_ids": first.rule_ids,
                    "primitive_ids": primitive_ids,
                    "evidence_ids": evidence_ids,
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
                    "primitive_ids": pattern.primitive_ids,
                    "evidence_ids": pattern.evidence_ids,
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

    def _build_facts_payload(self, result: AnalysisResult) -> dict[str, object]:
        relations: dict[str, dict[str, object]] = {}
        for relation_name, rows in sorted(result.facts.items()):
            columns = self._fact_columns(relation_name, rows)
            relations[relation_name] = {
                "columns": columns,
                "rows": [
                    {column: to_jsonable(value) for column, value in zip(columns, row)}
                    for row in rows
                ],
            }
        return {"relations": relations}

    def _build_graph_payload(self, result: AnalysisResult) -> dict[str, object]:
        nodes = [dict(node) for node in result.graph.get("nodes", [])]
        edges = [dict(edge) for edge in result.graph.get("edges", [])]
        existing_node_ids = {str(node.get("id", "")) for node in nodes}
        existing_edge_keys = {
            (str(edge.get("source", "")), str(edge.get("target", "")), str(edge.get("type", "")))
            for edge in edges
        }
        focus_artifact_ids: set[str] = set()
        focus_evidence_ids: set[str] = set()
        focus_primitive_ids: set[str] = set()
        focus_pattern_ids: list[str] = []

        for pattern in result.patterns:
            focus_pattern_ids.append(pattern.pattern_id)
            focus_evidence_ids.update(pattern.evidence_ids)
            focus_primitive_ids.update(pattern.primitive_ids)
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
            for primitive_id in pattern.primitive_ids:
                edge_key = (primitive_id, pattern.pattern_id, "triggers")
                if edge_key not in existing_edge_keys:
                    edges.append({"source": primitive_id, "target": pattern.pattern_id, "type": "triggers"})
                    existing_edge_keys.add(edge_key)
            for evidence_id in pattern.evidence_ids:
                edge_key = (evidence_id, pattern.pattern_id, "explains")
                if edge_key not in existing_edge_keys:
                    edges.append({"source": evidence_id, "target": pattern.pattern_id, "type": "explains"})
                    existing_edge_keys.add(edge_key)

        verdict_node_id = "verdict"
        if verdict_node_id not in existing_node_ids:
            nodes.append(
                {
                    "id": verdict_node_id,
                    "kind": "verdict",
                    "type": result.verdict.label,
                    "score": result.verdict.score,
                }
            )
        for pattern in result.patterns:
            edge_key = (pattern.pattern_id, verdict_node_id, "decides")
            if edge_key not in existing_edge_keys:
                edges.append({"source": pattern.pattern_id, "target": verdict_node_id, "type": "decides"})
                existing_edge_keys.add(edge_key)

        artifact_ids_by_evidence = {item.evidence_id: item.artifact_id for item in result.combined_evidence}
        focus_artifact_ids.update(
            artifact_id
            for evidence_id, artifact_id in artifact_ids_by_evidence.items()
            if evidence_id in focus_evidence_ids
        )
        focus_logical_object_ids = {
            str(edge.get("target", ""))
            for edge in edges
            if str(edge.get("source", "")) in focus_evidence_ids | focus_primitive_ids
            and str(edge.get("type", "")) in {"acts_on", "associated_with"}
        }
        payload = {
            "nodes": nodes,
            "edges": edges,
            "artifacts": list(result.graph.get("artifacts", [])),
            "focus": {
                "artifact_ids": sorted(focus_artifact_ids),
                "evidence_ids": sorted(focus_evidence_ids),
                "primitive_ids": sorted(focus_primitive_ids),
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
            f"- Score: `{result.verdict.score:.2f}`",
            f"- Malicious patterns: {', '.join(result.verdict.malicious_patterns) or 'none'}",
            f"- Suspicious patterns: {', '.join(result.verdict.suspicious_patterns) or 'none'}",
            "",
            "## Artifact Inventory",
            "",
            f"- Artifacts: {len(result.artifacts)}",
            f"- Evidence facts: {len(result.evidence)}",
            f"- Primitive-support evidence facts: {len(result.derived_evidence)}",
            f"- Combined evidence facts: {len(result.combined_evidence)}",
            f"- Primitive facts: {len(result.primitives)}",
            "",
            "## Triggered Patterns",
        ]
        if not result.patterns:
            lines.append("- None")
        for summary in pattern_summaries:
            lines.append(f"- `{summary['name']}` [{summary['source']}] ({summary['severity']}, matches={summary['match_count']}): {summary['explanation']}")
            lines.append(f"  - Rules: {', '.join(summary['rule_ids'])}")
            lines.append(f"  - Primitive IDs: {', '.join(summary['primitive_ids'][:5])}")
        lines.extend(["", "## Primitive Counts", ""])
        counts: dict[str, int] = {}
        for primitive in result.primitives:
            counts[primitive.primitive_type] = counts.get(primitive.primitive_type, 0) + 1
        if not counts:
            lines.append("- None")
        else:
            for name, count in sorted(counts.items()):
                lines.append(f"- `{name}`: {count}")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _render_graph_dot(self, graph: dict[str, object]) -> str:
        lines = [
            "digraph evidence_graph {",
            "  rankdir=LR;",
            '  graph [label="MalSkills Evidence Graph", labelloc=t];',
            '  node [shape=box, style="rounded"];',
        ]
        for node in sorted(graph.get("nodes", []), key=lambda item: str(item.get("id", ""))):
            node_id = str(node.get("id", ""))
            label_parts = [node_id]
            kind = str(node.get("kind", "")).strip()
            node_type = str(node.get("type", "")).strip()
            subtype = str(node.get("subtype", "")).strip()
            name = str(node.get("name", "")).strip()
            score = node.get("score")
            path = str(node.get("path", "")).strip()
            if kind:
                label_parts.append(f"kind={kind}")
            if node_type:
                label_parts.append(f"type={node_type}")
            if subtype:
                label_parts.append(f"subtype={subtype}")
            if name:
                label_parts.append(f"name={name}")
            if score is not None:
                label_parts.append(f"score={score}")
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

    def _fact_columns(self, relation_name: str, rows: list[tuple[object, ...]]) -> list[str]:
        schema = {
            "analysis_meta": ["key", "value"],
            "artifact": ["artifact_id", "artifact_type", "artifact_path"],
            "artifact_meta": ["artifact_id", "key", "value"],
            "evidence": ["evidence_id", "artifact_id", "evidence_type", "subtype", "value"],
            "evidence_attr": ["evidence_id", "key", "value"],
            "evidence_confidence": ["evidence_id", "confidence"],
            "evidence_span": ["evidence_id", "start_line", "end_line"],
            "graph_edge": ["source", "target", "type"],
            "pattern_match": ["pattern_id", "pattern_name", "severity"],
            "pattern_support": ["pattern_id", "primitive_id"],
            "primitive": ["primitive_id", "primitive_type"],
            "primitive_confidence": ["primitive_id", "confidence"],
            "primitive_evidence": ["primitive_id", "evidence_id"],
            "primitive_object": ["primitive_id", "object_id", "object_identity_kind"],
            "primitive_param": ["primitive_id", "key", "value"],
            "verdict": ["label", "score"],
        }
        if relation_name in schema:
            return schema[relation_name]
        width = max((len(row) for row in rows), default=0)
        return [f"col_{index}" for index in range(width)]
