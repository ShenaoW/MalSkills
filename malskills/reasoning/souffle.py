from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from ..models import ArtifactRecord, SSOFinding, PatternMatch, SSORecord, SkillVerdict
from ..utils import ensure_dir


class SouffleExporter:
    def build_facts(
        self,
        artifacts: list[ArtifactRecord],
        findings: list[SSOFinding],
        ssos: list[SSORecord],
        graph: dict[str, Any],
        patterns: list[PatternMatch],
        verdict: SkillVerdict,
        *,
        runtime_sec: float | None,
        reasoning_mode: str,
    ) -> dict[str, list[tuple[object, ...]]]:
        facts: dict[str, list[tuple[object, ...]]] = {
            "artifact": [],
            "artifact_meta": [],
            "finding": [],
            "finding_span": [],
            "finding_confidence": [],
            "finding_attr": [],
            "graph_edge": [],
            "sso": [],
            "sso_finding": [],
            "sso_operand": [],
            "operand": [],
            "value": [],
            "value_flow": [],
            "sso_object": [],
            "sso_attr": [],
            "sso_confidence": [],
            "pattern_match": [],
            "pattern_support": [],
            "pattern_attr": [],
            "analysis_meta": [("reasoning_mode", reasoning_mode)],
            "verdict": [(verdict.label, f"{verdict.score:.2f}")],
        }
        if runtime_sec is not None:
            facts["analysis_meta"].append(("runtime_sec", f"{runtime_sec:.4f}"))
        for artifact in artifacts:
            facts["artifact"].append((artifact.artifact_id, artifact.artifact_type, artifact.relative_path))
            facts["artifact_meta"].append((artifact.artifact_id, "content_hash", artifact.content_hash))
            facts["artifact_meta"].append((artifact.artifact_id, "size_bytes", artifact.size_bytes))
            facts["artifact_meta"].append((artifact.artifact_id, "line_count", artifact.line_count))
            facts["artifact_meta"].append((artifact.artifact_id, "is_text", int(artifact.is_text)))
        for item in findings:
            facts["finding"].append(
                (
                    item.finding_id,
                    item.artifact_id,
                    item.category,
                    item.subtype,
                    item.matched_text,
                )
            )
            if item.confidence is not None:
                facts["finding_confidence"].append(
                    (item.finding_id, f"{item.confidence:.4f}")
                )
            if item.span:
                facts["finding_span"].append((item.finding_id, item.span.start_line, item.span.end_line))
            for key, value in self._flatten_fact_values(item.attributes):
                facts["finding_attr"].append((item.finding_id, key, value))
        for edge in graph.get("edges", []):
            facts["graph_edge"].append((edge.get("source", ""), edge.get("target", ""), edge.get("type", "")))
            if edge.get("type") == "has_operand":
                facts["sso_operand"].append(
                    (edge.get("source", ""), edge.get("target", ""), edge.get("role", ""))
                )
            elif edge.get("type") == "value_flow":
                facts["value_flow"].append(
                    (
                        edge.get("source", ""),
                        edge.get("target", ""),
                        edge.get("flow_kind", "propagation"),
                    )
                )
        for node in graph.get("nodes", []):
            if node.get("kind") == "operand":
                facts["operand"].append(
                    (
                        node.get("id", ""),
                        node.get("role", ""),
                        node.get("object_kind", ""),
                        node.get("identity_key", ""),
                    )
                )
            elif node.get("kind") == "value":
                facts["value"].append(
                    (
                        node.get("id", ""),
                        node.get("value_kind", ""),
                        node.get("value", ""),
                    )
                )
        for sso in ssos:
            facts["sso"].append(
                (
                    sso.sso_id,
                    sso.category,
                    sso.subtype,
                )
            )
            for finding_id in sso.finding_ids:
                facts["sso_finding"].append((sso.sso_id, finding_id))
            if sso.confidence is not None:
                facts["sso_confidence"].append(
                    (sso.sso_id, f"{sso.confidence:.4f}")
                )
            operation_object = sso.attributes.get("operation_object")
            object_identity_kind = sso.attributes.get("object_identity_kind")
            if operation_object:
                facts["sso_object"].append((sso.sso_id, operation_object, object_identity_kind or ""))
            for key, value in self._flatten_fact_values(sso.attributes):
                facts["sso_attr"].append((sso.sso_id, key, value))
        for pattern in patterns:
            facts["pattern_match"].append((pattern.pattern_id, pattern.name, pattern.severity))
            facts["pattern_attr"].append((pattern.pattern_id, "source", pattern.source))
            for sso_id in pattern.sso_ids:
                facts["pattern_support"].append((pattern.pattern_id, sso_id))
        return facts

    def export_facts(self, facts: dict[str, list[tuple[object, ...]]], output_dir: str | Path) -> None:
        destination = Path(output_dir)
        ensure_dir(destination)
        for fact_name, rows in facts.items():
            with (destination / f"{fact_name}.facts").open("w", encoding="utf-8") as handle:
                for row in rows:
                    handle.write("\t".join(str(item).replace("\t", " ") for item in row) + "\n")
        rules_src = Path(__file__).resolve().parents[1] / "rules" / "malskills.dl"
        if rules_src.exists():
            shutil.copyfile(rules_src, destination / "malskills.dl")

    def _flatten_fact_values(
        self,
        payload: dict[str, Any],
        prefix: str = "",
    ) -> list[tuple[str, object]]:
        rows: list[tuple[str, object]] = []
        for key, value in payload.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, dict):
                rows.extend(self._flatten_fact_values(value, name))
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    if isinstance(item, dict):
                        rows.extend(self._flatten_fact_values(item, f"{name}[{index}]"))
                    else:
                        rows.append((f"{name}[{index}]", item))
            else:
                rows.append((name, value))
        return rows
