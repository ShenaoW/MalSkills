from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from ..models import ArtifactRecord, EvidenceRecord, PatternMatch, PrimitiveRecord, SkillVerdict
from ..utils import ensure_dir


class SouffleExporter:
    def build_facts(
        self,
        artifacts: list[ArtifactRecord],
        evidence: list[EvidenceRecord],
        primitives: list[PrimitiveRecord],
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
            "evidence": [],
            "evidence_span": [],
            "evidence_confidence": [],
            "evidence_attr": [],
            "graph_edge": [],
            "primitive": [],
            "primitive_object": [],
            "primitive_param": [],
            "primitive_evidence": [],
            "primitive_confidence": [],
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
        for item in evidence:
            matched_text = str(item.attributes.get("matched_text", "")).strip()
            facts["evidence"].append(
                (item.evidence_id, item.artifact_id, item.evidence_type, item.subtype, matched_text)
            )
            facts["evidence_confidence"].append((item.evidence_id, f"{item.confidence:.4f}"))
            if item.span:
                facts["evidence_span"].append((item.evidence_id, item.span.start_line, item.span.end_line))
            for key, value in self._flatten_fact_values(item.attributes):
                facts["evidence_attr"].append((item.evidence_id, key, value))
        for edge in graph.get("edges", []):
            facts["graph_edge"].append((edge.get("source", ""), edge.get("target", ""), edge.get("type", "")))
        for primitive in primitives:
            facts["primitive"].append((primitive.primitive_id, primitive.primitive_type))
            facts["primitive_confidence"].append((primitive.primitive_id, f"{primitive.confidence:.4f}"))
            operation_object = primitive.params.get("operation_object")
            object_identity_kind = primitive.params.get("object_identity_kind")
            if operation_object:
                facts["primitive_object"].append((primitive.primitive_id, operation_object, object_identity_kind or ""))
            for key, value in self._flatten_fact_values(primitive.params):
                facts["primitive_param"].append((primitive.primitive_id, key, value))
            for evidence_id in primitive.evidence_ids:
                facts["primitive_evidence"].append((primitive.primitive_id, evidence_id))
        for pattern in patterns:
            facts["pattern_match"].append((pattern.pattern_id, pattern.name, pattern.severity))
            facts["pattern_attr"].append((pattern.pattern_id, "source", pattern.source))
            for primitive_id in pattern.primitive_ids:
                facts["pattern_support"].append((pattern.pattern_id, primitive_id))
        return facts

    def export_facts(self, facts: dict[str, list[tuple[object, ...]]], output_dir: str | Path) -> None:
        destination = Path(output_dir)
        ensure_dir(destination)
        for fact_name, rows in facts.items():
            with (destination / f"{fact_name}.facts").open("w", encoding="utf-8") as handle:
                for row in rows:
                    handle.write("\t".join(str(item).replace("\t", " ") for item in row) + "\n")
        rules_src = Path(__file__).resolve().parents[1] / "rules" / "skillguard.dl"
        if rules_src.exists():
            shutil.copyfile(rules_src, destination / "skillguard.dl")

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
