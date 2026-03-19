from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from ..models import ArtifactRecord, EvidenceRecord
from .semgrep import SemgrepAdapter
from .yasa import YasaAdapter


@dataclass
class StaticExtractionResult:
    evidence: list[EvidenceRecord]


class StaticExtractor:
    def __init__(self) -> None:
        self.semgrep_adapter = SemgrepAdapter()
        self.yasa_adapter = YasaAdapter()
        self.fusion = EvidenceFusion()

    def extract(
        self,
        skill_root: str,
        artifacts: list[ArtifactRecord],
        *,
        enable_semgrep: bool = True,
        enable_yasa: bool = True,
    ) -> StaticExtractionResult:
        evidence_batches: list[list[EvidenceRecord]] = []
        if enable_semgrep:
            evidence_batches.append(self.semgrep_adapter.extract(skill_root, artifacts))
        if enable_yasa:
            evidence_batches.append(self.yasa_adapter.extract(skill_root, artifacts))
        fused = self.fusion.fuse(self._flatten(evidence_batches))
        return StaticExtractionResult(evidence=fused)

    def _flatten(self, batches: Iterable[list[EvidenceRecord]]) -> list[EvidenceRecord]:
        flattened: list[EvidenceRecord] = []
        for batch in batches:
            flattened.extend(batch)
        return flattened


class EvidenceFusion:
    def fuse(self, evidence: list[EvidenceRecord]) -> list[EvidenceRecord]:
        grouped: dict[tuple[object, ...], list[EvidenceRecord]] = {}
        for item in evidence:
            key = (
                item.artifact_id,
                item.evidence_type,
                item.subtype,
                item.value.strip(),
                item.span.start_line if item.span else None,
                item.span.end_line if item.span else None,
            )
            grouped.setdefault(key, []).append(item)

        fused: list[EvidenceRecord] = []
        for group in grouped.values():
            primary = max(group, key=lambda item: item.confidence)
            attrs = self._merge_attributes(group)
            fused.append(
                EvidenceRecord(
                    evidence_id=primary.evidence_id,
                    artifact_id=primary.artifact_id,
                    artifact_path=primary.artifact_path,
                    evidence_type=primary.evidence_type,
                    subtype=primary.subtype,
                    value=primary.value,
                    confidence=max(item.confidence for item in group),
                    span=primary.span,
                    attributes=attrs,
                )
            )
        fused.sort(key=lambda item: (item.artifact_path, item.span.start_line if item.span else 0, item.evidence_type, item.subtype, item.evidence_id))
        return fused

    def _merge_attributes(self, group: list[EvidenceRecord]) -> dict[str, object]:
        merged: dict[str, object] = {}
        for item in group:
            for key, value in item.attributes.items():
                if value in (None, "", [], {}):
                    continue
                existing = merged.get(key)
                if existing is None:
                    merged[key] = value
                elif existing == value:
                    continue
                elif isinstance(existing, list):
                    if value not in existing:
                        existing.append(value)
                else:
                    merged[key] = [existing, value] if value != existing else existing
        merged["engines"] = sorted(self._collect_attr(group, "engine"))
        merged["rule_ids"] = sorted(self._collect_attr(group, "rule_id"))
        merged["supporting_evidence_ids"] = [item.evidence_id for item in group]
        return merged

    def _collect_attr(self, group: list[EvidenceRecord], key: str) -> set[str]:
        values: set[str] = set()
        for item in group:
            value = item.attributes.get(key)
            if isinstance(value, str) and value:
                values.add(value)
        return values
