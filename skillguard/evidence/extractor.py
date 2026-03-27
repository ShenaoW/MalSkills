from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..ingest import LARGE_REPO_ARTIFACT_THRESHOLD
from ..models import ArtifactRecord, EvidenceRecord
from .llm import LlmEvidenceExtractor
from .semgrep import SemgrepEvidenceExtractor


@dataclass
class EvidenceExtractionResult:
    evidence: list[EvidenceRecord]


class EvidenceExtractor:
    def __init__(self) -> None:
        self.semgrep = SemgrepEvidenceExtractor(rules_dir=Path("skillguard/rules/semgrep"))
        self.llm = LlmEvidenceExtractor()

    def extract(
        self,
        skill_root: str | Path,
        artifacts: list[ArtifactRecord],
        *,
        enable_semgrep: bool = True,
        enable_llm_evidence: bool = True,
    ) -> EvidenceExtractionResult:
        evidence_facts: list[EvidenceRecord] = []
        large_repo = len(artifacts) > LARGE_REPO_ARTIFACT_THRESHOLD
        semgrep_evidence: list[EvidenceRecord] = []
        should_run_semgrep = enable_semgrep or (enable_llm_evidence and large_repo and self.semgrep.available())
        if should_run_semgrep:
            semgrep_evidence = self.semgrep.extract(skill_root, artifacts)
            if enable_semgrep:
                evidence_facts.extend(semgrep_evidence)
        if enable_llm_evidence:
            llm_artifacts = self._select_llm_artifacts(artifacts, semgrep_evidence) if large_repo else artifacts
            evidence_facts.extend(self.llm.extract(llm_artifacts).evidence)
        evidence_facts = self._dedupe_evidence(evidence_facts)
        evidence_facts.sort(key=lambda item: (item.artifact_path, item.span.start_line if item.span else 0, item.evidence_id))
        return EvidenceExtractionResult(evidence=evidence_facts)

    def _select_llm_artifacts(
        self,
        artifacts: list[ArtifactRecord],
        semgrep_evidence: list[EvidenceRecord],
    ) -> list[ArtifactRecord]:
        eligible = [artifact for artifact in artifacts if artifact.is_text and artifact.content and not artifact.generated]
        if not eligible:
            return []
        doc_names = {"skill.md", "agents.md", "claude.md", "readme.md"}
        artifact_by_path = {artifact.relative_path: artifact for artifact in eligible}
        artifact_lookup = {artifact.relative_path.lower(): artifact.relative_path for artifact in eligible}
        all_artifacts = {artifact.relative_path: artifact for artifact in artifacts}
        selected_paths: set[str] = set()

        def add_if_present(path: str) -> None:
            normalized = path.lstrip("./")
            actual_path = artifact_lookup.get(normalized.lower())
            if actual_path is not None:
                selected_paths.add(actual_path)

        hit_paths: set[str] = set()
        for item in semgrep_evidence:
            artifact = all_artifacts.get(item.artifact_path)
            if artifact is None:
                continue
            if artifact.generated and artifact.source_artifact_path:
                add_if_present(artifact.source_artifact_path)
                hit_paths.add(artifact.source_artifact_path)
                continue
            add_if_present(artifact.relative_path)
            hit_paths.add(artifact.relative_path)

        if hit_paths:
            for hit_path in hit_paths:
                parent = Path(hit_path).parent
                for doc_name in doc_names:
                    candidate = Path(doc_name) if str(parent) == "." else parent / doc_name
                    add_if_present(candidate.as_posix())
            for doc_name in doc_names:
                add_if_present(doc_name)
        else:
            for artifact in eligible:
                if Path(artifact.relative_path).name.lower() in doc_names:
                    selected_paths.add(artifact.relative_path)

        return [artifact_by_path[path] for path in sorted(selected_paths)]

    def _dedupe_evidence(self, evidence: list[EvidenceRecord]) -> list[EvidenceRecord]:
        grouped: dict[tuple[object, ...], list[EvidenceRecord]] = {}
        for item in evidence:
            matched_text = str(item.attributes.get("matched_text", "")).strip()
            key = (
                item.artifact_id,
                item.artifact_path,
                item.evidence_type,
                item.subtype,
                matched_text,
                item.span.start_line if item.span else None,
                item.span.end_line if item.span else None,
            )
            grouped.setdefault(key, []).append(item)

        deduped: list[EvidenceRecord] = []
        for group in grouped.values():
            primary = max(group, key=lambda item: item.confidence)
            merged_attributes = dict(primary.attributes)
            engines = sorted({str(item.attributes.get("engine", "")) for item in group if str(item.attributes.get("engine", "")).strip()})
            producers = sorted({item.producer for item in group if item.producer})
            rule_ids = sorted({str(item.attributes.get("rule_id", "")) for item in group if str(item.attributes.get("rule_id", "")).strip()})
            backends = sorted({str(item.attributes.get("backend", "")) for item in group if str(item.attributes.get("backend", "")).strip()})
            models = sorted({str(item.attributes.get("model", "")) for item in group if str(item.attributes.get("model", "")).strip()})
            if engines:
                merged_attributes["engines"] = engines
            if producers:
                merged_attributes["producers"] = producers
            if rule_ids:
                merged_attributes["rule_ids"] = rule_ids
            if backends:
                merged_attributes["backends"] = backends
            if models:
                merged_attributes["models"] = models
            deduped.append(
                EvidenceRecord(
                    evidence_id=primary.evidence_id,
                    producer=primary.producer,
                    artifact_id=primary.artifact_id,
                    artifact_path=primary.artifact_path,
                    evidence_type=primary.evidence_type,
                    subtype=primary.subtype,
                    value="",
                    confidence=max(item.confidence for item in group),
                    span=primary.span,
                    binding=dict(primary.binding),
                    attributes=merged_attributes,
                    provenance=dict(primary.provenance),
                )
            )
        return deduped
