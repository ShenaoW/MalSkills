from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from pathlib import Path
from typing import Any


@dataclass
class Span:
    start_line: int
    end_line: int


@dataclass
class ArtifactRecord:
    artifact_id: str
    relative_path: str
    artifact_type: str
    content_hash: str
    size_bytes: int
    line_count: int
    is_text: bool
    content: str | None = None
    generated: bool = False
    source_artifact_id: str | None = None
    source_artifact_path: str | None = None
    source_start_line: int | None = None
    source_end_line: int | None = None


@dataclass
class EvidenceRecord:
    evidence_id: str
    artifact_id: str
    artifact_path: str
    evidence_type: str
    subtype: str
    value: str
    confidence: float
    producer: str = ""
    span: Span | None = None
    binding: dict[str, Any] = field(default_factory=dict)
    attributes: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)


@dataclass
class PrimitiveRecord:
    primitive_id: str
    primitive_type: str
    params: dict[str, Any]
    confidence: float
    evidence_ids: list[str]
    artifact_paths: list[str]
    primitive_category: str = ""


@dataclass
class PatternMatch:
    pattern_id: str
    name: str
    severity: str
    rule_ids: list[str]
    primitive_ids: list[str]
    evidence_ids: list[str]
    explanation: str
    source: str = "formal"


@dataclass
class SkillVerdict:
    skill_path: str
    label: str
    score: float
    malicious_patterns: list[str]
    suspicious_patterns: list[str]
    summary: str


@dataclass
class AnalysisResult:
    skill_path: str
    artifacts: list[ArtifactRecord]
    evidence: list[EvidenceRecord]
    derived_evidence: list[EvidenceRecord]
    combined_evidence: list[EvidenceRecord]
    primitives: list[PrimitiveRecord]
    patterns: list[PatternMatch]
    verdict: SkillVerdict
    graph: dict[str, Any]
    facts: dict[str, list[tuple[Any, ...]]]


@dataclass
class BenchmarkEntry:
    entry_id: str
    dataset: str
    source: str
    repo: str
    skill_name: str
    label: str
    local_path: str | None
    analyzable: bool = False
    split: str = "unknown"
    label_source: str = "unknown"
    pattern_labels: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


def to_jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return {k: to_jsonable(v) for k, v in asdict(value).items()}
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [to_jsonable(v) for v in value]
    if isinstance(value, tuple):
        return [to_jsonable(v) for v in value]
    return value
