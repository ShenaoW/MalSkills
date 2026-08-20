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
class SSOFinding:
    finding_id: str
    artifact_id: str
    artifact_path: str
    category: str
    subtype: str
    matched_text: str
    confidence: float | None
    producer: str = ""
    span: Span | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)


@dataclass
class SSORecord:
    sso_id: str
    category: str
    subtype: str
    confidence: float | None
    finding_ids: list[str]
    artifact_ids: list[str]
    artifact_paths: list[str]
    operand_ids: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class OperandRecord:
    operand_id: str
    role: str
    object_kind: str
    identity_key: str
    display_value: str
    resolution_methods: list[str] = field(default_factory=list)


@dataclass
class ValueRecord:
    value_id: str
    value_kind: str
    display_value: str
    artifact_path: str = ""
    span: Span | None = None


@dataclass
class OperandResolution:
    resolution_id: str
    sso_id: str
    role: str
    operand_id: str
    value_id: str
    method: str
    confidence: float
    artifact_path: str
    span: Span | None = None
    flow_steps: list[dict[str, Any]] = field(default_factory=list)
    source_finding_ids: list[str] = field(default_factory=list)


@dataclass
class OperandBinding:
    binding_id: str
    producer: str
    artifact_id: str
    artifact_path: str
    sink_api: str
    sink_subtype: str
    role: str
    value: str
    confidence: float
    span: Span | None = None
    object_kind: str = "unknown"
    identity_key: str = ""
    flow_steps: list[dict[str, Any]] = field(default_factory=list)
    source_finding_ids: list[str] = field(default_factory=list)


@dataclass
class PatternMatch:
    pattern_id: str
    name: str
    severity: str
    rule_ids: list[str]
    sso_ids: list[str]
    finding_ids: list[str]
    explanation: str
    source: str = "formal"
    generator: dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowDiscovery:
    discovery_id: str
    workflow_name: str
    pattern_name: str
    confidence: float
    sso_ids: list[str]
    finding_ids: list[str]
    explanation: str
    source: str = "llm"
    generator: dict[str, Any] = field(default_factory=dict)


@dataclass
class SkillVerdict:
    skill_path: str
    label: str
    malicious_patterns: list[str]
    summary: str


@dataclass
class AnalysisResult:
    skill_path: str
    artifacts: list[ArtifactRecord]
    findings: list[SSOFinding]
    ssos: list[SSORecord]
    operands: list[OperandRecord]
    values: list[ValueRecord]
    operand_resolutions: list[OperandResolution]
    patterns: list[PatternMatch]
    verdict: SkillVerdict
    graph: dict[str, Any]
    workflow_discoveries: list[WorkflowDiscovery] = field(default_factory=list)
    findings_by_producer: dict[str, list[SSOFinding]] = field(default_factory=dict)
    analysis_metadata: dict[str, Any] = field(default_factory=dict)
    feedback_payload: dict[str, Any] = field(default_factory=dict)


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
