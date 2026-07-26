from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from ..llm_runtime import build_llm_runtime_config, invoke_structured_json
from ..models import ArtifactRecord, EvidenceRecord, PatternMatch, PrimitiveRecord

REASONING_PROMPT_VERSION = "2026-03-22-v2"

PATTERN_TAXONOMY: dict[str, dict[str, str]] = {
    "Execution_and_Delivery": {
        "severity": "high",
        "definition": "Execution-capable behavior is present, optionally linked to delivery of remote content or payload staging.",
    },
    "Persistence": {
        "severity": "high",
        "definition": "The skill establishes persistence through startup, service, scheduled, event-triggered, or boot-chain control.",
    },
    "Privilege_Escalation_and_Identity_Abuse": {
        "severity": "high",
        "definition": "The skill manipulates identities, privileges, tokens, groups, ACLs, or trust boundaries.",
    },
    "Injection_and_Covert_Residency": {
        "severity": "high",
        "definition": "The skill performs process, memory, or remote-thread style manipulation consistent with injection or covert residency.",
    },
    "Information_Theft": {
        "severity": "high",
        "definition": "The skill accesses credentials, secrets, or sensitive data, optionally linking that collection to staging or external transfer.",
    },
    "Command_and_Control": {
        "severity": "high",
        "definition": "The skill establishes or uses external command-and-control style communication channels.",
    },
    "Lateral_Movement": {
        "severity": "high",
        "definition": "The skill can authenticate to, execute on, transfer to, or control other hosts or remote nodes.",
    },
    "Defense_Evasion_and_Anti_Forensics": {
        "severity": "high",
        "definition": "The skill impairs defenses, suppresses logging, weakens policy controls, cleans artifacts, or hides objects.",
    },
    "Destruction_and_Ransomware": {
        "severity": "high",
        "definition": "The skill destroys data, encrypts or locks it, impairs recovery, disrupts availability, or damages low-level boot components.",
    },
}

LLM_REASONING_SYSTEM_PROMPT = """You are a reasoning engine for malicious-pattern classification.

Task:
- Consume structured evidence facts, primitive facts, and an object/dependency graph.
- Output only reasoning taxonomy pattern matches.
- Do not invent new pattern names.
- Do not output raw evidence facts, extracted operands, or primitive facts as patterns.
- Use object identity, binding, and cross-artifact links when deciding whether multiple operations belong to the same chain.
- Follow the structured schema exactly.

Allowed pattern taxonomy:
- Execution_and_Delivery: execution-capable behavior is present, optionally linked to remote delivery or payload staging.
- Persistence: the skill establishes persistence through startup, service, scheduled, event-triggered, or boot-chain control.
- Privilege_Escalation_and_Identity_Abuse: the skill manipulates identities, privileges, tokens, groups, ACLs, or trust boundaries.
- Injection_and_Covert_Residency: the skill performs process, memory, or remote-thread style manipulation consistent with injection or covert residency.
- Information_Theft: the skill accesses credentials, secrets, or sensitive data, optionally linking that collection to staging or external transfer.
- Command_and_Control: the skill establishes or uses external command-and-control style communication channels.
- Lateral_Movement: the skill can authenticate to, execute on, transfer to, or control other hosts or remote nodes.
- Defense_Evasion_and_Anti_Forensics: the skill impairs defenses, suppresses logging, weakens policy controls, cleans artifacts, or hides objects.
- Destruction_and_Ransomware: the skill destroys data, encrypts or locks it, impairs recovery, disrupts availability, or damages low-level boot components.

Reasoning discipline:
- Base your answer on the provided structured facts, not on free-form speculation.
- Prefer patterns supported by linked objects or explicit evidence/primitive chains.
- Only emit a pattern if the supporting facts materially satisfy the taxonomy definition.
- If a behavior is only a single sensitive operation without a higher-level malicious pattern, emit no pattern.
- If no taxonomy pattern applies, return an empty list.

Examples:
1. curl/wget remote URL + shell execution or dynamic module load => Execution_and_Delivery.
2. cron/systemd/RunKey/service registration => Persistence.
3. setuid/sudo/UAC bypass/token impersonation => Privilege_Escalation_and_Identity_Abuse.
4. ptrace/ReadProcessMemory/CreateRemoteThread/mprotect RWX => Injection_and_Covert_Residency.
5. API key access, session token access, SSH key access, or sensitive file read paired with external transfer => Information_Theft.
6. listener/tunnel/proxy/protocol encapsulation or explicit external send channel => Command_and_Control.
7. ssh/WinRM/remote exec/cluster node control => Lateral_Movement.
8. stop EDR / clear logs / disable firewall / hide artifacts => Defense_Evasion_and_Anti_Forensics.
9. data destruction / data encryption / recovery impairment / shutdown / boot damage => Destruction_and_Ransomware.

Counterexamples:
- A standalone outbound_connection to a benign-looking endpoint is not automatically a malicious pattern.
- A standalone content_read_and_parse on an ordinary file is not enough for Information_Theft.
- Generic capability summaries are not patterns.
- Use only the official reasoning taxonomy above; do not resurrect legacy pattern names.

Output JSON only with key "patterns".
Each pattern item must contain exactly:
- pattern_name
- severity
- confidence
- supporting_evidence_ids
- supporting_primitive_ids
- explanation

Constraints:
- pattern_name must be one of the allowed taxonomy names above.
- severity must equal the official taxonomy severity for that pattern.
- supporting_evidence_ids and supporting_primitive_ids must reference provided ids only.
- explanation must be brief and pattern-specific, not a generic risk summary.
"""


def reasoning_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["patterns"],
        "properties": {
            "patterns": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "pattern_name",
                        "severity",
                        "confidence",
                        "supporting_evidence_ids",
                        "supporting_primitive_ids",
                        "explanation",
                    ],
                    "properties": {
                        "pattern_name": {"type": "string", "enum": sorted(PATTERN_TAXONOMY)},
                        "severity": {"type": "string", "enum": ["high"]},
                        "confidence": {"type": "number"},
                        "supporting_evidence_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "supporting_primitive_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "explanation": {"type": "string"},
                    },
                },
            }
        },
    }


class LlmPatternReasoner:
    def __init__(self, cache_dir: str | Path | None = None) -> None:
        default_cache = Path(".cache") / "malskills_llm_reasoning"
        configured = cache_dir or os.environ.get("MALSKILLS_LLM_REASONING_CACHE") or default_cache
        self.cache_dir = Path(configured)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.runtime = build_llm_runtime_config()

    def reason(
        self,
        *,
        skill_path: str,
        artifacts: list[ArtifactRecord],
        evidence: list[EvidenceRecord],
        primitives: list[PrimitiveRecord],
        graph: dict[str, Any] | None = None,
    ) -> list[PatternMatch]:
        cache_path = self._cache_path_for(skill_path, artifacts, evidence, primitives, graph or {})
        if cache_path.exists():
            try:
                cached = json.loads(cache_path.read_text(encoding="utf-8"))
                return self._parse_patterns(cached, evidence, primitives)
            except (OSError, json.JSONDecodeError):
                pass
        payload = invoke_structured_json(
            prompt=self._build_prompt(skill_path, artifacts, evidence, primitives, graph or {}),
            schema=reasoning_schema(),
            system_prompt=LLM_REASONING_SYSTEM_PROMPT,
            cwd=Path(skill_path),
            config=self.runtime,
        )
        if isinstance(payload, dict):
            cache_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return self._parse_patterns(payload or {}, evidence, primitives)

    def _build_prompt(
        self,
        skill_path: str,
        artifacts: list[ArtifactRecord],
        evidence: list[EvidenceRecord],
        primitives: list[PrimitiveRecord],
        graph: dict[str, Any],
    ) -> str:
        evidence_by_id = {item.evidence_id: item for item in evidence}
        primitive_by_id = {item.primitive_id: item for item in primitives}
        artifact_summary = [
            {
                "artifact_id": artifact.artifact_id,
                "relative_path": artifact.relative_path,
                "artifact_type": artifact.artifact_type,
                "generated": artifact.generated,
                "source_artifact_path": artifact.source_artifact_path,
            }
            for artifact in artifacts
        ]
        evidence_summary = [
            {
                "evidence_id": item.evidence_id,
                "artifact_path": item.artifact_path,
                "type": item.evidence_type,
                "subtype": item.subtype,
                "confidence": item.confidence,
                "attributes": self._trim_mapping(
                    item.attributes,
                    keys=["engine", "matched_text", "sink_api", "config_kind", "endpoint_class", "dst_class", "command_class", "path_class", "resolved_from", "flow_kind"],
                ),
            }
            for item in evidence
        ]
        primitive_summary = [
            {
                "primitive_id": item.primitive_id,
                "primitive_type": item.primitive_type,
                "confidence": item.confidence,
                "evidence_ids": item.evidence_ids,
                "params": self._trim_mapping(
                    item.params,
                    keys=[
                        "operation_object",
                        "object_identity_kind",
                        "command",
                        "command_class",
                        "endpoint",
                        "endpoint_class",
                        "resolved_dst_class",
                        "network_role",
                        "path",
                        "path_class",
                        "sensitivity_class",
                        "resolved_from",
                        "related_objects",
                        "config_kind",
                        "tool_surface_class",
                        "tool_class",
                        "secret_class",
                        "implied_capabilities",
                    ],
                ),
            }
            for item in primitives
        ]
        graph_summary = {
            "nodes": [
                {
                    "id": str(node.get("id", "")),
                    "kind": str(node.get("kind", "")),
                    "type": str(node.get("type", "")),
                    "name": str(node.get("name", "")),
                }
                for node in graph.get("nodes", [])
                if str(node.get("kind", "")) in {"logical_object", "primitive", "evidence"}
            ],
            "edges": [
                {
                    "source": str(edge.get("source", "")),
                    "target": str(edge.get("target", "")),
                    "type": str(edge.get("type", "")),
                }
                for edge in graph.get("edges", [])
                if str(edge.get("type", "")) in {"supports", "acts_on", "associated_with", "resolved_via", "resolved_from", "same_object"}
            ],
        }
        return (
            "Reasoning task: classify malicious patterns from structured facts only.\n"
            f"Skill path: {skill_path}\n"
            f"Allowed patterns: {json.dumps(sorted(PATTERN_TAXONOMY), ensure_ascii=True)}\n"
            "Use the official taxonomy definitions from the system prompt.\n"
            "Prefer chains supported by shared objects, resolved config links, or explicit evidence/primitive references.\n"
            "Return JSON only.\n\n"
            "Artifacts:\n"
            f"{json.dumps(artifact_summary, indent=2, sort_keys=True, ensure_ascii=True)}\n\n"
            "Evidence facts:\n"
            f"{json.dumps(evidence_summary, indent=2, sort_keys=True, ensure_ascii=True)}\n\n"
            "Primitive facts:\n"
            f"{json.dumps(primitive_summary, indent=2, sort_keys=True, ensure_ascii=True)}\n\n"
            "Object graph:\n"
            f"{json.dumps(graph_summary, indent=2, sort_keys=True, ensure_ascii=True)}\n\n"
            "Reference sets:\n"
            f"{json.dumps({'evidence_ids': sorted(evidence_by_id), 'primitive_ids': sorted(primitive_by_id)}, indent=2, sort_keys=True, ensure_ascii=True)}"
        )

    def _parse_patterns(
        self,
        payload: dict[str, Any],
        evidence: list[EvidenceRecord],
        primitives: list[PrimitiveRecord],
    ) -> list[PatternMatch]:
        if not isinstance(payload, dict):
            return []
        raw_patterns = payload.get("patterns", [])
        if not isinstance(raw_patterns, list):
            return []
        valid_evidence_ids = {item.evidence_id for item in evidence}
        valid_primitive_ids = {item.primitive_id for item in primitives}
        parsed: list[PatternMatch] = []
        for index, raw in enumerate(raw_patterns):
            if not isinstance(raw, dict):
                continue
            name = str(raw.get("pattern_name", "")).strip()
            if name not in PATTERN_TAXONOMY:
                continue
            severity = str(raw.get("severity", "")).strip()
            expected_severity = PATTERN_TAXONOMY[name]["severity"]
            if severity != expected_severity:
                continue
            try:
                confidence = float(raw.get("confidence", 0.0))
            except (TypeError, ValueError):
                confidence = 0.0
            if confidence <= 0:
                continue
            evidence_ids = self._stable_unique(
                [
                    str(item).strip()
                    for item in raw.get("supporting_evidence_ids", [])
                    if str(item).strip() in valid_evidence_ids
                ]
            )
            primitive_ids = self._stable_unique(
                [
                    str(item).strip()
                    for item in raw.get("supporting_primitive_ids", [])
                    if str(item).strip() in valid_primitive_ids
                ]
            )
            if not evidence_ids and not primitive_ids:
                continue
            explanation = str(raw.get("explanation", "")).strip()
            if not explanation:
                explanation = PATTERN_TAXONOMY[name]["definition"]
            parsed.append(
                PatternMatch(
                    pattern_id=f"llm_pat_{index:05d}",
                    name=name,
                    severity=severity,
                    rule_ids=[f"LLM_REASONING::{name}"],
                    primitive_ids=primitive_ids,
                    evidence_ids=evidence_ids,
                    explanation=explanation,
                    source="llm",
                )
            )
        return parsed

    def _cache_path_for(
        self,
        skill_path: str,
        artifacts: list[ArtifactRecord],
        evidence: list[EvidenceRecord],
        primitives: list[PrimitiveRecord],
        graph: dict[str, Any],
    ) -> Path:
        payload = {
            "skill_path": str(Path(skill_path).resolve()),
            "artifacts": [(item.artifact_id, item.relative_path, item.content_hash) for item in artifacts],
            "evidence": [(item.evidence_id, item.subtype, item.attributes.get("matched_text", ""), item.confidence) for item in evidence],
            "primitives": [(item.primitive_id, item.primitive_type, item.params, item.evidence_ids) for item in primitives],
            "graph_edges": graph.get("edges", []),
            "schema": sorted(PATTERN_TAXONOMY),
            "version": REASONING_PROMPT_VERSION,
            "runtime_backend": self.runtime.backend,
            "runtime_model": self.runtime.model,
            "runtime_base_url": self.runtime.base_url,
        }
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=True).encode("utf-8")).hexdigest()
        return self.cache_dir / f"{digest}.json"

    def _trim_mapping(self, payload: dict[str, Any], *, keys: list[str]) -> dict[str, Any]:
        trimmed: dict[str, Any] = {}
        for key in keys:
            if key not in payload:
                continue
            trimmed[key] = payload[key]
        return trimmed

    def _stable_unique(self, values: list[str]) -> list[str]:
        seen: set[str] = set()
        ordered: list[str] = []
        for value in values:
            if value in seen:
                continue
            seen.add(value)
            ordered.append(value)
        return ordered
