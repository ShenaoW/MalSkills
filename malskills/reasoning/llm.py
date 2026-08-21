from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from .. import llm_runtime
from ..llm_runtime import build_llm_runtime_config, invoke_structured_json
from ..models import ArtifactRecord, SSOFinding, PatternMatch, SSORecord, WorkflowDiscovery

REASONING_PROMPT_VERSION = "2026-08-04-v10"

PATTERN_TAXONOMY: dict[str, dict[str, str]] = {
    "Data_Exfiltration": {"severity": "high", "definition": "Sensitive or host data reaches an external data-transfer sink."},
    "Credential_Theft": {"severity": "high", "definition": "Credential material is collected and reaches an exfiltration sink."},
    "Remote_Code_Execution": {"severity": "high", "definition": "Network-controlled input reaches an execution-capable operation."},
    "Malware_Delivery": {"severity": "high", "definition": "Received content is staged and subsequently executed."},
    "Persistence": {"severity": "high", "definition": "An execution payload is registered in a startup or recurring-execution resource."},
    "Reverse_Shell": {"severity": "high", "definition": "Network command input drives execution and its output returns through the network."},
    "Ransomware": {"severity": "high", "definition": "File data flows through encryption into destructive rewrite or deletion."},
    "Resource_Abuse": {"severity": "high", "definition": "Externally supplied work drives intensive computation and results are submitted externally."},
    "Privilege_Escalation": {"severity": "high", "definition": "Execution is connected to a privilege or authorization boundary modification."},
}

LLM_REASONING_SYSTEM_PROMPT = """You are a reasoning engine for malicious-pattern classification.

Task:
- Consume structured SSOFinding records, normalized SSO facts, and an object/dependency graph.
- Output only reasoning taxonomy pattern matches.
- Do not invent new pattern names.
- Do not output raw SSOFinding records, extracted operands, or SSO facts as patterns.
- Use object identity, binding, and cross-artifact links when deciding whether multiple operations belong to the same chain.
- Follow the structured schema exactly.

Reusable workflow discovery:
- You also receive symbolic pattern matches that the static rule base already found.
- If a grounded, connected workflow is not covered by those symbolic matches, you may nominate it under `candidate_workflows`.
- A candidate is not a verdict and does not affect the current classification.
- Candidate workflows must use at least two provided SSO ids connected by shared operands or value flow.
- Use a stable snake_case workflow_name that describes the operation sequence, not package-specific names.
- Map the workflow to one existing pattern_name; do not invent a new verdict taxonomy.

Allowed pattern taxonomy:
- Data_Exfiltration: sensitive or host data flows to a data_send sink.
- Credential_Theft: credential data flows to an exfiltration sink.
- Remote_Code_Execution: network-controlled input flows to execution.
- Malware_Delivery: received content is staged and then executed.
- Persistence: an execution payload is registered in a startup or recurring-execution resource.
- Reverse_Shell: received commands flow to execution and execution output flows to data_send.
- Ransomware: file data flows through encryption into rewrite or deletion.
- Resource_Abuse: remote work flows through intensive computation and results are submitted externally.
- Privilege_Escalation: execution is connected to a privilege-boundary modification.

Reasoning discipline:
- Base your answer on the provided structured facts, not on free-form speculation.
- Prefer patterns supported by linked objects or explicit findings/SSO chains.
- Only emit a pattern if the supporting facts materially satisfy the taxonomy definition.
- If a behavior is only a single sensitive operation without a higher-level malicious pattern, emit no pattern.
- If no taxonomy pattern applies, return an empty list.

Required graph reasoning:
- Treat value_flow as directed; never reverse an edge to make a pattern fit.
- Require all behavior roles to form one connected SDG subgraph.
- Use same-object support only when object identity represents the handoff.
- Standalone sensitive operations do not establish a behavior.

Counterexamples:
- A standalone connection_create to a benign-looking endpoint is not automatically a malicious pattern.
- A standalone file_read is not Data_Exfiltration.
- A credential used only for intended authentication is not Credential_Theft.
- HTTPS or a listener by itself is not Reverse_Shell.
- Downloading content without a linked staging-and-execution path is not Malware_Delivery.
- A scheduled backup, documented service restart, process-manager cron restart, or ordinary recurring job is not malicious Persistence without an unauthorized or covert execution chain.
- Deleting a calendar event or performing a documented backup restore is not Ransomware.
- git reset, git clean, and ordinary source rollback are not Ransomware.
- chmod +x on an ordinary application executable is not Privilege_Escalation.
- Generic capability summaries are not patterns.
- Use only the official reasoning taxonomy above; do not resurrect legacy pattern names.

Output JSON only with keys "patterns" and "candidate_workflows".
Each pattern item must contain exactly:
- pattern_name
- severity
- confidence
- supporting_finding_ids
- supporting_sso_ids
- explanation

Constraints:
- pattern_name must be one of the allowed taxonomy names above.
- severity must equal the official taxonomy severity for that pattern.
- supporting_finding_ids and supporting_sso_ids must reference provided ids only.
- explanation must be brief and pattern-specific, not a generic risk summary.

Each candidate_workflows item must contain exactly:
- workflow_name
- pattern_name
- confidence
- supporting_finding_ids
- supporting_sso_ids
- explanation
"""


def reasoning_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["patterns", "candidate_workflows"],
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
                        "supporting_finding_ids",
                        "supporting_sso_ids",
                        "explanation",
                    ],
                    "properties": {
                        "pattern_name": {"type": "string", "enum": sorted(PATTERN_TAXONOMY)},
                        "severity": {"type": "string", "enum": ["high"]},
                        "confidence": {"type": "number"},
                        "supporting_finding_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "supporting_sso_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "explanation": {"type": "string"},
                    },
                },
            },
            "candidate_workflows": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "workflow_name",
                        "pattern_name",
                        "confidence",
                        "supporting_finding_ids",
                        "supporting_sso_ids",
                        "explanation",
                    ],
                    "properties": {
                        "workflow_name": {"type": "string"},
                        "pattern_name": {"type": "string", "enum": sorted(PATTERN_TAXONOMY)},
                        "confidence": {"type": "number"},
                        "supporting_finding_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "supporting_sso_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "explanation": {"type": "string"},
                    },
                },
            },
        },
    }


class LlmPatternReasoner:
    def __init__(self, cache_dir: str | Path | None = None) -> None:
        default_cache = Path(".cache") / "malskills_llm_reasoning"
        configured = cache_dir or os.environ.get("MALSKILLS_LLM_REASONING_CACHE") or default_cache
        self.cache_dir = Path(configured)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.runtime = build_llm_runtime_config("pattern_reasoning")

    def reason(
        self,
        *,
        skill_path: str,
        artifacts: list[ArtifactRecord],
        findings: list[SSOFinding],
        ssos: list[SSORecord],
        graph: dict[str, Any] | None = None,
        symbolic_patterns: list[PatternMatch] | None = None,
    ) -> tuple[list[PatternMatch], list[WorkflowDiscovery]]:
        symbolic_patterns = symbolic_patterns or []
        artifacts, findings, ssos, graph = self._focus_reasoning_context(
            artifacts,
            findings,
            ssos,
            graph or {},
        )
        cache_path = self._cache_path_for(
            skill_path, artifacts, findings, ssos, graph, symbolic_patterns
        )
        if cache_path.exists():
            try:
                cached = json.loads(cache_path.read_text(encoding="utf-8"))
                patterns = self._parse_patterns(cached, findings, ssos)
                discoveries = self._parse_discoveries(
                    cached,
                    findings,
                    ssos,
                    symbolic_patterns,
                )
                return patterns, discoveries or self._fallback_discoveries(patterns, symbolic_patterns)
            except (OSError, json.JSONDecodeError):
                pass
        payload = invoke_structured_json(
            prompt=self._build_prompt(
                skill_path, artifacts, findings, ssos, graph, symbolic_patterns
            ),
            schema=reasoning_schema(),
            system_prompt=LLM_REASONING_SYSTEM_PROMPT,
            cwd=Path(skill_path),
            config=self.runtime,
        )
        if isinstance(payload, dict):
            cache_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        parsed_payload = payload or {}
        patterns = self._parse_patterns(parsed_payload, findings, ssos)
        discoveries = self._parse_discoveries(
            parsed_payload,
            findings,
            ssos,
            symbolic_patterns,
        )
        return patterns, discoveries or self._fallback_discoveries(patterns, symbolic_patterns)

    def _focus_reasoning_context(
        self,
        artifacts: list[ArtifactRecord],
        findings: list[SSOFinding],
        ssos: list[SSORecord],
        graph: dict[str, Any],
    ) -> tuple[
        list[ArtifactRecord],
        list[SSOFinding],
        list[SSORecord],
        dict[str, Any],
    ]:
        allowed_edges = {
            "has_operand",
            "value_flow",
            "same_object",
        }
        adjacency: dict[str, set[str]] = {}
        eligible_edges: list[dict[str, Any]] = []
        for edge in graph.get("edges", []):
            if str(edge.get("type", "")) not in allowed_edges:
                continue
            source = str(edge.get("source", ""))
            target = str(edge.get("target", ""))
            if not source or not target:
                continue
            adjacency.setdefault(source, set()).add(target)
            adjacency.setdefault(target, set()).add(source)
            eligible_edges.append(edge)

        sso_ids = {item.sso_id for item in ssos}
        focused_nodes: set[str] = set()
        focused_sso_ids: set[str] = set()
        visited: set[str] = set()
        for sso_id in sorted(sso_ids):
            if sso_id in visited:
                continue
            stack = [sso_id]
            component: set[str] = set()
            while stack:
                current = stack.pop()
                if current in component:
                    continue
                component.add(current)
                stack.extend(adjacency.get(current, ()))
            visited.update(component)
            component_ssos = component & sso_ids
            if len(component_ssos) >= 2:
                focused_nodes.update(component)
                focused_sso_ids.update(component_ssos)

        if not focused_sso_ids:
            return artifacts, findings, ssos, graph
        focused_ssos = [item for item in ssos if item.sso_id in focused_sso_ids]
        finding_ids = {
            finding_id
            for item in focused_ssos
            for finding_id in item.finding_ids
        }
        focused_findings = [item for item in findings if item.finding_id in finding_ids]
        artifact_paths = {
            path
            for item in focused_ssos
            for path in item.artifact_paths
        }
        focused_artifacts = [item for item in artifacts if item.relative_path in artifact_paths]
        focused_graph = {
            "nodes": [
                node
                for node in graph.get("nodes", [])
                if str(node.get("id", "")) in focused_nodes
            ],
            "edges": [
                edge
                for edge in eligible_edges
                if str(edge.get("source", "")) in focused_nodes
                and str(edge.get("target", "")) in focused_nodes
            ],
            "artifacts": list(graph.get("artifacts", [])),
        }
        return focused_artifacts, focused_findings, focused_ssos, focused_graph

    def _build_prompt(
        self,
        skill_path: str,
        artifacts: list[ArtifactRecord],
        findings: list[SSOFinding],
        ssos: list[SSORecord],
        graph: dict[str, Any],
        symbolic_patterns: list[PatternMatch],
    ) -> str:
        finding_by_id = {item.finding_id: item for item in findings}
        sso_by_id = {item.sso_id: item for item in ssos}
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
        finding_summary = []
        for item in findings:
            finding_payload = {
                "finding_id": item.finding_id,
                "artifact_path": item.artifact_path,
                "type": item.category,
                "subtype": item.subtype,
                "matched_text": item.matched_text,
                "attributes": self._trim_mapping(
                    item.attributes,
                    keys=["engine", "sink_api", "config_kind", "endpoint_class", "dst_class", "command_class", "path_class", "resolved_from", "flow_kind"],
                ),
            }
            if item.confidence is not None:
                finding_payload["confidence"] = item.confidence
            finding_summary.append(finding_payload)
        sso_summary = []
        for item in ssos:
            sso_payload = {
                "sso_id": item.sso_id,
                "category": item.category,
                "subtype": item.subtype,
                "finding_ids": item.finding_ids,
                "attributes": self._trim_mapping(
                    item.attributes,
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
            if item.confidence is not None:
                sso_payload["confidence"] = item.confidence
            sso_summary.append(sso_payload)
        graph_summary = {
            "nodes": [
                {
                    "id": str(node.get("id", "")),
                    "kind": str(node.get("kind", "")),
                    "type": str(node.get("type", "")),
                    "name": str(node.get("name", "")),
                }
                for node in graph.get("nodes", [])
                if str(node.get("kind", "")) in {"operand", "value", "sso"}
            ],
            "edges": [
                {
                    "source": str(edge.get("source", "")),
                    "target": str(edge.get("target", "")),
                    "type": str(edge.get("type", "")),
                    "role": str(edge.get("role", "")),
                    "flow_kind": str(edge.get("flow_kind", "")),
                }
                for edge in graph.get("edges", [])
                if str(edge.get("type", ""))
                in {
                    "has_operand",
                    "value_flow",
                    "same_object",
                }
            ],
        }
        symbolic_summary = [
            {
                "pattern_name": item.name,
                "rule_ids": item.rule_ids,
                "sso_ids": item.sso_ids,
                "finding_ids": item.finding_ids,
            }
            for item in symbolic_patterns
        ]
        return (
            "Reasoning task: classify malicious patterns from structured facts only.\n"
            f"Skill path: {skill_path}\n"
            f"Allowed patterns: {json.dumps(sorted(PATTERN_TAXONOMY), ensure_ascii=True)}\n"
            "Use the official taxonomy definitions from the system prompt.\n"
            "Prefer chains supported by shared objects, resolved config links, or explicit findings/SSO references.\n"
            "Nominate reusable workflow candidates only when the connected workflow is not covered by symbolic matches.\n"
            "Return JSON only with patterns and candidate_workflows.\n\n"
            "Existing symbolic matches:\n"
            f"{json.dumps(symbolic_summary, indent=2, sort_keys=True, ensure_ascii=True)}\n\n"
            "Artifacts:\n"
            f"{json.dumps(artifact_summary, indent=2, sort_keys=True, ensure_ascii=True)}\n\n"
            "Finding facts:\n"
            f"{json.dumps(finding_summary, indent=2, sort_keys=True, ensure_ascii=True)}\n\n"
            "SSO facts:\n"
            f"{json.dumps(sso_summary, indent=2, sort_keys=True, ensure_ascii=True)}\n\n"
            "Object graph:\n"
            f"{json.dumps(graph_summary, indent=2, sort_keys=True, ensure_ascii=True)}\n\n"
            "Reference sets:\n"
            f"{json.dumps({'finding_ids': sorted(finding_by_id), 'sso_ids': sorted(sso_by_id)}, indent=2, sort_keys=True, ensure_ascii=True)}"
        )

    def _parse_patterns(
        self,
        payload: dict[str, Any],
        findings: list[SSOFinding],
        ssos: list[SSORecord],
    ) -> list[PatternMatch]:
        if not isinstance(payload, dict):
            return []
        raw_patterns = payload.get("patterns", [])
        if not isinstance(raw_patterns, list):
            return []
        valid_finding_ids = {item.finding_id for item in findings}
        valid_sso_ids = {item.sso_id for item in ssos}
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
            finding_ids = self._stable_unique(
                [
                    str(item).strip()
                    for item in raw.get("supporting_finding_ids", [])
                    if str(item).strip() in valid_finding_ids
                ]
            )
            sso_ids = self._stable_unique(
                [
                    str(item).strip()
                    for item in raw.get("supporting_sso_ids", [])
                    if str(item).strip() in valid_sso_ids
                ]
            )
            if not finding_ids and not sso_ids:
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
                    sso_ids=sso_ids,
                    finding_ids=finding_ids,
                    explanation=explanation,
                    source="llm",
                    generator={
                        "backend": self.runtime.backend,
                        "model": self.runtime.model,
                        "prompt_version": REASONING_PROMPT_VERSION,
                    },
                )
            )
        return parsed

    def _parse_discoveries(
        self,
        payload: dict[str, Any],
        findings: list[SSOFinding],
        ssos: list[SSORecord],
        symbolic_patterns: list[PatternMatch] | None = None,
    ) -> list[WorkflowDiscovery]:
        raw_discoveries = payload.get("candidate_workflows", []) if isinstance(payload, dict) else []
        if not isinstance(raw_discoveries, list):
            return []
        valid_finding_ids = {item.finding_id for item in findings}
        valid_sso_ids = {item.sso_id for item in ssos}
        discoveries: list[WorkflowDiscovery] = []
        for index, raw in enumerate(raw_discoveries):
            if not isinstance(raw, dict):
                continue
            pattern_name = str(raw.get("pattern_name", "")).strip()
            workflow_name = self._workflow_slug(str(raw.get("workflow_name", "")))
            if pattern_name not in PATTERN_TAXONOMY or not workflow_name:
                continue
            try:
                confidence = float(raw.get("confidence", 0.0))
            except (TypeError, ValueError):
                continue
            sso_ids = self._stable_unique(
                [
                    str(item).strip()
                    for item in raw.get("supporting_sso_ids", [])
                    if str(item).strip() in valid_sso_ids
                ]
            )
            finding_ids = self._stable_unique(
                [
                    str(item).strip()
                    for item in raw.get("supporting_finding_ids", [])
                    if str(item).strip() in valid_finding_ids
                ]
            )
            explanation = str(raw.get("explanation", "")).strip()
            if confidence <= 0 or len(sso_ids) < 2 or not explanation:
                continue
            if self._covered_by_symbolic(
                pattern_name,
                sso_ids,
                symbolic_patterns or [],
            ):
                continue
            discoveries.append(
                WorkflowDiscovery(
                    discovery_id=f"llm_workflow_{index:05d}",
                    workflow_name=workflow_name,
                    pattern_name=pattern_name,
                    confidence=min(confidence, 1.0),
                    sso_ids=sso_ids,
                    finding_ids=finding_ids,
                    explanation=explanation,
                    generator={
                        "backend": self.runtime.backend,
                        "model": self.runtime.model,
                        "prompt_version": REASONING_PROMPT_VERSION,
                    },
                )
            )
        return discoveries

    def _fallback_discoveries(
        self,
        patterns: list[PatternMatch],
        symbolic_patterns: list[PatternMatch],
    ) -> list[WorkflowDiscovery]:
        discoveries: list[WorkflowDiscovery] = []
        for index, pattern in enumerate(patterns):
            if len(pattern.sso_ids) < 2 or self._covered_by_symbolic(
                pattern.name,
                pattern.sso_ids,
                symbolic_patterns,
            ):
                continue
            discoveries.append(
                WorkflowDiscovery(
                    discovery_id=f"llm_workflow_fallback_{index:05d}",
                    workflow_name=self._workflow_slug(f"uncovered_{pattern.name}"),
                    pattern_name=pattern.name,
                    confidence=0.7,
                    sso_ids=list(pattern.sso_ids),
                    finding_ids=list(pattern.finding_ids),
                    explanation=pattern.explanation,
                    generator={
                        "backend": self.runtime.backend,
                        "model": self.runtime.model,
                        "prompt_version": REASONING_PROMPT_VERSION,
                    },
                )
            )
        return discoveries

    def _covered_by_symbolic(
        self,
        pattern_name: str,
        sso_ids: list[str],
        symbolic_patterns: list[PatternMatch],
    ) -> bool:
        candidate_ssos = set(sso_ids)
        return any(
            symbolic.name == pattern_name
            and candidate_ssos
            and candidate_ssos <= set(symbolic.sso_ids)
            for symbolic in symbolic_patterns
        )

    def _cache_path_for(
        self,
        skill_path: str,
        artifacts: list[ArtifactRecord],
        findings: list[SSOFinding],
        ssos: list[SSORecord],
        graph: dict[str, Any],
        symbolic_patterns: list[PatternMatch],
    ) -> Path:
        payload = {
            "skill_path": str(Path(skill_path).resolve()),
            "artifacts": [(item.artifact_id, item.relative_path, item.content_hash) for item in artifacts],
            "findings": [
                (item.finding_id, item.subtype, item.matched_text, item.confidence)
                for item in findings
            ],
            "ssos": [(item.sso_id, item.subtype, item.attributes, item.finding_ids) for item in ssos],
            "graph_edges": graph.get("edges", []),
            "symbolic_patterns": [
                (item.name, item.rule_ids, item.sso_ids, item.finding_ids)
                for item in symbolic_patterns
            ],
            "schema": sorted(PATTERN_TAXONOMY),
            "version": REASONING_PROMPT_VERSION,
            "runtime_protocol_version": llm_runtime.LLM_RUNTIME_PROTOCOL_VERSION,
            "runtime_backend": self.runtime.backend,
            "runtime_model": self.runtime.model,
            "runtime_reasoning_effort": self.runtime.reasoning_effort,
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

    def _workflow_slug(self, value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")[:80]
