from __future__ import annotations

import shutil
from collections import defaultdict
from pathlib import Path
from typing import Any

from ..models import ArtifactRecord, EvidenceRecord, PatternMatch, PrimitiveRecord, SkillVerdict
from ..utils import ensure_dir


HIGH_SEVERITY = {
    "Sensitive_Exfiltration",
    "Credential_Theft",
    "Remote_Code_Execution",
    "Downloader_Installer",
    "Dynamic_Sink_Injection",
    "Obfuscated_Execution",
}
MEDIUM_SEVERITY = {
    "Secret_Request",
    "Filesystem_Recon",
    "Prompt_Instruction_Override",
    "Hidden_Setup_Trap",
    "Capability_Mismatch",
    "External_Service_Bootstrap",
}


class FormalReasoner:
    def __init__(self) -> None:
        self._counter = 0

    def reason(
        self,
        skill_path: str,
        primitives: list[PrimitiveRecord],
        *,
        artifacts: list[ArtifactRecord] | None = None,
        evidence: list[EvidenceRecord] | None = None,
        graph: dict[str, Any] | None = None,
        enable_capability_mismatch: bool = True,
        mode: str = "formal",
        runtime_sec: float | None = None,
    ) -> tuple[list[PatternMatch], SkillVerdict, dict[str, list[tuple[object, ...]]]]:
        if mode == "heuristic":
            patterns, verdict = self._heuristic_reason(skill_path, primitives)
        else:
            patterns, verdict = self._formal_reason(skill_path, primitives, enable_capability_mismatch=enable_capability_mismatch)
        facts = self._build_facts(
            artifacts or [],
            evidence or [],
            primitives,
            graph or {},
            patterns,
            verdict,
            runtime_sec=runtime_sec,
            reasoning_mode=mode,
        )
        return patterns, verdict, facts

    def export_souffle(self, facts: dict[str, list[tuple[object, ...]]], output_dir: str | Path) -> None:
        destination = Path(output_dir)
        ensure_dir(destination)
        for fact_name, rows in facts.items():
            with (destination / f"{fact_name}.facts").open("w", encoding="utf-8") as handle:
                for row in rows:
                    handle.write("\t".join(str(item).replace("\t", " ") for item in row) + "\n")
        rules_src = Path(__file__).resolve().parents[2] / "rules" / "skillguard.dl"
        if rules_src.exists():
            shutil.copyfile(rules_src, destination / "skillguard.dl")

    def _formal_reason(
        self,
        skill_path: str,
        primitives: list[PrimitiveRecord],
        *,
        enable_capability_mismatch: bool,
    ) -> tuple[list[PatternMatch], SkillVerdict]:
        by_type: dict[str, list[PrimitiveRecord]] = defaultdict(list)
        for primitive in primitives:
            by_type[primitive.primitive_type].append(primitive)
        patterns: list[PatternMatch] = []

        patterns.extend(self._rule_sensitive_exfiltration(by_type))
        patterns.extend(self._rule_credential_theft(by_type))
        patterns.extend(self._rule_secret_request(by_type))
        patterns.extend(self._rule_remote_code_execution(by_type))
        patterns.extend(self._rule_downloader_installer(by_type))
        patterns.extend(self._rule_filesystem_recon(by_type))
        patterns.extend(self._rule_prompt_override(by_type))
        patterns.extend(self._rule_hidden_setup(by_type))
        patterns.extend(self._rule_external_service_bootstrap(by_type))
        patterns.extend(self._rule_dynamic_sink(by_type))
        if enable_capability_mismatch:
            patterns.extend(self._rule_capability_mismatch(by_type))
        patterns.extend(self._rule_obfuscated_execution(by_type))

        deduped = self._dedupe_patterns(patterns)
        verdict = self._patterns_to_verdict(skill_path, deduped)
        return deduped, verdict

    def _heuristic_reason(self, skill_path: str, primitives: list[PrimitiveRecord]) -> tuple[list[PatternMatch], SkillVerdict]:
        patterns: list[PatternMatch] = []
        high_risk = {"SHELL_EXEC", "OBFUSCATED_EXEC", "REQUEST_SECRET", "TAINT_FLOW"}
        medium_risk = {"READ_FILE", "READ_ENV", "NETWORK_SEND", "NETWORK_FETCH", "DYNAMIC_LOAD", "EMBED_HIDDEN_INSTRUCTION", "LIST_DIR"}
        for primitive in primitives:
            if primitive.primitive_type in high_risk:
                patterns.append(
                    self._pattern(
                        "Heuristic_High_Risk",
                        "high",
                        ["H1_HIGH_RISK_PRIMITIVE"],
                        [primitive],
                        "The ablation heuristic marks explicit high-risk primitives without formal composition.",
                    )
                )
            elif primitive.primitive_type in medium_risk:
                patterns.append(
                    self._pattern(
                        "Heuristic_Suspicious_Primitive",
                        "medium",
                        ["H2_SUSPICIOUS_PRIMITIVE"],
                        [primitive],
                        "The ablation heuristic marks suspicious primitives without cross-primitive reasoning.",
                    )
                )
        deduped = self._dedupe_patterns(patterns)
        verdict = self._patterns_to_verdict(skill_path, deduped)
        return deduped, verdict

    def _dedupe_patterns(self, patterns: list[PatternMatch]) -> list[PatternMatch]:
        seen_names: set[tuple[str, tuple[str, ...]]] = set()
        deduped: list[PatternMatch] = []
        for pattern in patterns:
            key = (pattern.name, tuple(sorted(pattern.primitive_ids)))
            if key in seen_names:
                continue
            seen_names.add(key)
            deduped.append(pattern)
        return deduped

    def _patterns_to_verdict(self, skill_path: str, patterns: list[PatternMatch]) -> SkillVerdict:
        malicious_patterns = sorted({pattern.name for pattern in patterns if pattern.name in HIGH_SEVERITY or pattern.severity == "high"})
        suspicious_patterns = sorted({pattern.name for pattern in patterns if pattern.name in MEDIUM_SEVERITY or pattern.severity == "medium"})
        if malicious_patterns:
            label = "malicious"
            score = min(0.99, 0.7 + 0.08 * len(malicious_patterns))
        elif suspicious_patterns:
            label = "suspicious"
            score = min(0.89, 0.5 + 0.06 * len(suspicious_patterns))
        else:
            label = "benign"
            score = 0.1
        return SkillVerdict(
            skill_path=skill_path,
            label=label,
            score=score,
            malicious_patterns=malicious_patterns,
            suspicious_patterns=suspicious_patterns,
            summary=self._summarize(label, malicious_patterns, suspicious_patterns),
        )

    def _build_facts(
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
            "primitive_param": [],
            "primitive_evidence": [],
            "primitive_confidence": [],
            "pattern_match": [],
            "pattern_support": [],
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
            facts["evidence"].append((item.evidence_id, item.artifact_id, item.evidence_type, item.subtype, item.value))
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
            for key, value in self._flatten_fact_values(primitive.params):
                facts["primitive_param"].append((primitive.primitive_id, key, value))
            for evidence_id in primitive.evidence_ids:
                facts["primitive_evidence"].append((primitive.primitive_id, evidence_id))
        for pattern in patterns:
            facts["pattern_match"].append((pattern.pattern_id, pattern.name, pattern.severity))
            for primitive_id in pattern.primitive_ids:
                facts["pattern_support"].append((pattern.pattern_id, primitive_id))
        return facts

    def _flatten_fact_values(self, payload: dict[str, Any], prefix: str = "") -> list[tuple[str, object]]:
        rows: list[tuple[str, object]] = []
        for key, value in payload.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, dict):
                rows.extend(self._flatten_fact_values(value, name))
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    if isinstance(item, dict):
                        rows.extend(self._flatten_fact_values(item, f"{name}[{index}]") )
                    else:
                        rows.append((f"{name}[{index}]", item))
            else:
                rows.append((name, value))
        return rows

    def _rule_sensitive_exfiltration(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        sensitive_reads = [p for p in by_type.get("READ_FILE", []) if p.params.get("sensitivity_class") == "sensitive"]
        sensitive_reads.extend([p for p in by_type.get("READ_ENV", []) if p.params.get("sensitivity_class") == "sensitive"])
        sends = [p for p in by_type.get("NETWORK_SEND", []) if p.params.get("dst_class") == "external" or p.params.get("resolved_dst_class") == "external"]
        for source in sensitive_reads:
            for sink in sends:
                patterns.append(self._pattern("Sensitive_Exfiltration", "high", ["R1_SENSITIVE_EXFIL"], [source, sink], "Sensitive local data can reach an external network sink."))
        for flow in by_type.get("TAINT_FLOW", []):
            if flow.params.get("flow_kind") == "env_to_network":
                patterns.append(self._pattern("Sensitive_Exfiltration", "high", ["R1_SENSITIVE_EXFIL_FLOW"], [flow], "A taint-flow engine confirms sensitive environment data can reach a network sink."))
        return patterns

    def _rule_credential_theft(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        credential_sources = [p for p in by_type.get("READ_ENV", []) if p.params.get("sensitivity_class") == "sensitive"]
        credential_sources.extend([p for p in by_type.get("REQUEST_SECRET", [])])
        credential_sources.extend([p for p in by_type.get("READ_FILE", []) if any(token in str(p.params.get("path", "")).lower() for token in [".ssh", "id_rsa", "mnemonic", "seed", "wallet", "passwd"])])
        sends = [p for p in by_type.get("NETWORK_SEND", []) if p.params.get("dst_class") == "external" or p.params.get("resolved_dst_class") == "external"]
        for source in credential_sources:
            for sink in sends:
                patterns.append(self._pattern("Credential_Theft", "high", ["R2_CREDENTIAL_THEFT"], [source, sink], "Credential-like material is exposed to an external sink."))
        for flow in by_type.get("TAINT_FLOW", []):
            if flow.params.get("flow_kind") == "env_to_network":
                patterns.append(self._pattern("Credential_Theft", "high", ["R2_CREDENTIAL_FLOW"], [flow], "A taint-flow engine confirms environment-derived secrets can reach an external sink."))
        return patterns

    def _rule_secret_request(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        for primitive in by_type.get("REQUEST_SECRET", []):
            patterns.append(
                self._pattern(
                    "Secret_Request",
                    "medium",
                    ["R2B_SECRET_REQUEST"],
                    [primitive],
                    "The skill explicitly asks the operator for secrets or credentials during setup or use.",
                )
            )
        return patterns

    def _rule_remote_code_execution(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        execs = [p for p in by_type.get("SHELL_EXEC", []) if p.params.get("command_class") == "high_risk"]
        fetches = [p for p in by_type.get("NETWORK_FETCH", []) if p.params.get("dst_class") == "external" or p.params.get("resolved_dst_class") == "external"]
        for exec_primitive in execs:
            if fetches:
                for fetch in fetches:
                    patterns.append(self._pattern("Remote_Code_Execution", "high", ["R3_REMOTE_EXEC"], [fetch, exec_primitive], "The skill downloads or references external content and executes shell commands."))
            elif any(token in str(exec_primitive.params.get("command", "")).lower() for token in ["http://", "https://", "curl ", "wget ", "invoke-webrequest"]):
                patterns.append(self._pattern("Remote_Code_Execution", "high", ["R3_REMOTE_EXEC_DIRECT"], [exec_primitive], "The skill directly invokes high-risk shell execution."))
        for flow in by_type.get("TAINT_FLOW", []):
            if flow.params.get("flow_kind") == "env_to_exec":
                patterns.append(self._pattern("Remote_Code_Execution", "high", ["R3_REMOTE_EXEC_FLOW"], [flow], "A taint-flow engine confirms attacker-controlled data can reach command execution."))
        return patterns

    def _rule_downloader_installer(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        fetches = [p for p in by_type.get("NETWORK_FETCH", []) if p.params.get("dst_class") == "external" or p.params.get("resolved_dst_class") == "external"]
        execs = [p for p in by_type.get("SHELL_EXEC", []) if p.params.get("command_class") == "high_risk"]
        hidden = by_type.get("EMBED_HIDDEN_INSTRUCTION", [])
        setup = by_type.get("SETUP_INSTRUCTION", [])
        suspicious_fetches = [
            p
            for p in fetches
            if p.params.get("download_kind") in {"archive", "executable", "script", "script_page", "installer"}
        ]
        for fetch in fetches:
            for exec_primitive in execs:
                patterns.append(self._pattern("Downloader_Installer", "high", ["R4_DOWNLOADER"], [fetch, exec_primitive], "The skill contains a downloader-and-execute installation chain."))
        for instruction in hidden + setup:
            if suspicious_fetches:
                support = [instruction] + suspicious_fetches[:1] + execs[:1]
                patterns.append(
                    self._pattern(
                        "Downloader_Installer",
                        "high",
                        ["R4_DOWNLOADER_INTENT"],
                        support,
                        "Natural language setup instructions conceal a downloader-installer chain.",
                    )
                )
        return patterns

    def _rule_filesystem_recon(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        lists = [p for p in by_type.get("LIST_DIR", []) if p.params.get("path_class") in {"system", "sensitive"}]
        reads = [p for p in by_type.get("READ_FILE", []) if p.params.get("path_class") in {"system", "sensitive"}]
        for primitive in lists + reads:
            patterns.append(self._pattern("Filesystem_Recon", "medium", ["R5_FS_RECON"], [primitive], "The skill enumerates or reads system-sensitive filesystem locations."))
        return patterns

    def _rule_prompt_override(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        for primitive in by_type.get("EMBED_HIDDEN_INSTRUCTION", []):
            patterns.append(self._pattern("Prompt_Instruction_Override", "medium", ["R6_PROMPT_OVERRIDE"], [primitive], "The skill embeds hidden or coercive setup instructions."))
        return patterns

    def _rule_hidden_setup(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        hidden = by_type.get("EMBED_HIDDEN_INSTRUCTION", [])
        fetches = by_type.get("NETWORK_FETCH", [])
        execs = by_type.get("SHELL_EXEC", [])
        for primitive in hidden:
            support = [primitive] + fetches[:1] + execs[:1]
            patterns.append(self._pattern("Hidden_Setup_Trap", "medium", ["R7_HIDDEN_SETUP"], support, "The skill requires concealed setup or pre-execution steps that expand attack surface."))
        return patterns

    def _rule_external_service_bootstrap(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        setup = by_type.get("SETUP_INSTRUCTION", [])
        execs = by_type.get("SHELL_EXEC", [])
        secrets = by_type.get("REQUEST_SECRET", [])
        for instruction in setup:
            if execs:
                patterns.append(
                    self._pattern(
                        "External_Service_Bootstrap",
                        "medium",
                        ["R7B_EXTERNAL_BOOTSTRAP"],
                        [instruction, execs[0]],
                        "The skill couples operator setup guidance with direct command execution against an external or provisioned service.",
                    )
                )
            elif secrets:
                patterns.append(
                    self._pattern(
                        "External_Service_Bootstrap",
                        "medium",
                        ["R7C_EXTERNAL_BOOTSTRAP_SECRET"],
                        [instruction, secrets[0]],
                        "The skill bootstrap flow requires both setup actions and credentials before normal use.",
                    )
                )
        return patterns

    def _rule_dynamic_sink(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        for primitive in by_type.get("NETWORK_SEND", []) + by_type.get("NETWORK_FETCH", []):
            if primitive.params.get("resolved_from") and primitive.params.get("resolved_dst_class") == "external":
                patterns.append(self._pattern("Dynamic_Sink_Injection", "high", ["R8_DYNAMIC_SINK"], [primitive], "The network sink is injected indirectly through configuration and resolves to an external endpoint."))
        return patterns

    def _rule_capability_mismatch(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        declared = by_type.get("DECLARED_CAPABILITY", [])
        high_risk_actual = []
        for name in ["READ_FILE", "READ_ENV", "NETWORK_SEND", "SHELL_EXEC", "REQUEST_SECRET", "DYNAMIC_LOAD"]:
            high_risk_actual.extend(by_type.get(name, []))
        if not declared or not high_risk_actual:
            return patterns
        for dec in declared:
            implied = set(dec.params.get("implied_capabilities", []))
            if "LOW_RISK_HELPER" in implied or "BLOCKCHAIN_ASSISTANCE" in implied:
                patterns.append(self._pattern("Capability_Mismatch", "medium", ["R9_CAP_MISMATCH"], [dec, high_risk_actual[0]], "The declared benign capability envelope is inconsistent with high-risk behavior in code or setup instructions."))
        return patterns

    def _rule_obfuscated_execution(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        for primitive in by_type.get("OBFUSCATED_EXEC", []):
            patterns.append(self._pattern("Obfuscated_Execution", "high", ["R10_OBFUSCATED_EXEC"], [primitive], "The skill uses obfuscated shell execution, such as base64-decoded command pipelines."))
        return patterns

    def _pattern(self, name: str, severity: str, rule_ids: list[str], primitives: list[PrimitiveRecord], explanation: str) -> PatternMatch:
        pattern_id = f"pat_{self._counter:05d}"
        self._counter += 1
        primitive_ids = [primitive.primitive_id for primitive in primitives]
        evidence_ids = [evidence_id for primitive in primitives for evidence_id in primitive.evidence_ids]
        return PatternMatch(
            pattern_id=pattern_id,
            name=name,
            severity=severity,
            rule_ids=rule_ids,
            primitive_ids=primitive_ids,
            evidence_ids=evidence_ids,
            explanation=explanation,
        )

    def _summarize(self, label: str, malicious_patterns: list[str], suspicious_patterns: list[str]) -> str:
        if label == "malicious":
            return f"Detected malicious behavior patterns: {', '.join(malicious_patterns)}."
        if label == "suspicious":
            return f"Detected suspicious behavior patterns: {', '.join(suspicious_patterns)}."
        return "No malicious capability composition was inferred from the current primitive set."
