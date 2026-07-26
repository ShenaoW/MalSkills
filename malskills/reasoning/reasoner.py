from __future__ import annotations

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from ..models import ArtifactRecord, EvidenceRecord, PatternMatch, PrimitiveRecord, SkillVerdict
from .llm import LlmPatternReasoner
from .souffle import SouffleExporter
from .verdict import PatternVerdictBuilder


class FormalReasoner:
    def __init__(self) -> None:
        self._counter = 0
        self._exporter = SouffleExporter()
        self._verdicts = PatternVerdictBuilder()
        self._llm_reasoner = LlmPatternReasoner()

    def reason(
        self,
        skill_path: str,
        primitives: list[PrimitiveRecord],
        *,
        artifacts: list[ArtifactRecord] | None = None,
        evidence: list[EvidenceRecord] | None = None,
        graph: dict[str, Any] | None = None,
        mode: str = "formal",
        runtime_sec: float | None = None,
    ) -> tuple[list[PatternMatch], SkillVerdict, dict[str, list[tuple[object, ...]]]]:
        if mode == "llm":
            patterns = self._llm_reasoner.reason(
                skill_path=skill_path,
                artifacts=artifacts or [],
                evidence=evidence or [],
                primitives=primitives,
                graph=graph or {},
            )
            patterns = self._finalize_patterns(patterns)
            verdict = self._verdicts.patterns_to_verdict(skill_path, patterns)
        elif mode == "hybrid":
            patterns, verdict = self._hybrid_reason(
                skill_path,
                primitives,
                artifacts=artifacts or [],
                evidence=evidence or [],
                graph=graph or {},
            )
        else:
            patterns, verdict = self._formal_reason(skill_path, primitives)
        facts = self._exporter.build_facts(
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

    def _hybrid_reason(
        self,
        skill_path: str,
        primitives: list[PrimitiveRecord],
        *,
        artifacts: list[ArtifactRecord],
        evidence: list[EvidenceRecord],
        graph: dict[str, Any],
    ) -> tuple[list[PatternMatch], SkillVerdict]:
        with ThreadPoolExecutor(max_workers=2) as executor:
            formal_future = executor.submit(self._formal_reason, skill_path, primitives)
            llm_future = executor.submit(
                self._llm_reasoner.reason,
                skill_path=skill_path,
                artifacts=artifacts,
                evidence=evidence,
                primitives=primitives,
                graph=graph,
            )
            formal_patterns, _ = formal_future.result()
            llm_patterns = llm_future.result()
        merged = self._finalize_patterns([*formal_patterns, *llm_patterns])
        verdict = self._verdicts.patterns_to_verdict(skill_path, merged)
        return merged, verdict

    def export_souffle(self, facts: dict[str, list[tuple[object, ...]]], output_dir: str | Path) -> None:
        self._exporter.export_facts(facts, output_dir)

    def _formal_reason(
        self,
        skill_path: str,
        primitives: list[PrimitiveRecord],
    ) -> tuple[list[PatternMatch], SkillVerdict]:
        by_type: dict[str, list[PrimitiveRecord]] = defaultdict(list)
        for primitive in primitives:
            by_type[primitive.primitive_type].append(primitive)

        patterns: list[PatternMatch] = []
        patterns.extend(self._rule_execution_and_delivery(by_type))
        patterns.extend(self._rule_persistence(by_type))
        patterns.extend(self._rule_privilege_and_identity_abuse(by_type))
        patterns.extend(self._rule_injection_and_covert_residency(by_type))
        patterns.extend(self._rule_information_theft(by_type))
        patterns.extend(self._rule_command_and_control(by_type))
        patterns.extend(self._rule_lateral_movement(by_type))
        patterns.extend(self._rule_defense_evasion(by_type))
        patterns.extend(self._rule_destruction_and_ransomware(by_type))

        deduped = self._finalize_patterns(patterns)
        verdict = self._verdicts.patterns_to_verdict(skill_path, deduped)
        return deduped, verdict

    def _finalize_patterns(self, patterns: list[PatternMatch]) -> list[PatternMatch]:
        deduped = self._verdicts.dedupe_patterns(patterns)
        for pattern in deduped:
            if not hasattr(pattern, "explanation_chain") or not getattr(pattern, "explanation_chain", None):
                setattr(
                    pattern,
                    "explanation_chain",
                    self._build_pattern_chain(
                        pattern_id=pattern.pattern_id,
                        name=pattern.name,
                        severity=pattern.severity,
                        rule_ids=pattern.rule_ids,
                        primitive_ids=pattern.primitive_ids,
                        evidence_ids=pattern.evidence_ids,
                        source=pattern.source,
                    ),
                )
        return deduped

    def _rule_execution_and_delivery(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        execs = self._execution_primitives(by_type)
        fetches = self._external_network_primitives(by_type, roles={"fetch"})
        for primitive in execs:
            linked_fetches = self._linked_candidates(primitive, fetches)
            support = [primitive, *linked_fetches[:1]]
            explanation = (
                "The skill combines remote retrieval with execution-capable behavior."
                if linked_fetches
                else "The skill exposes explicit execution-capable behavior."
            )
            patterns.append(
                self._pattern(
                    "Execution_and_Delivery",
                    "high",
                    ["R_EXECUTION_AND_DELIVERY"],
                    support,
                    explanation,
                )
            )
        return patterns

    def _rule_persistence(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        for primitive in self._persistence_primitives(by_type):
            patterns.append(
                self._pattern(
                    "Persistence",
                    "high",
                    ["R_PERSISTENCE"],
                    [primitive],
                    "The skill establishes persistence through startup, service, scheduled, event, or boot-chain control.",
                )
            )
        return patterns

    def _rule_privilege_and_identity_abuse(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        for primitive in self._privilege_primitives(by_type):
            patterns.append(
                self._pattern(
                    "Privilege_Escalation_and_Identity_Abuse",
                    "high",
                    ["R_PRIVILEGE_IDENTITY"],
                    [primitive],
                    "The skill manipulates identities, privileges, tokens, groups, or trust boundaries.",
                )
            )
        return patterns

    def _rule_injection_and_covert_residency(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        for primitive in self._process_and_memory_primitives(by_type):
            patterns.append(
                self._pattern(
                    "Injection_and_Covert_Residency",
                    "high",
                    ["R_INJECTION_RESIDENCY"],
                    [primitive],
                    "The skill manipulates processes, memory, or execution context in a way consistent with injection or covert residency.",
                )
            )
        return patterns

    def _rule_information_theft(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        sources = self._information_source_primitives(by_type)
        exfil = self._external_network_primitives(by_type, roles={"send", "fetch"})
        archive = by_type.get("bulk_copy_and_archive", [])
        for source in sources:
            linked_exfil = self._linked_candidates(source, exfil)
            if linked_exfil:
                selected = linked_exfil[0]
                severity = "high"
                rule_id = "R_INFORMATION_THEFT_EXFIL"
                explanation = "Sensitive information is collected and paired with an external communication sink."
                if not self._share_object_chain(source, selected):
                    rule_id = "R_INFORMATION_THEFT_ARTIFACT_CHAIN"
                    explanation = "Sensitive information access and external communication appear in the same operational scope."
                patterns.append(
                    self._pattern(
                        "Information_Theft",
                        severity,
                        [rule_id],
                        [source, selected],
                        explanation,
                    )
                )
                continue
            linked_archive = self._linked_candidates(source, archive)
            if linked_archive:
                selected = linked_archive[0]
                patterns.append(
                    self._pattern(
                        "Information_Theft",
                        "high",
                        ["R_INFORMATION_THEFT_STAGE"],
                        [source, selected],
                        "Sensitive information is collected and staged through bulk copy or archival behavior.",
                    )
                )
                continue
            patterns.append(
                self._pattern(
                    "Information_Theft",
                    "high",
                    ["R_INFORMATION_THEFT_SOURCE"],
                    [source],
                    "The skill directly accesses sensitive credentials, tokens, secrets, or sensitive local data.",
                )
            )
        return patterns

    def _rule_command_and_control(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        c2_primitives = self._command_and_control_primitives(by_type)
        for primitive in c2_primitives:
            patterns.append(
                self._pattern(
                    "Command_and_Control",
                    "high",
                    ["R_COMMAND_AND_CONTROL"],
                    [primitive],
                    "The skill establishes or uses command-and-control style communication channels.",
                )
            )
        return patterns

    def _rule_lateral_movement(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        for primitive in self._lateral_movement_primitives(by_type):
            patterns.append(
                self._pattern(
                    "Lateral_Movement",
                    "high",
                    ["R_LATERAL_MOVEMENT"],
                    [primitive],
                    "The skill can move across hosts, remote sessions, or orchestrated nodes.",
                )
            )
        return patterns

    def _rule_defense_evasion(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        for primitive in self._defense_evasion_primitives(by_type):
            patterns.append(
                self._pattern(
                    "Defense_Evasion_and_Anti_Forensics",
                    "high",
                    ["R_DEFENSE_EVASION"],
                    [primitive],
                    "The skill suppresses logs, weakens controls, hides artifacts, or impairs defensive tooling.",
                )
            )
        return patterns

    def _rule_destruction_and_ransomware(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        for primitive in self._impact_primitives(by_type):
            patterns.append(
                self._pattern(
                    "Destruction_and_Ransomware",
                    "high",
                    ["R_DESTRUCTION_RANSOMWARE"],
                    [primitive],
                    "The skill destroys, encrypts, disables recovery, or disrupts system availability.",
                )
            )
        return patterns

    def _execution_primitives(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PrimitiveRecord]:
        values: list[PrimitiveRecord] = []
        for key in [
            "direct_process_execution",
            "shell_interpreter_execution",
            "script_host_execution",
            "dynamic_module_load",
            "proxy_execution_or_lolbin_abuse",
        ]:
            values.extend(by_type.get(key, []))
        return values

    def _persistence_primitives(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PrimitiveRecord]:
        values: list[PrimitiveRecord] = []
        for key in [
            "startup_or_logon_persistence",
            "service_or_daemon_persistence",
            "scheduled_persistence",
            "event_triggered_persistence",
            "boot_chain_persistence",
        ]:
            values.extend(by_type.get(key, []))
        return values

    def _privilege_primitives(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PrimitiveRecord]:
        values: list[PrimitiveRecord] = []
        for key in [
            "identity_switch",
            "privilege_adjustment",
            "token_or_session_impersonation",
            "group_or_acl_modification",
            "boundary_bypass",
        ]:
            values.extend(by_type.get(key, []))
        return values

    def _process_and_memory_primitives(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PrimitiveRecord]:
        values: list[PrimitiveRecord] = []
        for key in [
            "process_attach",
            "cross_process_memory_read",
            "cross_process_memory_write",
            "remote_thread_or_async_execution",
            "executable_memory_mapping",
            "process_hollowing_or_image_replacement",
        ]:
            values.extend(by_type.get(key, []))
        return values

    def _information_source_primitives(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PrimitiveRecord]:
        values: list[PrimitiveRecord] = []
        for key in [
            "password_or_hash_access",
            "session_or_token_access",
            "private_key_or_api_key_access",
            "credential_decryption",
            "authentication_input_capture",
        ]:
            values.extend(by_type.get(key, []))
        values.extend(
            [
                primitive
                for primitive in by_type.get("content_read_and_parse", [])
                if primitive.params.get("sensitivity_class") == "sensitive"
            ]
        )
        values.extend(
            [
                primitive
                for primitive in by_type.get("file_enumeration_and_location", [])
                if primitive.params.get("path_class") in {"system", "sensitive"}
            ]
        )
        return values

    def _external_network_primitives(self, by_type: dict[str, list[PrimitiveRecord]], *, roles: set[str]) -> list[PrimitiveRecord]:
        values: list[PrimitiveRecord] = []
        for key in [
            "outbound_connection",
            "listener_and_receive",
            "tunneling_and_forwarding",
            "proxy_or_route_manipulation",
            "protocol_encapsulation_or_encrypted_comm",
        ]:
            values.extend(by_type.get(key, []))
        result: list[PrimitiveRecord] = []
        for primitive in values:
            role = str(primitive.params.get("network_role", "send"))
            dst_class = primitive.params.get("resolved_dst_class") or primitive.params.get("dst_class") or primitive.params.get("endpoint_class")
            if role in roles and dst_class == "external":
                result.append(primitive)
        return result

    def _command_and_control_primitives(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PrimitiveRecord]:
        values: list[PrimitiveRecord] = []
        for key in [
            "listener_and_receive",
            "tunneling_and_forwarding",
            "proxy_or_route_manipulation",
            "protocol_encapsulation_or_encrypted_comm",
        ]:
            values.extend(by_type.get(key, []))
        values.extend(
            [
                primitive
                for primitive in by_type.get("outbound_connection", [])
                if str(primitive.params.get("network_role", "send")) == "send"
                and (primitive.params.get("resolved_dst_class") or primitive.params.get("dst_class") or primitive.params.get("endpoint_class")) == "external"
            ]
        )
        return values

    def _lateral_movement_primitives(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PrimitiveRecord]:
        values: list[PrimitiveRecord] = []
        for key in [
            "remote_login",
            "remote_command_execution",
            "remote_file_transfer",
            "remote_management_abuse",
            "cluster_or_cloud_node_control",
        ]:
            values.extend(by_type.get(key, []))
        return values

    def _defense_evasion_primitives(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PrimitiveRecord]:
        values: list[PrimitiveRecord] = []
        for key in [
            "security_tool_impairment",
            "logging_or_audit_suppression",
            "policy_or_access_control_weakening",
            "artifact_cleanup_or_timestomp",
            "object_hiding_or_visibility_evasion",
        ]:
            values.extend(by_type.get(key, []))
        return values

    def _impact_primitives(self, by_type: dict[str, list[PrimitiveRecord]]) -> list[PrimitiveRecord]:
        values: list[PrimitiveRecord] = []
        for key in [
            "data_destruction",
            "data_encryption_or_locking",
            "recovery_impairment",
            "availability_disruption",
            "boot_or_low_level_destruction",
        ]:
            values.extend(by_type.get(key, []))
        return values

    def _linked_candidates(self, primitive: PrimitiveRecord, candidates: list[PrimitiveRecord]) -> list[PrimitiveRecord]:
        if not candidates:
            return []
        linked = [candidate for candidate in candidates if self._share_object_chain(primitive, candidate)]
        if linked:
            return linked
        artifact_linked = [candidate for candidate in candidates if self._share_artifact_scope(primitive, candidate)]
        return artifact_linked or candidates

    def _share_object_chain(self, left: PrimitiveRecord, right: PrimitiveRecord) -> bool:
        return bool(self._primitive_object_neighborhood(left) & self._primitive_object_neighborhood(right))

    def _share_artifact_scope(self, left: PrimitiveRecord, right: PrimitiveRecord) -> bool:
        return bool(set(left.artifact_paths) & set(right.artifact_paths))

    def _primitive_object_neighborhood(self, primitive: PrimitiveRecord) -> set[str]:
        objects: set[str] = set()
        operation_object = primitive.params.get("operation_object")
        if operation_object:
            objects.add(str(operation_object))
        related_objects = primitive.params.get("related_objects") or []
        if isinstance(related_objects, list):
            objects.update(str(item) for item in related_objects if item)
        return objects

    def _pattern(
        self,
        name: str,
        severity: str,
        rule_ids: list[str],
        primitives: list[PrimitiveRecord],
        explanation: str,
    ) -> PatternMatch:
        pattern_id = f"pat_{self._counter:05d}"
        self._counter += 1
        primitive_ids = self._stable_unique([primitive.primitive_id for primitive in primitives])
        evidence_ids = self._stable_unique(
            [evidence_id for primitive in primitives for evidence_id in primitive.evidence_ids]
        )
        stable_rule_ids = self._stable_unique(rule_ids)
        pattern = PatternMatch(
            pattern_id=pattern_id,
            name=name,
            severity=severity,
            rule_ids=stable_rule_ids,
            primitive_ids=primitive_ids,
            evidence_ids=evidence_ids,
            explanation=explanation,
            source="formal",
        )
        setattr(
            pattern,
            "explanation_chain",
            self._build_pattern_chain(
                pattern_id=pattern_id,
                name=name,
                severity=severity,
                rule_ids=stable_rule_ids,
                primitive_ids=primitive_ids,
                evidence_ids=evidence_ids,
                source=pattern.source,
            ),
        )
        return pattern

    def _stable_unique(self, values: list[str]) -> list[str]:
        seen: set[str] = set()
        ordered: list[str] = []
        for value in values:
            if value in seen:
                continue
            seen.add(value)
            ordered.append(value)
        return ordered

    def _build_pattern_chain(
        self,
        *,
        pattern_id: str,
        name: str,
        severity: str,
        rule_ids: list[str],
        primitive_ids: list[str],
        evidence_ids: list[str],
        source: str,
    ) -> list[dict[str, object]]:
        return [
            {"stage": "evidence_fact", "evidence_ids": evidence_ids},
            {"stage": "primitive_fact", "primitive_ids": primitive_ids},
            {"stage": "rule", "rule_ids": rule_ids},
            {"stage": "reasoning_source", "source": source},
            {
                "stage": "pattern",
                "pattern_id": pattern_id,
                "pattern_name": name,
                "severity": severity,
            },
        ]
