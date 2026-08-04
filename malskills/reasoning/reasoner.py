from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

from ..models import (
    ArtifactRecord,
    SSOFinding,
    PatternMatch,
    SSORecord,
    SkillVerdict,
    WorkflowDiscovery,
)
from ..rule_learning.workflow import WorkflowRuleMatcher
from .llm import LlmPatternReasoner
from .souffle import SouffleExporter
from .verdict import PatternVerdictBuilder


class PatternReasoner:
    def __init__(self) -> None:
        self._counter = 0
        self._exporter = SouffleExporter()
        self._verdicts = PatternVerdictBuilder()
        self._llm_reasoner = LlmPatternReasoner()
        self._workflow_rules = WorkflowRuleMatcher()
        self._active_graph: dict[str, Any] = {}

    def reason(
        self,
        skill_path: str,
        ssos: list[SSORecord],
        *,
        artifacts: list[ArtifactRecord] | None = None,
        findings: list[SSOFinding] | None = None,
        graph: dict[str, Any] | None = None,
        mode: str = "formal",
        runtime_sec: float | None = None,
        learned_workflow_rules_dir: str | Path | None = None,
    ) -> tuple[
        list[PatternMatch],
        SkillVerdict,
        dict[str, list[tuple[object, ...]]],
        list[WorkflowDiscovery],
    ]:
        workflow_discoveries: list[WorkflowDiscovery] = []
        if mode == "llm":
            patterns, workflow_discoveries = self._llm_reasoner.reason(
                skill_path=skill_path,
                artifacts=artifacts or [],
                findings=findings or [],
                ssos=ssos,
                graph=graph or {},
            )
            symbolic_patterns, _ = self._formal_reason(
                skill_path,
                ssos,
                graph=graph or {},
                learned_workflow_rules_dir=learned_workflow_rules_dir,
            )
            workflow_discoveries = [
                discovery
                for discovery in workflow_discoveries
                if not self._workflow_discovery_covered(
                    discovery,
                    symbolic_patterns,
                )
            ]
            patterns = self._finalize_patterns(patterns)
            verdict = self._verdicts.patterns_to_verdict(skill_path, patterns)
        elif mode == "hybrid":
            patterns, verdict, workflow_discoveries = self._hybrid_reason(
                skill_path,
                ssos,
                artifacts=artifacts or [],
                findings=findings or [],
                graph=graph or {},
                learned_workflow_rules_dir=learned_workflow_rules_dir,
            )
        else:
            patterns, verdict = self._formal_reason(
                skill_path,
                ssos,
                graph=graph or {},
                learned_workflow_rules_dir=learned_workflow_rules_dir,
            )
        facts = self._exporter.build_facts(
            artifacts or [],
            findings or [],
            ssos,
            graph or {},
            patterns,
            verdict,
            runtime_sec=runtime_sec,
            reasoning_mode=mode,
        )
        return patterns, verdict, facts, workflow_discoveries

    def _hybrid_reason(
        self,
        skill_path: str,
        ssos: list[SSORecord],
        *,
        artifacts: list[ArtifactRecord],
        findings: list[SSOFinding],
        graph: dict[str, Any],
        learned_workflow_rules_dir: str | Path | None,
    ) -> tuple[list[PatternMatch], SkillVerdict, list[WorkflowDiscovery]]:
        formal_patterns, _ = self._formal_reason(
            skill_path,
            ssos,
            graph=graph,
            learned_workflow_rules_dir=learned_workflow_rules_dir,
        )
        llm_patterns, discoveries = self._llm_reasoner.reason(
            skill_path=skill_path,
            artifacts=artifacts,
            findings=findings,
            ssos=ssos,
            graph=graph,
            symbolic_patterns=formal_patterns,
        )
        discoveries = [
            discovery
            for discovery in discoveries
            if not self._workflow_discovery_covered(discovery, formal_patterns)
        ]
        merged = self._finalize_patterns([*formal_patterns, *llm_patterns])
        verdict = self._verdicts.patterns_to_verdict(skill_path, merged)
        return merged, verdict, discoveries

    def _workflow_discovery_covered(
        self,
        discovery: WorkflowDiscovery,
        symbolic_patterns: list[PatternMatch],
    ) -> bool:
        discovery_ssos = set(discovery.sso_ids)
        return any(
            pattern.name == discovery.pattern_name
            and discovery_ssos
            and discovery_ssos <= set(pattern.sso_ids)
            for pattern in symbolic_patterns
        )

    def export_souffle(self, facts: dict[str, list[tuple[object, ...]]], output_dir: str | Path) -> None:
        self._exporter.export_facts(facts, output_dir)

    def _formal_reason(
        self,
        skill_path: str,
        ssos: list[SSORecord],
        *,
        graph: dict[str, Any] | None = None,
        learned_workflow_rules_dir: str | Path | None = None,
    ) -> tuple[list[PatternMatch], SkillVerdict]:
        self._active_graph = graph or {}
        by_type: dict[str, list[SSORecord]] = defaultdict(list)
        for sso in ssos:
            by_type[sso.subtype].append(sso)

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
        learned_rules = self._workflow_rules.load_rules(learned_workflow_rules_dir)
        patterns.extend(self._workflow_rules.match(ssos, graph or {}, learned_rules))

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
                        sso_ids=pattern.sso_ids,
                        finding_ids=pattern.finding_ids,
                        source=pattern.source,
                    ),
                )
        return deduped

    def _rule_execution_and_delivery(self, by_type: dict[str, list[SSORecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        execs = self._execution_ssos(by_type)
        fetches = self._external_network_ssos(by_type, roles={"fetch"})
        for sso in execs:
            linked_fetches = self._linked_candidates(sso, fetches)
            if not linked_fetches:
                continue
            support = [sso, linked_fetches[0]]
            patterns.append(
                self._pattern(
                    "Execution_and_Delivery",
                    "high",
                    ["R_EXECUTION_AND_DELIVERY"],
                    support,
                    "The skill combines linked remote retrieval with execution-capable behavior.",
                )
            )
        return patterns

    def _rule_persistence(self, by_type: dict[str, list[SSORecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        for sso in self._persistence_ssos(by_type):
            patterns.append(
                self._pattern(
                    "Persistence",
                    "high",
                    ["R_PERSISTENCE"],
                    [sso],
                    "The skill establishes persistence through startup, service, scheduled, event, or boot-chain control.",
                )
            )
        return patterns

    def _rule_privilege_and_identity_abuse(self, by_type: dict[str, list[SSORecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        for sso in self._privilege_ssos(by_type):
            patterns.append(
                self._pattern(
                    "Privilege_Escalation_and_Identity_Abuse",
                    "high",
                    ["R_PRIVILEGE_IDENTITY"],
                    [sso],
                    "The skill manipulates identities, privileges, tokens, groups, or trust boundaries.",
                )
            )
        return patterns

    def _rule_injection_and_covert_residency(self, by_type: dict[str, list[SSORecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        for sso in self._process_and_memory_ssos(by_type):
            patterns.append(
                self._pattern(
                    "Injection_and_Covert_Residency",
                    "high",
                    ["R_INJECTION_RESIDENCY"],
                    [sso],
                    "The skill manipulates processes, memory, or execution context in a way consistent with injection or covert residency.",
                )
            )
        return patterns

    def _rule_information_theft(self, by_type: dict[str, list[SSORecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        sources = self._information_source_ssos(by_type)
        exfil = self._external_network_ssos(by_type, roles={"send"})
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
        return patterns

    def _rule_command_and_control(self, by_type: dict[str, list[SSORecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        c2_ssos = self._command_and_control_ssos(by_type)
        for sso in c2_ssos:
            patterns.append(
                self._pattern(
                    "Command_and_Control",
                    "high",
                    ["R_COMMAND_AND_CONTROL"],
                    [sso],
                    "The skill establishes or uses command-and-control style communication channels.",
                )
            )
        return patterns

    def _rule_lateral_movement(self, by_type: dict[str, list[SSORecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        for sso in self._lateral_movement_ssos(by_type):
            patterns.append(
                self._pattern(
                    "Lateral_Movement",
                    "high",
                    ["R_LATERAL_MOVEMENT"],
                    [sso],
                    "The skill can move across hosts, remote sessions, or orchestrated nodes.",
                )
            )
        return patterns

    def _rule_defense_evasion(self, by_type: dict[str, list[SSORecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        for sso in self._defense_evasion_ssos(by_type):
            patterns.append(
                self._pattern(
                    "Defense_Evasion_and_Anti_Forensics",
                    "high",
                    ["R_DEFENSE_EVASION"],
                    [sso],
                    "The skill suppresses logs, weakens controls, hides artifacts, or impairs defensive tooling.",
                )
            )
        return patterns

    def _rule_destruction_and_ransomware(self, by_type: dict[str, list[SSORecord]]) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        for sso in self._impact_ssos(by_type):
            patterns.append(
                self._pattern(
                    "Destruction_and_Ransomware",
                    "high",
                    ["R_DESTRUCTION_RANSOMWARE"],
                    [sso],
                    "The skill destroys, encrypts, disables recovery, or disrupts system availability.",
                )
            )
        return patterns

    def _execution_ssos(self, by_type: dict[str, list[SSORecord]]) -> list[SSORecord]:
        values: list[SSORecord] = []
        for key in [
            "direct_process_execution",
            "shell_interpreter_execution",
            "script_host_execution",
            "dynamic_module_load",
            "proxy_execution_or_lolbin_abuse",
        ]:
            values.extend(by_type.get(key, []))
        return values

    def _persistence_ssos(self, by_type: dict[str, list[SSORecord]]) -> list[SSORecord]:
        values: list[SSORecord] = []
        for key in [
            "startup_or_logon_persistence",
            "service_or_daemon_persistence",
            "scheduled_persistence",
            "event_triggered_persistence",
            "boot_chain_persistence",
        ]:
            values.extend(by_type.get(key, []))
        return values

    def _privilege_ssos(self, by_type: dict[str, list[SSORecord]]) -> list[SSORecord]:
        values: list[SSORecord] = []
        for key in [
            "identity_switch",
            "privilege_adjustment",
            "token_or_session_impersonation",
            "group_or_acl_modification",
            "boundary_bypass",
        ]:
            values.extend(by_type.get(key, []))
        return values

    def _process_and_memory_ssos(self, by_type: dict[str, list[SSORecord]]) -> list[SSORecord]:
        values: list[SSORecord] = []
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

    def _information_source_ssos(self, by_type: dict[str, list[SSORecord]]) -> list[SSORecord]:
        values: list[SSORecord] = []
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
                sso
                for sso in by_type.get("content_read_and_parse", [])
                if sso.attributes.get("sensitivity_class") == "sensitive"
            ]
        )
        values.extend(
            [
                sso
                for sso in by_type.get("file_enumeration_and_location", [])
                if sso.attributes.get("path_class") in {"system", "sensitive"}
            ]
        )
        return values

    def _external_network_ssos(self, by_type: dict[str, list[SSORecord]], *, roles: set[str]) -> list[SSORecord]:
        values: list[SSORecord] = []
        for key in [
            "outbound_connection",
            "listener_and_receive",
            "tunneling_and_forwarding",
            "proxy_or_route_manipulation",
            "protocol_encapsulation_or_encrypted_comm",
        ]:
            values.extend(by_type.get(key, []))
        result: list[SSORecord] = []
        for sso in values:
            role = str(sso.attributes.get("network_role", "send"))
            dst_class = sso.attributes.get("resolved_dst_class") or sso.attributes.get("dst_class") or sso.attributes.get("endpoint_class")
            if role in roles and dst_class == "external":
                result.append(sso)
        return result

    def _command_and_control_ssos(self, by_type: dict[str, list[SSORecord]]) -> list[SSORecord]:
        values: list[SSORecord] = []
        for key in [
            "listener_and_receive",
            "tunneling_and_forwarding",
            "proxy_or_route_manipulation",
            "protocol_encapsulation_or_encrypted_comm",
        ]:
            values.extend(by_type.get(key, []))
        return values

    def _lateral_movement_ssos(self, by_type: dict[str, list[SSORecord]]) -> list[SSORecord]:
        values: list[SSORecord] = []
        for key in [
            "remote_login",
            "remote_command_execution",
            "remote_file_transfer",
            "remote_management_abuse",
            "cluster_or_cloud_node_control",
        ]:
            values.extend(by_type.get(key, []))
        return values

    def _defense_evasion_ssos(self, by_type: dict[str, list[SSORecord]]) -> list[SSORecord]:
        values: list[SSORecord] = []
        for key in [
            "security_tool_impairment",
            "logging_or_audit_suppression",
            "policy_or_access_control_weakening",
            "artifact_cleanup_or_timestomp",
            "object_hiding_or_visibility_evasion",
        ]:
            values.extend(by_type.get(key, []))
        return values

    def _impact_ssos(self, by_type: dict[str, list[SSORecord]]) -> list[SSORecord]:
        values: list[SSORecord] = []
        for key in [
            "data_destruction",
            "data_encryption_or_locking",
            "recovery_impairment",
            "availability_disruption",
            "boot_or_low_level_destruction",
        ]:
            values.extend(by_type.get(key, []))
        return values

    def _linked_candidates(self, sso: SSORecord, candidates: list[SSORecord]) -> list[SSORecord]:
        if not candidates:
            return []
        return [
            candidate
            for candidate in candidates
            if self._share_object_chain(sso, candidate)
            or self._workflow_rules.connected(sso, candidate, self._active_graph)
        ]

    def _share_object_chain(self, left: SSORecord, right: SSORecord) -> bool:
        return bool(self._sso_object_neighborhood(left) & self._sso_object_neighborhood(right))

    def _share_artifact_scope(self, left: SSORecord, right: SSORecord) -> bool:
        return bool(set(left.artifact_paths) & set(right.artifact_paths))

    def _sso_object_neighborhood(self, sso: SSORecord) -> set[str]:
        objects: set[str] = set()
        operation_object = sso.attributes.get("operation_object")
        if operation_object:
            objects.add(str(operation_object))
        related_objects = sso.attributes.get("related_objects") or []
        if isinstance(related_objects, list):
            objects.update(str(item) for item in related_objects if item)
        return objects

    def _pattern(
        self,
        name: str,
        severity: str,
        rule_ids: list[str],
        ssos: list[SSORecord],
        explanation: str,
    ) -> PatternMatch:
        pattern_id = f"pat_{self._counter:05d}"
        self._counter += 1
        sso_ids = self._stable_unique([sso.sso_id for sso in ssos])
        finding_ids = self._stable_unique(
            [finding_id for sso in ssos for finding_id in sso.finding_ids]
        )
        stable_rule_ids = self._stable_unique(rule_ids)
        pattern = PatternMatch(
            pattern_id=pattern_id,
            name=name,
            severity=severity,
            rule_ids=stable_rule_ids,
            sso_ids=sso_ids,
            finding_ids=finding_ids,
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
                sso_ids=sso_ids,
                finding_ids=finding_ids,
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
        sso_ids: list[str],
        finding_ids: list[str],
        source: str,
    ) -> list[dict[str, object]]:
        return [
            {"stage": "sso_finding", "finding_ids": finding_ids},
            {"stage": "sso", "sso_ids": sso_ids},
            {"stage": "rule", "rule_ids": rule_ids},
            {"stage": "reasoning_source", "source": source},
            {
                "stage": "pattern",
                "pattern_id": pattern_id,
                "pattern_name": name,
                "severity": severity,
            },
        ]
