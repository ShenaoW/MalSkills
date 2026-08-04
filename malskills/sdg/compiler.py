from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from ..models import (
    ArtifactRecord,
    SSOFinding,
    OperandBinding,
    OperandRecord,
    OperandResolution,
    SSORecord,
    Span,
    ValueRecord,
)
from ..taxonomy import command_class, endpoint_class, path_class, secret_class, url_class
from ..findings.schema import SSO_SUBTYPES
from .llm import LlmObjectAnalyzer
from .yasa import YasaAdapter


@dataclass
class SDGCompilation:
    ssos: list[SSORecord]
    operands: list[OperandRecord]
    values: list[ValueRecord]
    resolutions: list[OperandResolution]
    graph: dict[str, Any]
    findings: list[SSOFinding]


class SDGCompiler:
    def __init__(self) -> None:
        self.llm_analyzer = LlmObjectAnalyzer()
        self.yasa_adapter = YasaAdapter()
        self._counter = 0

    def synthesize(
        self,
        artifacts: list[ArtifactRecord],
        findings: list[SSOFinding],
        *,
        skill_root: str | Path | None = None,
        enable_llm_object_analysis: bool = True,
        enable_yasa: bool = True,
        enable_cross_artifact_resolution: bool = True,
        precomputed_llm_bindings: list[OperandBinding] | None = None,
    ) -> SDGCompilation:
        self._counter = 0
        binding_facts: list[OperandBinding] = []
        if enable_yasa and skill_root is not None and self._should_run_yasa(artifacts):
            yasa_bindings = self.yasa_adapter.extract(skill_root, artifacts)
            binding_facts.extend(self._attach_supporting_findings(yasa_bindings, findings))
        if enable_llm_object_analysis:
            if precomputed_llm_bindings is not None:
                binding_facts.extend(
                    self._attach_supporting_findings(
                        precomputed_llm_bindings,
                        findings,
                    )
                )
            else:
                unresolved = self._findings_without_bindings(findings, binding_facts)
                if unresolved:
                    unresolved_paths = {item.artifact_path for item in unresolved}
                    focused_artifacts = [
                        artifact
                        for artifact in artifacts
                        if artifact.relative_path in unresolved_paths
                    ]
                    fallback_bindings = self.llm_analyzer.extract(
                        focused_artifacts,
                        unresolved,
                    )
                    binding_facts.extend(
                        self._attach_supporting_findings(
                            fallback_bindings,
                            findings,
                        )
                    )

        parameter_bindings = self._parameter_bindings_index(binding_facts)

        ssos_by_key: dict[tuple[str, str, int, str], SSORecord] = {}
        for item in findings:
            generated = self._compile_finding(
                item,
                parameter_bindings=parameter_bindings,
            )
            for sso, _, _ in generated:
                key = self._sso_merge_key(item)
                existing = ssos_by_key.get(key)
                if existing is None:
                    ssos_by_key[key] = sso
                    continue
                existing.finding_ids = self._stable([*existing.finding_ids, *sso.finding_ids])
                existing.artifact_ids = self._stable([*existing.artifact_ids, *sso.artifact_ids])
                existing.artifact_paths = self._stable([*existing.artifact_paths, *sso.artifact_paths])
                available_confidences = [
                    value
                    for value in (existing.confidence, sso.confidence)
                    if value is not None
                ]
                existing.confidence = max(available_confidences, default=None)
                existing.attributes = self._merge_sso_attributes(existing.attributes, sso.attributes)

        ssos = list(ssos_by_key.values())
        graph = self._init_graph(artifacts)
        operands, values, resolutions = self._build_sdg(
            graph,
            ssos,
            binding_facts,
            enable_cross_artifact_resolution=enable_cross_artifact_resolution,
        )
        graph["nodes"] = self._dedupe_nodes(graph["nodes"])
        graph["edges"] = self._dedupe_edges(graph["edges"])
        return SDGCompilation(
            ssos=ssos,
            operands=operands,
            values=values,
            resolutions=resolutions,
            graph=graph,
            findings=list(findings),
        )

    def _findings_without_bindings(
        self,
        findings: list[SSOFinding],
        bindings: list[OperandBinding],
    ) -> list[SSOFinding]:
        by_sink = {
            (item.artifact_path, item.sink_api)
            for item in bindings
            if item.sink_api
        }
        by_subtype = {
            (item.artifact_path, item.sink_subtype)
            for item in bindings
            if item.sink_subtype
        }
        unresolved: list[SSOFinding] = []
        for finding in findings:
            sink_api = str(finding.attributes.get("sink_api", "")).strip()
            if sink_api and (finding.artifact_path, sink_api) in by_sink:
                continue
            if (finding.artifact_path, finding.subtype) in by_subtype:
                continue
            unresolved.append(finding)
        return unresolved

    def _compile_finding(
        self,
        item: SSOFinding,
        *,
        parameter_bindings: dict[tuple[str, str], list[OperandBinding]],
    ) -> list[tuple[SSORecord, list[dict[str, str]], list[str]]]:
        return self._compile_taxonomy_finding(
            item,
            parameter_bindings=parameter_bindings,
        )

    def _compile_taxonomy_finding(
        self,
        item: SSOFinding,
        *,
        parameter_bindings: dict[tuple[str, str], list[OperandBinding]],
    ) -> list[tuple[SSORecord, list[dict[str, str]], list[str]]]:
        subtype = item.subtype
        text = self._finding_text(item)
        if subtype in {"direct_process_execution", "shell_interpreter_execution", "script_host_execution", "proxy_execution_or_lolbin_abuse"}:
            return [self._execution_sso_tuple(item, parameter_bindings)]
        if subtype == "dynamic_module_load":
            return [self._sso_tuple(item.subtype, item, {"matched_text": text}, self._generic_operation_object(item))]
        if subtype == "outbound_connection":
            subtype = item.subtype
            return [self._network_sso_tuple(subtype, item, parameter_bindings)]
        if subtype in {"listener_and_receive", "tunneling_and_forwarding", "proxy_or_route_manipulation", "protocol_encapsulation_or_encrypted_comm"}:
            return [self._network_sso_tuple(item.subtype, item, parameter_bindings)]
        if subtype in {
            "private_key_or_api_key_access",
            "password_or_hash_access",
            "session_or_token_access",
            "credential_decryption",
            "authentication_input_capture",
        }:
            params = {
                "matched_text": text,
                "sensitivity_class": "sensitive",
                "secret_class": secret_class(text),
            }
            return [self._sso_tuple(item.subtype, item, params, self._source_operation_object(item, text))]
        if subtype == "file_enumeration_and_location":
            params = {
                "matched_text": text,
                "path_class": self._path_class_from_text(text),
            }
            return [self._sso_tuple(item.subtype, item, params, self._source_operation_object(item, text))]
        if subtype == "content_read_and_parse":
            path_cls = self._path_class_from_text(text)
            params = {
                "matched_text": text,
                "path_class": path_cls,
                "sensitivity_class": "sensitive" if path_cls in {"system", "sensitive"} or self._looks_sensitive_text(text) else "ordinary",
            }
            return [self._sso_tuple(item.subtype, item, params, self._source_operation_object(item, text))]
        if subtype in {"scheduled_persistence", "startup_or_logon_persistence", "service_or_daemon_persistence", "event_triggered_persistence", "boot_chain_persistence"}:
            return [self._sso_tuple(item.subtype, item, {"text": text}, f"obj::instruction::{self._identity_fragment(str(text))}")]
        if subtype in SSO_SUBTYPES:
            params: dict[str, Any] = {
                "matched_text": text,
                "sso_category": item.category,
            }
            if item.category == "file_and_data_access":
                params["path_class"] = self._path_class_from_text(text)
            if item.category == "credential_and_secret_access":
                params["sensitivity_class"] = "sensitive"
                params["secret_class"] = secret_class(text)
            return [
                self._sso_tuple(
                    subtype,
                    item,
                    params,
                    self._generic_operation_object(item),
                )
            ]
        return []

    def _network_sso_tuple(
        self,
        subtype: str,
        item: SSOFinding,
        parameter_bindings: dict[tuple[str, str], list[OperandBinding]],
    ) -> tuple[SSORecord, list[dict[str, str]], list[str]]:
        endpoint_value = self._finding_text(item)
        endpoint_cls = item.attributes.get("endpoint_class", item.attributes.get("dst_class", self._network_destination_class(item, endpoint_value)))
        original_endpoint_cls = endpoint_cls
        bindings = self._bindings_for_sink(item, parameter_bindings)
        endpoint_binding: OperandBinding | None = None
        if bindings:
            endpoint_binding = next(
                (binding for binding in bindings if binding.role == "endpoint"), None
            )
            if endpoint_binding is not None:
                endpoint_value = endpoint_binding.value
                endpoint_cls = original_endpoint_cls

        object_id = self._resolve_network_object(
            endpoint_binding or item,
            endpoint_value,
        )
        related_objects = self._related_objects_from_bindings(item, bindings)
        inline_payload = self._inline_payload_object(item)
        if inline_payload:
            related_objects.append(inline_payload)
        params = {
            "endpoint": endpoint_value,
            "endpoint_class": endpoint_cls,
            "dst_class": item.attributes.get("dst_class", endpoint_cls),
            "network_role": "fetch" if self._looks_like_fetch(item) else "send",
            "parameter_bindings": [
                {
                    "role": binding.role,
                    "value": binding.value,
                    "binding_id": binding.binding_id,
                }
                for binding in bindings
            ],
            "related_objects": related_objects,
            "sink_api": item.attributes.get("sink_api", ""),
            "sink_callsite_id": self._callsite_id(item),
        }
        return self._sso_tuple(subtype, item, params, object_id, related_objects=related_objects)

    def _execution_sso_tuple(
        self,
        item: SSOFinding,
        parameter_bindings: dict[tuple[str, str], list[OperandBinding]],
    ) -> tuple[SSORecord, list[dict[str, str]], list[str]]:
        text = self._finding_text(item)
        bindings = self._bindings_for_sink(item, parameter_bindings)
        command_binding = next(
            (binding for binding in bindings if binding.role == "command"), None
        )
        operation_object = self._generic_operation_object(item)
        if command_binding is not None:
            operation_object = self._object_id_from_binding(command_binding) or operation_object
        else:
            inline_command = self._inline_command_object(item)
            if inline_command:
                operation_object = inline_command
        params = {
            "matched_text": text,
            "command_class": item.attributes.get("command_class", self._command_class_for(item)),
            "sink_callsite_id": self._callsite_id(item),
            "parameter_bindings": [
                {
                    "role": binding.role,
                    "value": binding.value,
                    "binding_id": binding.binding_id,
                }
                for binding in bindings
            ],
        }
        return self._sso_tuple(
            item.subtype,
            item,
            params,
            operation_object,
        )

    def _callsite_id(self, item: SSOFinding) -> str:
        start = item.span.start_line if item.span else 0
        end = item.span.end_line if item.span else start
        sink_api = str(item.attributes.get("sink_api", item.subtype)).strip() or item.subtype
        return f"{item.artifact_path}:{start}:{end}:{sink_api}"

    def _sso_tuple(
        self,
        subtype: str,
        item: SSOFinding,
        params: dict[str, Any],
        operation_object: str,
        *,
        extra_edges: list[dict[str, str]] | None = None,
        related_objects: list[str] | None = None,
    ) -> tuple[SSORecord, list[dict[str, str]], list[str]]:
        related_object_values = [
            value
            for value in (related_objects or [])
            if value and not str(value).startswith("obj::callsite::")
        ]
        sso_attributes = {
            **params,
            "operation_object": operation_object,
            "object_identity_kind": self._object_kind_from_id(operation_object),
            "source_start_line": item.span.start_line if item.span else 0,
            "source_end_line": item.span.end_line if item.span else 0,
        }
        if related_object_values:
            sso_attributes["related_objects"] = self._stable(related_object_values)
        sso = SSORecord(
            sso_id=f"sso_{self._counter:05d}",
            category=item.category,
            subtype=subtype,
            confidence=item.confidence,
            finding_ids=[item.finding_id],
            artifact_ids=[item.artifact_id],
            artifact_paths=[item.artifact_path],
            attributes=sso_attributes,
        )
        self._counter += 1
        return sso, list(extra_edges or []), related_object_values

    def _resolve_network_object(
        self,
        item: SSOFinding | OperandBinding,
        endpoint_value: str,
    ) -> str:
        if isinstance(item, OperandBinding):
            explicit_kind = item.object_kind
            identity_key = item.identity_key
        else:
            explicit_kind = ""
            identity_key = ""
        if isinstance(explicit_kind, str) and isinstance(identity_key, str) and explicit_kind and identity_key:
            return f"obj::{explicit_kind}::{identity_key}"

        if endpoint_value.startswith("http://") or endpoint_value.startswith("https://"):
            return f"obj::endpoint::{endpoint_value}"

        subtype = item.sink_subtype if isinstance(item, OperandBinding) else item.subtype
        return f"obj::symbolic_reference::{item.artifact_path}::{subtype}::{endpoint_value}"

    def _bindings_for_sink(
        self,
        item: SSOFinding,
        parameter_bindings: dict[tuple[str, str], list[OperandBinding]],
    ) -> list[OperandBinding]:
        sink_api = str(item.attributes.get("sink_api", "")).strip()
        if sink_api:
            matches = list(parameter_bindings.get((item.artifact_path, sink_api), []))
            if matches:
                return self._nearest_callsite_bindings(item, matches)
        matches = list(parameter_bindings.get((item.artifact_path, f"subtype::{item.subtype}"), []))
        return self._nearest_callsite_bindings(item, matches)

    def _nearest_callsite_bindings(
        self,
        sink: SSOFinding,
        bindings: list[OperandBinding],
    ) -> list[OperandBinding]:
        if not bindings or sink.span is None:
            return bindings

        def distance(binding: OperandBinding) -> int:
            if binding.span is None:
                return 1_000_000
            if binding.span.end_line < sink.span.start_line:
                return sink.span.start_line - binding.span.end_line
            if sink.span.end_line < binding.span.start_line:
                return binding.span.start_line - sink.span.end_line
            return 0

        minimum = min(distance(binding) for binding in bindings)
        if minimum > 2:
            return []
        return [binding for binding in bindings if distance(binding) == minimum]

    def _related_objects_from_bindings(self, item: SSOFinding, bindings: list[OperandBinding]) -> list[str]:
        related: list[str] = []
        for binding in bindings:
            role = binding.role.strip()
            if role != "payload":
                continue
            bound_object = self._object_id_from_binding(binding)
            if bound_object:
                related.append(bound_object)
            cls = secret_class(binding.value)
            if cls != "unknown":
                related.append(f"obj::secret::{cls}")
            related.append(self._symbolic_reference_object(item.artifact_path, binding.value))
        return self._stable(related)

    def _attach_supporting_findings(
        self,
        yasa_bindings: list[OperandBinding],
        findings: list[SSOFinding],
    ) -> list[OperandBinding]:
        by_sink: dict[tuple[str, str], list[str]] = defaultdict(list)
        for item in findings:
            sink_api = str(item.attributes.get("sink_api", "")).strip()
            if sink_api:
                by_sink[(item.artifact_path, sink_api)].append(item.finding_id)
        enriched: list[OperandBinding] = []
        for binding in yasa_bindings:
            supporting = by_sink.get((binding.artifact_path, binding.sink_api), [])
            enriched.append(
                replace(
                    binding,
                    source_finding_ids=sorted(self._stable(supporting)),
                )
            )
        return enriched

    def _sso_merge_key(self, item: SSOFinding) -> tuple[str, str, int, str]:
        start_line = item.span.start_line if item.span else 0
        sink_api = str(item.attributes.get("sink_api", "")).strip().lower()
        return (item.artifact_path, item.subtype, start_line, sink_api)

    def _merge_sso_attributes(
        self,
        left: dict[str, Any],
        right: dict[str, Any],
    ) -> dict[str, Any]:
        merged = dict(left)
        for key, value in right.items():
            if key not in merged or merged[key] in (None, "", [], {}):
                merged[key] = value
                continue
            if key in {"parameter_bindings", "related_objects"}:
                current = merged[key] if isinstance(merged[key], list) else []
                incoming = value if isinstance(value, list) else []
                if key == "related_objects":
                    merged[key] = self._stable([*current, *incoming])
                else:
                    seen: set[str] = set()
                    combined: list[dict[str, Any]] = []
                    for item in [*current, *incoming]:
                        if not isinstance(item, dict):
                            continue
                        fingerprint = json.dumps(item, sort_keys=True, ensure_ascii=True)
                        if fingerprint in seen:
                            continue
                        seen.add(fingerprint)
                        combined.append(item)
                    merged[key] = combined
        return merged

    def _build_sdg(
        self,
        graph: dict[str, Any],
        ssos: list[SSORecord],
        binding_facts: list[OperandBinding],
        *,
        enable_cross_artifact_resolution: bool,
    ) -> tuple[list[OperandRecord], list[ValueRecord], list[OperandResolution]]:
        binding_by_id = {item.binding_id: item for item in binding_facts}
        operands: dict[str, OperandRecord] = {}
        values: dict[str, ValueRecord] = {}
        resolutions: list[OperandResolution] = []
        ssos_by_operand: dict[str, list[str]] = defaultdict(list)

        for sso in ssos:
            sso_node = {
                "id": sso.sso_id,
                "kind": "sso",
                "type": sso.category,
                "subtype": sso.subtype,
                "finding_ids": list(sso.finding_ids),
            }
            if sso.confidence is not None:
                sso_node["confidence"] = sso.confidence
            graph["nodes"].append(sso_node)
            for artifact_id in sso.artifact_ids:
                graph["edges"].append(
                    {"source": artifact_id, "target": sso.sso_id, "type": "contains"}
                )

            referenced_bindings = [
                binding_by_id.get(str(item.get("binding_id", "")))
                for item in sso.attributes.get("parameter_bindings", [])
                if isinstance(item, dict)
            ]
            referenced_bindings = [item for item in referenced_bindings if item is not None]
            objects = self._stable(
                [
                    str(sso.attributes.get("operation_object", "")),
                    *[
                        str(item)
                        for item in sso.attributes.get("related_objects", [])
                        if item
                    ],
                ]
            )
            objects = [item for item in objects if item and not item.startswith("obj::callsite::")]

            for object_id in objects:
                binding = next(
                    (
                        item
                        for item in referenced_bindings
                        if self._object_id_from_binding(item) == object_id
                    ),
                    None,
                )
                role = self._operand_role(sso, object_id, binding)
                method = binding.producer if binding is not None else "syntax"
                operand = operands.get(object_id)
                if operand is None:
                    operand = OperandRecord(
                        operand_id=object_id,
                        role=role,
                        object_kind=self._object_kind_from_id(object_id),
                        identity_key=self._object_identity_key(object_id),
                        display_value=self._object_identity_key(object_id),
                        resolution_methods=[method],
                    )
                    operands[object_id] = operand
                    graph["nodes"].append(
                        {
                            "id": object_id,
                            "kind": "operand",
                            "role": role,
                            "object_kind": operand.object_kind,
                            "identity_key": operand.identity_key,
                        }
                    )
                elif method not in operand.resolution_methods:
                    operand.resolution_methods.append(method)
                sso.operand_ids.append(object_id)
                ssos_by_operand[object_id].append(sso.sso_id)
                graph["edges"].append(
                    {
                        "source": sso.sso_id,
                        "target": object_id,
                        "type": "has_operand",
                        "role": role,
                    }
                )

                value_id = self._ensure_operand_value(
                    graph,
                    values,
                    object_id,
                    binding,
                )
                if binding is None:
                    continue
                resolution = OperandResolution(
                    resolution_id=f"resolution::{sso.sso_id}::{binding.binding_id}",
                    sso_id=sso.sso_id,
                    role=role,
                    operand_id=object_id,
                    value_id=value_id,
                    method=binding.producer or "unknown",
                    confidence=binding.confidence,
                    artifact_path=binding.artifact_path,
                    span=binding.span,
                    flow_steps=list(binding.flow_steps),
                    source_finding_ids=self._stable(
                        [
                            *sso.finding_ids,
                            *[
                                str(item)
                                for item in binding.source_finding_ids
                            ],
                        ]
                    ),
                )
                resolutions.append(resolution)
                self._add_resolution_flow(graph, values, resolution)

            sso.operand_ids = self._stable(sso.operand_ids)
            sso.attributes["operand_roles"] = {
                operand_id: operands[operand_id].role for operand_id in sso.operand_ids
            }

        if enable_cross_artifact_resolution:
            for sso_ids in ssos_by_operand.values():
                ordered = self._stable(sso_ids)
                for index, left in enumerate(ordered):
                    for right in ordered[index + 1 :]:
                        graph["edges"].append(
                            {"source": left, "target": right, "type": "same_object"}
                        )
        return list(operands.values()), list(values.values()), resolutions

    def _ensure_operand_value(
        self,
        graph: dict[str, Any],
        values: dict[str, ValueRecord],
        operand_id: str,
        binding: OperandBinding | None,
    ) -> str:
        display_value = binding.value if binding is not None and binding.value else self._object_identity_key(operand_id)
        digest = hashlib.sha256(
            f"binding\0{operand_id}\0{display_value}".encode("utf-8")
        ).hexdigest()[:20]
        value_id = f"value::{digest}"
        if value_id not in values:
            value_kind = "literal" if display_value.startswith(("http://", "https://", "/", "~")) else "symbolic"
            values[value_id] = ValueRecord(
                value_id=value_id,
                value_kind=value_kind,
                display_value=display_value,
                artifact_path=binding.artifact_path if binding is not None else "",
                span=binding.span if binding is not None else None,
            )
            graph["nodes"].append(
                {
                    "id": value_id,
                    "kind": "value",
                    "value_kind": value_kind,
                    "value": display_value,
                }
            )
        graph["edges"].append(
            {
                "source": operand_id,
                "target": value_id,
                "type": "value_flow",
                "flow_kind": "binding",
            }
        )
        return value_id

    def _add_resolution_flow(
        self,
        graph: dict[str, Any],
        values: dict[str, ValueRecord],
        resolution: OperandResolution,
    ) -> None:
        previous_id: str | None = None
        for index, step in enumerate(resolution.flow_steps):
            if not isinstance(step, dict):
                continue
            display_value = str(step.get("affected_node") or step.get("snippet") or "").strip()
            if not display_value:
                continue
            artifact_path = str(step.get("artifact_path", resolution.artifact_path))
            start_line = int(step.get("start_line", 1) or 1)
            end_line = int(step.get("end_line", start_line) or start_line)
            digest = hashlib.sha256(
                f"flow\0{artifact_path}\0{start_line}\0{end_line}\0{display_value}".encode(
                    "utf-8"
                )
            ).hexdigest()[:20]
            value_id = f"value::{digest}"
            if value_id not in values:
                values[value_id] = ValueRecord(
                    value_id=value_id,
                    value_kind="program_value",
                    display_value=display_value,
                    artifact_path=artifact_path,
                    span=Span(start_line, end_line),
                )
                graph["nodes"].append(
                    {
                        "id": value_id,
                        "kind": "value",
                        "value_kind": "program_value",
                        "value": display_value,
                        "path": artifact_path,
                        "start_line": start_line,
                        "end_line": end_line,
                    }
                )
            if previous_id is not None and previous_id != value_id:
                graph["edges"].append(
                    {
                        "source": previous_id,
                        "target": value_id,
                        "type": "value_flow",
                        "flow_kind": "propagation",
                        "resolution_id": resolution.resolution_id,
                        "step": index,
                    }
                )
            previous_id = value_id
        if previous_id is not None and previous_id != resolution.value_id:
            graph["edges"].append(
                {
                    "source": previous_id,
                    "target": resolution.value_id,
                    "type": "value_flow",
                    "flow_kind": "sink_binding",
                    "resolution_id": resolution.resolution_id,
                }
            )

    def _operand_role(
        self,
        sso: SSORecord,
        object_id: str,
        binding: OperandBinding | None,
    ) -> str:
        if binding is not None:
            role = binding.role.strip()
            if role:
                return role
        if object_id.startswith("obj::payload::"):
            return "payload"
        if object_id.startswith("obj::secret::"):
            return "credential"
        if sso.subtype in {
            "outbound_connection",
            "listener_and_receive",
            "tunneling_and_forwarding",
            "proxy_or_route_manipulation",
            "protocol_encapsulation_or_encrypted_comm",
        }:
            return "endpoint"
        if sso.subtype in {
            "direct_process_execution",
            "shell_interpreter_execution",
            "script_host_execution",
            "dynamic_module_load",
            "proxy_execution_or_lolbin_abuse",
        }:
            return "command"
        if sso.category in {"file_and_data_access", "credential_and_secret_access"}:
            return "path"
        return "target"

    def _object_identity_key(self, object_id: str) -> str:
        return object_id.split("::", 2)[2] if object_id.count("::") >= 2 else object_id

    def _should_run_yasa(self, artifacts: list[ArtifactRecord]) -> bool:
        for artifact in artifacts:
            if self.yasa_adapter.language_for_artifact(artifact):
                return True
        return False

    def _init_graph(self, artifacts: list[ArtifactRecord]) -> dict[str, Any]:
        nodes = [{"id": artifact.artifact_id, "kind": "artifact", "type": artifact.artifact_type, "path": artifact.relative_path} for artifact in artifacts]
        return {"nodes": nodes, "edges": [], "artifacts": [{"id": artifact.artifact_id, "path": artifact.relative_path, "type": artifact.artifact_type} for artifact in artifacts]}

    def _generic_operation_object(self, item: SSOFinding) -> str:
        start_line = item.span.start_line if item.span else 0
        return f"obj::operation::{item.artifact_path}::{item.subtype}::{start_line}"

    def _finding_text(self, item: SSOFinding) -> str:
        return item.matched_text.strip()

    def _path_class_from_text(self, text: str) -> str:
        return path_class(self._finding_text_like_path(text))

    def _finding_text_like_path(self, text: str) -> str:
        lower = text.lower()
        for token in (
            "~/.env",
            ".env",
            "~/.ssh",
            "id_rsa",
            "id_ed25519",
            "/etc/passwd",
            "/etc/shadow",
            "credentials",
            "credential",
            "token",
            "secret",
            "wallet",
            "mnemonic",
            "seed",
            "auth",
        ):
            if token in lower:
                return token
        return text

    def _looks_sensitive_text(self, text: str) -> bool:
        lower = text.lower()
        return any(
            token in lower
            for token in (
                ".env",
                ".ssh",
                "id_rsa",
                "id_ed25519",
                "passwd",
                "shadow",
                "credential",
                "credentials",
                "token",
                "secret",
                "api_key",
                "private key",
                "wallet",
                "mnemonic",
                "seed",
            )
        )

    def _network_destination_class(self, item: SSOFinding, endpoint_value: str) -> str:
        cls = url_class(endpoint_value)
        if cls != "unknown":
            return cls
        text = self._finding_text(item)
        url_token = self._extract_url_like_token(text)
        if url_token:
            return url_class(url_token)
        lower = text.lower()
        if any(token in lower for token in ("webhook", "discord.com/api/webhooks", "slack.com/api", "api.telegram.org", "https://", "http://")):
            return "external"
        return "unknown"

    def _extract_url_like_token(self, text: str) -> str:
        normalized = text.replace("(", " ").replace(")", " ").replace(",", " ").replace('"', " ").replace("'", " ").replace("`", " ")
        for token in normalized.split():
            if token.startswith(("http://", "https://", "www.")):
                return token
        return ""

    def _parameter_bindings_index(
        self,
        bindings: list[OperandBinding],
    ) -> dict[tuple[str, str], list[OperandBinding]]:
        grouped: dict[tuple[str, str], list[OperandBinding]] = {}
        for item in bindings:
            sink_api = item.sink_api.strip()
            if sink_api:
                grouped.setdefault((item.artifact_path, sink_api), []).append(item)
            grouped.setdefault((item.artifact_path, f"subtype::{item.sink_subtype}"), []).append(item)
        return grouped

    def _source_operation_object(self, item: SSOFinding, text: str) -> str:
        variable_name = self._assigned_variable_name(text)
        if variable_name:
            return self._symbolic_reference_object(item.artifact_path, variable_name)
        return self._generic_operation_object(item)

    def _assigned_variable_name(self, text: str) -> str:
        match = re.search(r"(?:const|let|var)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", text)
        if match:
            return match.group(1)
        return ""

    def _symbolic_reference_object(self, artifact_path: str, value: str) -> str:
        return f"obj::symbolic_reference::{artifact_path}::{value}"

    def _object_id_from_binding(self, binding: OperandBinding) -> str:
        object_kind = binding.object_kind.strip()
        identity_key = binding.identity_key.strip()
        if object_kind and identity_key:
            return f"obj::{object_kind}::{identity_key}"
        value = str(binding.value).strip()
        if value:
            return self._symbolic_reference_object(binding.artifact_path, value)
        return ""

    def _inline_payload_object(self, item: SSOFinding) -> str:
        text = self._finding_text(item)
        if "requests.post" in text:
            match = re.search(r"json\s*=\s*\{[^{}]*:\s*([A-Za-z_][A-Za-z0-9_]*)", text)
            if match:
                return self._symbolic_reference_object(item.artifact_path, match.group(1))
        if "axios.post" in text:
            match = re.search(r"axios\.post\([^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*[\),]", text, re.DOTALL)
            if match:
                return self._symbolic_reference_object(item.artifact_path, match.group(1))
        return ""

    def _inline_command_object(self, item: SSOFinding) -> str:
        text = self._finding_text(item)
        match = re.search(r"(?:exec|execSync|check_output|run)\((?:\s*)([A-Za-z_][A-Za-z0-9_\.]*)", text)
        if not match:
            return ""
        value = match.group(1)
        if "." in value or "[" in value:
            return f"obj::config_key::{value.split('.')[-1].strip(']')}"
        return self._symbolic_reference_object(item.artifact_path, value)

    def _identity_fragment(self, value: str) -> str:
        return value.replace("\n", " ").strip()

    def _looks_like_fetch(self, item: SSOFinding) -> bool:
        text = self._finding_text(item).lower()
        return any(token in text for token in ("download", "curl", "wget", ".zip", ".tar", ".tgz", ".sh", ".ps1", ".exe", ".msi", ".pkg", ".dmg", "http://", "https://"))

    def _command_class_for(self, item: SSOFinding) -> str:
        text = self._finding_text(item)
        if item.subtype in {"shell_interpreter_execution", "proxy_execution_or_lolbin_abuse"}:
            return "high_risk"
        lowered = text.lower()
        if any(token in lowered for token in ("bash", "sh ", "powershell", "cmd ", "curl ", "wget ", "http://", "https://", "terminal", "run the executable")):
            return "high_risk"
        return item.attributes.get("command_class", command_class(self._finding_text(item)))

    def _object_kind_from_id(self, object_id: str) -> str:
        if object_id.startswith("obj::") and "::" in object_id[5:]:
            return object_id.split("::", 2)[1]
        return "unknown"

    def _stable(self, values: list[str]) -> list[str]:
        seen: set[str] = set()
        ordered: list[str] = []
        for value in values:
            if not value or value in seen:
                continue
            seen.add(value)
            ordered.append(value)
        return ordered

    def _dedupe_nodes(self, nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: dict[str, dict[str, Any]] = {}
        for node in nodes:
            node_id = str(node.get("id", ""))
            if node_id and node_id not in seen:
                seen[node_id] = node
        return list(seen.values())

    def _dedupe_edges(self, edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: set[str] = set()
        deduped: list[dict[str, Any]] = []
        for edge in edges:
            normalized = dict(edge)
            normalized["source"] = str(normalized.get("source", ""))
            normalized["target"] = str(normalized.get("target", ""))
            normalized["type"] = str(normalized.get("type", ""))
            fingerprint = json.dumps(normalized, sort_keys=True, ensure_ascii=True)
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            deduped.append(normalized)
        return deduped
