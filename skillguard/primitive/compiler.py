from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import re
from typing import Any

from ..models import ArtifactRecord, EvidenceRecord, PrimitiveRecord
from ..taxonomy import command_class, endpoint_class, path_class, secret_class, url_class
from .llm import LlmObjectAnalyzer
from .yasa import YasaAdapter


class PrimitiveCompiler:
    def __init__(self) -> None:
        self.llm_analyzer = LlmObjectAnalyzer()
        self.yasa_adapter = YasaAdapter()
        self._counter = 0

    def synthesize(
        self,
        artifacts: list[ArtifactRecord],
        evidence: list[EvidenceRecord],
        *,
        skill_root: str | Path | None = None,
        enable_yasa: bool = True,
        enable_cross_artifact_resolution: bool = True,
    ) -> tuple[list[PrimitiveRecord], dict[str, Any], list[EvidenceRecord], list[EvidenceRecord]]:
        combined = list(evidence)
        derived_evidence: list[EvidenceRecord] = []
        llm_evidence_facts = self._attach_llm_object_metadata(self.llm_analyzer.extract(artifacts, evidence))
        derived_evidence.extend(llm_evidence_facts)
        combined.extend(llm_evidence_facts)
        if enable_yasa and skill_root is not None and self._should_run_yasa(artifacts):
            yasa_evidence_facts = self.yasa_adapter.extract(skill_root, artifacts)
            enriched_yasa = self._attach_supporting_evidence(yasa_evidence_facts, combined)
            derived_evidence.extend(enriched_yasa)
            combined.extend(enriched_yasa)

        graph = self._init_graph(artifacts, combined)
        parameter_bindings = self._parameter_bindings_index(combined)

        primitives: list[PrimitiveRecord] = []
        primitive_objects: dict[str, list[str]] = {}
        evidence_object: dict[str, str] = {}

        for item in combined:
            generated = self._compile_evidence(
                item,
                parameter_bindings=parameter_bindings,
            )
            for primitive, extra_edges, related_objects in generated:
                primitives.append(primitive)
                evidence_object[item.evidence_id] = primitive.params.get("operation_object", "")
                primitive_objects[primitive.primitive_id] = [
                    primitive.params.get("operation_object", ""),
                    *related_objects,
                ]
                graph["nodes"].append(
                    {
                        "id": primitive.primitive_id,
                        "kind": "primitive",
                        "type": primitive.primitive_type,
                    }
                )
                graph["edges"].append({"source": item.evidence_id, "target": primitive.primitive_id, "type": "supports"})
                operation_object = primitive.params.get("operation_object")
                if operation_object:
                    graph["edges"].append({"source": item.evidence_id, "target": operation_object, "type": "acts_on"})
                    graph["edges"].append({"source": primitive.primitive_id, "target": operation_object, "type": "acts_on"})
                    self._ensure_logical_object_node(graph, operation_object, primitive.params)
                for related in related_objects:
                    self._ensure_logical_object_node(graph, related, {"object_identity_kind": self._object_kind_from_id(related)})
                    graph["edges"].append({"source": primitive.primitive_id, "target": related, "type": "associated_with"})
                graph["edges"].extend(extra_edges)

        if enable_cross_artifact_resolution:
            self._add_same_object_edges(graph, combined, primitives, evidence_object, primitive_objects)
        graph["nodes"] = self._dedupe_nodes(graph["nodes"])
        graph["edges"] = self._dedupe_edges(graph["edges"])
        return primitives, graph, derived_evidence, combined

    def _compile_evidence(
        self,
        item: EvidenceRecord,
        *,
        parameter_bindings: dict[tuple[str, str], list[EvidenceRecord]],
    ) -> list[tuple[PrimitiveRecord, list[dict[str, str]], list[str]]]:
        return self._compile_taxonomy_evidence(
            item,
            parameter_bindings=parameter_bindings,
        )

    def _compile_taxonomy_evidence(
        self,
        item: EvidenceRecord,
        *,
        parameter_bindings: dict[tuple[str, str], list[EvidenceRecord]],
    ) -> list[tuple[PrimitiveRecord, list[dict[str, str]], list[str]]]:
        subtype = item.subtype
        text = self._evidence_text(item)
        if subtype in {"direct_process_execution", "shell_interpreter_execution", "script_host_execution", "proxy_execution_or_lolbin_abuse"}:
            return [self._execution_primitive_tuple(item, parameter_bindings)]
        if subtype == "dynamic_module_load":
            return [self._primitive_tuple(item.subtype, item, {"matched_text": text}, self._generic_operation_object(item))]
        if subtype == "outbound_connection":
            primitive_type = item.subtype
            return [self._network_primitive_tuple(primitive_type, item, parameter_bindings)]
        if subtype in {"listener_and_receive", "tunneling_and_forwarding", "proxy_or_route_manipulation", "protocol_encapsulation_or_encrypted_comm"}:
            return [self._network_primitive_tuple(item.subtype, item, parameter_bindings)]
        if subtype in {"private_key_or_api_key_access", "password_or_hash_access", "session_or_token_access"}:
            params = {
                "matched_text": text,
                "sensitivity_class": "sensitive",
                "secret_class": secret_class(text),
            }
            return [self._primitive_tuple(item.subtype, item, params, self._source_operation_object(item, text))]
        if subtype == "file_enumeration_and_location":
            params = {
                "matched_text": text,
                "path_class": self._path_class_from_text(text),
            }
            return [self._primitive_tuple(item.subtype, item, params, self._source_operation_object(item, text))]
        if subtype == "content_read_and_parse":
            path_cls = self._path_class_from_text(text)
            params = {
                "matched_text": text,
                "path_class": path_cls,
                "sensitivity_class": "sensitive" if path_cls in {"system", "sensitive"} or self._looks_sensitive_text(text) else "ordinary",
            }
            return [self._primitive_tuple(item.subtype, item, params, self._source_operation_object(item, text))]
        if subtype in {"scheduled_persistence", "startup_or_logon_persistence", "service_or_daemon_persistence", "event_triggered_persistence", "boot_chain_persistence"}:
            return [self._primitive_tuple(item.subtype, item, {"text": text}, f"obj::instruction::{self._identity_fragment(str(text))}")]
        if subtype == "parameter_binding":
            return []
        return []

    def _network_primitive_tuple(
        self,
        primitive_type: str,
        item: EvidenceRecord,
        parameter_bindings: dict[tuple[str, str], list[EvidenceRecord]],
    ) -> tuple[PrimitiveRecord, list[dict[str, str]], list[str]]:
        endpoint_value = self._evidence_text(item)
        endpoint_cls = item.attributes.get("endpoint_class", item.attributes.get("dst_class", self._network_destination_class(item, endpoint_value)))
        original_endpoint_cls = endpoint_cls
        bindings = self._bindings_for_sink(item, parameter_bindings)
        endpoint_binding: EvidenceRecord | None = None
        if bindings:
            endpoint_binding = next((binding for binding in bindings if binding.binding.get("parameter_role") == "endpoint"), None)
            if endpoint_binding is not None:
                endpoint_value = endpoint_binding.value
                endpoint_cls = original_endpoint_cls

        object_id, extra_edges, resolved_value = self._resolve_network_object(
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
                    "role": binding.binding.get("parameter_role"),
                    "value": binding.value,
                    "evidence_id": binding.evidence_id,
                }
                for binding in bindings
            ],
            "related_objects": related_objects,
            "sink_api": item.attributes.get("sink_api", ""),
        }
        if resolved_value is not None:
            params["resolved_from"] = resolved_value.evidence_id
            params["resolved_endpoint_class"] = resolved_value.attributes.get(
                "endpoint_class",
                resolved_value.attributes.get("dst_class", endpoint_class(resolved_value.value)),
            )
            params["resolved_dst_class"] = resolved_value.attributes.get("dst_class", url_class(resolved_value.value))
        return self._primitive_tuple(primitive_type, item, params, object_id, extra_edges=extra_edges, related_objects=related_objects)

    def _execution_primitive_tuple(
        self,
        item: EvidenceRecord,
        parameter_bindings: dict[tuple[str, str], list[EvidenceRecord]],
    ) -> tuple[PrimitiveRecord, list[dict[str, str]], list[str]]:
        text = self._evidence_text(item)
        bindings = self._bindings_for_sink(item, parameter_bindings)
        command_binding = next((binding for binding in bindings if binding.binding.get("parameter_role") == "command"), None)
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
            "parameter_bindings": [
                {
                    "role": binding.binding.get("parameter_role"),
                    "value": binding.value,
                    "evidence_id": binding.evidence_id,
                }
                for binding in bindings
            ],
        }
        return self._primitive_tuple(item.subtype, item, params, operation_object)

    def _primitive_tuple(
        self,
        primitive_type: str,
        item: EvidenceRecord,
        params: dict[str, Any],
        operation_object: str,
        *,
        extra_edges: list[dict[str, str]] | None = None,
        related_objects: list[str] | None = None,
    ) -> tuple[PrimitiveRecord, list[dict[str, str]], list[str]]:
        primitive = PrimitiveRecord(
            primitive_id=f"prim_{self._counter:05d}",
            primitive_type=primitive_type,
            params={
                **params,
                "operation_object": operation_object,
                "object_identity_kind": self._object_kind_from_id(operation_object),
            },
            confidence=item.confidence,
            evidence_ids=[item.evidence_id],
            artifact_paths=[item.artifact_path],
            primitive_category=item.evidence_type,
        )
        self._counter += 1
        return primitive, list(extra_edges or []), list(related_objects or [])

    def _resolve_network_object(
        self,
        item: EvidenceRecord,
        endpoint_value: str,
    ) -> tuple[str, list[dict[str, str]], EvidenceRecord | None]:
        binding = item.binding if isinstance(item.binding, dict) else {}
        explicit_kind = binding.get("object_kind")
        identity_key = binding.get("identity_key")
        if isinstance(explicit_kind, str) and isinstance(identity_key, str) and explicit_kind and identity_key:
            return f"obj::{explicit_kind}::{identity_key}", [], None

        if endpoint_value.startswith("http://") or endpoint_value.startswith("https://"):
            return f"obj::endpoint::{endpoint_value}", [], None

        return f"obj::symbolic_reference::{item.artifact_path}::{item.subtype}::{endpoint_value}", [], None

    def _bindings_for_sink(
        self,
        item: EvidenceRecord,
        parameter_bindings: dict[tuple[str, str], list[EvidenceRecord]],
    ) -> list[EvidenceRecord]:
        sink_api = str(item.attributes.get("sink_api", "")).strip()
        if sink_api:
            matches = list(parameter_bindings.get((item.artifact_path, sink_api), []))
            if matches:
                return matches
        return list(parameter_bindings.get((item.artifact_path, f"subtype::{item.subtype}"), []))

    def _related_objects_from_bindings(self, item: EvidenceRecord, bindings: list[EvidenceRecord]) -> list[str]:
        related: list[str] = []
        for binding in bindings:
            role = str(binding.binding.get("parameter_role", "")).strip()
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

    def _attach_supporting_evidence(self, yasa_evidence_facts: list[EvidenceRecord], combined: list[EvidenceRecord]) -> list[EvidenceRecord]:
        by_sink: dict[tuple[str, str], list[str]] = defaultdict(list)
        for item in combined:
            sink_api = str(item.attributes.get("sink_api", "")).strip()
            if sink_api:
                by_sink[(item.artifact_path, sink_api)].append(item.evidence_id)
        enriched: list[EvidenceRecord] = []
        for evidence_fact in yasa_evidence_facts:
            supporting = list(by_sink.get((evidence_fact.artifact_path, str(evidence_fact.attributes.get("sink_api", "")).strip()), []))
            provenance = dict(evidence_fact.provenance)
            provenance["supporting_evidence_ids"] = sorted(self._stable(supporting))
            provenance.setdefault("analysis_stage", "primitive_compilation")
            provenance.setdefault("analysis_component", "yasa_object_analysis")
            attributes = dict(evidence_fact.attributes)
            attributes.setdefault("analysis_stage", "primitive_compilation")
            attributes.setdefault("analysis_component", "yasa_object_analysis")
            enriched.append(
                EvidenceRecord(
                    evidence_id=evidence_fact.evidence_id,
                    producer=evidence_fact.producer or "yasa",
                    artifact_id=evidence_fact.artifact_id,
                    artifact_path=evidence_fact.artifact_path,
                    evidence_type=evidence_fact.evidence_type,
                    subtype=evidence_fact.subtype,
                    value=evidence_fact.value,
                    confidence=evidence_fact.confidence,
                    span=evidence_fact.span,
                    binding=dict(evidence_fact.binding),
                    attributes=attributes,
                    provenance=provenance,
                )
            )
        return enriched

    def _attach_llm_object_metadata(self, llm_evidence_facts: list[EvidenceRecord]) -> list[EvidenceRecord]:
        enriched: list[EvidenceRecord] = []
        for evidence_fact in llm_evidence_facts:
            provenance = dict(evidence_fact.provenance)
            provenance.setdefault("analysis_stage", "primitive_compilation")
            provenance.setdefault("analysis_component", "llm_object_analysis")
            attributes = dict(evidence_fact.attributes)
            attributes.setdefault("analysis_stage", "primitive_compilation")
            attributes.setdefault("analysis_component", "llm_object_analysis")
            enriched.append(
                EvidenceRecord(
                    evidence_id=evidence_fact.evidence_id,
                    producer=evidence_fact.producer or "llm",
                    artifact_id=evidence_fact.artifact_id,
                    artifact_path=evidence_fact.artifact_path,
                    evidence_type=evidence_fact.evidence_type,
                    subtype=evidence_fact.subtype,
                    value=evidence_fact.value,
                    confidence=evidence_fact.confidence,
                    span=evidence_fact.span,
                    binding=dict(evidence_fact.binding),
                    attributes=attributes,
                    provenance=provenance,
                )
            )
        return enriched

    def _should_run_yasa(self, artifacts: list[ArtifactRecord]) -> bool:
        for artifact in artifacts:
            if self.yasa_adapter.language_for_artifact(artifact):
                return True
        return False

    def _init_graph(self, artifacts: list[ArtifactRecord], evidence: list[EvidenceRecord]) -> dict[str, Any]:
        nodes = [{"id": artifact.artifact_id, "kind": "artifact", "type": artifact.artifact_type, "path": artifact.relative_path} for artifact in artifacts]
        edges: list[dict[str, str]] = []
        for item in evidence:
            nodes.append({"id": item.evidence_id, "kind": "evidence", "type": item.evidence_type, "subtype": item.subtype, "path": item.artifact_path})
            edges.append({"source": item.artifact_id, "target": item.evidence_id, "type": "contains"})
        return {"nodes": nodes, "edges": edges, "artifacts": [{"id": artifact.artifact_id, "path": artifact.relative_path, "type": artifact.artifact_type} for artifact in artifacts]}

    def _add_same_object_edges(
        self,
        graph: dict[str, Any],
        evidence: list[EvidenceRecord],
        primitives: list[PrimitiveRecord],
        evidence_object: dict[str, str],
        primitive_objects: dict[str, list[str]],
    ) -> None:
        by_object_evidence: dict[str, list[str]] = defaultdict(list)
        for evidence_id, object_id in evidence_object.items():
            if object_id:
                by_object_evidence[object_id].append(evidence_id)
        for ids in by_object_evidence.values():
            ordered_ids = self._stable(ids)
            for index, left in enumerate(ordered_ids):
                for right in ordered_ids[index + 1:]:
                    graph["edges"].append({"source": left, "target": right, "type": "same_object"})

        by_object_primitive: dict[str, list[str]] = defaultdict(list)
        for primitive_id, object_ids in primitive_objects.items():
            for object_id in self._stable(object_ids):
                if object_id:
                    by_object_primitive[object_id].append(primitive_id)
        for ids in by_object_primitive.values():
            ordered_ids = self._stable(ids)
            for index, left in enumerate(ordered_ids):
                for right in ordered_ids[index + 1:]:
                    graph["edges"].append({"source": left, "target": right, "type": "same_object"})

    def _ensure_logical_object_node(self, graph: dict[str, Any], object_id: str, params: dict[str, Any]) -> None:
        identity_kind = str(params.get("object_identity_kind", self._object_kind_from_id(object_id)))
        suffix = object_id.split("::", 2)[2] if object_id.count("::") >= 2 else object_id
        graph["nodes"].append(
            {
                "id": object_id,
                "kind": "logical_object",
                "object_kind": identity_kind,
                "identity_key": suffix,
            }
        )

    def _generic_operation_object(self, item: EvidenceRecord) -> str:
        start_line = item.span.start_line if item.span else 0
        return f"obj::operation::{item.artifact_path}::{item.subtype}::{start_line}"

    def _evidence_text(self, item: EvidenceRecord) -> str:
        matched_text = str(item.attributes.get("matched_text", "")).strip()
        if matched_text:
            return matched_text
        return str(item.value).strip()

    def _path_class_from_text(self, text: str) -> str:
        return path_class(self._evidence_text_like_path(text))

    def _evidence_text_like_path(self, text: str) -> str:
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

    def _network_destination_class(self, item: EvidenceRecord, endpoint_value: str) -> str:
        cls = url_class(endpoint_value)
        if cls != "unknown":
            return cls
        text = self._evidence_text(item)
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

    def _parameter_bindings_index(self, evidence: list[EvidenceRecord]) -> dict[tuple[str, str], list[EvidenceRecord]]:
        grouped: dict[tuple[str, str], list[EvidenceRecord]] = {}
        for item in evidence:
            if item.subtype != "parameter_binding":
                continue
            sink_api = str(item.attributes.get("sink_api", "")).strip()
            if sink_api:
                grouped.setdefault((item.artifact_path, sink_api), []).append(item)
            grouped.setdefault((item.artifact_path, f"subtype::{item.attributes.get('sink_subtype', '')}"), []).append(item)
        return grouped

    def _source_operation_object(self, item: EvidenceRecord, text: str) -> str:
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

    def _object_id_from_binding(self, binding: EvidenceRecord) -> str:
        object_kind = str(binding.binding.get("object_kind", "")).strip()
        identity_key = str(binding.binding.get("identity_key", "")).strip()
        if object_kind and identity_key:
            return f"obj::{object_kind}::{identity_key}"
        value = str(binding.value).strip()
        if value:
            return self._symbolic_reference_object(binding.artifact_path, value)
        return ""

    def _inline_payload_object(self, item: EvidenceRecord) -> str:
        text = self._evidence_text(item)
        if "requests.post" in text:
            match = re.search(r"json\s*=\s*\{[^{}]*:\s*([A-Za-z_][A-Za-z0-9_]*)", text)
            if match:
                return self._symbolic_reference_object(item.artifact_path, match.group(1))
        if "axios.post" in text:
            match = re.search(r"axios\.post\([^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*[\),]", text, re.DOTALL)
            if match:
                return self._symbolic_reference_object(item.artifact_path, match.group(1))
        return ""

    def _inline_command_object(self, item: EvidenceRecord) -> str:
        text = self._evidence_text(item)
        match = re.search(r"(?:exec|execSync|check_output|run)\((?:\s*)([A-Za-z_][A-Za-z0-9_\.]*)", text)
        if not match:
            return ""
        value = match.group(1)
        if "." in value or "[" in value:
            return f"obj::config_key::{value.split('.')[-1].strip(']')}"
        return self._symbolic_reference_object(item.artifact_path, value)

    def _identity_fragment(self, value: str) -> str:
        return value.replace("\n", " ").strip()

    def _looks_like_fetch(self, item: EvidenceRecord) -> bool:
        text = self._evidence_text(item).lower()
        return any(token in text for token in ("download", "curl", "wget", ".zip", ".tar", ".tgz", ".sh", ".ps1", ".exe", ".msi", ".pkg", ".dmg", "http://", "https://"))

    def _command_class_for(self, item: EvidenceRecord) -> str:
        text = self._evidence_text(item)
        if item.subtype in {"shell_interpreter_execution", "proxy_execution_or_lolbin_abuse"}:
            return "high_risk"
        lowered = text.lower()
        if any(token in lowered for token in ("bash", "sh ", "powershell", "cmd ", "curl ", "wget ", "http://", "https://", "terminal", "run the executable")):
            return "high_risk"
        return item.attributes.get("command_class", command_class(self._evidence_text(item)))

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

    def _dedupe_edges(self, edges: list[dict[str, str]]) -> list[dict[str, str]]:
        seen: set[tuple[str, str, str]] = set()
        deduped: list[dict[str, str]] = []
        for edge in edges:
            key = (str(edge.get("source", "")), str(edge.get("target", "")), str(edge.get("type", "")))
            if key in seen:
                continue
            seen.add(key)
            deduped.append({"source": key[0], "target": key[1], "type": key[2]})
        return deduped
