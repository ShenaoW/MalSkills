from __future__ import annotations

from collections import defaultdict

from .models import ArtifactRecord, EvidenceRecord, PrimitiveRecord
from .taxonomy import command_class, env_class, path_class, url_class


class PrimitiveSynthesizer:
    def __init__(self) -> None:
        self._counter = 0

    def synthesize(
        self,
        artifacts: list[ArtifactRecord],
        evidence: list[EvidenceRecord],
        *,
        enable_cross_artifact_resolution: bool = True,
    ) -> tuple[list[PrimitiveRecord], dict[str, object]]:
        primitives: list[PrimitiveRecord] = []
        graph_nodes: list[dict[str, object]] = []
        graph_edges: list[dict[str, object]] = []

        config_values: dict[str, list[EvidenceRecord]] = defaultdict(list)
        config_urls: dict[str, list[EvidenceRecord]] = defaultdict(list)
        refs_by_artifact: dict[str, list[EvidenceRecord]] = defaultdict(list)
        for ev in evidence:
            graph_nodes.append({"id": ev.evidence_id, "kind": "evidence", "type": ev.evidence_type, "subtype": ev.subtype})
            if ev.subtype == "config_value":
                key = str(ev.attributes.get("key", "")).split(".")[-1]
                config_values[key].append(ev)
                if ev.attributes.get("dst_class") == "external":
                    config_urls[key].append(ev)
            if ev.subtype == "config_ref":
                refs_by_artifact[ev.artifact_id].append(ev)

        artifact_map = {artifact.artifact_id: artifact for artifact in artifacts}
        for artifact in artifacts:
            graph_nodes.append({"id": artifact.artifact_id, "kind": "artifact", "type": artifact.artifact_type, "path": artifact.relative_path})

        for ev in evidence:
            primitive_type: str | None = None
            params: dict[str, object] = {}
            if ev.subtype == "file_read":
                primitive_type = "READ_FILE"
                params = {
                    "path": ev.value,
                    "path_class": ev.attributes.get("path_class", path_class(ev.value)),
                    "sensitivity_class": ev.attributes.get("path_class", path_class(ev.value)),
                    "source": ev.artifact_path,
                }
            elif ev.subtype == "list_dir":
                primitive_type = "LIST_DIR"
                params = {"path": ev.value, "path_class": ev.attributes.get("path_class", path_class(ev.value)), "source": ev.artifact_path}
            elif ev.subtype == "env_read":
                primitive_type = "READ_ENV"
                params = {
                    "key": ev.value,
                    "key_class": ev.attributes.get("env_class", env_class(ev.value)),
                    "sensitivity_class": ev.attributes.get("env_class", env_class(ev.value)),
                    "source": ev.artifact_path,
                }
            elif ev.subtype == "config_value":
                primitive_type = "READ_CONFIG"
                params = {
                    "key": ev.attributes.get("key", ev.value),
                    "value": ev.value,
                    "dst_class": ev.attributes.get("dst_class", url_class(ev.value)),
                    "path_class": ev.attributes.get("path_class", path_class(ev.value)),
                    "source": ev.artifact_path,
                }
            elif ev.subtype in {"network_send", "network_fetch", "installer_download"}:
                primitive_type = "NETWORK_SEND" if ev.subtype == "network_send" else "NETWORK_FETCH"
                params = {
                    "endpoint": ev.value,
                    "dst_class": ev.attributes.get("dst_class", url_class(ev.value)),
                    "source": ev.artifact_path,
                }
                if ev.subtype == "installer_download":
                    params["download_kind"] = ev.attributes.get("download_kind", "installer")
                resolved = None
                if enable_cross_artifact_resolution:
                    resolved = self._resolve_endpoint(ev, refs_by_artifact, config_values, config_urls)
                if resolved:
                    params.update(resolved)
                    graph_edges.append({"source": ev.evidence_id, "target": resolved["resolved_from_evidence_id"], "type": "resolved_from"})
            elif ev.subtype == "shell_exec":
                primitive_type = "SHELL_EXEC"
                params = {
                    "command": ev.value,
                    "command_class": ev.attributes.get("command_class", command_class(ev.value)),
                    "source": ev.artifact_path,
                }
            elif ev.subtype == "dynamic_load":
                primitive_type = "DYNAMIC_LOAD"
                params = {"module_source": ev.value, "source": ev.artifact_path}
            elif ev.subtype == "hidden_instruction":
                primitive_type = "EMBED_HIDDEN_INSTRUCTION"
                params = {"intent_class": ev.subtype, "source": ev.artifact_path, "text": ev.value}
            elif ev.subtype == "setup_instruction":
                primitive_type = "SETUP_INSTRUCTION"
                params = {"intent_class": ev.subtype, "source": ev.artifact_path, "text": ev.value}
            elif ev.subtype == "secret_request":
                primitive_type = "REQUEST_SECRET"
                params = {"secret_type": ev.value, "source": ev.artifact_path}
            elif ev.subtype == "declared_action":
                primitive_type = "DECLARED_CAPABILITY"
                params = {"declared": ev.value, "implied_capabilities": ev.attributes.get("implied_capabilities", []), "source": ev.artifact_path}
            elif ev.subtype == "declared_capability":
                primitive_type = "DECLARED_CAPABILITY"
                params = {"declared": ev.value, "implied_capabilities": ev.attributes.get("implied_capabilities", []), "source": ev.artifact_path}
            elif ev.subtype == "obfuscated_exec":
                primitive_type = "OBFUSCATED_EXEC"
                params = {"command": ev.value, "source": ev.artifact_path, "command_class": "high_risk"}
            elif ev.subtype == "taint_flow":
                primitive_type = "TAINT_FLOW"
                params = {
                    "flow_kind": ev.attributes.get("flow_kind", "taint_flow"),
                    "sink_attribute": ev.attributes.get("sink_attribute", ""),
                    "sink_rule": ev.attributes.get("sink_rule", ""),
                    "source": ev.artifact_path,
                }
            if not primitive_type:
                continue
            primitive = self._new_primitive(primitive_type, params, ev.confidence, [ev.evidence_id], [ev.artifact_path])
            primitives.append(primitive)
            graph_nodes.append({"id": primitive.primitive_id, "kind": "primitive", "type": primitive.primitive_type})
            graph_edges.append({"source": ev.artifact_id, "target": ev.evidence_id, "type": "contains"})
            graph_edges.append({"source": ev.evidence_id, "target": primitive.primitive_id, "type": "supports"})

        graph = {
            "nodes": graph_nodes,
            "edges": graph_edges,
            "artifacts": [artifact_map[artifact_id].relative_path for artifact_id in artifact_map],
        }
        return primitives, graph

    def _resolve_endpoint(
        self,
        evidence: EvidenceRecord,
        refs_by_artifact: dict[str, list[EvidenceRecord]],
        config_values: dict[str, list[EvidenceRecord]],
        config_urls: dict[str, list[EvidenceRecord]],
    ) -> dict[str, object] | None:
        if evidence.attributes.get("dst_class") in {"external", "local"}:
            return None
        refs = refs_by_artifact.get(evidence.artifact_id, [])
        for ref in refs:
            key = str(ref.attributes.get("key") or ref.value).split(".")[-1]
            candidates = config_urls.get(key) or config_values.get(key)
            if not candidates:
                continue
            candidate = candidates[0]
            resolved_value = candidate.value
            return {
                "resolved_from": key,
                "resolved_value": resolved_value,
                "resolved_dst_class": candidate.attributes.get("dst_class", url_class(resolved_value)),
                "resolved_from_evidence_id": candidate.evidence_id,
            }
        return None

    def _new_primitive(self, primitive_type: str, params: dict[str, object], confidence: float, evidence_ids: list[str], artifact_paths: list[str]) -> PrimitiveRecord:
        primitive_id = f"prim_{self._counter:05d}"
        self._counter += 1
        return PrimitiveRecord(
            primitive_id=primitive_id,
            primitive_type=primitive_type,
            params=params,
            confidence=confidence,
            evidence_ids=evidence_ids,
            artifact_paths=artifact_paths,
        )
