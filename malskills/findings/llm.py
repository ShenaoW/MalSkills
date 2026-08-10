from __future__ import annotations

import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from .. import llm_runtime
from ..llm_runtime import build_llm_runtime_config, invoke_structured_json
from ..models import ArtifactRecord, OperandBinding, SSOFinding, Span
from .schema import (
    SSO_CATEGORIES,
    SSO_SUBTYPES,
    SCHEMA_VERSION,
    canonical_sso_category,
    normalize_sso_finding,
    sanitize_llm_attributes,
)

SEMANTIC_PROMPT_VERSION = "2026-08-10-neutral-sso-v4"
SEMANTIC_SYSTEM_PROMPT = """Extract source-grounded, behavior-neutral security-sensitive operations and their operands.

Return two arrays:
- records: atomic sensitive operations using only the schema taxonomy.
- operand_bindings: command, endpoint, payload, module, or path values bound to a sensitive sink.

Rules:
- Do not classify the package or infer malicious intent.
- Do not emit generic capabilities, ordinary metadata, passive links, troubleshooting text, or prose without a concrete command, API, URL, path, or credential identifier.
- Preserve exact artifact paths, line spans, matched text, sink APIs, and symbolic values.
- Third-party execution and network wrappers are real sinks.
- Prefer stable object identity such as a config key or symbolic variable.
- Existing static findings may be used to resolve operands but must not be duplicated unless the model identifies a distinct grounded operation.
- Never emit malicious-behavior labels such as persistence, lateral movement, command and control, defense evasion, information theft, or ransomware.
- Decompose compound statements into atomic operations. A download piped to a shell is data_receive plus system_command_execution; base64 decoding is a separate decoding operation.
- Select data_send/data_receive only when the API or syntax establishes direction. Use connection_create for direction-ambiguous network APIs.
- Select file_read/file_write/file_create/file_delete only when the operation establishes that effect. Use file_access for direction-ambiguous open or handle acquisition.
- Environment, process, user, and system information access are sensitive facts but do not imply malicious intent.
- Encoding, decoding, encryption, hashing, and package installation are neutral transformations or effects, not malicious conclusions.
- Treat explicit archive extraction or decompression as a separate decoding operation with operation_class=archive_extraction. Do not merge it into a following execution operation.
- For archive_extraction, emit one input binding for the archive and one output binding for each explicitly named extracted artifact. Reuse the exact object kind and identity_key used by the producing download and consuming execution bindings. Do not derive an output member from a similar filename or archive basename.
- Explicit instructions to run, open, or launch a file are external_file_execution when the file operand is grounded.
- Shell interpreters and process-spawn APIs are system_command_execution; eval/exec/script engines are dynamic_code_execution.
- Emit operand bindings for each grounded sink operand, not only for URLs. For data_receive, bind the endpoint and also the returned or downloaded payload when the payload has a stable name. For external_file_execution, bind the executed path or named payload.
- Resolve explicit local coreference such as "download X and run it" or "run the executable" within the same sentence or enumerated step by reusing one payload identity_key. Do not infer identity from line proximity, similar names, or separate prose sections.
- Follow the structured schema exactly and return no explanatory text.
"""

SEMANTIC_OBJECT_KINDS = (
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
OPERAND_ROLES = (
    "command",
    "interpreter",
    "endpoint",
    "payload",
    "path",
    "credential",
    "module",
    "target",
    "input",
    "output",
)


@dataclass
class LlmSSOFindingResult:
    findings: list[SSOFinding]
    operand_bindings: list[OperandBinding]


class LlmSSOFindingExtractor:
    def __init__(
        self,
        cache_dir: str | Path | None = None,
        max_workers: int = 4,
        batch_size: int = 6,
    ) -> None:
        default_cache = Path(".cache") / "malskills_llm"
        configured = cache_dir or os.environ.get("MALSKILLS_LLM_CACHE") or default_cache
        self.cache_dir = Path(configured)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_workers = max_workers
        configured_batch_size = int(os.environ.get("MALSKILLS_LLM_SSO_BATCH_SIZE", batch_size))
        self.batch_size = max(1, configured_batch_size)
        self.runtime = build_llm_runtime_config("sso_extraction")

    def extract(
        self,
        artifacts: list[ArtifactRecord],
        *,
        existing_findings: list[SSOFinding] | None = None,
        include_operand_bindings: bool = True,
    ) -> LlmSSOFindingResult:
        eligible = [artifact for artifact in artifacts if artifact.is_text and artifact.content and not artifact.generated]
        if not eligible:
            return LlmSSOFindingResult(findings=[], operand_bindings=[])
        existing_findings = existing_findings or []

        def extract_one(artifact: ArtifactRecord) -> LlmSSOFindingResult:
            relevant = [
                item for item in existing_findings
                if item.artifact_path == artifact.relative_path
            ]
            return self._extract_artifact_records(
                artifact,
                relevant,
                include_operand_bindings,
            )

        def extract_batch(batch: list[ArtifactRecord]) -> LlmSSOFindingResult:
            paths = {artifact.relative_path for artifact in batch}
            relevant = [item for item in existing_findings if item.artifact_path in paths]
            return self._extract_batch_records(batch, relevant, include_operand_bindings)

        if len(eligible) == 1:
            batches = [extract_one(eligible[0])]
        else:
            artifact_batches = [
                eligible[index : index + self.batch_size]
                for index in range(0, len(eligible), self.batch_size)
            ]
            with ThreadPoolExecutor(max_workers=max(1, min(self.max_workers, len(artifact_batches)))) as executor:
                batches = list(executor.map(extract_batch, artifact_batches))
        findings = [record for batch in batches for record in batch.findings]
        bindings = [record for batch in batches for record in batch.operand_bindings]
        findings.sort(key=lambda item: (item.artifact_path, item.span.start_line if item.span else 0, item.finding_id))
        bindings.sort(key=lambda item: (item.artifact_path, item.span.start_line if item.span else 0, item.binding_id))
        return LlmSSOFindingResult(findings=findings, operand_bindings=bindings)

    def _extract_artifact_records(
        self,
        artifact: ArtifactRecord,
        existing_findings: list[SSOFinding],
        include_operand_bindings: bool,
    ) -> LlmSSOFindingResult:
        payload = self._load_or_extract_records(
            artifact,
            existing_findings,
            include_operand_bindings,
        )
        return LlmSSOFindingResult(
            findings=self._normalize_records(artifact, payload.get("records", [])),
            operand_bindings=self._normalize_operand_bindings(
                [artifact],
                payload.get("operand_bindings", []),
                cache_key=artifact.content_hash,
            ),
        )

    def _extract_batch_records(
        self,
        artifacts: list[ArtifactRecord],
        existing_findings: list[SSOFinding],
        include_operand_bindings: bool,
    ) -> LlmSSOFindingResult:
        payload = self._load_or_extract_batch_records(
            artifacts,
            existing_findings,
            include_operand_bindings,
        )
        digest = hashlib.sha256(
            "|".join(item.content_hash for item in artifacts).encode("utf-8")
        ).hexdigest()
        return LlmSSOFindingResult(
            findings=self._normalize_batch_records(artifacts, payload.get("records", [])),
            operand_bindings=self._normalize_operand_bindings(
                artifacts,
                payload.get("operand_bindings", []),
                cache_key=digest,
            ),
        )

    def _load_or_extract_records(
        self,
        artifact: ArtifactRecord,
        existing_findings: list[SSOFinding],
        include_operand_bindings: bool,
    ) -> dict[str, list[dict[str, object]]]:
        cache_path = self._cache_path_for(
            artifact,
            existing_findings,
            include_operand_bindings,
        )
        if cache_path.exists():
            try:
                payload = json.loads(cache_path.read_text(encoding="utf-8"))
                if self._valid_cached_payload(payload):
                    return {
                        "records": payload["records"],
                        "operand_bindings": payload["operand_bindings"],
                    }
            except (OSError, json.JSONDecodeError, AttributeError):
                pass
        payload = invoke_structured_json(
            prompt=self._build_prompt(
                artifact,
                existing_findings,
                include_operand_bindings,
            ),
            schema=_semantic_schema(batch=False),
            system_prompt=SEMANTIC_SYSTEM_PROMPT,
            cwd=Path.cwd(),
            config=self.runtime,
        )
        normalized = self._coerce_semantic_payload(payload, include_operand_bindings)
        if normalized is not None:
            cache_path.write_text(
                json.dumps(
                    {"schema_version": SCHEMA_VERSION, **normalized},
                    indent=2,
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            return normalized
        return {"records": [], "operand_bindings": []}

    def _load_or_extract_batch_records(
        self,
        artifacts: list[ArtifactRecord],
        existing_findings: list[SSOFinding],
        include_operand_bindings: bool,
    ) -> dict[str, list[dict[str, object]]]:
        cache_path = self._cache_path_for_batch(
            artifacts,
            existing_findings,
            include_operand_bindings,
        )
        if cache_path.exists():
            try:
                payload = json.loads(cache_path.read_text(encoding="utf-8"))
                if self._valid_cached_payload(payload):
                    return {
                        "records": payload["records"],
                        "operand_bindings": payload["operand_bindings"],
                    }
            except (OSError, json.JSONDecodeError, AttributeError):
                pass
        payload = invoke_structured_json(
            prompt=self._build_batch_prompt(
                artifacts,
                existing_findings,
                include_operand_bindings,
            ),
            schema=_semantic_schema(batch=True),
            system_prompt=SEMANTIC_SYSTEM_PROMPT,
            cwd=Path.cwd(),
            config=self.runtime,
        )
        normalized = self._coerce_semantic_payload(payload, include_operand_bindings)
        if normalized is not None:
            cache_path.write_text(
                json.dumps(
                    {"schema_version": SCHEMA_VERSION, **normalized},
                    indent=2,
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            return normalized
        return {"records": [], "operand_bindings": []}

    def _valid_cached_payload(self, payload: object) -> bool:
        return bool(
            isinstance(payload, dict)
            and payload.get("schema_version") == SCHEMA_VERSION
            and isinstance(payload.get("records"), list)
            and isinstance(payload.get("operand_bindings"), list)
        )

    def _coerce_semantic_payload(
        self,
        payload: object,
        include_operand_bindings: bool,
    ) -> dict[str, list[dict[str, object]]] | None:
        if not isinstance(payload, dict) or not isinstance(payload.get("records"), list):
            return None
        bindings = payload.get("operand_bindings", [])
        if not isinstance(bindings, list):
            return None
        return {
            "records": [item for item in payload["records"] if isinstance(item, dict)],
            "operand_bindings": (
                [item for item in bindings if isinstance(item, dict)]
                if include_operand_bindings
                else []
            ),
        }

    def _normalize_records(self, artifact: ArtifactRecord, records: list[dict[str, object]]) -> list[SSOFinding]:
        findings: list[SSOFinding] = []
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                continue
            record_type = str(record.get("type", "")).strip()
            subtype = str(record.get("subtype", "")).strip()
            attributes = record.get("attributes", {})
            if (
                record_type not in SSO_CATEGORIES
                or subtype not in SSO_SUBTYPES
                or canonical_sso_category(subtype, "unknown") != record_type
                or not isinstance(attributes, dict)
            ):
                continue
            attrs = sanitize_llm_attributes(attributes)
            try:
                start_line = max(1, int(record.get("start_line", 1)))
                end_line = max(start_line, int(record.get("end_line", start_line)))
                confidence = float(record.get("confidence", 0.75))
            except (TypeError, ValueError):
                continue
            findings.append(
                normalize_sso_finding(
                    SSOFinding(
                        finding_id=f"llm_{artifact.artifact_id}_{index:05d}",
                        producer="llm",
                        artifact_id=artifact.artifact_id,
                        artifact_path=artifact.relative_path,
                        category=canonical_sso_category(subtype, "unknown"),
                        subtype=subtype,
                        matched_text=str(attrs.get("matched_text") or ""),
                        confidence=confidence,
                        span=Span(start_line, end_line),
                        attributes={
                            "engine": "llm",
                            "backend": self.runtime.backend,
                            "model": self.runtime.model,
                            "analysis_stage": "sso_extraction",
                            "analysis_component": "llm_finding",
                            **(
                                {"operation_class": attrs["operation_class"]}
                                if attrs.get("operation_class")
                                else {}
                            ),
                        },
                        provenance={
                            "artifact": {"id": artifact.artifact_id, "path": artifact.relative_path},
                            "span": {"start_line": start_line, "end_line": end_line},
                            "producer": "llm",
                            "backend": self.runtime.backend,
                            "analysis_stage": "sso_extraction",
                            "analysis_component": "llm_finding",
                        },
                    )
                )
            )
        return findings

    def _normalize_batch_records(self, artifacts: list[ArtifactRecord], records: list[dict[str, object]]) -> list[SSOFinding]:
        artifact_by_path = {artifact.relative_path: artifact for artifact in artifacts}
        findings: list[SSOFinding] = []
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                continue
            artifact_path = str(record.get("artifact_path", "")).strip()
            artifact = artifact_by_path.get(artifact_path)
            if artifact is None:
                continue
            record_type = str(record.get("type", "")).strip()
            subtype = str(record.get("subtype", "")).strip()
            attributes = record.get("attributes", {})
            if (
                record_type not in SSO_CATEGORIES
                or subtype not in SSO_SUBTYPES
                or canonical_sso_category(subtype, "unknown") != record_type
                or not isinstance(attributes, dict)
            ):
                continue
            attrs = sanitize_llm_attributes(attributes)
            try:
                start_line = max(1, int(record.get("start_line", 1)))
                end_line = max(start_line, int(record.get("end_line", start_line)))
                confidence = float(record.get("confidence", 0.75))
            except (TypeError, ValueError):
                continue
            findings.append(
                normalize_sso_finding(
                    SSOFinding(
                        finding_id=f"llm_batch_{artifact.artifact_id}_{index:05d}",
                        producer="llm",
                        artifact_id=artifact.artifact_id,
                        artifact_path=artifact.relative_path,
                        category=canonical_sso_category(subtype, "unknown"),
                        subtype=subtype,
                        matched_text=str(attrs.get("matched_text") or ""),
                        confidence=confidence,
                        span=Span(start_line, end_line),
                        attributes={
                            "engine": "llm",
                            "backend": self.runtime.backend,
                            "model": self.runtime.model,
                            "analysis_stage": "sso_extraction",
                            "analysis_component": "llm_finding_batch",
                            **(
                                {"operation_class": attrs["operation_class"]}
                                if attrs.get("operation_class")
                                else {}
                            ),
                        },
                        provenance={
                            "artifact": {"id": artifact.artifact_id, "path": artifact.relative_path},
                            "span": {"start_line": start_line, "end_line": end_line},
                            "producer": "llm",
                            "backend": self.runtime.backend,
                            "analysis_stage": "sso_extraction",
                            "analysis_component": "llm_finding_batch",
                        },
                    )
                )
            )
        return findings

    def _normalize_operand_bindings(
        self,
        artifacts: list[ArtifactRecord],
        records: object,
        *,
        cache_key: str,
    ) -> list[OperandBinding]:
        if not isinstance(records, list):
            return []
        artifacts_by_path = {item.relative_path: item for item in artifacts}
        bindings: list[OperandBinding] = []
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                continue
            artifact = artifacts_by_path.get(str(record.get("artifact_path", "")).strip())
            attributes = record.get("attributes", {})
            descriptor = record.get("object", {})
            if artifact is None or not isinstance(attributes, dict) or not isinstance(descriptor, dict):
                continue
            subtype = str(attributes.get("sink_subtype", "")).strip()
            role = str(attributes.get("parameter_role", "")).strip()
            value = str(record.get("value", "")).strip()
            object_kind = str(descriptor.get("kind", "unknown")).strip() or "unknown"
            if (
                subtype not in SSO_SUBTYPES
                or not role
                or not value
                or object_kind not in SEMANTIC_OBJECT_KINDS
            ):
                continue
            try:
                confidence = min(max(float(record.get("confidence", 0.72)), 0.0), 1.0)
                start_line = max(1, int(record.get("start_line", 1)))
                end_line = max(start_line, int(record.get("end_line", start_line)))
            except (TypeError, ValueError):
                continue
            bindings.append(
                OperandBinding(
                    binding_id=f"llm_semantic_{cache_key[:10]}_{index:05d}",
                    producer="llm",
                    artifact_id=artifact.artifact_id,
                    artifact_path=artifact.relative_path,
                    sink_api=str(attributes.get("sink_api", "")).strip(),
                    sink_subtype=subtype,
                    role=role,
                    value=value,
                    confidence=confidence,
                    span=Span(start_line, end_line),
                    object_kind=object_kind,
                    identity_key=str(descriptor.get("identity_key", "")).strip(),
                )
            )
        return bindings

    def _build_prompt(
        self,
        artifact: ArtifactRecord,
        existing_findings: list[SSOFinding] | None = None,
        include_operand_bindings: bool = True,
    ) -> str:
        return (
            "Analyze this artifact once. Extract new SSO findings and resolve operands for existing or new sensitive sinks.\n"
            f"Operand bindings enabled: {str(include_operand_bindings).lower()}. Return an empty operand_bindings array when disabled.\n"
            f"Operand parameter_role must be one of: {', '.join(OPERAND_ROLES)}.\n"
            f"Existing static findings: {self._existing_findings_json(existing_findings or [])}\n\n"
            f"Artifact path: {artifact.relative_path}\n"
            f"Artifact type: {artifact.artifact_type}\n"
            "Line-numbered content:\n"
            f"{self._line_numbered(artifact.content or '', start_line=artifact.source_start_line or 1)}"
        )

    def _build_batch_prompt(
        self,
        artifacts: list[ArtifactRecord],
        existing_findings: list[SSOFinding] | None = None,
        include_operand_bindings: bool = True,
    ) -> str:
        parts = [
            "Analyze these artifacts once. Extract new SSO findings and resolve operands for existing or new sensitive sinks.",
            f"Operand bindings enabled: {str(include_operand_bindings).lower()}. Return an empty operand_bindings array when disabled.",
            f"Existing static findings: {self._existing_findings_json(existing_findings or [])}",
            "",
        ]
        for artifact in artifacts:
            parts.extend(
                [
                    f"=== Artifact: {artifact.relative_path} ===",
                    f"Artifact type: {artifact.artifact_type}",
                    "Line-numbered content:",
                    self._line_numbered(
                        artifact.content or "",
                        start_line=artifact.source_start_line or 1,
                    ),
                    "",
                ]
            )
        return "\n".join(parts)

    def _existing_findings_json(self, findings: list[SSOFinding]) -> str:
        return json.dumps(
            [
                {
                    "finding_id": item.finding_id,
                    "artifact_path": item.artifact_path,
                    "subtype": item.subtype,
                    "matched_text": item.matched_text[:500],
                    "sink_api": item.attributes.get("sink_api", ""),
                }
                for item in findings
            ],
            separators=(",", ":"),
            ensure_ascii=True,
        )

    def _line_numbered(self, content: str, *, start_line: int = 1) -> str:
        return "\n".join(
            f"{index:06d}: {line}"
            for index, line in enumerate(content.splitlines(), start=start_line)
        )

    def _cache_path_for(
        self,
        artifact: ArtifactRecord,
        existing_findings: list[SSOFinding],
        include_operand_bindings: bool,
    ) -> Path:
        finding_digest = hashlib.sha256(
            self._existing_findings_json(existing_findings).encode("utf-8")
        ).hexdigest()
        digest = hashlib.sha256(
            (
                f"single:{artifact.relative_path}:{artifact.content_hash}:{SCHEMA_VERSION}:{SEMANTIC_PROMPT_VERSION}:"
                f"{llm_runtime.LLM_RUNTIME_PROTOCOL_VERSION}:"
                f"{self.runtime.backend}:{self.runtime.model}:{self.runtime.reasoning_effort}:{self.runtime.base_url}:"
                f"{include_operand_bindings}:{finding_digest}"
            ).encode("utf-8")
        ).hexdigest()
        return self.cache_dir / f"{digest}.json"

    def _cache_path_for_batch(
        self,
        artifacts: list[ArtifactRecord],
        existing_findings: list[SSOFinding],
        include_operand_bindings: bool,
    ) -> Path:
        digest_input = "|".join(
            f"{artifact.relative_path}:{artifact.content_hash}" for artifact in artifacts
        )
        finding_digest = hashlib.sha256(
            self._existing_findings_json(existing_findings).encode("utf-8")
        ).hexdigest()
        digest = hashlib.sha256(
            (
                f"batch:{digest_input}:{SCHEMA_VERSION}:{SEMANTIC_PROMPT_VERSION}:"
                f"{llm_runtime.LLM_RUNTIME_PROTOCOL_VERSION}:"
                f"{self.runtime.backend}:{self.runtime.model}:{self.runtime.reasoning_effort}:{self.runtime.base_url}:"
                f"{include_operand_bindings}:{finding_digest}"
            ).encode("utf-8")
        ).hexdigest()
        return self.cache_dir / f"{digest}.json"


def _finding_schema() -> dict[str, object]:
    return {
        "type": "object",
        "properties": {
            "records": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "type": {"type": "string", "enum": sorted(SSO_CATEGORIES)},
                        "subtype": {"type": "string", "enum": sorted(SSO_SUBTYPES)},
                        "confidence": {"type": "number"},
                        "start_line": {"type": "integer"},
                        "end_line": {"type": "integer"},
                        "attributes": {
                            "type": "object",
                            "properties": {
                                "matched_text": {"type": "string"},
                                "operation_class": {
                                    "type": "string",
                                    "enum": ["", "archive_extraction"],
                                },
                            },
                            "required": ["matched_text", "operation_class"],
                            "additionalProperties": False,
                        },
                    },
                    "required": ["type", "subtype", "confidence", "start_line", "end_line", "attributes"],
                    "additionalProperties": False,
                },
            }
        },
        "required": ["records"],
        "additionalProperties": False,
    }


def _batch_finding_schema() -> dict[str, object]:
    schema = _finding_schema()
    record_properties = schema["properties"]["records"]["items"]["properties"]
    record_required = schema["properties"]["records"]["items"]["required"]
    record_properties["artifact_path"] = {"type": "string"}
    record_required.insert(0, "artifact_path")
    return schema


def _semantic_schema(*, batch: bool) -> dict[str, object]:
    schema = _batch_finding_schema() if batch else _finding_schema()
    schema["properties"]["operand_bindings"] = {
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
                        "parameter_role": {"type": "string", "enum": list(OPERAND_ROLES)},
                    },
                    "required": ["sink_api", "sink_subtype", "parameter_role"],
                    "additionalProperties": False,
                },
                "object": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "kind": {"type": "string", "enum": list(SEMANTIC_OBJECT_KINDS)},
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
    schema["required"].append("operand_bindings")
    return schema
