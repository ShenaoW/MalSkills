from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import error, request

from ..models import ArtifactRecord, EvidenceRecord, Span, to_jsonable
from ..taxonomy import HIDDEN_INTENT_TOKENS, SAFE_INTENT_TOKENS, SECRET_REQUEST_TOKENS
from ..utils import ensure_dir, iter_code_fences, load_env_file


SCHEMA_VERSION = "intent-v4"
ALLOWED_SUBTYPES = {"hidden_instruction", "setup_instruction", "secret_request", "declared_capability", "declared_action"}


@dataclass
class IntentExtractionResult:
    evidence: list[EvidenceRecord]


class StructuredIntentExtractor:
    def __init__(self, cache_dir: str | Path | None = None) -> None:
        load_env_file(Path(__file__).resolve().parents[2])
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self._counter = 0
        configured_backend = (os.environ.get("SKILLGUARD_LLM_MODE") or "").strip().lower()
        self.base_url = (
            os.environ.get("SKILLGUARD_LLM_BASE_URL")
            or os.environ.get("OPENAI_BASE_URL")
            or os.environ.get("PACKY_API_URL")
            or ""
        ).strip()
        self.api_key = (
            os.environ.get("SKILLGUARD_LLM_API_KEY")
            or os.environ.get("OPENAI_API_KEY")
            or os.environ.get("PACKY_API_KEY")
            or ""
        ).strip()
        self.backend = configured_backend or ("api" if self.base_url and self.api_key else "heuristic")
        self.model_name = (
            os.environ.get("SKILLGUARD_LLM_MODEL")
            or os.environ.get("OPENAI_MODEL")
            or os.environ.get("LLM_MODEL")
            or "gpt-5.3-codex-medium"
        )
        if self.cache_dir:
            ensure_dir(self.cache_dir)

    def extract(self, artifacts: list[ArtifactRecord]) -> IntentExtractionResult:
        evidence: list[EvidenceRecord] = []
        for artifact in artifacts:
            if artifact.artifact_type not in {"markdown", "prompt", "text"} or not artifact.content:
                continue
            records = self._load_or_extract_records(artifact)
            evidence.extend(self._records_to_evidence(artifact, records))
        return IntentExtractionResult(evidence=evidence)

    def _load_or_extract_records(self, artifact: ArtifactRecord) -> list[dict[str, Any]]:
        cache_file = self._cache_file(artifact)
        if cache_file and cache_file.exists():
            try:
                payload = json.loads(cache_file.read_text(encoding="utf-8"))
                if payload.get("schema_version") == SCHEMA_VERSION and payload.get("backend") == self.backend:
                    return self._validate_records(payload.get("records", []))
            except (OSError, json.JSONDecodeError, TypeError, ValueError):
                pass
        records = self._extract_records(artifact)
        if cache_file:
            cache_file.write_text(
                json.dumps(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "backend": self.backend,
                        "model": self.model_name if self.backend == "api" else "deterministic-heuristic",
                        "artifact_path": artifact.relative_path,
                        "artifact_hash": artifact.content_hash,
                        "records": to_jsonable(records),
                    },
                    indent=2,
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
        return records

    def _cache_file(self, artifact: ArtifactRecord) -> Path | None:
        if not self.cache_dir:
            return None
        digest = hashlib.sha256(f"{artifact.content_hash}:{self.backend}:{SCHEMA_VERSION}".encode("utf-8")).hexdigest()
        return self.cache_dir / f"{digest}.json"

    def _extract_records(self, artifact: ArtifactRecord) -> list[dict[str, Any]]:
        if self.backend == "api":
            records = self._extract_via_api(artifact)
            if records:
                return records
        return self._extract_heuristic(artifact)

    def _extract_via_api(self, artifact: ArtifactRecord) -> list[dict[str, Any]]:
        if not self.base_url or not self.api_key:
            return []
        prompt = self._build_prompt(artifact)
        payload = {
            "model": self.model_name,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "Extract structured intent evidence only. Return JSON with key 'records'. "
                        "Each record must contain subtype, value, confidence, start_line, end_line, and attributes. "
                        "Allowed subtypes: hidden_instruction, setup_instruction, secret_request, declared_capability, declared_action."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
        }
        endpoint = self.base_url.rstrip("/") + "/chat/completions"
        http_request = request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with request.urlopen(http_request, timeout=30) as response:
                body = json.loads(response.read().decode("utf-8"))
        except (error.URLError, error.HTTPError, TimeoutError, json.JSONDecodeError):
            return []
        try:
            content = body["choices"][0]["message"]["content"]
            parsed = json.loads(content)
        except (KeyError, IndexError, TypeError, json.JSONDecodeError):
            return []
        return self._validate_records(parsed.get("records", []))

    def _build_prompt(self, artifact: ArtifactRecord) -> str:
        return (
            f"Artifact path: {artifact.relative_path}\n"
            "Return JSON only with key 'records'. Extract structured intent evidence for hidden instructions, setup instructions, secret requests, declared actions, and declared capabilities.\n"
            "Each record must preserve an exact text span from the artifact. Do not emit security verdicts.\n"
            "When a line or fenced block requests credentials, environment variables, tokens, private keys, wallets, or seed phrases, emit secret_request.\n"
            "When a line or fenced block requires running commands, bootstrap scripts, MCP setup, downloader steps, or mandatory preflight, emit setup_instruction or hidden_instruction.\n"
            "When a line declares what the skill claims to do, emit declared_action or declared_capability with implied_capabilities.\n\n"
            f"Content:\n{artifact.content}"
        )

    def _extract_heuristic(self, artifact: ArtifactRecord) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        seen: set[tuple[str, int, str]] = set()
        lines = artifact.content.splitlines() if artifact.content else []
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            lowered = stripped.lower()
            if not lowered:
                continue
            if any(token in lowered for token in HIDDEN_INTENT_TOKENS):
                records.append(
                    self._record(
                        "hidden_instruction",
                        stripped,
                        0.86,
                        idx,
                        idx,
                        implied_capabilities=self._infer_implied_capabilities(lowered),
                        consistency_target="skill",
                    )
                )
            elif self._looks_setup_instruction(lowered):
                records.append(
                    self._record(
                        "setup_instruction",
                        stripped,
                        0.81,
                        idx,
                        idx,
                        implied_capabilities=self._infer_implied_capabilities(lowered),
                        consistency_target="skill",
                    )
                )
            if self._looks_secret_request(lowered):
                records.append(
                    self._record(
                        "secret_request",
                        stripped,
                        0.84,
                        idx,
                        idx,
                        implied_capabilities=["REQUEST_SECRET"],
                        secret_class=self._infer_secret_class(lowered),
                    )
                )
            declared = self._infer_declared_capabilities(lowered)
            if declared:
                records.append(
                    self._record(
                        "declared_action",
                        stripped,
                        0.68,
                        idx,
                        idx,
                        implied_capabilities=declared,
                        consistency_target="skill",
                    )
                )
            if re.search(r"\bread\b.+(~/.ssh|/etc/passwd|\.env)", lowered):
                records.append(
                    self._record(
                        "declared_capability",
                        stripped,
                        0.8,
                        idx,
                        idx,
                        implied_capabilities=["READ_FILE"],
                    )
                )
        for language, body, start_line, end_line in iter_code_fences(artifact.content or ""):
            records.extend(self._extract_from_code_fence(language, body, start_line, end_line))
        validated = []
        for record in self._validate_records(records):
            key = (record["subtype"], int(record["start_line"]), record["value"])
            if key in seen:
                continue
            seen.add(key)
            validated.append(record)
        return validated

    def _extract_from_code_fence(self, language: str, body: str, start_line: int, end_line: int) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        lowered = body.lower()
        if language in {"env", "bash", "sh", "shell", "zsh", ""}:
            if any(token in lowered for token in ["private_key", "mnemonic", "seed", "api_secret", "token="]):
                records.append(
                    self._record(
                        "secret_request",
                        body.strip(),
                        0.83,
                        start_line,
                        end_line,
                        implied_capabilities=["REQUEST_SECRET"],
                        secret_class=self._infer_secret_class(lowered),
                    )
                )
            if any(token in lowered for token in ["curl", "wget", "bash", "powershell", "chmod +x"]):
                records.append(
                    self._record(
                        "setup_instruction",
                        body.strip(),
                        0.78,
                        start_line,
                        end_line,
                        implied_capabilities=["NETWORK_FETCH", "SHELL_EXEC"],
                        consistency_target="skill",
                    )
                )
        return records

    def _validate_records(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        validated: list[dict[str, Any]] = []
        for record in records:
            if not isinstance(record, dict):
                continue
            subtype = str(record.get("subtype", "")).strip()
            value = str(record.get("value", "")).strip()
            if subtype not in ALLOWED_SUBTYPES or not value:
                continue
            try:
                confidence = float(record.get("confidence", 0.5))
                start_line = int(record.get("start_line", 1))
                end_line = int(record.get("end_line", start_line))
            except (TypeError, ValueError):
                continue
            attributes = record.get("attributes", {})
            if not isinstance(attributes, dict):
                attributes = {}
            validated.append(
                {
                    "subtype": subtype,
                    "value": value,
                    "confidence": min(max(confidence, 0.0), 1.0),
                    "start_line": max(start_line, 1),
                    "end_line": max(end_line, start_line),
                    "attributes": attributes,
                }
            )
        return validated

    def _record(
        self,
        subtype: str,
        value: str,
        confidence: float,
        start_line: int,
        end_line: int,
        **attributes: object,
    ) -> dict[str, Any]:
        return {
            "subtype": subtype,
            "value": value,
            "confidence": confidence,
            "start_line": start_line,
            "end_line": end_line,
            "attributes": attributes,
        }

    def _looks_setup_instruction(self, lowered: str) -> bool:
        return any(
            token in lowered
            for token in [
                "download",
                "paste it into terminal",
                "copy the installation script",
                "run the executable",
                "without ",
                "will not work",
                "extract using pass",
                "password:",
                "before proceeding",
                "before setting up",
            ]
        )

    def _looks_secret_request(self, lowered: str) -> bool:
        return any(token in lowered for token in SECRET_REQUEST_TOKENS) or any(
            token in lowered for token in ["private_key", "api_secret", "mnemonic", "seed phrase", "wallet", ".env"]
        )

    def _infer_secret_class(self, lowered: str) -> str:
        if any(token in lowered for token in ["private key", "private_key", "wallet", "mnemonic", "seed"]):
            return "wallet_or_private_key"
        if any(token in lowered for token in ["api key", "api_key", "api secret", "api_secret", "token"]):
            return "api_credential"
        return "generic_secret"

    def _infer_declared_capabilities(self, lowered: str) -> list[str]:
        implied: list[str] = []
        if any(token in lowered for token in SAFE_INTENT_TOKENS):
            implied.append("LOW_RISK_HELPER")
        if "portfolio" in lowered or "wallet" in lowered:
            implied.append("BLOCKCHAIN_ASSISTANCE")
        if any(token in lowered for token in ["update", "auto-update", "cron job", "cron add"]):
            implied.append("SYSTEM_AUTOMATION")
        if any(token in lowered for token in ["install", "setup", "bootstrap"]):
            implied.append("SETUP_WORKFLOW")
        return implied

    def _infer_implied_capabilities(self, lowered: str) -> list[str]:
        implied: list[str] = []
        if any(token in lowered for token in ["download", "http://", "https://", "glot.io", "pastebin", "githubusercontent"]):
            implied.append("NETWORK_FETCH")
        if any(token in lowered for token in ["run", "terminal", "bash", "powershell", ".exe", "script"]):
            implied.append("SHELL_EXEC")
        if any(token in lowered for token in ["password", "private key", "mnemonic", "token", ".env"]):
            implied.append("REQUEST_SECRET")
        if any(token in lowered for token in ["update", "cron", "schedule"]):
            implied.append("TOOL_INVOKE")
        return implied or ["LOW_RISK_HELPER"]

    def _records_to_evidence(self, artifact: ArtifactRecord, records: list[dict[str, Any]]) -> list[EvidenceRecord]:
        evidence: list[EvidenceRecord] = []
        for record in records:
            evidence_id = f"intent_{self._counter:05d}"
            self._counter += 1
            attrs = {"schema_version": SCHEMA_VERSION, "backend": self.backend, **record.get("attributes", {})}
            evidence.append(
                EvidenceRecord(
                    evidence_id=evidence_id,
                    artifact_id=artifact.artifact_id,
                    artifact_path=artifact.relative_path,
                    evidence_type="intent_object",
                    subtype=record["subtype"],
                    value=record["value"],
                    confidence=float(record["confidence"]),
                    span=Span(record["start_line"], record["end_line"]),
                    attributes=attrs,
                )
            )
        return evidence


def build_intent_extractor() -> StructuredIntentExtractor:
    cache_dir = os.environ.get("SKILLGUARD_LLM_CACHE", ".skillguard_cache/intent")
    return StructuredIntentExtractor(cache_dir)
