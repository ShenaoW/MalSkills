from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..models import ArtifactRecord, EvidenceRecord, Span
from ..taxonomy import command_class, env_class, path_class, url_class


class SemgrepAdapter:
    def __init__(self, rules_dir: str | Path | None = None) -> None:
        self.rules_dir = Path(rules_dir) if rules_dir else Path(__file__).resolve().parents[2] / "rules" / "semgrep"
        self._counter = 0
        self.binary = shutil.which("pysemgrep") or shutil.which("semgrep")

    def available(self) -> bool:
        return self.binary is not None and self.rules_dir.exists()

    def extract(self, skill_root: str | Path, artifacts: list[ArtifactRecord]) -> list[EvidenceRecord]:
        if not self.available():
            return []
        target_artifacts = [artifact for artifact in artifacts if artifact.is_text and artifact.content]
        if not target_artifacts:
            return []
        cmd = [
            str(self.binary),
            "scan",
            "--config",
            str(self.rules_dir),
            "--json",
            "--quiet",
            "--metrics=off",
            "--disable-version-check",
            "--scan-unknown-extensions",
            str(Path(skill_root).resolve()),
        ]
        with tempfile.TemporaryDirectory(prefix="skillguard-semgrep-") as tmpdir:
            temp_root = Path(tmpdir)
            env = os.environ.copy()
            env["XDG_CONFIG_HOME"] = str(temp_root / ".config")
            env["SEMGREP_USER_HOME"] = str(temp_root / ".semgrep")
            env["SEMGREP_SETTINGS_FILE"] = str(temp_root / ".semgrep" / "settings.yml")
            env["SEMGREP_VERSION_CACHE_PATH"] = str(temp_root / ".semgrep" / "version-cache.txt")
            (temp_root / ".config").mkdir(parents=True, exist_ok=True)
            (temp_root / ".semgrep").mkdir(parents=True, exist_ok=True)
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False, env=env)
        if proc.returncode not in {0, 1}:
            return []
        try:
            payload = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            return []

        root = Path(skill_root).resolve()
        artifact_by_path = {artifact.relative_path: artifact for artifact in target_artifacts}
        evidence: list[EvidenceRecord] = []
        for result in payload.get("results", []):
            artifact = self._resolve_artifact(result, root, artifact_by_path)
            if artifact is None:
                continue
            metadata = result.get("extra", {}).get("metadata", {})
            evidence_type = metadata.get("skillguard_evidence_type")
            subtype = metadata.get("skillguard_subtype")
            if not evidence_type or not subtype:
                continue
            start = result.get("start", {})
            end = result.get("end", {})
            start_line = int(start.get("line", 1) or 1)
            end_line = int(end.get("line", start_line) or start_line)
            snippet = self._extract_snippet(artifact, start_line, end_line)
            value = self._extract_value(result, metadata, artifact, snippet)
            attrs = {
                "engine": "semgrep",
                "rule_id": result.get("check_id"),
                "message": result.get("extra", {}).get("message", ""),
                "matched_text": snippet,
            }
            attrs.update(self._infer_attrs(subtype, value, snippet, metadata))
            evidence.append(
                EvidenceRecord(
                    evidence_id=f"semgrep_{self._counter:05d}",
                    artifact_id=artifact.artifact_id,
                    artifact_path=artifact.relative_path,
                    evidence_type=str(evidence_type),
                    subtype=str(subtype),
                    value=value,
                    confidence=float(metadata.get("skillguard_confidence", 0.9)),
                    span=Span(start_line, end_line),
                    attributes=attrs,
                )
            )
            self._counter += 1
        return evidence

    def _resolve_artifact(
        self,
        result: dict[str, object],
        root: Path,
        artifact_by_path: dict[str, ArtifactRecord],
    ) -> ArtifactRecord | None:
        path = Path(str(result.get("path", "")))
        try:
            rel = str(path.resolve().relative_to(root))
        except Exception:
            rel = str(path).replace(str(root) + "/", "").lstrip("./")
        return artifact_by_path.get(rel)

    def _extract_snippet(self, artifact: ArtifactRecord, start_line: int, end_line: int) -> str:
        if not artifact.content:
            return ""
        lines = artifact.content.splitlines()
        start_index = max(start_line - 1, 0)
        end_index = max(end_line, start_line)
        return "\n".join(lines[start_index:end_index]).strip()

    def _extract_value(
        self,
        result: dict[str, object],
        metadata: dict[str, object],
        artifact: ArtifactRecord,
        snippet: str,
    ) -> str:
        value_metavar = metadata.get("skillguard_value_metavar")
        metavars = result.get("extra", {}).get("metavars", {})
        if isinstance(value_metavar, str) and isinstance(metavars, dict) and value_metavar in metavars:
            abstract = metavars[value_metavar].get("abstract_content") or metavars[value_metavar].get("content")
            if isinstance(abstract, str) and abstract.strip():
                return self._clean_value(abstract)
        subtype = str(metadata.get("skillguard_subtype", ""))
        if subtype == "config_value":
            _, raw_value = self._parse_key_value(snippet)
            if raw_value:
                return raw_value
        if subtype in {"network_send", "network_fetch", "installer_download", "url_literal"}:
            token = self._extract_url(snippet)
            if token:
                return token
        if subtype == "env_read":
            token = self._extract_env_name(snippet)
            if token:
                return token
        if subtype in {"file_read", "list_dir", "shell_exec", "dynamic_load", "config_ref"}:
            token = self._extract_argument(snippet)
            if token:
                return token
        if subtype in {"secret_request", "setup_instruction", "hidden_instruction", "declared_action", "declared_capability", "obfuscated_exec"}:
            return snippet or str(result.get("check_id", "TEXT"))
        return snippet or str(result.get("check_id", "DYNAMIC"))

    def _infer_attrs(self, subtype: str, value: str, snippet: str, metadata: dict[str, object]) -> dict[str, object]:
        attrs: dict[str, object] = {}
        if subtype == "env_read":
            attrs["env_class"] = env_class(value)
        elif subtype in {"file_read", "list_dir"}:
            attrs["path_class"] = path_class(value)
        elif subtype in {"network_send", "network_fetch", "installer_download", "url_literal"}:
            attrs["dst_class"] = url_class(value)
            if subtype == "installer_download":
                attrs["download_kind"] = metadata.get("skillguard_download_kind", self._classify_download_kind(value))
        elif subtype == "shell_exec":
            attrs["command_class"] = command_class(value)
        elif subtype == "obfuscated_exec":
            attrs["command_class"] = "high_risk"
        elif subtype == "dynamic_load":
            attrs["module_source"] = value
        elif subtype == "config_value":
            key, raw_value = self._parse_key_value(snippet)
            if key:
                attrs["key"] = key
            if raw_value:
                attrs["path_class"] = path_class(raw_value)
                attrs["dst_class"] = url_class(raw_value)
        elif subtype == "config_ref":
            attrs["key"] = value.split(".")[-1].strip("'\"`")
        return attrs

    def _parse_key_value(self, snippet: str) -> tuple[str, str]:
        text = snippet.strip().rstrip(",")
        if not text:
            return "", ""
        separators = [":", "="]
        for separator in separators:
            if separator not in text:
                continue
            left, right = text.split(separator, 1)
            key = left.strip().strip("{}[](),'\"` ")
            value = right.strip().strip("{}[](),'\"` ")
            return key, value
        return "", self._clean_value(text)

    def _extract_url(self, snippet: str) -> str | None:
        for token in snippet.replace("(", " ").replace(")", " ").replace(",", " ").split():
            candidate = token.strip("'\"`")
            if candidate.startswith("http://") or candidate.startswith("https://"):
                return candidate
        return None

    def _extract_env_name(self, snippet: str) -> str | None:
        if "process.env." in snippet:
            tail = snippet.split("process.env.", 1)[1]
            token = tail.split()[0].strip(" ;,)'\"`")
            if token:
                return token
        if "os.getenv(" in snippet:
            inner = snippet.split("os.getenv(", 1)[1].split(")", 1)[0]
            token = self._clean_value(inner)
            if token:
                return token
        if "os.environ[" in snippet:
            inner = snippet.split("os.environ[", 1)[1].split("]", 1)[0]
            token = self._clean_value(inner)
            if token:
                return token
        tokens = snippet.replace("[", " ").replace("]", " ").replace("(", " ").replace(")", " ").replace(",", " ").split()
        for token in tokens:
            candidate = token.strip("'\"`")
            if candidate.isupper() and "_" in candidate:
                return candidate
        return None

    def _extract_argument(self, snippet: str) -> str | None:
        if "(" in snippet and ")" in snippet:
            inner = snippet.split("(", 1)[1].rsplit(")", 1)[0]
            candidate = inner.split(",", 1)[0].strip()
            return self._clean_value(candidate)
        return self._clean_value(snippet)

    def _clean_value(self, value: str) -> str:
        cleaned = value.strip()
        if cleaned.startswith(("'", '"', "`")) and cleaned.endswith(("'", '"', "`")) and len(cleaned) >= 2:
            cleaned = cleaned[1:-1]
        return cleaned.strip()

    def _classify_download_kind(self, value: str) -> str:
        lowered = value.lower()
        if any(token in lowered for token in [".exe", ".msi", ".app"]):
            return "executable"
        if any(token in lowered for token in [".zip", ".tar", ".tgz", ".pkg", ".dmg"]):
            return "archive"
        if any(token in lowered for token in [".sh", "raw.githubusercontent", "pastebin", "glot.io"]):
            return "script"
        return "installer"
