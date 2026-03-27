from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .schema import canonical_evidence_type, normalize_evidence_record
from ..models import ArtifactRecord, EvidenceRecord, Span
from ..utils import ensure_dir


class SemgrepEvidenceExtractor:
    def __init__(self, rules_dir: str | Path | None = None) -> None:
        self.rules_dir = Path(rules_dir) if rules_dir else Path(__file__).resolve().parents[1] / "rules" / "semgrep"
        self.binary = shutil.which("pysemgrep") or shutil.which("semgrep")
        self._counter = 0

    def available(self) -> bool:
        return self.binary is not None and self.rules_dir.exists()

    def extract(self, skill_root: str | Path, artifacts: list[ArtifactRecord]) -> list[EvidenceRecord]:
        if not self.available():
            return []
        target_artifacts = [artifact for artifact in artifacts if artifact.is_text and artifact.content]
        if not target_artifacts:
            return []
        with tempfile.TemporaryDirectory(prefix="skillguard-semgrep-") as tmpdir:
            temp_root = Path(tmpdir)
            source_root = temp_root / "source"
            self._materialize_targets(source_root, target_artifacts)
            cmd = [
                str(self.binary),
                "scan",
                "--config",
                str(self.rules_dir),
                "--json",
                "--quiet",
                "--metrics=off",
                "--disable-version-check",
                "--no-git-ignore",
                "--scan-unknown-extensions",
                str(source_root),
            ]
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

        artifact_by_path = {artifact.relative_path: artifact for artifact in target_artifacts}
        evidence_facts: list[EvidenceRecord] = []
        for result in payload.get("results", []):
            artifact = self._resolve_artifact(result, source_root, artifact_by_path)
            if artifact is None:
                continue
            metadata = result.get("extra", {}).get("metadata", {})
            subtype = str(metadata.get("skillguard_subtype") or "").strip()
            if not subtype:
                continue
            evidence_type = str(metadata.get("skillguard_evidence_type") or canonical_evidence_type(subtype, "unknown"))
            start = result.get("start", {})
            end = result.get("end", {})
            start_line = int(start.get("line", 1) or 1)
            end_line = int(end.get("line", start_line) or start_line)
            snippet = self._extract_snippet(artifact, start_line, end_line)
            evidence_facts.append(
                normalize_evidence_record(
                    EvidenceRecord(
                        evidence_id=f"semgrep_{self._counter:05d}",
                        producer="semgrep",
                        artifact_id=artifact.artifact_id,
                        artifact_path=artifact.relative_path,
                        evidence_type=evidence_type,
                        subtype=subtype,
                        value="",
                        confidence=float(metadata.get("skillguard_confidence", 0.9)),
                        span=Span(start_line, end_line),
                        binding={},
                        attributes={
                            "engine": "semgrep",
                            "rule_id": result.get("check_id"),
                            "message": result.get("extra", {}).get("message", ""),
                            "matched_text": snippet,
                            "analysis_stage": "evidence_extraction",
                            "analysis_component": "semgrep_evidence",
                        },
                        provenance={
                            "artifact": {"id": artifact.artifact_id, "path": artifact.relative_path},
                            "span": {"start_line": start_line, "end_line": end_line},
                            "producer": "semgrep",
                            "analysis_stage": "evidence_extraction",
                            "analysis_component": "semgrep_evidence",
                        },
                    )
                )
            )
            self._counter += 1
        return evidence_facts

    def _materialize_targets(self, root: Path, artifacts: list[ArtifactRecord]) -> None:
        for artifact in artifacts:
            path = root / artifact.relative_path
            ensure_dir(path.parent)
            path.write_text(artifact.content or "", encoding="utf-8")

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
