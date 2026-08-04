from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .schema import canonical_sso_category, normalize_sso_finding
from ..models import ArtifactRecord, SSOFinding, Span
from ..utils import ensure_dir


def semgrep_timeout_sec() -> float:
    try:
        configured = float(os.environ.get("MALSKILLS_SEMGREP_TIMEOUT_SEC", "120"))
    except ValueError:
        configured = 120.0
    return min(max(configured, 1.0), 600.0)


class SemgrepSSOFindingExtractor:
    def __init__(
        self,
        rules_dir: str | Path | None = None,
        *,
        additional_rules_dirs: list[str | Path] | None = None,
    ) -> None:
        self.rules_dir = Path(rules_dir) if rules_dir else Path(__file__).resolve().parents[1] / "rules" / "semgrep"
        self.additional_rules_dirs = [Path(item) for item in (additional_rules_dirs or [])]
        self.binary = self._resolve_binary()
        self._counter = 0
        self.last_run: dict[str, object] = {"status": "not_run"}

    def available(self) -> bool:
        return self.binary is not None and any(path.exists() for path in self._rules_dirs())

    def _resolve_binary(self) -> str | None:
        binary = shutil.which("pysemgrep") or shutil.which("semgrep")
        if binary:
            return binary
        script_dirs = [Path(sys.executable).parent, Path(sys.prefix) / "bin"]
        for script_dir in script_dirs:
            for name in ("pysemgrep", "semgrep"):
                candidate = script_dir / name
                if candidate.is_file():
                    return str(candidate)
        return None

    def extract(
        self,
        skill_root: str | Path,
        artifacts: list[ArtifactRecord],
        *,
        additional_rules_dirs: list[str | Path] | None = None,
        ruleset_digest: str = "none",
    ) -> list[SSOFinding]:
        if not self.available():
            self.last_run = {"status": "unavailable", "ruleset_digest": ruleset_digest}
            return []
        target_artifacts = [artifact for artifact in artifacts if artifact.is_text and artifact.content]
        if not target_artifacts:
            self.last_run = {"status": "no_targets", "ruleset_digest": ruleset_digest}
            return []
        with tempfile.TemporaryDirectory(prefix="malskills-semgrep-") as tmpdir:
            temp_root = Path(tmpdir)
            source_root = temp_root / "source"
            self._materialize_targets(source_root, target_artifacts)
            cmd = [
                str(self.binary),
                "scan",
                "--json",
                "--quiet",
                "--metrics=off",
                "--disable-version-check",
                "--no-git-ignore",
                "--scan-unknown-extensions",
            ]
            rule_dirs = self._rules_dirs(additional_rules_dirs)
            for rule_dir in rule_dirs:
                cmd.extend(["--config", str(rule_dir)])
            cmd.append(str(source_root))
            env = os.environ.copy()
            env["XDG_CONFIG_HOME"] = str(temp_root / ".config")
            env["SEMGREP_USER_HOME"] = str(temp_root / ".semgrep")
            env["SEMGREP_SETTINGS_FILE"] = str(temp_root / ".semgrep" / "settings.yml")
            env["SEMGREP_VERSION_CACHE_PATH"] = str(temp_root / ".semgrep" / "version-cache.txt")
            (temp_root / ".config").mkdir(parents=True, exist_ok=True)
            (temp_root / ".semgrep").mkdir(parents=True, exist_ok=True)
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=False,
                    env=env,
                    timeout=semgrep_timeout_sec(),
                )
            except subprocess.TimeoutExpired:
                self.last_run = {
                    "status": "timeout",
                    "timeout_sec": semgrep_timeout_sec(),
                    "ruleset_digest": ruleset_digest,
                }
                return []
        if proc.returncode not in {0, 1}:
            self.last_run = {
                "status": "error",
                "returncode": proc.returncode,
                "stderr": proc.stderr[-4000:],
                "ruleset_digest": ruleset_digest,
            }
            return []
        try:
            payload = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            self.last_run = {
                "status": "invalid_output",
                "ruleset_digest": ruleset_digest,
            }
            return []

        artifact_by_path = {artifact.relative_path: artifact for artifact in target_artifacts}
        findings: list[SSOFinding] = []
        for result in payload.get("results", []):
            artifact = self._resolve_artifact(result, source_root, artifact_by_path)
            if artifact is None:
                continue
            metadata = result.get("extra", {}).get("metadata", {})
            subtype = str(metadata.get("malskills_subtype") or "").strip()
            if not subtype:
                continue
            category = str(metadata.get("malskills_sso_category") or canonical_sso_category(subtype, "unknown"))
            start = result.get("start", {})
            end = result.get("end", {})
            start_line = int(start.get("line", 1) or 1)
            end_line = int(end.get("line", start_line) or start_line)
            snippet = self._extract_snippet(artifact, start_line, end_line)
            findings.append(
                normalize_sso_finding(
                    SSOFinding(
                        finding_id=f"semgrep_{self._counter:05d}",
                        producer="semgrep",
                        artifact_id=artifact.artifact_id,
                        artifact_path=artifact.relative_path,
                        category=category,
                        subtype=subtype,
                        matched_text=snippet,
                        confidence=None,
                        span=Span(start_line, end_line),
                        attributes={
                            "engine": "semgrep",
                            "rule_id": result.get("check_id"),
                            "message": result.get("extra", {}).get("message", ""),
                            "analysis_stage": "sso_extraction",
                            "analysis_component": "semgrep_finding",
                            "rule_origin": metadata.get("malskills_origin", "offline"),
                            "ruleset_digest": ruleset_digest,
                        },
                        provenance={
                            "artifact": {"id": artifact.artifact_id, "path": artifact.relative_path},
                            "span": {"start_line": start_line, "end_line": end_line},
                            "producer": "semgrep",
                            "analysis_stage": "sso_extraction",
                            "analysis_component": "semgrep_finding",
                        },
                    )
                )
            )
            self._counter += 1
        self.last_run = {
            "status": "ok",
            "match_count": len(findings),
            "ruleset_digest": ruleset_digest,
        }
        return findings

    def _rules_dirs(self, additional: list[str | Path] | None = None) -> list[Path]:
        values = [self.rules_dir, *self.additional_rules_dirs, *(Path(item) for item in (additional or []))]
        seen: set[Path] = set()
        result: list[Path] = []
        for value in values:
            resolved = value.resolve()
            if resolved in seen or not resolved.exists():
                continue
            seen.add(resolved)
            result.append(resolved)
        return result

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
