from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..models import ArtifactRecord, EvidenceRecord, Span


class YasaAdapter:
    def __init__(self, yasa_root: str | Path | None = None) -> None:
        self.yasa_root = Path(yasa_root) if yasa_root else Path(__file__).resolve().parents[1] / "yasa"
        self.rules_dir = Path(__file__).resolve().parents[2] / "rules" / "yasa"
        self._counter = 0

    def available(self) -> bool:
        return shutil.which("node") is not None and self.yasa_root.exists() and (self.yasa_root / "dist" / "main.js").exists()

    def extract(self, skill_root: str | Path, artifacts: list[ArtifactRecord]) -> list[EvidenceRecord]:
        if not self.available():
            return []
        root = Path(skill_root).resolve()
        js_like = [artifact for artifact in artifacts if artifact.artifact_type == "javascript"]
        py_like = [artifact for artifact in artifacts if artifact.artifact_type == "python"]
        evidence: list[EvidenceRecord] = []
        if js_like:
            evidence.extend(
                self._run_yasa(
                    root,
                    artifacts,
                    language="javascript",
                    checker_id="taint_flow_js_input",
                    rule_config=self._rule_config_for("javascript"),
                )
            )
        if py_like and os.environ.get("SKILLGUARD_YASA_UAST_SDK"):
            evidence.extend(
                self._run_yasa(
                    root,
                    artifacts,
                    language="python",
                    checker_id="taint_flow_python_input",
                    rule_config=self._rule_config_for("python"),
                    uast_sdk=os.environ.get("SKILLGUARD_YASA_UAST_SDK"),
                )
            )
        return evidence

    def _run_yasa(
        self,
        root: Path,
        artifacts: list[ArtifactRecord],
        language: str,
        checker_id: str,
        rule_config: str,
        uast_sdk: str | None = None,
    ) -> list[EvidenceRecord]:
        with tempfile.TemporaryDirectory(prefix="skillguard-yasa-") as tmpdir:
            report_dir = Path(tmpdir) / "report"
            cmd = [
                "node",
                "dist/main.js",
                "--sourcePath",
                str(root),
                "--language",
                language,
                "--report",
                str(report_dir),
                "--checkerIds",
                checker_id,
                "--ruleConfigFile",
                rule_config,
            ]
            if uast_sdk:
                cmd.extend(["--uastSDKPath", uast_sdk])
            try:
                proc = subprocess.run(cmd, cwd=self.yasa_root, capture_output=True, text=True, check=False, timeout=90)
            except subprocess.TimeoutExpired:
                return []
            sarif = report_dir / "report.sarif"
            if proc.returncode != 0 or not sarif.exists():
                return []
            try:
                payload = json.loads(sarif.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return []

        artifact_map = {artifact.relative_path: artifact for artifact in artifacts}
        evidence: list[EvidenceRecord] = []
        for run in payload.get("runs", []):
            for result in run.get("results", []):
                artifact_path, start_line, end_line = self._extract_location(result, root)
                artifact = artifact_map.get(artifact_path)
                if artifact is None:
                    continue
                sink_info = result.get("sinkInfo", {}) if isinstance(result.get("sinkInfo", {}), dict) else {}
                flow_steps = self._extract_flow_steps(result, root)
                flow_kind = self._map_flow_kind(sink_info.get("sinkAttribute", ""), flow_steps)
                value = f"{flow_kind}:{sink_info.get('sinkRule', 'unknown')}"
                evidence.append(
                    EvidenceRecord(
                        evidence_id=f"yasa_{self._counter:05d}",
                        artifact_id=artifact.artifact_id,
                        artifact_path=artifact.relative_path,
                        evidence_type="flow_relation",
                        subtype="taint_flow",
                        value=value,
                        confidence=0.94,
                        span=Span(start_line, end_line),
                        attributes={
                            "engine": "yasa",
                            "rule_id": checker_id,
                            "language": language,
                            "sink_attribute": sink_info.get("sinkAttribute", ""),
                            "sink_rule": sink_info.get("sinkRule", ""),
                            "flow_kind": flow_kind,
                            "entrypoint_type": (result.get("entrypoint") or {}).get("type", ""),
                            "message": (result.get("message") or {}).get("text", ""),
                            "flow_steps": flow_steps,
                            "source_locator": flow_steps[0]["artifact_path"] if flow_steps else artifact.relative_path,
                        },
                    )
                )
                self._counter += 1
        return evidence

    def _rule_config_for(self, language: str) -> str:
        if language == "javascript":
            return "resource/example-rule-config/rule_config_js.json"
        candidate = self.rules_dir / f"{language}.json"
        if candidate.exists():
            return str(candidate.resolve())
        fallback = {
            "python": "resource/example-rule-config/rule_config_python.json",
        }
        return fallback[language]

    def _extract_location(self, result: dict[str, object], root: Path) -> tuple[str, int, int]:
        physical = self._pick_physical_location(result)
        artifact_path = self._resolve_artifact_path(physical, root)
        region = physical.get("region", {}) if isinstance(physical, dict) else {}
        start = int(region.get("startLine", 1) or 1)
        end = int(region.get("endLine", start) or start)
        return artifact_path, start, end

    def _pick_physical_location(self, result: dict[str, object]) -> dict[str, object]:
        locations = result.get("locations", [])
        if isinstance(locations, list) and locations:
            first = locations[0]
            if isinstance(first, dict):
                return first.get("physicalLocation", {})
        flow_steps = self._extract_flow_locations(result)
        if flow_steps:
            return flow_steps[-1]
        return {}

    def _extract_flow_steps(self, result: dict[str, object], root: Path) -> list[dict[str, object]]:
        steps: list[dict[str, object]] = []
        for physical in self._extract_flow_locations(result):
            artifact_path = self._resolve_artifact_path(physical, root)
            region = physical.get("region", {}) if isinstance(physical, dict) else {}
            snippet = region.get("snippet", {}) if isinstance(region.get("snippet", {}), dict) else {}
            text = snippet.get("text", "")
            affected = snippet.get("affectedNodeName", "")
            steps.append(
                {
                    "artifact_path": artifact_path,
                    "start_line": int(region.get("startLine", 1) or 1),
                    "end_line": int(region.get("endLine", region.get("startLine", 1) or 1) or 1),
                    "affected_node": affected,
                    "snippet": text,
                }
            )
        return steps

    def _extract_flow_locations(self, result: dict[str, object]) -> list[dict[str, object]]:
        physical_locations: list[dict[str, object]] = []
        code_flows = result.get("codeFlows", [])
        if not isinstance(code_flows, list):
            return physical_locations
        for code_flow in code_flows:
            if not isinstance(code_flow, dict):
                continue
            for thread_flow in code_flow.get("threadFlows", []):
                if not isinstance(thread_flow, dict):
                    continue
                for location in thread_flow.get("locations", []):
                    if not isinstance(location, dict):
                        continue
                    physical = (location.get("location") or {}).get("physicalLocation", {})
                    if isinstance(physical, dict):
                        physical_locations.append(physical)
        return physical_locations

    def _resolve_artifact_path(self, physical: dict[str, object], root: Path) -> str:
        artifact_location = physical.get("artifactLocation", {}) if isinstance(physical, dict) else {}
        uri = artifact_location.get("uri", "") if isinstance(artifact_location, dict) else ""
        if not isinstance(uri, str) or not uri:
            return ""
        if uri.startswith("file://"):
            candidate = Path(uri[len("file://") :])
            if candidate.exists():
                resolved = candidate.resolve()
            else:
                resolved = (root / candidate.as_posix().lstrip("/")).resolve()
        else:
            candidate = Path(uri)
            resolved = candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()
        try:
            return str(resolved.relative_to(root))
        except ValueError:
            return candidate.as_posix().lstrip("/")

    def _map_flow_kind(self, sink_attribute: str, flow_steps: list[dict[str, object]]) -> str:
        mapping = {
            "NodejsSSRF": "env_to_network",
            "PythonSSRF": "env_to_network",
            "NodejsCommandInjection": "env_to_exec",
            "PythonCommandInjection": "env_to_exec",
            "NodejsExec": "env_to_exec",
            "PythonCommandExec": "env_to_exec",
            "NodejsPathTraversal": "input_to_file",
            "PythonPathTraversal": "input_to_file",
        }
        flow_kind = mapping.get(sink_attribute)
        if flow_kind:
            return flow_kind
        if not flow_steps:
            return "taint_flow"
        first = flow_steps[0]
        last = flow_steps[-1]
        source_text = f"{first.get('affected_node', '')} {first.get('snippet', '')}".lower()
        sink_text = f"{last.get('affected_node', '')} {last.get('snippet', '')}".lower()
        if "process.env" in source_text or "os.environ" in source_text:
            if any(token in sink_text for token in ["fetch", "axios", "request", "http", "https"]):
                return "env_to_network"
            if any(token in sink_text for token in ["exec", "spawn", "system", "subprocess"]):
                return "env_to_exec"
        return "taint_flow"
