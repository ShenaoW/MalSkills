from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from ..utils import ensure_dir
from .external_tools import (
    SKILL_SCANNER_TIMEOUT_SEC,
    _finalize_baseline_result,
    _load_json_file,
    _resolve_tool_python,
    _run_baseline_command,
    _run_json_baseline_command,
)


LLM_BASELINE_TIMEOUT_SEC = 900
AGENTGUARD_FALLBACK_VERSION = "1.1.29-beta.0"


def run_snyk_agent_scan_baseline(skill_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    skill_root = Path(skill_path).resolve()
    destination = Path(output_dir)
    ensure_dir(destination)

    source_root = _baseline_root() / "agent-scan"
    command = [
        _resolve_tool_python(source_root),
        "-m",
        "agent_scan.cli",
        "scan",
        "--json",
        "--storage-file",
        str(destination / "snyk_state.json"),
        str(skill_root),
    ]
    payload = _run_json_baseline_command(
        command,
        env_overrides={"PYTHONPATH": str(source_root / "src")},
        timeout_sec=SKILL_SCANNER_TIMEOUT_SEC,
    )
    normalized = _normalize_snyk_payload(payload)
    if not normalized["scan_results"]:
        raise RuntimeError("Snyk Agent Scan returned no scan results")
    if normalized["errors"] and not normalized["issues"] and not normalized["usable_results"]:
        raise RuntimeError(f"Snyk Agent Scan failed: {normalized['errors'][0]}")

    predicted, score = _prediction_from_severities(normalized["severities"])
    patterns = sorted(
        {
            str(item.get("code", "")).strip()
            for item in normalized["issues"]
            if str(item.get("code", "")).strip()
        }
    )
    return _finalize_baseline_result(
        destination=destination,
        artifact_name="snyk_agent_scan_report.json",
        manifest_key="snyk_agent_scan_report",
        payload=normalized,
        runtime={"tool": "snyk-agent-scan", "command": command},
        predicted=predicted,
        score=score,
        patterns=patterns,
    )


def run_ai_infra_guard_baseline(skill_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    skill_root = Path(skill_path).resolve()
    destination = Path(output_dir)
    ensure_dir(destination)

    source_root = _baseline_root() / "AI-Infra-Guard" / "skill-scan"
    raw_report = destination / "ai_infra_guard_raw.sarif.json"
    command = [
        _resolve_tool_python(source_root),
        "-m",
        "skill_scan",
        "--repo",
        str(skill_root),
        "--language",
        "en",
        "--output",
        str(raw_report),
    ]
    completed = _run_baseline_command(
        command,
        env_overrides={"PYTHONPATH": str(source_root)},
        timeout_sec=LLM_BASELINE_TIMEOUT_SEC,
    )
    if not raw_report.exists():
        if completed.returncode != 0:
            raise subprocess.CalledProcessError(
                completed.returncode,
                command,
                output=completed.stdout,
                stderr=completed.stderr,
            )
        raise FileNotFoundError(f"AI-Infra-Guard report not found: {raw_report}")

    normalized = _normalize_sarif_payload(_load_json_file(raw_report))
    predicted, score = _prediction_from_severities(normalized["severities"])
    return _finalize_baseline_result(
        destination=destination,
        artifact_name="ai_infra_guard_report.json",
        manifest_key="ai_infra_guard_report",
        payload=normalized,
        runtime={
            "tool": "aig-skill-scan",
            "attribution": "Tencent Zhuque Lab (https://github.com/Tencent/AI-Infra-Guard)",
            "command": command,
        },
        predicted=predicted,
        score=score,
        patterns=normalized["rule_ids"],
    )


def run_agentguard_baseline(skill_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    skill_root = Path(skill_path).resolve()
    destination = Path(output_dir)
    ensure_dir(destination)

    command, source = _agentguard_command(skill_root)
    payload = _run_json_baseline_command(command, timeout_sec=SKILL_SCANNER_TIMEOUT_SEC)
    normalized = _normalize_agentguard_payload(payload)
    predicted, score = _prediction_from_risk_level(normalized["risk_level"])
    return _finalize_baseline_result(
        destination=destination,
        artifact_name="agentguard_report.json",
        manifest_key="agentguard_report",
        payload=normalized,
        runtime={"tool": "agentguard", "source": source, "command": command},
        predicted=predicted,
        score=score,
        patterns=normalized["risk_tags"],
    )


def _baseline_root() -> Path:
    return Path(__file__).resolve().parents[2] / "baseline"


def _normalize_snyk_payload(payload: dict[str, Any]) -> dict[str, Any]:
    scan_results: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    errors: list[str] = []
    usable_results = 0
    severities: list[str] = []

    for path, result in payload.items():
        if not isinstance(result, dict):
            continue
        normalized_result = dict(result)
        normalized_result.setdefault("path", str(path))
        scan_results.append(normalized_result)
        if result.get("servers") is not None:
            usable_results += 1
        error = result.get("error")
        if error:
            errors.append(_error_text(error))
        for issue in result.get("issues", []):
            if not isinstance(issue, dict):
                continue
            issues.append(issue)
            severities.append(_snyk_issue_severity(issue))

    return {
        "scan_results": scan_results,
        "usable_results": usable_results,
        "issues": issues,
        "errors": errors,
        "severities": severities,
    }


def _snyk_issue_severity(issue: dict[str, Any]) -> str:
    extra_data = issue.get("extra_data")
    if isinstance(extra_data, dict) and str(extra_data.get("severity", "")).strip():
        return str(extra_data["severity"]).strip().lower()
    code = str(issue.get("code", "")).upper()
    if code.startswith("E"):
        return "high"
    if code.startswith("W"):
        return "medium"
    return "info"


def _error_text(error: Any) -> str:
    if isinstance(error, dict):
        return str(error.get("message") or error.get("exception") or error).strip()
    return str(error).strip()


def _normalize_sarif_payload(payload: dict[str, Any]) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    severities: list[str] = []
    rule_ids: set[str] = set()
    runs = payload.get("runs")
    if not isinstance(runs, list):
        runs = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        for result in run.get("results", []):
            if not isinstance(result, dict):
                continue
            results.append(result)
            rule_id = str(result.get("ruleId", "")).strip()
            if rule_id:
                rule_ids.add(rule_id)
            properties = result.get("properties")
            severity = str(properties.get("severity", "")).strip().lower() if isinstance(properties, dict) else ""
            if not severity:
                severity = str(result.get("level", "")).strip().lower()
            severities.append(severity)
    return {
        "sarif": payload,
        "results": results,
        "severities": severities,
        "rule_ids": sorted(rule_ids),
    }


def _agentguard_command(skill_root: Path) -> tuple[list[str], str]:
    project_root = _baseline_root() / "agentguard"
    local_cli = project_root / "dist" / "cli.js"
    if local_cli.exists():
        return ["node", str(local_cli), "scan", str(skill_root), "--json"], "local-build"

    version = AGENTGUARD_FALLBACK_VERSION
    package_json = project_root / "package.json"
    if package_json.exists():
        try:
            candidate = json.loads(package_json.read_text(encoding="utf-8")).get("version")
            if str(candidate or "").strip():
                version = str(candidate).strip()
        except (OSError, json.JSONDecodeError):
            pass
    return (
        [
            "npx",
            "--yes",
            "--package",
            f"@goplus/agentguard@{version}",
            "agentguard",
            "scan",
            str(skill_root),
            "--json",
        ],
        "pinned-npm-package",
    )


def _normalize_agentguard_payload(payload: dict[str, Any]) -> dict[str, Any]:
    evidence = payload.get("evidence")
    if not isinstance(evidence, list):
        evidence = payload.get("findings")
    if not isinstance(evidence, list):
        evidence = []
    risk_tags = payload.get("risk_tags")
    if not isinstance(risk_tags, list):
        risk_tags = [
            item.get("tag") or item.get("rule_id")
            for item in evidence
            if isinstance(item, dict) and (item.get("tag") or item.get("rule_id"))
        ]
    return {
        "risk_level": str(payload.get("risk_level", "low")).strip().lower(),
        "risk_tags": sorted({str(item).strip() for item in risk_tags if str(item).strip()}),
        "evidence": [item for item in evidence if isinstance(item, dict)],
        "summary": str(payload.get("summary", "")).strip(),
        "metadata": payload.get("metadata", {}) if isinstance(payload.get("metadata"), dict) else {},
    }


def _prediction_from_risk_level(level: str) -> tuple[str, float]:
    normalized = str(level).strip().lower()
    if normalized in {"critical", "high", "malicious", "dangerous", "reject", "block"}:
        return "malicious", 0.95
    if normalized in {"medium", "low", "warning", "suspicious", "review"}:
        return "suspicious", 0.6
    return "benign", 0.1


def _prediction_from_severities(severities: list[str]) -> tuple[str, float]:
    normalized = {str(item).strip().lower() for item in severities}
    if normalized & {"critical", "high", "error", "malicious", "dangerous"}:
        return "malicious", 0.95
    if normalized & {"medium", "low", "warning", "note", "suspicious"}:
        return "suspicious", 0.6
    return "benign", 0.1
