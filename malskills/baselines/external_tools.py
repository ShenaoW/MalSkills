from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any

from ..utils import ensure_dir


DEFAULT_TIMEOUT_SEC = 120
SKILL_SCANNER_TIMEOUT_SEC = 300
MASB_DEFAULT_THRESHOLDS = {
    "critical": 8.0,
    "high": 6.0,
    "medium": 4.0,
    "low": 2.0,
}


def run_skill_security_scan_baseline(skill_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    skill_root = Path(skill_path).resolve()
    destination = Path(output_dir)
    ensure_dir(destination)

    payload = _run_json_baseline_command(
        [
            "python3",
            "-m",
            "src.cli",
            "scan",
            str(skill_root),
            "--format",
            "json",
        ],
        env_overrides={"PYTHONPATH": str((Path(__file__).resolve().parents[2] / "baseline" / "skill-security-scan").resolve())},
    )
    normalized = _normalize_skill_security_scan_payload(payload)
    return _finalize_baseline_result(
        destination=destination,
        artifact_name="skill_security_scan_report.json",
        manifest_key="skill_security_scan_report",
        payload=normalized,
        runtime={
            "tool": "skill-security-scan",
            "command": [
                "python3",
                "-m",
                "src.cli",
                "scan",
                str(skill_root),
                "--format",
                "json",
            ],
        },
        predicted=_map_skill_security_scan_prediction(normalized),
        score=_map_skill_security_scan_score(normalized),
        patterns=sorted(
            {
                str(item.get("rule_id", "")).strip()
                for item in normalized.get("issues", [])
                if str(item.get("rule_id", "")).strip()
            }
        ),
    )


def run_masb_baseline(skill_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    skill_root = Path(skill_path).resolve()
    destination = Path(output_dir)
    ensure_dir(destination)

    runtime_root = _prepare_masb_runtime(skill_root, destination)
    step4_command = ["bash", "scripts/04_scan.sh"]
    command_results = _run_masb_native_pipeline(runtime_root, [step4_command])
    static_payload = _collect_masb_static_payload(runtime_root, skill_root)
    static_level = str(static_payload.get("risk_level", "SAFE")).upper()
    normalized: dict[str, Any]
    if static_level in {"CRITICAL", "HIGH"}:
        follow_up_commands = [
            ["bash", "scripts/05_gen_cc_queue.sh"],
            ["bash", "scripts/06_cc_analyze.sh"],
            ["bash", "scripts/07_gen_run_queue.sh"],
            ["bash", "scripts/08_execute.sh"],
        ]
        command_results.extend(_run_masb_native_pipeline(runtime_root, follow_up_commands))
        normalized = _collect_masb_runtime_payload_from_static(runtime_root, skill_root, static_payload)
    else:
        normalized = _normalize_masb_static_payload(static_payload, skill_root)
    return _finalize_baseline_result(
        destination=destination,
        artifact_name="masb_report.json",
        manifest_key="masb_report",
        payload=normalized,
        runtime={
            "tool": "masb_native_pipeline",
            "commands": [item["command"] for item in command_results],
            "results": command_results,
            "runtime_root": str(runtime_root),
        },
        predicted=_map_masb_prediction(normalized),
        score=_map_masb_score(normalized),
        patterns=sorted(
            {
                str(item.get("pattern_id", "")).strip() or str(item.get("rule_id", "")).strip()
                for item in normalized.get("vulnerabilities", [])
                if str(item.get("pattern_id", "")).strip() or str(item.get("rule_id", "")).strip()
            }
        ),
    )


def run_skill_security_audit_baseline(skill_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    skill_root = Path(skill_path).resolve()
    destination = Path(output_dir)
    ensure_dir(destination)

    payload = _run_json_baseline_command(
        [
            "python3",
            "baseline/skill-security-audit/scripts/skill_audit.py",
            "--path",
            str(skill_root),
            "--json",
        ],
    )
    normalized = _normalize_skill_security_audit_payload(payload)
    return _finalize_baseline_result(
        destination=destination,
        artifact_name="skill_security_audit_report.json",
        manifest_key="skill_security_audit_report",
        payload=normalized,
        runtime={
            "tool": "skill-security-audit",
            "command": [
                "python3",
                "baseline/skill-security-audit/scripts/skill_audit.py",
                "--path",
                str(skill_root),
                "--json",
            ],
        },
        predicted=_map_skill_security_audit_prediction(normalized),
        score=_map_skill_security_audit_score(normalized),
        patterns=sorted(
            {
                str(item.get("category", "")).strip()
                for findings in normalized.get("skills", {}).values()
                if isinstance(findings, list)
                for item in findings
                if isinstance(item, dict) and str(item.get("category", "")).strip()
            }
        ),
    )


def run_skills_security_audit_baseline(skill_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    skill_root = Path(skill_path).resolve()
    destination = Path(output_dir)
    ensure_dir(destination)

    payload = _run_json_baseline_command(
        [
            "python3",
            "-m",
            "skills_security_audit",
            str(skill_root),
            "--mode",
            "static",
        ],
        env_overrides={"PYTHONPATH": str((Path(__file__).resolve().parents[2] / "baseline").resolve())},
    )
    normalized = _normalize_skills_security_audit_payload(payload)
    return _finalize_baseline_result(
        destination=destination,
        artifact_name="skills_security_audit_report.json",
        manifest_key="skills_security_audit_report",
        payload=normalized,
        runtime={
            "tool": "skills_security_audit",
            "command": [
                "python3",
                "-m",
                "skills_security_audit",
                str(skill_root),
                "--mode",
                "static",
            ],
        },
        predicted=_map_skills_security_audit_prediction(normalized),
        score=_map_skills_security_audit_score(normalized),
        patterns=sorted(
            {
                str(finding.get("category", "")).strip()
                for item in normalized.get("files", [])
                for finding in item.get("findings", [])
                if str(finding.get("category", "")).strip()
            }
        ),
    )


def run_caterpillar_baseline(skill_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    skill_root = Path(skill_path).resolve()
    destination = Path(output_dir)
    ensure_dir(destination)

    payload = _run_json_baseline_command(
        [
            "node",
            "baseline/caterpillar/dist/cli.js",
            "ask",
            str(skill_root),
            "--json",
            "--mode",
            "offline",
        ],
    )
    normalized = _normalize_caterpillar_payload(payload)
    return _finalize_baseline_result(
        destination=destination,
        artifact_name="caterpillar_report.json",
        manifest_key="caterpillar_report",
        payload=normalized,
        runtime={
            "tool": "caterpillar",
            "command": [
                "node",
                "baseline/caterpillar/dist/cli.js",
                "ask",
                str(skill_root),
                "--json",
                "--mode",
                "offline",
            ],
        },
        predicted=_map_caterpillar_prediction(normalized),
        score=_map_caterpillar_score(normalized),
        patterns=sorted(
            {
                str(item.get("category", "")).strip()
                for item in normalized.get("data", {}).get("findings", [])
                if str(item.get("category", "")).strip()
            }
        ),
    )


def run_clawscan_baseline(skill_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    skill_root = Path(skill_path).resolve()
    destination = Path(output_dir)
    ensure_dir(destination)

    payload = _run_json_baseline_command(
        [
            "node",
            "baseline/clawscan/src/cli.js",
            "scan",
            str(skill_root),
            "--json",
        ],
    )
    normalized = _normalize_clawscan_payload(payload)
    return _finalize_baseline_result(
        destination=destination,
        artifact_name="clawscan_report.json",
        manifest_key="clawscan_report",
        payload=normalized,
        runtime={
            "tool": "clawscan",
            "command": [
                "node",
                "baseline/clawscan/src/cli.js",
                "scan",
                str(skill_root),
                "--json",
            ],
        },
        predicted=_map_clawscan_prediction(normalized),
        score=float(normalized.get("risk", {}).get("score", 0.0) or 0.0) / 100.0,
        patterns=sorted(
            {
                str(item.get("ruleId", "")).strip()
                for item in normalized.get("findings", [])
                if str(item.get("ruleId", "")).strip()
            }
        ),
    )


def run_skill_scanner_baseline(skill_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    skill_root = Path(skill_path).resolve()
    destination = Path(output_dir)
    ensure_dir(destination)

    python_bin = _resolve_skill_scanner_python()
    payload = _run_json_baseline_command(
        [
            str(python_bin),
            "-m",
            "skill_scanner.cli.cli",
            "scan",
            str(skill_root),
            "--format",
            "json",
        ],
        env_overrides={"PYTHONPATH": str((Path(__file__).resolve().parents[2] / "baseline" / "skill-scanner").resolve())},
        timeout_sec=SKILL_SCANNER_TIMEOUT_SEC,
    )
    normalized = _normalize_skill_scanner_payload(payload)
    return _finalize_baseline_result(
        destination=destination,
        artifact_name="skill_scanner_report.json",
        manifest_key="skill_scanner_report",
        payload=normalized,
        runtime={
            "tool": "skill-scanner",
            "command": [
                str(python_bin),
                "-m",
                "skill_scanner.cli.cli",
                "scan",
                str(skill_root),
                "--format",
                "json",
            ],
        },
        predicted=_map_skill_scanner_prediction(normalized),
        score=_map_skill_scanner_score(normalized),
        patterns=sorted(
            {
                str(item.get("rule_id", "")).strip()
                for item in normalized.get("findings", [])
                if str(item.get("rule_id", "")).strip()
            }
        ),
    )


def run_nova_proximity_baseline(skill_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    skill_root = Path(skill_path).resolve()
    destination = Path(output_dir)
    ensure_dir(destination)

    output_prefix = destination / "nova_proximity"
    command = [
        _resolve_python_bin(),
        "baseline/nova-proximity/novaprox.py",
        "--skill",
        str(skill_root),
        "--skill-recursive",
        "--json-report",
        "--output-prefix",
        str(output_prefix),
    ]
    _run_baseline_command(command)
    report_paths = sorted(destination.glob("nova_proximity_*.json"))
    if not report_paths:
        raise FileNotFoundError(f"nova-proximity report not found under {destination}")
    payload = _load_json_file(report_paths[-1])
    normalized = _normalize_nova_proximity_payload(payload)
    return _finalize_baseline_result(
        destination=destination,
        artifact_name="nova_proximity_report.json",
        manifest_key="nova_proximity_report",
        payload=normalized,
        runtime={
            "tool": "nova-proximity",
            "command": command,
        },
        predicted=_map_nova_proximity_prediction(normalized),
        score=_map_nova_proximity_score(normalized),
        patterns=sorted(
            {
                str(item.get("type", "")).strip()
                for item in normalized.get("security_flags", [])
                if str(item.get("type", "")).strip()
            }
        ),
    )


def _run_json_baseline_command(
    command: list[str],
    *,
    env_overrides: dict[str, str] | None = None,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> dict[str, Any]:
    completed = _run_baseline_command(command, env_overrides=env_overrides, timeout_sec=timeout_sec)
    payload = _extract_json_object(completed.stdout)
    if completed.returncode != 0 and not payload:
        raise subprocess.CalledProcessError(
            completed.returncode,
            command,
            output=completed.stdout,
            stderr=completed.stderr,
        )
    return payload


def _run_baseline_command(
    command: list[str],
    *,
    env_overrides: dict[str, str] | None = None,
    cwd: str | Path | None = None,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if env_overrides:
        env.update(env_overrides)
    process = subprocess.Popen(
        command,
        text=True,
        env=env,
        cwd=str(Path(cwd).resolve()) if cwd else None,
        start_new_session=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout_sec)
    except subprocess.TimeoutExpired as exc:
        _terminate_process_group(process)
        process.wait(timeout=5)
        raise exc
    completed = subprocess.CompletedProcess(
        args=command,
        returncode=process.returncode,
        stdout=stdout,
        stderr=stderr,
    )
    return completed


def _terminate_process_group(process: subprocess.Popen[str]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except OSError:
        try:
            process.terminate()
        except OSError:
            return
        return

    try:
        process.wait(timeout=3)
        return
    except subprocess.TimeoutExpired:
        pass

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except OSError:
        try:
            process.kill()
        except OSError:
            return


def _extract_json_object(stdout: str) -> dict[str, Any]:
    text = stdout.strip()
    if not text:
        return {}
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        pass

    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        return {}
    try:
        parsed = json.loads(text[start : end + 1])
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


def _load_json_file(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


def _normalize_skill_security_scan_payload(payload: dict[str, Any]) -> dict[str, Any]:
    issues = payload.get("issues")
    if not isinstance(issues, list):
        issues = []
    return {
        "skill_path": str(payload.get("skill_path", "")).strip(),
        "skill_name": str(payload.get("skill_name", "")).strip(),
        "risk_score": float(payload.get("risk_score", 0.0) or 0.0),
        "risk_level": str(payload.get("risk_level", "UNKNOWN")).upper(),
        "total_files": int(payload.get("total_files", 0) or 0),
        "total_issues": int(payload.get("total_issues", len(issues)) or 0),
        "issues": [item for item in issues if isinstance(item, dict)],
        "summary": payload.get("summary", {}) if isinstance(payload.get("summary"), dict) else {},
        "recommendation": str(payload.get("recommendation", "")).strip(),
    }


def _normalize_skills_security_audit_payload(payload: dict[str, Any]) -> dict[str, Any]:
    files = payload.get("files")
    if not isinstance(files, list):
        files = []
    return {
        "files": [item for item in files if isinstance(item, dict)],
        "summary": payload.get("summary", {}) if isinstance(payload.get("summary"), dict) else {},
    }


def _normalize_skill_security_audit_payload(payload: dict[str, Any]) -> dict[str, Any]:
    skills = payload.get("skills")
    if not isinstance(skills, dict):
        skills = {}
    normalized_skills: dict[str, list[dict[str, Any]]] = {}
    for skill_name, findings in skills.items():
        if not isinstance(findings, list):
            continue
        normalized_skills[str(skill_name)] = [item for item in findings if isinstance(item, dict)]
    return {
        "skills": normalized_skills,
        "summary": payload.get("summary", {}) if isinstance(payload.get("summary"), dict) else {},
    }


def _normalize_caterpillar_payload(payload: dict[str, Any]) -> dict[str, Any]:
    data = payload.get("data")
    if not isinstance(data, dict):
        data = {}
    findings = data.get("findings")
    return {
        "success": bool(payload.get("success", False)),
        "data": {
            "skill": str(data.get("skill", "")).strip(),
            "grade": str(data.get("grade", "")).strip().upper(),
            "score": int(data.get("score", 0) or 0),
            "summary": str(data.get("summary", "")).strip(),
            "findings": [item for item in findings if isinstance(item, dict)] if isinstance(findings, list) else [],
        },
    }


def _normalize_clawscan_payload(payload: dict[str, Any]) -> dict[str, Any]:
    findings = payload.get("findings")
    analyzers = payload.get("analyzers")
    return {
        "target": str(payload.get("target", "")).strip(),
        "path": str(payload.get("path", "")).strip(),
        "timestamp": str(payload.get("timestamp", "")).strip(),
        "findings": [item for item in findings if isinstance(item, dict)] if isinstance(findings, list) else [],
        "analyzers": [item for item in analyzers if isinstance(item, dict)] if isinstance(analyzers, list) else [],
        "summary": payload.get("summary", {}) if isinstance(payload.get("summary"), dict) else {},
        "risk": payload.get("risk", {}) if isinstance(payload.get("risk"), dict) else {},
    }


def _normalize_skill_scanner_payload(payload: dict[str, Any]) -> dict[str, Any]:
    findings = payload.get("findings")
    return {
        "skill_name": str(payload.get("skill_name", "")).strip(),
        "skill_path": str(payload.get("skill_path", "")).strip(),
        "is_safe": bool(payload.get("is_safe", False)),
        "max_severity": str(payload.get("max_severity", "SAFE")).upper(),
        "findings_count": int(payload.get("findings_count", 0) or 0),
        "findings": [item for item in findings if isinstance(item, dict)] if isinstance(findings, list) else [],
    }


def _normalize_nova_proximity_payload(payload: dict[str, Any]) -> dict[str, Any]:
    scan_results = payload.get("scan_results")
    if not isinstance(scan_results, dict):
        scan_results = {}
    skills = scan_results.get("skills")
    if not isinstance(skills, list):
        skills = []
    nova_analysis = payload.get("nova_analysis")
    if not isinstance(nova_analysis, dict):
        nova_analysis = {}
    security_flags: list[dict[str, Any]] = []
    for skill in skills:
        if not isinstance(skill, dict):
            continue
        for flag in skill.get("security_flags", []):
            if isinstance(flag, dict):
                security_flags.append(flag)
    return {
        "scan_results": scan_results,
        "nova_analysis": nova_analysis,
        "total_skills": int(scan_results.get("total_skills", len(skills)) or 0),
        "security_flags": security_flags,
        "nova_flagged_count": int(nova_analysis.get("flagged_count", 0) or 0),
    }


def _prepare_masb_runtime(skill_root: Path, destination: Path) -> Path:
    source_root = Path(__file__).resolve().parents[2] / "baseline" / "MASB"
    runtime_root = destination / "masb_runtime"
    runtime_root.mkdir(parents=True, exist_ok=True)

    for name in ("analyzer", "executor", "scanner", "scripts", "utils"):
        target = runtime_root / name
        if not target.exists():
            target.symlink_to(source_root / name, target_is_directory=True)

    for name in ("Dockerfile", "api_keys.conf"):
        source = source_root / name
        target = runtime_root / name
        if source.exists() and not target.exists():
            target.symlink_to(source)

    runtime_paths = {
        "data_dir": "./runtime_data",
        "workspace_dir": "./runtime_workspace",
        "scan_results_dir": "./runtime_scan_results",
        "execution_logs_dir": "./runtime_execution_logs",
        "tasks_dir": "./runtime_tasks",
        "scripts_dir": "./scripts",
    }
    config_payload = {
        "project": {"name": "masb-runtime", "version": "1.0.0"},
        "paths": runtime_paths,
        "scanner": {
            "max_workers": 5,
            "timeout": 60,
            "batch_size": 100,
            "thresholds": dict(MASB_DEFAULT_THRESHOLDS),
        },
        "analyzer": {
            "jobs": 10,
            "max_retries": 3,
            "prompt_file": "./analyzer/prompts/audit_prompt.txt",
            "output_suffix": "_audit.json",
            "api": {
                "key_env": "PACKY_API_KEY",
                "base_url_env": "PACKY_API_URL",
                "default_base_url": "https://www.packyapi.com/v1",
            },
        },
        "executor": {
            "docker_image": "codex-skill-sandbox",
            "max_workers": 3,
            "timeout": 900,
            "use_nova": True,
            "nova_block": False,
        },
        "logging": {
            "level": "INFO",
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        },
    }
    try:
        import yaml
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("PyYAML is required for MASB runtime configuration") from exc
    (runtime_root / "config.yaml").write_text(yaml.safe_dump(config_payload, sort_keys=False), encoding="utf-8")

    repo_root = runtime_root / "runtime_workspace" / "repo" / skill_root.name
    if repo_root.exists():
        shutil.rmtree(repo_root)
    repo_root.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(skill_root, repo_root)
    return runtime_root


def _run_masb_native_pipeline(runtime_root: Path, commands: list[list[str]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    env_overrides = {
        "PYTHONPATH": str(runtime_root),
    }
    for command in commands:
        completed = _run_baseline_command(command, cwd=runtime_root, env_overrides=env_overrides, timeout_sec=DEFAULT_TIMEOUT_SEC * 8)
        results.append(
            {
                "command": command,
                "returncode": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
            }
        )
        if completed.returncode != 0:
            raise subprocess.CalledProcessError(
                completed.returncode,
                command,
                output=completed.stdout,
                stderr=completed.stderr,
            )
    return results


def _collect_masb_runtime_payload(runtime_root: Path, skill_root: Path) -> dict[str, Any]:
    static_payload = _collect_masb_static_payload(runtime_root, skill_root)
    return _collect_masb_runtime_payload_from_static(runtime_root, skill_root, static_payload)


def _collect_masb_runtime_payload_from_static(runtime_root: Path, skill_root: Path, static_payload: dict[str, Any]) -> dict[str, Any]:
    scan_results_dir = runtime_root / "runtime_scan_results"
    execution_logs_dir = runtime_root / "runtime_execution_logs"
    audit_reports: list[dict[str, Any]] = []
    for category in ("MALICIOUS", "SUSPICIOUS", "SAFE", "ERROR"):
        category_dir = scan_results_dir / category
        if not category_dir.exists():
            continue
        for report_path in sorted(category_dir.glob("*_audit.json")):
            payload = _load_json_file(report_path)
            if payload:
                payload["_masb_category"] = category
                payload["_report_path"] = str(report_path)
                audit_reports.append(payload)

    if not audit_reports:
        raise FileNotFoundError(f"MASB audit report not found under {scan_results_dir}")

    collected_reports = []
    vulnerabilities: list[dict[str, Any]] = []
    execution_artifacts: list[str] = []
    statuses: set[str] = set()
    for report in audit_reports:
        summary = report.get("audit_summary", {})
        status = str(summary.get("intent_alignment_status", report.get("_masb_category", "ERROR"))).upper()
        statuses.add(status)
        collected_reports.append(
            {
                "skill_name": str(report.get("skill_name", "")).strip(),
                "skill_path": str(report.get("skill_path", "")).strip(),
                "repo_id": str(report.get("repo_id", "")).strip(),
                "category": str(report.get("_masb_category", "")).strip(),
                "report_path": str(report.get("_report_path", "")).strip(),
                "audit_summary": summary if isinstance(summary, dict) else {},
            }
        )
        for vuln in report.get("vulnerabilities", []):
            if isinstance(vuln, dict):
                vulnerabilities.append(vuln)

    if execution_logs_dir.exists():
        execution_artifacts = sorted(
            str(path.relative_to(runtime_root))
            for path in execution_logs_dir.rglob("*")
            if path.is_file()
        )

    if "MALICIOUS" in statuses:
        risk_level = "MALICIOUS"
    elif "SUSPICIOUS" in statuses:
        risk_level = "SUSPICIOUS"
    elif "SAFE" in statuses:
        risk_level = "SAFE"
    else:
        risk_level = "ERROR"

    return {
        "skill_path": str(skill_root),
        "risk_level": risk_level,
        "static_scan": static_payload,
        "audit_reports": collected_reports,
        "vulnerabilities": vulnerabilities,
        "execution_artifacts": execution_artifacts,
    }


def _collect_masb_static_payload(runtime_root: Path, skill_root: Path) -> dict[str, Any]:
    workspace_root = runtime_root / "runtime_workspace"
    report_paths = sorted(workspace_root.glob("*/*_report.json"))
    if not report_paths:
        raise FileNotFoundError(f"MASB static report not found under {workspace_root}")

    target_report: dict[str, Any] | None = None
    target_skill_name = skill_root.name
    for report_path in report_paths:
        payload = _load_json_file(report_path)
        for skill_report in payload.get("skills_reports", []):
            if not isinstance(skill_report, dict):
                continue
            if str(skill_report.get("skill_name", "")).strip() == target_skill_name:
                target_report = payload
                break
        if target_report is not None:
            break

    if target_report is None:
        target_report = _load_json_file(report_paths[0])
    return target_report


def _normalize_masb_static_payload(payload: dict[str, Any], skill_root: Path) -> dict[str, Any]:
    skill_reports = payload.get("skills_reports", [])
    target_skill_name = skill_root.name
    target_report: dict[str, Any] | None = None
    if isinstance(skill_reports, list):
        for item in skill_reports:
            if not isinstance(item, dict):
                continue
            if str(item.get("skill_name", "")).strip() == target_skill_name:
                target_report = item
                break
    if target_report is None:
        target_report = {}

    issues = target_report.get("issues", [])
    vulnerabilities = [item for item in issues if isinstance(item, dict)]
    level = str(target_report.get("risk_level", payload.get("risk_level", "SAFE"))).upper()
    return {
        "skill_path": str(skill_root),
        "risk_level": level,
        "static_scan": {
            "repo_id": str(payload.get("repo_id", "")).strip(),
            "repo_name": str(payload.get("repo_name", "")).strip(),
            "repo_path": str(payload.get("repo_path", "")).strip(),
            "scan_timestamp": str(payload.get("scan_timestamp", "")).strip(),
            "risk_level": str(payload.get("risk_level", "")).upper(),
            "risk_summary": payload.get("risk_summary", {}) if isinstance(payload.get("risk_summary"), dict) else {},
            "skill_report": target_report,
        },
        "audit_reports": [],
        "vulnerabilities": vulnerabilities,
        "execution_artifacts": [],
    }


def _map_skill_security_scan_prediction(payload: dict[str, Any]) -> str:
    level = str(payload.get("risk_level", "UNKNOWN")).upper()
    if level in {"CRITICAL", "HIGH"}:
        return "malicious"
    if level in {"MEDIUM", "WARNING", "LOW"}:
        return "suspicious"
    return "benign"


def _map_skill_security_scan_score(payload: dict[str, Any]) -> float:
    level = str(payload.get("risk_level", "UNKNOWN")).upper()
    if level in {"CRITICAL", "HIGH"}:
        return 0.95
    if level in {"MEDIUM", "WARNING", "LOW"}:
        return 0.6
    return 0.1


def _map_skill_security_audit_prediction(payload: dict[str, Any]) -> str:
    severities = {
        str(item.get("severity", "")).upper()
        for findings in payload.get("skills", {}).values()
        if isinstance(findings, list)
        for item in findings
        if isinstance(item, dict)
    }
    if "CRITICAL" in severities or "HIGH" in severities:
        return "malicious"
    if "MEDIUM" in severities or "LOW" in severities:
        return "suspicious"
    return "benign"


def _map_skill_security_audit_score(payload: dict[str, Any]) -> float:
    predicted = _map_skill_security_audit_prediction(payload)
    if predicted == "malicious":
        return 0.95
    if predicted == "suspicious":
        return 0.6
    return 0.1


def _map_skills_security_audit_prediction(payload: dict[str, Any]) -> str:
    decisions = {
        str(item.get("decision", "")).strip().lower()
        for item in payload.get("files", [])
        if str(item.get("decision", "")).strip()
    }
    if "deny" in decisions or "quarantine" in decisions:
        return "malicious"
    if "review" in decisions:
        return "suspicious"
    return "benign"


def _map_skills_security_audit_score(payload: dict[str, Any]) -> float:
    predicted = _map_skills_security_audit_prediction(payload)
    if predicted == "malicious":
        return 0.9
    if predicted == "suspicious":
        return 0.6
    return 0.1


def _map_caterpillar_prediction(payload: dict[str, Any]) -> str:
    data = payload.get("data", {})
    grade = str(data.get("grade", "")).upper()
    severities = {
        str(item.get("severity", "")).lower()
        for item in data.get("findings", [])
        if isinstance(item, dict)
    }
    if grade == "F" or {"critical", "high"} & severities:
        return "malicious"
    if grade in {"D", "C"} or {"medium", "warning"} & severities:
        return "suspicious"
    return "benign"


def _map_caterpillar_score(payload: dict[str, Any]) -> float:
    data = payload.get("data", {})
    score = int(data.get("score", 0) or 0)
    predicted = _map_caterpillar_prediction(payload)
    if predicted == "malicious":
        return max(0.75, 1.0 - (score / 100.0))
    if predicted == "suspicious":
        return max(0.4, 1.0 - (score / 100.0))
    return min(0.25, 1.0 - (score / 100.0))


def _map_clawscan_prediction(payload: dict[str, Any]) -> str:
    level = str(payload.get("risk", {}).get("level", "")).strip().lower()
    if level == "dangerous":
        return "malicious"
    if level == "warning":
        return "suspicious"
    return "benign"


def _map_skill_scanner_prediction(payload: dict[str, Any]) -> str:
    severity = str(payload.get("max_severity", "SAFE")).upper()
    if severity in {"CRITICAL", "HIGH"}:
        return "malicious"
    if severity in {"MEDIUM", "LOW", "INFO"}:
        return "suspicious"
    return "benign"


def _map_skill_scanner_score(payload: dict[str, Any]) -> float:
    predicted = _map_skill_scanner_prediction(payload)
    if predicted == "malicious":
        return 0.95
    if predicted == "suspicious":
        return 0.6
    return 0.1


def _map_nova_proximity_prediction(payload: dict[str, Any]) -> str:
    severities = {
        str(item.get("severity", "")).lower()
        for item in payload.get("security_flags", [])
        if isinstance(item, dict)
    }
    if {"critical", "high"} & severities:
        return "malicious"
    if "medium" in severities or "low" in severities or int(payload.get("nova_flagged_count", 0) or 0) > 0:
        return "suspicious"
    return "benign"


def _map_nova_proximity_score(payload: dict[str, Any]) -> float:
    severities = {
        str(item.get("severity", "")).lower()
        for item in payload.get("security_flags", [])
        if isinstance(item, dict)
    }
    if {"critical", "high"} & severities:
        return 0.95
    if "medium" in severities:
        return 0.7
    if "low" in severities or int(payload.get("nova_flagged_count", 0) or 0) > 0:
        return 0.45
    return 0.1


def _map_masb_prediction(payload: dict[str, Any]) -> str:
    level = str(payload.get("risk_level", "ERROR")).upper()
    if level == "MALICIOUS":
        return "malicious"
    if level == "SUSPICIOUS":
        return "suspicious"
    return "benign"


def _map_masb_score(payload: dict[str, Any]) -> float:
    predicted = _map_masb_prediction(payload)
    if predicted == "malicious":
        return 0.95
    if predicted == "suspicious":
        return 0.6
    return 0.1


def _resolve_skill_scanner_python() -> Path:
    root = Path(__file__).resolve().parents[2]
    candidate = root / "baseline" / "skill-scanner" / ".venv" / "bin" / "python"
    if candidate.exists():
        return candidate
    return Path("python3.10")


def _resolve_python_bin() -> str:
    candidates = ["python3.10", "python3", sys.executable]
    for candidate in candidates:
        if not candidate:
            continue
        try:
            completed = subprocess.run(
                [candidate, "--version"],
                check=True,
                capture_output=True,
                text=True,
            )
        except Exception:
            continue
        version_text = (completed.stdout or completed.stderr).strip()
        if any(version in version_text for version in ("Python 3.10", "Python 3.11", "Python 3.12", "Python 3.13")):
            return candidate
    return sys.executable


def _finalize_baseline_result(
    *,
    destination: Path,
    artifact_name: str,
    manifest_key: str,
    payload: dict[str, Any],
    runtime: dict[str, Any],
    predicted: str,
    score: float,
    patterns: list[str],
) -> dict[str, Any]:
    (destination / artifact_name).write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "root": ".",
        "files": {
            manifest_key: artifact_name,
        },
        "directories": {},
        "available": {},
        "runtime": runtime,
    }
    (destination / "output_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return {
        "status": "ok",
        "predicted": predicted,
        "score": score,
        "patterns": patterns,
        "evidence_count": 0,
        "derived_evidence_count": 0,
        "combined_evidence_count": 0,
        "primitive_count": 0,
    }
