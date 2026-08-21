from __future__ import annotations

import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from ..utils import ensure_dir
from .codex_bridge import llm_api_bridge
from .external_tools import (
    DEFAULT_TIMEOUT_SEC,
    _extract_json_object,
    _finalize_baseline_result,
    _load_json_file,
    _resolve_primary_skill_root,
    _run_baseline_command,
    _run_json_baseline_command,
)


RESEARCH_BASELINE_TIMEOUT_SEC = DEFAULT_TIMEOUT_SEC * 20
SKILLWARD_OPENCLAW_MODEL_ALIAS = "gpt-4o-mini"

_BASELINE_ROOT = Path(__file__).resolve().parents[2] / "baseline"
_PATTERN_DETAIL_KEYS = {
    "attack",
    "attack_class",
    "attack_type",
    "category",
    "finding_type",
    "pattern",
    "pattern_id",
    "patterns",
    "rule",
    "rule_id",
    "threat",
    "threat_category",
    "threat_type",
    "type",
}


def run_skillsieve_baseline(skill_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    skill_root = Path(skill_path).resolve()
    destination = Path(output_dir)
    ensure_dir(destination)

    tool_root = _BASELINE_ROOT / "skillsieve"
    python = _resolve_tool_executable("skillsieve", "python", fallback=sys.executable)
    with llm_api_bridge(cwd=skill_root) as bridge:
        command = [
            python,
            "-m",
            "malskills.baselines.skillsieve_llm",
            str(skill_root),
            bridge.base_url,
            bridge.api_key,
            bridge.model,
            "3",
        ]
        payload = _run_json_baseline_command(
            command,
            env_overrides={
                "PYTHONPATH": os.pathsep.join(
                    [str(_BASELINE_ROOT.parent), str(tool_root), os.environ.get("PYTHONPATH", "")]
                )
            },
            timeout_sec=RESEARCH_BASELINE_TIMEOUT_SEC,
        )
    if not payload:
        raise ValueError("SkillSieve did not emit a JSON scan result")
    normalized = _normalize_skillsieve_payload(payload)
    predicted = _map_skillsieve_prediction(normalized)
    return _finalize_baseline_result(
        destination=destination,
        artifact_name="skillsieve_report.json",
        manifest_key="skillsieve_report",
        payload=normalized,
        runtime={
            "tool": "skillsieve",
            "command": command,
            "llm_backend": bridge.backend,
            "llm_model": bridge.model,
        },
        predicted=predicted,
        score=_score_from_confidence(
            predicted,
            _as_float(normalized.get("final_confidence"), default=0.0),
        ),
        patterns=_skillsieve_patterns(normalized),
    )


def run_skillward_baseline(skill_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    skill_root = _resolve_primary_skill_root(skill_path)
    # SkillWard passes its generated safe-skill path directly to `docker -v`;
    # Docker interprets relative paths containing '/' as invalid volume names.
    destination = Path(output_dir).resolve()
    ensure_dir(destination)
    native_output = destination / "skillward_native"
    ensure_dir(native_output)
    report_path = native_output / "guardian_report.json"
    report_path.unlink(missing_ok=True)

    command = [
        _resolve_tool_executable("skillward", "python", fallback="python3"),
        str(_BASELINE_ROOT / "skillward" / "guardian-api" / "guardian.py"),
        "-i",
        str(skill_root.parent),
        "-o",
        str(native_output),
        "-s",
        skill_root.name,
        "--stage",
        "full",
        "--parallel",
        "1",
    ]
    isolated_home = destination / "skillward_home"
    ensure_dir(isolated_home)
    with llm_api_bridge(cwd=skill_root) as bridge:
        completed = _run_baseline_command(
            command,
            env_overrides={
                "HOME": str(isolated_home),
                "LLM_PROVIDER": "openai",
                "LLM_ID": bridge.model,
                "LLM_API_BASE": bridge.base_url,
                "LLM_API_KEY": bridge.api_key,
                "AGENT_PROVIDER": "deepseek",
                # The pinned OpenClaw image rejects unknown future model IDs;
                # The bridge still executes the configured model.
                "AGENT_ID": SKILLWARD_OPENCLAW_MODEL_ALIAS,
                "AGENT_API_BASE": bridge.docker_base_url,
                "AGENT_API_KEY": bridge.api_key,
                "OPENAI_API_KEY": bridge.api_key,
            },
            timeout_sec=RESEARCH_BASELINE_TIMEOUT_SEC,
        )
    if completed.returncode != 0:
        raise subprocess.CalledProcessError(
            completed.returncode,
            command,
            output=completed.stdout,
            stderr=completed.stderr,
        )
    if not report_path.exists():
        raise FileNotFoundError(f"SkillWard report not found at {report_path}")

    payload = _load_json_file(report_path)
    if not payload:
        raise ValueError(f"SkillWard report at {report_path} is empty or not an object")
    normalized = _normalize_skillward_payload(payload, skill_root)
    _raise_for_skillward_report_errors(normalized)
    predicted = _map_skillward_prediction(normalized)
    return _finalize_baseline_result(
        destination=destination,
        artifact_name="skillward_report.json",
        manifest_key="skillward_report",
        payload=normalized,
        runtime={
            "tool": "skillward",
            "command": command,
            "native_report": str(report_path),
            "returncode": completed.returncode,
            "llm_backend": bridge.backend,
            "llm_model": bridge.model,
            "openclaw_model_alias": SKILLWARD_OPENCLAW_MODEL_ALIAS,
        },
        predicted=predicted,
        score=_map_skillward_score(normalized, predicted),
        patterns=_skillward_patterns(normalized),
    )


def run_runtime_skill_audit_baseline(skill_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    skill_root = _resolve_primary_skill_root(skill_path)
    destination = Path(output_dir).resolve()
    ensure_dir(destination)

    tool_root = _BASELINE_ROOT / "runtime-skill-audit"
    with llm_api_bridge(cwd=skill_root) as bridge:
        config_path = destination / "runtime_skill_audit_llm.yaml"
        _write_runtime_skill_audit_llm_config(
            source=tool_root / "configs" / "default.yaml",
            destination=config_path,
            model=bridge.model,
            ollama_chat_url=bridge.ollama_chat_url,
            openai_base_url=bridge.base_url,
        )
        command = [
            _resolve_tool_executable("runtime-skill-audit", "python", fallback="python3"),
            "scripts/run_pipeline.py",
            str(skill_root),
            "--config",
            str(config_path),
        ]
        existing_sandboxes = _runtime_skill_audit_sandbox_ids()
        try:
            completed = _run_baseline_command(
                command,
                cwd=tool_root,
                env_overrides={
                    "PATH": os.pathsep.join(
                        [str(tool_root / ".openclaw" / "tools" / "node_modules" / ".bin"), os.environ.get("PATH", "")]
                    ),
                    "MALSKILLS_LLM_BRIDGE_API_KEY": bridge.api_key,
                },
                timeout_sec=RESEARCH_BASELINE_TIMEOUT_SEC,
            )
        finally:
            _remove_runtime_skill_audit_sandboxes(_runtime_skill_audit_sandbox_ids() - existing_sandboxes)
    (destination / "runtime_skill_audit_stdout.log").write_text(completed.stdout, encoding="utf-8")
    (destination / "runtime_skill_audit_stderr.log").write_text(completed.stderr, encoding="utf-8")
    payload = _extract_json_object(completed.stdout)
    if completed.returncode != 0:
        raise subprocess.CalledProcessError(
            completed.returncode,
            command,
            output=completed.stdout,
            stderr=completed.stderr,
        )
    if not payload:
        raise ValueError("Runtime Skill Audit did not emit a JSON pipeline result")

    normalized = _normalize_runtime_skill_audit_payload(payload, tool_root)
    _raise_for_runtime_skill_audit_errors(normalized)
    predicted = _map_runtime_skill_audit_prediction(normalized)
    return _finalize_baseline_result(
        destination=destination,
        artifact_name="runtime_skill_audit_report.json",
        manifest_key="runtime_skill_audit_report",
        payload=normalized,
        runtime={
            "tool": "runtime-skill-audit",
            "command": command,
            "cwd": str(tool_root),
            "returncode": completed.returncode,
            "llm_backend": bridge.backend,
            "llm_model": bridge.model,
        },
        predicted=predicted,
        score=_map_runtime_skill_audit_score(normalized, predicted),
        patterns=_runtime_skill_audit_patterns(normalized),
    )


def _runtime_skill_audit_sandbox_ids() -> set[str]:
    completed = subprocess.run(
        ["docker", "ps", "-aq", "--filter", "name=openclaw-sbx-agent-main-explicit-"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if completed.returncode != 0:
        return set()
    return {line.strip() for line in completed.stdout.splitlines() if line.strip()}


def _remove_runtime_skill_audit_sandboxes(container_ids: set[str]) -> None:
    if not container_ids:
        return
    subprocess.run(
        ["docker", "rm", "-f", *sorted(container_ids)],
        check=False,
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def run_skillfortify_baseline(skill_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    skill_root = _resolve_primary_skill_root(skill_path)
    destination = Path(output_dir)
    ensure_dir(destination)

    with tempfile.TemporaryDirectory(prefix="malskills-skillfortify-") as staging_dir:
        scan_root = _prepare_skillfortify_input(skill_root, Path(staging_dir))
        command = [
            _resolve_tool_executable("skillfortify", "skillfortify"),
            "scan",
            str(scan_root),
            "--format",
            "json",
        ]
        completed = _run_baseline_command(command, timeout_sec=DEFAULT_TIMEOUT_SEC)
    decoded = _extract_json_value(completed.stdout)
    if completed.returncode not in {0, 1}:
        raise subprocess.CalledProcessError(
            completed.returncode,
            command,
            output=completed.stdout,
            stderr=completed.stderr,
        )
    if decoded is None:
        raise ValueError("SkillFortify did not emit a JSON scan result")

    normalized = _normalize_skillfortify_payload(decoded)
    if not normalized["skills"]:
        raise ValueError("SkillFortify did not analyze any skills")
    predicted = _map_skillfortify_prediction(normalized)
    return _finalize_baseline_result(
        destination=destination,
        artifact_name="skillfortify_report.json",
        manifest_key="skillfortify_report",
        payload=normalized,
        runtime={
            "tool": "skillfortify",
            "command": command,
            "returncode": completed.returncode,
        },
        predicted=predicted,
        score=_score_for_prediction(predicted),
        patterns=_skillfortify_patterns(normalized),
    )


def _prepare_skillfortify_input(skill_root: Path, staging_root: Path) -> Path:
    skill_file = skill_root / "SKILL.md"
    if not skill_file.is_file():
        return skill_root

    skills_dir = staging_root / ".claude" / "skills"
    skills_dir.mkdir(parents=True)
    shutil.copyfile(skill_file, skills_dir / f"{skill_root.name}.md")
    return staging_root


def run_skill_sentinel_baseline(skill_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    skill_root = _resolve_primary_skill_root(skill_path)
    destination = Path(output_dir)
    ensure_dir(destination)

    native_report = destination / "skill_sentinel_native_report.json"
    native_report.unlink(missing_ok=True)
    with llm_api_bridge(cwd=skill_root) as bridge:
        command = [
            _resolve_tool_executable("skill-sentinel", "skill-sentinel"),
            "scan",
            "--skill",
            str(skill_root),
            "--model",
            bridge.model,
            "-o",
            str(native_report),
        ]
        completed = _run_baseline_command(
            command,
            env_overrides={
                "OPENAI_API_KEY": bridge.api_key,
                "OPENAI_BASE_URL": bridge.base_url,
                "OPENAI_API_BASE": bridge.base_url,
                "OPENAI_MODEL_NAME": bridge.model,
            },
            timeout_sec=RESEARCH_BASELINE_TIMEOUT_SEC,
        )
    (destination / "skill_sentinel_stdout.log").write_text(completed.stdout, encoding="utf-8")
    (destination / "skill_sentinel_stderr.log").write_text(completed.stderr, encoding="utf-8")
    if completed.returncode != 0:
        raise subprocess.CalledProcessError(
            completed.returncode,
            command,
            output=completed.stdout,
            stderr=completed.stderr,
        )
    if not native_report.exists():
        raise FileNotFoundError(f"Skill Sentinel report not found at {native_report}")
    payload = _load_json_file(native_report)
    if not payload:
        raise ValueError(f"Skill Sentinel report at {native_report} is empty or not an object")

    normalized = _normalize_skill_sentinel_payload(payload, skill_root)
    predicted = _map_skill_sentinel_prediction(normalized)
    return _finalize_baseline_result(
        destination=destination,
        artifact_name="skill_sentinel_report.json",
        manifest_key="skill_sentinel_report",
        payload=normalized,
        runtime={
            "tool": "skill-sentinel",
            "command": command,
            "native_report": str(native_report),
            "returncode": completed.returncode,
            "llm_backend": bridge.backend,
            "llm_model": bridge.model,
        },
        predicted=predicted,
        score=_map_skill_sentinel_score(normalized, predicted),
        patterns=_skill_sentinel_patterns(normalized),
    )


def _write_runtime_skill_audit_llm_config(
    *,
    source: Path,
    destination: Path,
    model: str,
    ollama_chat_url: str,
    openai_base_url: str,
) -> None:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("PyYAML is required for Runtime Skill Audit configuration") from exc
    payload = yaml.safe_load(source.read_text(encoding="utf-8")) or {}
    llm = payload.setdefault("llm", {})
    llm.update(
        {
            "model": model,
            "base_url": ollama_chat_url,
            "api_key_env": "MALSKILLS_LLM_BRIDGE_API_KEY",
            "timeout": 900,
        }
    )
    openclaw_config_path = destination.parent / "runtime_skill_audit_openclaw.json"
    openclaw_config = {
        "agents": {"defaults": {"model": {"primary": f"malskills/{model}"}}},
        "models": {
            "mode": "merge",
            "providers": {
                "malskills": {
                    "baseUrl": openai_base_url,
                    "apiKey": "${MALSKILLS_LLM_BRIDGE_API_KEY}",
                    "api": "openai-completions",
                    "models": [{"id": model, "name": model}],
                }
            },
        },
    }
    openclaw_config_path.write_text(json.dumps(openclaw_config, indent=2) + "\n", encoding="utf-8")
    paths = payload.setdefault("paths", {})
    tool_root = _BASELINE_ROOT / "runtime-skill-audit"
    paths["output_dir"] = str((tool_root / "outputs").resolve())
    paths["source_config"] = str(openclaw_config_path.resolve())
    paths["source_workspace"] = str((tool_root / ".openclaw" / "workspace").resolve())
    paths["memory_dir"] = str((tool_root / "outputs" / "memory").resolve())
    paths["defense_assets_dir"] = str((tool_root / "CIK-Bench" / "defense_assets").resolve())
    payload.setdefault("runtime", {})["thinking"] = "off"
    destination.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def _normalize_skillsieve_payload(payload: dict[str, Any]) -> dict[str, Any]:
    layer_results = payload.get("layer_results")
    if not isinstance(layer_results, list):
        layer_results = []
    verdict = str(payload.get("final_verdict", "")).strip().lower()
    if verdict not in {"safe", "suspicious", "malicious"}:
        raise ValueError(f"SkillSieve returned an unknown final verdict: {verdict or '<missing>'}")
    return {
        "skill_name": str(payload.get("skill_name", "")).strip(),
        "final_verdict": verdict,
        "final_confidence": _clamp(_as_float(payload.get("final_confidence"), default=0.0)),
        "layer_stopped": int(payload.get("layer_stopped", 0) or 0),
        "layer_results": [item for item in layer_results if isinstance(item, dict)],
        "report": payload.get("report"),
    }


def _normalize_skillward_payload(payload: dict[str, Any], skill_root: Path) -> dict[str, Any]:
    prescan_all = payload.get("prescan") if isinstance(payload.get("prescan"), dict) else {}
    runtime_all = payload.get("runtime") if isinstance(payload.get("runtime"), dict) else {}
    prescan = _select_skill_mapping(prescan_all, skill_root.name)
    runtime = _select_skill_mapping(runtime_all, skill_root.name)
    if not prescan and not runtime:
        raise ValueError(f"SkillWard report does not contain results for {skill_root.name}")
    return {
        "skill_path": str(skill_root),
        "skill_name": skill_root.name,
        "prescan": prescan,
        "runtime": runtime,
        "timestamp": str(payload.get("timestamp", "")).strip(),
    }


def _normalize_runtime_skill_audit_payload(payload: dict[str, Any], tool_root: Path) -> dict[str, Any]:
    run_results = payload.get("run_results")
    if not isinstance(run_results, list):
        run_results_path = str(payload.get("run_results_path", "")).strip()
        summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
        if not run_results_path:
            run_results_path = str(summary.get("run_results_path", "")).strip()
        if not run_results_path:
            raise FileNotFoundError("Runtime Skill Audit run_results report path is missing")
        report_path = Path(run_results_path)
        if not report_path.is_absolute():
            report_path = tool_root / report_path
        if not report_path.exists():
            raise FileNotFoundError(f"Runtime Skill Audit run_results report not found at {report_path}")
        decoded = json.loads(report_path.read_text(encoding="utf-8"))
        if isinstance(decoded, dict):
            run_results = decoded.get("run_results")
        else:
            run_results = decoded
    if not isinstance(run_results, list) or not run_results:
        raise ValueError("Runtime Skill Audit did not produce any task results")

    profile = payload.get("profile") if isinstance(payload.get("profile"), dict) else {}
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    return {
        "skill_path": str(payload.get("skill_path", "")).strip(),
        "skill_name": str(payload.get("skill_name", summary.get("skill", ""))).strip(),
        "run_dir": str(payload.get("run_dir", summary.get("run_dir", ""))).strip(),
        "completed": bool(summary.get("completed", False)),
        "profile": profile,
        "summary": summary,
        "run_results": [item for item in run_results if isinstance(item, dict)],
    }


def _normalize_skillfortify_payload(payload: Any) -> dict[str, Any]:
    if isinstance(payload, list):
        skills = payload
    elif isinstance(payload, dict):
        skills = payload.get("skills")
        if not isinstance(skills, list):
            skills = [payload] if "is_safe" in payload or "findings" in payload else []
    else:
        skills = []

    normalized_skills: list[dict[str, Any]] = []
    for item in skills:
        if not isinstance(item, dict):
            continue
        findings = item.get("findings")
        if not isinstance(findings, list):
            findings = []
        capabilities = item.get("inferred_capabilities")
        if not isinstance(capabilities, list):
            capabilities = []
        normalized_skills.append(
            {
                "skill_name": str(item.get("skill_name", "")).strip(),
                "is_safe": bool(item.get("is_safe", False)),
                "findings_count": int(item.get("findings_count", len(findings)) or 0),
                "max_severity": str(item.get("max_severity", "") or "").strip().upper(),
                "inferred_capabilities": [row for row in capabilities if isinstance(row, dict)],
                "findings": [row for row in findings if isinstance(row, dict)],
            }
        )
    return {"skills": normalized_skills}


def _normalize_skill_sentinel_payload(payload: dict[str, Any], skill_root: Path) -> dict[str, Any]:
    findings = payload.get("validated_findings")
    false_positives = payload.get("false_positives")
    assessment = payload.get("overall_risk_assessment")
    if not isinstance(assessment, dict) or not assessment:
        raise ValueError("Skill Sentinel report is missing overall_risk_assessment")
    return {
        "skill_path": str(payload.get("skill_path", skill_root)).strip(),
        "skill_name": str(payload.get("skill_name", skill_root.name)).strip(),
        "content_hash": str(payload.get("content_hash", "")).strip(),
        "validated_findings": [item for item in findings if isinstance(item, dict)] if isinstance(findings, list) else [],
        "false_positives": [item for item in false_positives if isinstance(item, dict)] if isinstance(false_positives, list) else [],
        "priority_order": payload.get("priority_order", []) if isinstance(payload.get("priority_order"), list) else [],
        "correlations": payload.get("correlations", []) if isinstance(payload.get("correlations"), list) else [],
        "recommendations": payload.get("recommendations", []) if isinstance(payload.get("recommendations"), list) else [],
        "references": payload.get("references", []) if isinstance(payload.get("references"), list) else [],
        "overall_risk_assessment": assessment if isinstance(assessment, dict) else {},
        "token_usage": payload.get("token_usage", {}) if isinstance(payload.get("token_usage"), dict) else {},
        "scan_duration": payload.get("scan_duration", {}) if isinstance(payload.get("scan_duration"), dict) else {},
    }


def _raise_for_skillward_report_errors(payload: dict[str, Any]) -> None:
    prescan = payload.get("prescan") if isinstance(payload.get("prescan"), dict) else {}
    static_error = str(prescan.get("error", "")).strip()
    if static_error:
        raise RuntimeError(f"SkillWard static scan failed: {static_error}")
    llm_reason = str(prescan.get("llm_reason", "")).strip()
    lowered_reason = llm_reason.lower()
    if lowered_reason.startswith("error:") or "litellm unavailable" in lowered_reason or "json parse error" in lowered_reason:
        raise RuntimeError(f"SkillWard LLM triage failed: {llm_reason}")

    runtime = payload.get("runtime") if isinstance(payload.get("runtime"), dict) else {}
    if bool(prescan.get("needs_sandbox", False)) and not runtime:
        raise RuntimeError("SkillWard runtime scan was required but produced no result")


def _raise_for_runtime_skill_audit_errors(payload: dict[str, Any]) -> None:
    for item in payload.get("run_results", []):
        if not isinstance(item, dict):
            continue
        status = str(item.get("status", "")).strip().lower()
        evaluation = item.get("evaluation") if isinstance(item.get("evaluation"), dict) else {}
        outcome = str(evaluation.get("outcome", "")).strip().lower()
        if status not in {"completed", "defended"} and outcome in {
            "infra_failure",
            "prep_failure",
            "semantic_failure",
        }:
            reason = str(evaluation.get("reason", "")).strip()
            suffix = f": {reason}" if reason else ""
            raise RuntimeError(f"Runtime Skill Audit task failed with {outcome}{suffix}")


def _map_skillsieve_prediction(payload: dict[str, Any]) -> str:
    verdict = str(payload.get("final_verdict", "safe")).strip().lower()
    if verdict == "malicious":
        return "malicious"
    if verdict == "suspicious":
        return "suspicious"
    return "benign"


def _map_skillward_prediction(payload: dict[str, Any]) -> str:
    prescan = payload.get("prescan") if isinstance(payload.get("prescan"), dict) else {}
    runtime = payload.get("runtime") if isinstance(payload.get("runtime"), dict) else {}
    runtime_status = str(runtime.get("status", "")).strip().lower()
    safety_verdict = str(prescan.get("safety_verdict", "")).strip().upper()

    if int(runtime.get("blocks", 0) or 0) > 0 or runtime_status in {"high risk", "malicious", "unsafe"}:
        return "malicious"
    if safety_verdict == "UNSAFE":
        return "malicious"
    if runtime_status in {"medium risk", "suspicious", "timeout", "error", "incomplete"}:
        return "suspicious"
    if bool(runtime.get("agent_crashed", False)) or int(runtime.get("content_risks", 0) or 0) > 0:
        return "suspicious"
    if bool(prescan.get("needs_sandbox", False)) and not runtime:
        return "suspicious"

    severity = str(prescan.get("max_severity", "")).strip().upper()
    if not safety_verdict and severity in {"CRITICAL", "HIGH"}:
        return "malicious"
    if not safety_verdict and severity in {"MEDIUM", "LOW"}:
        return "suspicious"
    return "benign"


def _map_runtime_skill_audit_prediction(payload: dict[str, Any]) -> str:
    verdicts: set[str] = set()
    labels: set[str] = set()
    for item in payload.get("run_results", []):
        if not isinstance(item, dict):
            continue
        assessment = item.get("harmfulness_assessment")
        if not isinstance(assessment, dict):
            continue
        verdicts.add(str(assessment.get("verdict", "")).strip().lower())
        labels.add(str(assessment.get("harmfulness_label", "")).strip().lower())
    if {"harmful_executed", "harmful_blocked"} & verdicts or "harmful" in labels:
        return "malicious"
    if "uncertain" in verdicts or "uncertain" in labels or not verdicts:
        return "suspicious"
    if verdicts == {"benign_executed"}:
        return "benign"
    return "suspicious"


def _map_skillfortify_prediction(payload: dict[str, Any]) -> str:
    severities = {
        str(item.get("max_severity", "")).strip().upper()
        for item in payload.get("skills", [])
        if isinstance(item, dict)
    }
    if {"CRITICAL", "HIGH"} & severities:
        return "malicious"
    if {"MEDIUM", "LOW"} & severities:
        return "suspicious"
    if any(not bool(item.get("is_safe", False)) for item in payload.get("skills", []) if isinstance(item, dict)):
        return "suspicious"
    return "benign"


def _map_skill_sentinel_prediction(payload: dict[str, Any]) -> str:
    assessment = payload.get("overall_risk_assessment")
    if not isinstance(assessment, dict):
        assessment = {}
    verdict = str(assessment.get("skill_verdict", "")).strip().upper()
    if verdict == "MALICIOUS":
        return "malicious"
    if verdict == "SUSPICIOUS":
        return "suspicious"
    if verdict == "SAFE":
        return "benign"

    level = str(assessment.get("risk_level", "")).strip().upper()
    if level in {"CRITICAL", "HIGH"}:
        return "malicious"
    if level in {"MEDIUM", "LOW"}:
        return "suspicious"
    severities = {
        str(item.get("severity", "")).strip().upper()
        for item in payload.get("validated_findings", [])
        if isinstance(item, dict)
    }
    if {"CRITICAL", "HIGH"} & severities:
        return "malicious"
    if severities:
        return "suspicious"
    return "benign"


def _map_skillward_score(payload: dict[str, Any], predicted: str) -> float:
    runtime = payload.get("runtime") if isinstance(payload.get("runtime"), dict) else {}
    runtime_status = str(runtime.get("status", "")).strip().lower()
    if runtime_status == "high risk" or int(runtime.get("blocks", 0) or 0) > 0:
        return 0.95
    if runtime_status == "medium risk":
        return 0.65
    prescan = payload.get("prescan") if isinstance(payload.get("prescan"), dict) else {}
    confidence = _as_float(prescan.get("safety_confidence"), default=0.0)
    if confidence:
        return _score_from_confidence(predicted, confidence)
    return _score_for_prediction(predicted)


def _map_runtime_skill_audit_score(payload: dict[str, Any], predicted: str) -> float:
    confidence_ranks = {"low": 0, "medium": 1, "high": 2}
    ranks = []
    for item in payload.get("run_results", []):
        if not isinstance(item, dict):
            continue
        assessment = item.get("harmfulness_assessment")
        if isinstance(assessment, dict):
            ranks.append(confidence_ranks.get(str(assessment.get("confidence", "")).lower(), 1))
    rank = max(ranks, default=1)
    if predicted == "malicious":
        return (0.75, 0.85, 0.95)[rank]
    if predicted == "suspicious":
        return (0.5, 0.6, 0.7)[rank]
    return (0.2, 0.1, 0.05)[rank]


def _map_skill_sentinel_score(payload: dict[str, Any], predicted: str) -> float:
    assessment = payload.get("overall_risk_assessment")
    if not isinstance(assessment, dict):
        assessment = {}
    numeric_score = _first_numeric_score(assessment, payload)
    if numeric_score is None:
        level = str(assessment.get("risk_level", "")).strip().upper()
        level_scores = {
            "CRITICAL": 0.98,
            "HIGH": 0.9,
            "MEDIUM": 0.65,
            "LOW": 0.4,
            "SAFE": 0.05,
        }
        numeric_score = level_scores.get(level, _score_for_prediction(predicted))
    return _directional_score(predicted, numeric_score)


def _skillsieve_patterns(payload: dict[str, Any]) -> list[str]:
    patterns: set[str] = set()
    for layer in payload.get("layer_results", []):
        if not isinstance(layer, dict):
            continue
        _add_pattern_values(patterns, layer.get("evidence"))
        details = layer.get("details")
        if isinstance(details, dict):
            _collect_detail_patterns(details, patterns)
    return sorted(patterns)


def _skillward_patterns(payload: dict[str, Any]) -> list[str]:
    patterns: set[str] = set()
    prescan = payload.get("prescan") if isinstance(payload.get("prescan"), dict) else {}
    for finding in prescan.get("findings", []):
        if isinstance(finding, dict):
            _add_preferred_finding_pattern(patterns, finding)
    _add_pattern_values(patterns, prescan.get("key_threats"))
    runtime = payload.get("runtime") if isinstance(payload.get("runtime"), dict) else {}
    _add_pattern_values(patterns, runtime.get("details"))
    return sorted(patterns)


def _runtime_skill_audit_patterns(payload: dict[str, Any]) -> list[str]:
    patterns: set[str] = set()
    profile = payload.get("profile") if isinstance(payload.get("profile"), dict) else {}
    for target in profile.get("static_risk_targets", []):
        if isinstance(target, dict):
            _add_pattern_values(patterns, target.get("risk_signals"))
    for item in payload.get("run_results", []):
        if not isinstance(item, dict):
            continue
        assessment = item.get("harmfulness_assessment")
        if isinstance(assessment, dict):
            _add_pattern_values(patterns, assessment.get("evidence"))
    return sorted(patterns)


def _skillfortify_patterns(payload: dict[str, Any]) -> list[str]:
    patterns: set[str] = set()
    for skill in payload.get("skills", []):
        if not isinstance(skill, dict):
            continue
        for finding in skill.get("findings", []):
            if isinstance(finding, dict):
                _add_preferred_finding_pattern(
                    patterns,
                    finding,
                    keys=("attack_type", "attack_class", "finding_type"),
                )
    return sorted(patterns)


def _skill_sentinel_patterns(payload: dict[str, Any]) -> list[str]:
    patterns: set[str] = set()
    for finding in payload.get("validated_findings", []):
        if isinstance(finding, dict):
            _add_preferred_finding_pattern(patterns, finding, keys=("id", "category"))
    return sorted(patterns)


def _select_skill_mapping(mapping: dict[str, Any], skill_name: str) -> dict[str, Any]:
    exact = mapping.get(skill_name)
    if isinstance(exact, dict):
        return exact
    if len(mapping) == 1:
        only = next(iter(mapping.values()))
        return only if isinstance(only, dict) else {}
    return {}


def _resolve_tool_executable(tool_directory: str, executable: str, *, fallback: str | None = None) -> str:
    for environment in (".venv", "venv"):
        candidate = _BASELINE_ROOT / tool_directory / environment / "bin" / executable
        if candidate.is_file():
            return str(candidate)
    return fallback or executable


def _extract_json_value(stdout: str) -> Any | None:
    text = stdout.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    for opening, closing in (("[", "]"), ("{", "}")):
        start = text.find(opening)
        end = text.rfind(closing)
        if start == -1 or end < start:
            continue
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            continue
    return None


def _collect_detail_patterns(value: Any, patterns: set[str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).strip().lower() in _PATTERN_DETAIL_KEYS:
                _add_pattern_values(patterns, item)
            if isinstance(item, (dict, list)):
                _collect_detail_patterns(item, patterns)
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, (dict, list)):
                _collect_detail_patterns(item, patterns)


def _add_preferred_finding_pattern(
    patterns: set[str],
    finding: dict[str, Any],
    *,
    keys: tuple[str, ...] = ("rule_id", "pattern_id", "attack_type", "category", "type"),
) -> None:
    for key in keys:
        values: set[str] = set()
        _add_pattern_values(values, finding.get(key))
        if values:
            patterns.update(values)
            return


def _add_pattern_values(patterns: set[str], value: Any) -> None:
    if isinstance(value, (list, tuple, set)):
        for item in value:
            _add_pattern_values(patterns, item)
        return
    if isinstance(value, dict):
        _collect_detail_patterns(value, patterns)
        return
    if value is None or isinstance(value, bool):
        return
    text = str(value).strip()
    if text:
        patterns.add(text)


def _score_from_confidence(predicted: str, confidence: float) -> float:
    confidence = _clamp(confidence)
    if predicted == "malicious":
        return max(0.75, confidence)
    if predicted == "suspicious":
        return min(0.74, max(0.4, confidence))
    return min(0.25, 1.0 - confidence)


def _score_for_prediction(predicted: str) -> float:
    if predicted == "malicious":
        return 0.95
    if predicted == "suspicious":
        return 0.6
    return 0.1


def _directional_score(predicted: str, score: float) -> float:
    score = _clamp(score)
    if predicted == "malicious":
        return max(0.75, score)
    if predicted == "suspicious":
        return min(0.74, max(0.4, score))
    return min(0.25, score)


def _first_numeric_score(*mappings: dict[str, Any]) -> float | None:
    for mapping in mappings:
        for key in ("risk_score", "score"):
            value = mapping.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                continue
            score = float(value)
            if score > 1.0:
                score /= 100.0
            return _clamp(score)
    return None


def _as_float(value: Any, *, default: float) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return default
    return result if math.isfinite(result) else default


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))
