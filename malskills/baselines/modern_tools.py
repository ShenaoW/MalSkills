from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from ..utils import ensure_dir
from .codex_bridge import resolve_baseline_codex_config
from .external_tools import (
    DEFAULT_TIMEOUT_SEC,
    _extract_json_object,
    _finalize_baseline_result,
    _load_json_file,
    _resolve_primary_skill_root,
    _run_baseline_command,
    _run_json_baseline_command,
)


MODERN_TOOLS_TIMEOUT_SEC = max(DEFAULT_TIMEOUT_SEC, 300)
_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def run_skillspector_baseline(skill_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    skill_root = Path(skill_path).resolve()
    destination = Path(output_dir)
    ensure_dir(destination)

    repo_root = _baseline_repo("skillspector", "SkillSpector")
    llm_runtime = resolve_baseline_codex_config()
    command, env_overrides = _python_tool_command(
        repo_root=repo_root,
        source_root=repo_root / "src",
        module="skillspector.cli",
        entry_file=repo_root / "src" / "skillspector" / "cli.py",
        executable="skillspector",
        args=["scan", str(skill_root), "--format", "json"],
    )
    env_overrides = dict(env_overrides or {})
    env_overrides.update(
        {
            "SKILLSPECTOR_PROVIDER": "codex_cli",
            "SKILLSPECTOR_MODEL": llm_runtime.model,
            "PATH": os.pathsep.join(
                [str(Path(llm_runtime.cli_path).resolve().parent), os.environ.get("PATH", "")]
            ),
        }
    )
    payload = _run_required_json_baseline_command(
        command,
        env_overrides=env_overrides,
        timeout_sec=MODERN_TOOLS_TIMEOUT_SEC,
    )
    predicted, score, patterns = _normalize_skillspector(payload)
    return _finalize_baseline_result(
        destination=destination,
        artifact_name="skillspector_report.json",
        manifest_key="skillspector_report",
        payload=payload,
        runtime={
            "tool": "skillspector",
            "command": command,
            "llm_backend": "codex_cli",
            "llm_model": llm_runtime.model,
        },
        predicted=predicted,
        score=score,
        patterns=patterns,
    )


def run_agentverus_baseline(skill_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    skill_root = _resolve_primary_skill_root(skill_path)
    destination = Path(output_dir)
    ensure_dir(destination)

    repo_root = _baseline_repo("agentverus", "agentverus-scanner")
    command = _node_tool_command(
        repo_root=repo_root,
        dist_entry=repo_root / "dist" / "scanner" / "cli.js",
        source_entry=repo_root / "src" / "scanner" / "cli.ts",
        executable="agentverus",
        args=["scan", str(skill_root), "--json"],
    )
    payload = _run_required_json_baseline_command(command, timeout_sec=MODERN_TOOLS_TIMEOUT_SEC)
    predicted, score, patterns = _normalize_agentverus(payload)
    return _finalize_baseline_result(
        destination=destination,
        artifact_name="agentverus_report.json",
        manifest_key="agentverus_report",
        payload=payload,
        runtime={"tool": "agentverus", "command": command},
        predicted=predicted,
        score=score,
        patterns=patterns,
    )


def run_skilltotal_baseline(skill_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    skill_root = Path(skill_path).resolve()
    destination = Path(output_dir)
    ensure_dir(destination)

    repo_root = _baseline_repo("skilltotal")
    command, env_overrides = _python_tool_command(
        repo_root=repo_root,
        source_root=repo_root,
        module="skilltotal",
        entry_file=repo_root / "skilltotal" / "__main__.py",
        executable="skilltotal",
        args=["scan", str(skill_root), "--json"],
    )
    payload = _run_required_json_baseline_command(
        command,
        env_overrides=env_overrides,
        timeout_sec=MODERN_TOOLS_TIMEOUT_SEC,
    )
    predicted, score, patterns = _normalize_skilltotal(payload)
    return _finalize_baseline_result(
        destination=destination,
        artifact_name="skilltotal_report.json",
        manifest_key="skilltotal_report",
        payload=payload,
        runtime={"tool": "skilltotal", "command": command},
        predicted=predicted,
        score=score,
        patterns=patterns,
    )


def run_clawvet_baseline(skill_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    skill_root = _resolve_primary_skill_root(skill_path)
    destination = Path(output_dir)
    ensure_dir(destination)

    repo_root = _baseline_repo("clawvet")
    command = _node_tool_command(
        repo_root=repo_root,
        dist_entry=repo_root / "packages" / "cli" / "dist" / "index.js",
        source_entry=repo_root / "packages" / "cli" / "src" / "index.ts",
        executable="clawvet",
        args=["scan", str(skill_root), "--format", "json"],
        extra_local_bins=[repo_root / "packages" / "cli" / "node_modules" / ".bin"],
    )
    payload = _run_required_json_baseline_command(command, timeout_sec=MODERN_TOOLS_TIMEOUT_SEC)
    predicted, score, patterns = _normalize_clawvet(payload)
    return _finalize_baseline_result(
        destination=destination,
        artifact_name="clawvet_report.json",
        manifest_key="clawvet_report",
        payload=payload,
        runtime={"tool": "clawvet", "command": command},
        predicted=predicted,
        score=score,
        patterns=patterns,
    )


def run_razin_baseline(skill_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    skill_root = Path(skill_path).resolve()
    destination = Path(output_dir)
    ensure_dir(destination)

    repo_root = _baseline_repo("razin")
    native_output = destination / "razin_native"
    ensure_dir(native_output)
    command, env_overrides = _python_tool_command(
        repo_root=repo_root,
        source_root=repo_root / "src",
        module="razin.cli.main",
        entry_file=repo_root / "src" / "razin" / "cli" / "main.py",
        executable="razin",
        args=[
            "scan",
            "--root",
            str(skill_root),
            "--output-dir",
            str(native_output),
            "--output-format",
            "json",
            "--no-cache",
            "--no-stdout",
        ],
    )
    completed = _run_baseline_command(
        command,
        env_overrides=env_overrides,
        timeout_sec=MODERN_TOOLS_TIMEOUT_SEC,
    )
    if completed.returncode != 0:
        raise subprocess.CalledProcessError(
            completed.returncode,
            command,
            output=completed.stdout,
            stderr=completed.stderr,
        )

    summaries = [_load_json_file(path) for path in sorted(native_output.rglob("summary.json"))]
    findings = _load_razin_findings(native_output)
    if not summaries:
        stdout_payload = _extract_json_object(completed.stdout)
        summaries = _dict_items(stdout_payload.get("summaries")) if stdout_payload else []
        if not findings and stdout_payload:
            findings = _dict_items(stdout_payload.get("findings"))
    if not summaries:
        raise FileNotFoundError(f"Razin summary.json not found under {native_output}")

    payload = {
        "schema_version": "malskills-razin-adapter-v1",
        "summaries": summaries,
        "findings": findings,
    }
    predicted, score, patterns = _normalize_razin(payload)
    return _finalize_baseline_result(
        destination=destination,
        artifact_name="razin_report.json",
        manifest_key="razin_report",
        payload=payload,
        runtime={"tool": "razin", "command": command, "native_output": str(native_output)},
        predicted=predicted,
        score=score,
        patterns=patterns,
    )


def run_openclaw_clawscan_baseline(skill_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    skill_root = Path(skill_path).resolve()
    destination = Path(output_dir)
    ensure_dir(destination)

    repo_root = _baseline_repo("openclaw-clawscan", "openclaw_clawscan")
    command, cwd = _openclaw_clawscan_command(repo_root, skill_root)
    payload = _run_json_command_with_cwd(command, cwd=cwd)
    predicted, score, patterns = _normalize_openclaw_clawscan(payload)
    return _finalize_baseline_result(
        destination=destination,
        artifact_name="openclaw_clawscan_report.json",
        manifest_key="openclaw_clawscan_report",
        payload=payload,
        runtime={"tool": "openclaw-clawscan", "command": command, "cwd": str(cwd) if cwd else ""},
        predicted=predicted,
        score=score,
        patterns=patterns,
    )


def _baseline_repo(*names: str) -> Path:
    candidates = [_PROJECT_ROOT / "baseline" / name for name in names]
    for candidate in candidates:
        if candidate.is_dir() and any(candidate.iterdir()):
            return candidate
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def _python_tool_command(
    *,
    repo_root: Path,
    source_root: Path,
    module: str,
    entry_file: Path,
    executable: str,
    args: list[str],
) -> tuple[list[str], dict[str, str] | None]:
    if entry_file.is_file():
        python_bin = repo_root / ".venv" / "bin" / "python"
        command = [str(python_bin) if python_bin.is_file() else sys.executable, "-m", module, *args]
        return command, {"PYTHONPATH": str(source_root.resolve())}
    return [executable, *args], None


def _node_tool_command(
    *,
    repo_root: Path,
    dist_entry: Path,
    source_entry: Path,
    executable: str,
    args: list[str],
    extra_local_bins: list[Path] | None = None,
) -> list[str]:
    if dist_entry.is_file():
        return ["node", str(dist_entry.resolve()), *args]

    local_bin_dirs = [repo_root / "node_modules" / ".bin", *(extra_local_bins or [])]
    for bin_dir in local_bin_dirs:
        tsx = bin_dir / "tsx"
        if source_entry.is_file() and tsx.is_file():
            return [str(tsx.resolve()), str(source_entry.resolve()), *args]
    for bin_dir in local_bin_dirs:
        local_cli = bin_dir / executable
        if local_cli.is_file():
            return [str(local_cli.resolve()), *args]
    return [executable, *args]


def _openclaw_clawscan_command(repo_root: Path, skill_root: Path) -> tuple[list[str], Path | None]:
    args = [str(skill_root), "--scanner", "clawscan-static", "--json"]
    for candidate in (repo_root / "clawscan", repo_root / "bin" / "clawscan"):
        if candidate.is_file():
            return [str(candidate.resolve()), *args], repo_root
    if (repo_root / "cmd" / "clawscan" / "main.go").is_file():
        return ["go", "run", "./cmd/clawscan", *args], repo_root
    return ["clawscan", *args], None


def _run_json_command_with_cwd(command: list[str], *, cwd: Path | None) -> dict[str, Any]:
    completed = _run_baseline_command(
        command,
        cwd=cwd,
        timeout_sec=MODERN_TOOLS_TIMEOUT_SEC,
    )
    payload = _extract_json_object(completed.stdout)
    if completed.returncode != 0 and not payload:
        raise subprocess.CalledProcessError(
            completed.returncode,
            command,
            output=completed.stdout,
            stderr=completed.stderr,
        )
    if not payload:
        raise ValueError(f"{command[0]} did not emit a JSON object")
    return payload


def _run_required_json_baseline_command(
    command: list[str],
    *,
    env_overrides: dict[str, str] | None = None,
    timeout_sec: int,
) -> dict[str, Any]:
    payload = _run_json_baseline_command(
        command,
        env_overrides=env_overrides,
        timeout_sec=timeout_sec,
    )
    if not payload:
        raise ValueError(f"{command[0]} did not emit a JSON object")
    return payload


def _normalize_skillspector(payload: dict[str, Any]) -> tuple[str, float, list[str]]:
    assessment = _mapping(payload.get("risk_assessment"))
    findings = _first_dict_list(payload, "issues", "findings", "vulnerabilities")
    recommendation = _first_text(
        assessment.get("recommendation"),
        payload.get("recommendation"),
        payload.get("verdict"),
    )
    severity = _first_text(
        assessment.get("severity"),
        payload.get("risk_level"),
        payload.get("max_severity"),
        payload.get("severity"),
    )
    predicted = _prediction_from_label(recommendation)
    if predicted is None:
        predicted = _prediction_from_severity(severity or _max_finding_severity(findings))
    score_value = _first_value(assessment, ("score", "risk_score", "riskScore"))
    if score_value is None:
        score_value = _first_value(payload, ("risk_score", "riskScore", "score"))
    return predicted, _calibrated_score(score_value, predicted, percent_scale=True), _patterns(findings)


def _normalize_agentverus(payload: dict[str, Any]) -> tuple[str, float, list[str]]:
    reports: list[dict[str, Any]] = []
    wrapped = payload.get("reports")
    if isinstance(wrapped, list):
        failures = payload.get("failures")
        if isinstance(failures, list) and failures:
            raise RuntimeError(f"AgentVerus reported {len(failures)} failed scan target(s)")
        for item in wrapped:
            entry = _mapping(item)
            report = _mapping(entry.get("report")) or entry
            if report:
                reports.append(report)
        if not reports:
            raise ValueError("AgentVerus did not return any completed scan reports")
    else:
        reports.append(payload)

    findings = [finding for report in reports for finding in _first_dict_list(report, "findings", "issues")]
    badges = {_first_text(report.get("badge")) for report in reports}
    badges.discard("")
    severities = {_finding_severity(finding) for finding in findings}

    if "rejected" in badges or "critical" in severities:
        predicted = "malicious"
    elif {"suspicious", "conditional"} & badges or severities & {"high", "medium", "low"}:
        predicted = "suspicious"
    else:
        predicted = "benign"

    risk_scores: list[float] = []
    for report in reports:
        explicit_risk = _first_value(report, ("risk_score", "riskScore"))
        if explicit_risk is not None:
            normalized = _score01(explicit_risk, percent_scale=True)
        else:
            trust_score = _first_value(report, ("overall", "trust_score", "trustScore", "score"))
            normalized_trust = _score01(trust_score, percent_scale=True)
            normalized = 1.0 - normalized_trust if normalized_trust is not None else None
        if normalized is not None:
            risk_scores.append(normalized)
    raw_score = max(risk_scores) if risk_scores else None
    return predicted, _calibrated_score(raw_score, predicted), _patterns(findings)


def _normalize_skilltotal(payload: dict[str, Any]) -> tuple[str, float, list[str]]:
    findings = _first_dict_list(payload, "findings", "issues")
    review_items = _first_dict_list(payload, "needs_review", "needsReview")
    verdict = _mapping(payload.get("verdict"))
    level = _first_text(verdict.get("level"), payload.get("risk_level"), payload.get("riskLevel"))
    has_malicious = verdict.get("has_malicious_indicators") is True or payload.get("malicious") is True
    if has_malicious or level == "malicious":
        predicted = "malicious"
    elif level in {"critical", "high", "medium", "warning", "review"} or findings or review_items:
        predicted = "suspicious"
    else:
        predicted = "benign"
    score_value = _first_value(payload, ("risk_score", "riskScore", "score"))
    patterns = sorted({*_patterns(findings), *_patterns(review_items)})
    return predicted, _calibrated_score(score_value, predicted, percent_scale=True), patterns


def _normalize_clawvet(payload: dict[str, Any]) -> tuple[str, float, list[str]]:
    findings = _first_dict_list(payload, "findings", "issues")
    status = _first_text(payload.get("status"))
    if status in {"failed", "error"}:
        raise RuntimeError(f"ClawVet scan status was {status}")

    recommendation = _first_text(payload.get("recommendation"), payload.get("verdict"))
    grade = _first_text(payload.get("riskGrade"), payload.get("risk_grade")).upper()
    disqualifying = any(finding.get("disqualifying") is True for finding in findings)
    if disqualifying or recommendation in {"block", "reject", "malicious"} or grade == "F":
        predicted = "malicious"
    elif recommendation in {"warn", "review", "caution"} or grade in {"C", "D"} or findings:
        predicted = "suspicious"
    else:
        predicted = "benign"
    score_value = _first_value(payload, ("riskScore", "risk_score", "score"))
    return predicted, _calibrated_score(score_value, predicted, percent_scale=True), _patterns(findings)


def _load_razin_findings(native_output: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in sorted(native_output.rglob("findings.json")):
        raw = json.loads(path.read_text(encoding="utf-8"))
        findings.extend(_dict_items(raw))
    return findings


def _normalize_razin(payload: dict[str, Any]) -> tuple[str, float, list[str]]:
    summaries = _dict_items(payload.get("summaries"))
    findings = _dict_items(payload.get("findings"))
    verdicts = {
        _first_text(summary.get("evidence_verdict"), summary.get("verdict"))
        for summary in summaries
    }
    severities = {
        _first_text(
            summary.get("review_priority_level"),
            summary.get("overall_severity"),
            summary.get("severity"),
        )
        for summary in summaries
    }
    severities.update(_finding_severity(finding) for finding in findings)

    malicious_verdicts = {
        "high-confidence-malicious-evidence",
        "contains-high-confidence-malicious-evidence",
    }
    if verdicts & malicious_verdicts:
        predicted = "malicious"
    elif verdicts & {"review-required", "capability-only"} or severities & {"high", "medium", "low"} or findings:
        predicted = "suspicious"
    else:
        predicted = "benign"

    score_values = [
        _score01(
            _first_value(summary, ("review_priority", "overall_score", "risk_score", "score")),
            percent_scale=True,
        )
        for summary in summaries
    ]
    raw_score = max((score for score in score_values if score is not None), default=None)
    patterns = set(_patterns(findings))
    for summary in summaries:
        counts = _mapping(summary.get("counts_by_rule"))
        patterns.update(str(rule_id).strip() for rule_id in counts if str(rule_id).strip())
        patterns.update(_patterns(_dict_items(summary.get("top_risks"))))
    return predicted, _calibrated_score(raw_score, predicted), sorted(patterns)


def _normalize_openclaw_clawscan(payload: dict[str, Any]) -> tuple[str, float, list[str]]:
    runs = _dict_items(payload.get("runs")) if isinstance(payload.get("runs"), list) else [payload]
    reports: list[dict[str, Any]] = []
    for run in runs:
        if _first_text(run.get("schemaVersion"), run.get("schema_version")) == "clawscan-static-v1":
            reports.append(run)
            continue
        scanners = _mapping(run.get("scanners"))
        scanner = _mapping(scanners.get("clawscan-static"))
        raw = scanner.get("raw")
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except json.JSONDecodeError:
                raw = None
        report = _mapping(raw)
        if report:
            reports.append(report)
        elif scanner:
            reports.append(scanner)

    findings = [finding for report in reports for finding in _first_dict_list(report, "findings", "issues")]
    severity = _max_finding_severity(findings)
    predicted = _prediction_from_severity(severity)
    score = _calibrated_score(_risk_for_severity(severity), predicted)
    return predicted, score, _patterns(findings)


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _dict_items(value: object) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def _first_dict_list(payload: dict[str, Any], *keys: str) -> list[dict[str, Any]]:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def _first_value(payload: dict[str, Any], keys: tuple[str, ...]) -> object | None:
    for key in keys:
        if key in payload and payload[key] is not None:
            return payload[key]
    return None


def _first_text(*values: object) -> str:
    for value in values:
        text = str(value).strip().lower() if value is not None else ""
        if text:
            return text
    return ""


def _finding_severity(finding: dict[str, Any]) -> str:
    return _first_text(finding.get("severity"), finding.get("level"), finding.get("risk_level"))


def _max_finding_severity(findings: list[dict[str, Any]]) -> str:
    ranks = {"info": 0, "safe": 0, "low": 1, "warning": 2, "medium": 2, "high": 3, "critical": 4}
    return max((_finding_severity(finding) for finding in findings), key=lambda value: ranks.get(value, -1), default="")


def _prediction_from_label(label: str) -> str | None:
    normalized = label.strip().lower().replace("-", "_").replace(" ", "_")
    if normalized in {"malicious", "rejected", "do_not_install", "block", "dangerous", "deny"}:
        return "malicious"
    if normalized in {"suspicious", "conditional", "caution", "warn", "warning", "review"}:
        return "suspicious"
    if normalized in {"benign", "safe", "certified", "approve", "clean", "passed", "pass"}:
        return "benign"
    return None


def _prediction_from_severity(severity: str) -> str:
    normalized = severity.strip().lower()
    if normalized in {"critical", "high"}:
        return "malicious"
    if normalized in {"medium", "warning", "low", "info"}:
        return "suspicious"
    return "benign"


def _score01(value: object, *, percent_scale: bool = False) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        is_ratio = False
        if isinstance(value, str):
            text = value.strip().rstrip("%")
            if "/" in text:
                is_ratio = True
                numerator, denominator = text.split("/", 1)
                number = float(numerator) / float(denominator)
            else:
                number = float(text)
        else:
            number = float(value)
    except (TypeError, ValueError, ZeroDivisionError):
        return None
    if percent_scale and not is_ratio:
        number /= 100.0
    elif number > 1.0:
        number /= 100.0
    return max(0.0, min(1.0, number))


def _calibrated_score(value: object, predicted: str, *, percent_scale: bool = False) -> float:
    score = _score01(value, percent_scale=percent_scale)
    if score is None:
        return {"malicious": 0.95, "suspicious": 0.6, "benign": 0.1}[predicted]
    if predicted == "malicious":
        return max(0.75, score)
    if predicted == "suspicious":
        return min(0.74, max(0.4, score))
    return min(0.25, score)


def _risk_for_severity(severity: str) -> float:
    return {
        "critical": 1.0,
        "high": 0.9,
        "medium": 0.6,
        "warning": 0.55,
        "low": 0.35,
        "info": 0.2,
    }.get(severity.strip().lower(), 0.1)


def _patterns(findings: list[dict[str, Any]]) -> list[str]:
    patterns: set[str] = set()
    for finding in findings:
        value = _first_raw_text(
            finding.get("rule_id"),
            finding.get("ruleId"),
            finding.get("id"),
            finding.get("code"),
            finding.get("category"),
            finding.get("type"),
        )
        if value:
            patterns.add(value)
    return sorted(patterns)


def _first_raw_text(*values: object) -> str:
    for value in values:
        text = str(value).strip() if value is not None else ""
        if text:
            return text
    return ""
