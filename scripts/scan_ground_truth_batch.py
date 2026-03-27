#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SampleTarget:
    source: str
    name: str
    path: Path


def resolve_python_bin() -> str:
    candidates = ["python3.10", "python3"]
    for candidate in candidates:
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
        if "Python 3.10" in version_text or "Python 3.11" in version_text or "Python 3.12" in version_text:
            return candidate
    return sys.executable


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Batch-scan data/ground_truth with baseline tools.")
    parser.add_argument(
        "--tool",
        required=True,
        choices=["nova-proximity", "ai-infra-guard"],
        help="Baseline tool to execute",
    )
    parser.add_argument(
        "--dataset-root",
        default="data/ground_truth/malicious",
        help="Ground-truth dataset root",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Output directory. Defaults to output/baseline/<tool>_ground_truth",
    )
    parser.add_argument("--limit", type=int, default=None, help="Optional max sample count")
    parser.add_argument(
        "--source",
        action="append",
        dest="sources",
        default=[],
        help="Restrict to one or more sources under malicious/, e.g. clawhub",
    )
    parser.add_argument("--resume", action="store_true", help="Skip samples with existing summary.json")
    parser.add_argument("--language", default="zh", choices=["zh", "en"], help="Output language for LLM-driven tools")
    parser.add_argument("-p", "--prompt", default="", help="Additional prompt appended for the tool")
    parser.add_argument("-m", "--model", default=None, help="Model override for LLM-driven tools")
    parser.add_argument("-k", "--api-key", dest="api_key", default=None, help="API key override for LLM-driven tools")
    parser.add_argument("-u", "--base-url", dest="base_url", default=None, help="Base URL override for LLM-driven tools")
    parser.add_argument("--agent-provider", default="", help="AI-Infra-Guard agent provider YAML")
    parser.add_argument("--nova-scan", action="store_true", help="Enable NOVA LLM analysis in nova-proximity")
    parser.add_argument("--nova-rule", default=None, help="Rule file for nova-proximity")
    parser.add_argument(
        "--nova-evaluator",
        default="openai",
        choices=["openai", "groq", "anthropic", "azure", "ollama"],
        help="Evaluator for nova-proximity NOVA mode",
    )
    return parser.parse_args()


def discover_targets(dataset_root: Path, allowed_sources: set[str] | None = None) -> list[SampleTarget]:
    targets: list[SampleTarget] = []
    for source_dir in sorted(path for path in dataset_root.iterdir() if path.is_dir()):
        if allowed_sources and source_dir.name not in allowed_sources:
            continue
        for sample_dir in sorted(path for path in source_dir.iterdir() if path.is_dir()):
            targets.append(SampleTarget(source=source_dir.name, name=sample_dir.name, path=sample_dir.resolve()))
    return targets


def build_command(args: argparse.Namespace, sample: SampleTarget, case_dir: Path) -> list[str]:
    repo_root = Path(__file__).resolve().parents[1]
    python_bin = resolve_python_bin()
    if args.tool == "nova-proximity":
        output_prefix = case_dir / "nova_proximity"
        command = [
            python_bin,
            str(repo_root / "baseline" / "nova-proximity" / "novaprox.py"),
            "--skill",
            str(sample.path),
            "--skill-recursive",
            "--json-report",
            "--output-prefix",
            str(output_prefix),
        ]
        if args.nova_scan:
            command.extend(["--nova-scan", "--evaluator", args.nova_evaluator])
            if args.nova_rule:
                command.extend(["--rule", args.nova_rule])
            if args.model:
                command.extend(["--model", args.model])
            if args.api_key:
                command.extend(["--api-key", args.api_key])
        return command

    command = [
        python_bin,
        str(repo_root / "scripts" / "run_aig_agent_scan.py"),
        "--repo",
        str(sample.path),
        "--output",
        str(case_dir / "ai_infra_guard_report.json"),
        "--language",
        args.language,
    ]
    if args.prompt:
        command.extend(["--prompt", args.prompt])
    if args.model:
        command.extend(["--model", args.model])
    if args.api_key:
        command.extend(["--api-key", args.api_key])
    if args.base_url:
        command.extend(["--base-url", args.base_url])
    if args.agent_provider:
        command.extend(["--agent-provider", args.agent_provider])
    return command


def parse_tool_summary(tool: str, case_dir: Path) -> dict[str, Any]:
    if tool == "nova-proximity":
        reports = sorted(case_dir.glob("nova_proximity_*.json"))
        if not reports:
            return {"status": "error", "error": "nova report not found"}
        report_path = reports[-1]
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        scan_results = payload.get("scan_results", {}) if isinstance(payload, dict) else {}
        nova_analysis = payload.get("nova_analysis") if isinstance(payload, dict) else {}
        if not isinstance(nova_analysis, dict):
            nova_analysis = {}
        security_flag_count = 0
        for skill in scan_results.get("skills", []) if isinstance(scan_results.get("skills"), list) else []:
            if isinstance(skill, dict):
                security_flag_count += len(skill.get("security_flags", []) or [])
        return {
            "status": "ok",
            "report": report_path.name,
            "total_skills": int(scan_results.get("total_skills", 0) or 0),
            "security_flag_count": security_flag_count,
            "nova_flagged_count": int(nova_analysis.get("flagged_count", 0) or 0),
        }

    report_path = case_dir / "ai_infra_guard_report.json"
    if not report_path.exists():
        return {"status": "error", "error": "ai-infra-guard report not found"}
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    results = payload.get("results", []) if isinstance(payload, dict) else []
    return {
        "status": "ok",
        "report": report_path.name,
        "risk_type": str(payload.get("risk_type", "")).strip(),
        "score": int(payload.get("score", 0) or 0),
        "finding_count": len(results) if isinstance(results, list) else 0,
    }


def run_one(args: argparse.Namespace, sample: SampleTarget, output_dir: Path) -> dict[str, Any]:
    case_dir = output_dir / "cases" / sample.source / sample.name
    case_dir.mkdir(parents=True, exist_ok=True)

    summary_path = case_dir / "summary.json"
    if args.resume and summary_path.exists():
        return json.loads(summary_path.read_text(encoding="utf-8"))

    command = build_command(args, sample, case_dir)
    started_at = time.time()
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[1],
    )
    runtime_sec = round(time.time() - started_at, 4)

    (case_dir / "stdout.log").write_text(completed.stdout, encoding="utf-8")
    (case_dir / "stderr.log").write_text(completed.stderr, encoding="utf-8")

    parsed = parse_tool_summary(args.tool, case_dir)
    status = "ok" if completed.returncode == 0 and parsed.get("status") == "ok" else "error"
    result = {
        "tool": args.tool,
        "source": sample.source,
        "sample": sample.name,
        "path": str(sample.path),
        "status": status,
        "returncode": completed.returncode,
        "runtime_sec": runtime_sec,
        "command": command,
        "parsed": parsed,
    }
    summary_path.write_text(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    return result


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[1]
    dataset_root = (repo_root / args.dataset_root).resolve()
    if not dataset_root.exists():
        print(f"Dataset root does not exist: {dataset_root}", file=sys.stderr)
        return 2

    output_dir = (
        Path(args.output_dir).resolve()
        if args.output_dir
        else (repo_root / "output" / "baseline" / f"{args.tool}_ground_truth").resolve()
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    allowed_sources = set(args.sources) if args.sources else None
    targets = discover_targets(dataset_root, allowed_sources)
    if args.limit is not None:
        targets = targets[: args.limit]

    results = [run_one(args, sample, output_dir) for sample in targets]
    summary = {
        "tool": args.tool,
        "dataset_root": str(dataset_root),
        "output_dir": str(output_dir),
        "sample_count": len(results),
        "ok_count": sum(1 for item in results if item["status"] == "ok"),
        "error_count": sum(1 for item in results if item["status"] != "ok"),
        "results": results,
    }
    (output_dir / "run_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "tool": args.tool,
                "sample_count": len(results),
                "ok_count": summary["ok_count"],
                "error_count": summary["error_count"],
                "output_dir": str(output_dir),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if summary["error_count"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
