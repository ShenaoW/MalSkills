from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from skillguard.utils import ensure_dir, load_env_file


@dataclass(frozen=True)
class RuntimeProfile:
    name: str
    model_env: str
    api_key_env: str
    base_url_envs: tuple[str, ...]


PROFILES = (
    RuntimeProfile(
        name="claude",
        model_env="RQ3_CLAUDE_MODEL",
        api_key_env="RQ3_CLAUDE_API_KEY",
        base_url_envs=("CLAUDE_API_URL", "PACKY_API_URL"),
    ),
    RuntimeProfile(
        name="gemini",
        model_env="RQ3_GEMINI_MODEL",
        api_key_env="RQ3_GEMINI_API_KEY",
        base_url_envs=("GEMINI_API_URL", "PACKY_API_URL"),
    ),
    RuntimeProfile(
        name="qwen",
        model_env="RQ3_QWEN_MODEL",
        api_key_env="RQ3_QWEN_API_KEY",
        base_url_envs=("RQ3_QWEN_API_URL", "QWEN_API_URL", "PACKY_API_URL"),
    ),
    RuntimeProfile(
        name="deepseek",
        model_env="RQ3_DEEPSEEK_MODEL",
        api_key_env="RQ3_DEEPSEEK_API_KEY",
        base_url_envs=("DEEPSEEK_API_URL", "DEEPSEKK_API_URL"),
    ),
)


def _first_set_env(*names: str) -> tuple[str | None, str]:
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return name, value
    return None, ""


def _build_env(profile: RuntimeProfile, timeout_sec: int) -> dict[str, str]:
    model = os.environ.get(profile.model_env, "").strip()
    api_key = os.environ.get(profile.api_key_env, "").strip()
    base_url_name, base_url = _first_set_env(*profile.base_url_envs)
    missing: list[str] = []
    if not model:
        missing.append(profile.model_env)
    if not api_key:
        missing.append(profile.api_key_env)
    if not base_url:
        missing.extend(profile.base_url_envs)
    if missing:
        missing_text = ", ".join(missing)
        raise RuntimeError(f"profile '{profile.name}' is missing required env vars: {missing_text}")
    env = os.environ.copy()
    env.update(
        {
            "SKILLGUARD_LLM_MODE": "openai_api",
            "SKILLGUARD_LLM_MODEL": model,
            "SKILLGUARD_LLM_API_KEY": api_key,
            "SKILLGUARD_LLM_BASE_URL": base_url,
            "SKILLGUARD_LLM_TIMEOUT_SEC": str(timeout_sec),
            "SKILLGUARD_LLM_CACHE": str((ROOT / ".cache" / "rq3" / profile.name / "evidence").resolve()),
            "SKILLGUARD_LLM_REASONING_CACHE": str((ROOT / ".cache" / "rq3" / profile.name / "reasoning").resolve()),
        }
    )
    env["RQ3_ACTIVE_BASE_URL_ENV"] = base_url_name or ""
    return env


def _run(command: list[str], *, env: dict[str, str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=str(cwd), env=env, check=True, capture_output=True, text=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--benchmark", default="output/ground_truth_final_benchmark.json")
    parser.add_argument("--output", default="output/rq3_llm_comparison")
    parser.add_argument("--variant", default="benchmark_full")
    parser.add_argument("--timeout-sec", type=int, default=45)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--profile", action="append", choices=[profile.name for profile in PROFILES], dest="profiles")
    parser.add_argument("--skip-render", action="store_true")
    args = parser.parse_args()

    load_env_file(ROOT)
    selected_profiles = [profile for profile in PROFILES if not args.profiles or profile.name in set(args.profiles)]
    output_root = (ROOT / args.output).resolve()
    ensure_dir(output_root)

    rows: list[dict[str, object]] = []
    for profile in selected_profiles:
        env = _build_env(profile, timeout_sec=args.timeout_sec)
        profile_dir = output_root / profile.name
        ensure_dir(profile_dir)

        config_result = _run(
            [sys.executable, "-m", "skillguard.cli", "show-llm-config"],
            env=env,
            cwd=ROOT,
        )
        config_payload = json.loads(config_result.stdout)
        (profile_dir / "resolved_runtime.json").write_text(
            json.dumps(config_payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )

        eval_result = _run(
            [
                sys.executable,
                "-m",
                "skillguard.cli",
                "run-eval",
                "--benchmark",
                str((ROOT / args.benchmark).resolve()),
                "--output",
                str(profile_dir),
                "--variant",
                args.variant,
                *([] if args.limit is None else ["--limit", str(args.limit)]),
            ],
            env=env,
            cwd=ROOT,
        )
        (profile_dir / "run_eval_stdout.txt").write_text(eval_result.stdout, encoding="utf-8")
        (profile_dir / "run_eval_stderr.txt").write_text(eval_result.stderr, encoding="utf-8")

        if not args.skip_render:
            render_result = _run(
                [sys.executable, "-m", "skillguard.cli", "render-report", "--results", str(profile_dir)],
                env=env,
                cwd=ROOT,
            )
            (profile_dir / "render_report_stdout.txt").write_text(render_result.stdout, encoding="utf-8")
            (profile_dir / "render_report_stderr.txt").write_text(render_result.stderr, encoding="utf-8")

        report_path = profile_dir / f"eval_{args.variant}.json"
        report_payload = json.loads(report_path.read_text(encoding="utf-8"))
        metrics = report_payload["metrics"]
        rows.append(
            {
                "profile": profile.name,
                "model": config_payload["model"],
                "backend": config_payload["resolved_backend"],
                "base_url_env": env.get("RQ3_ACTIVE_BASE_URL_ENV", ""),
                "tp": int(metrics["tp"]),
                "fp": int(metrics["fp"]),
                "tn": int(metrics["tn"]),
                "fn": int(metrics["fn"]),
                "precision": metrics["precision"],
                "recall": metrics["recall"],
                "f1": metrics["f1"],
                "false_positive_rate": metrics["false_positive_rate"],
            }
        )

    summary_json = output_root / "rq3_llm_comparison_summary.json"
    summary_csv = output_root / "rq3_llm_comparison_summary.csv"
    summary_payload = {
        "benchmark": str((ROOT / args.benchmark).resolve()),
        "variant": args.variant,
        "limit": args.limit,
        "profiles": rows,
    }
    summary_json.write_text(json.dumps(summary_payload, indent=2, sort_keys=True), encoding="utf-8")

    fieldnames = [
        "profile",
        "model",
        "backend",
        "base_url_env",
        "tp",
        "fp",
        "tn",
        "fn",
        "precision",
        "recall",
        "f1",
        "false_positive_rate",
    ]
    with summary_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(json.dumps(summary_payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
