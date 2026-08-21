from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import queue as queue_module
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, TextIO

from .baselines import (
    run_agentguard_baseline,
    run_agentverus_baseline,
    run_ai_infra_guard_baseline,
    run_caterpillar_baseline,
    run_clawvet_baseline,
    run_clawscan_baseline,
    run_masb_baseline,
    run_nova_proximity_baseline,
    run_openclaw_clawscan_baseline,
    run_razin_baseline,
    run_runtime_skill_audit_baseline,
    run_skill_sentinel_baseline,
    run_skill_scanner_baseline,
    run_skill_security_audit_baseline,
    run_skill_security_scan_baseline,
    run_skillfortify_baseline,
    run_skillsieve_baseline,
    run_skillspector_baseline,
    run_skills_security_audit_baseline,
    run_skilltotal_baseline,
    run_skillward_baseline,
    run_snyk_agent_scan_baseline,
)
from .baselines.external_tools import DEFAULT_TIMEOUT_SEC, SKILL_SCANNER_TIMEOUT_SEC
from .baselines.legacy_tools import LLM_BASELINE_TIMEOUT_SEC
from .baselines.modern_tools import MODERN_TOOLS_TIMEOUT_SEC
from .baselines.research_tools import RESEARCH_BASELINE_TIMEOUT_SEC
from .benchmark import load_benchmark_entries
from .models import BenchmarkEntry, to_jsonable
from .pipeline import AnalyzerConfig, SkillAnalyzer
from .utils import ensure_dir


VARIANTS: dict[str, AnalyzerConfig | str] = {
    "full": AnalyzerConfig(),
    "semgrep_findings_only": AnalyzerConfig(enable_llm_sso_extraction=False),
    "llm_findings_only": AnalyzerConfig(enable_semgrep=False, enable_llm_sso_extraction=True),
    "formal_reasoning_only": AnalyzerConfig(enable_llm_sso_extraction=True, reasoning_mode="formal"),
    "llm_reasoning_only": AnalyzerConfig(enable_llm_sso_extraction=True, reasoning_mode="llm"),
    "no_yasa": AnalyzerConfig(enable_llm_sso_extraction=True, enable_yasa=False),
    "no_cross_artifact_resolution": AnalyzerConfig(enable_llm_sso_extraction=True, enable_cross_artifact_resolution=False),
    "static_only": AnalyzerConfig(
        enable_llm_sso_extraction=False,
        enable_llm_object_analysis=False,
        enable_yasa=False,
        enable_cross_artifact_resolution=False,
        reasoning_mode="formal",
    ),
    "benchmark_full": AnalyzerConfig(max_artifacts=600, max_total_text_bytes=2_000_000),
    "benchmark_semgrep_findings_only": AnalyzerConfig(enable_llm_sso_extraction=False, max_artifacts=600, max_total_text_bytes=2_000_000),
    "benchmark_llm_findings_only": AnalyzerConfig(
        enable_semgrep=False,
        enable_llm_sso_extraction=True,
        max_artifacts=600,
        max_total_text_bytes=2_000_000,
    ),
    "benchmark_formal_reasoning_only": AnalyzerConfig(
        enable_llm_sso_extraction=True,
        reasoning_mode="formal",
        max_artifacts=600,
        max_total_text_bytes=2_000_000,
    ),
    "benchmark_llm_reasoning_only": AnalyzerConfig(enable_llm_sso_extraction=True, reasoning_mode="llm", max_artifacts=600, max_total_text_bytes=2_000_000),
    "benchmark_no_yasa": AnalyzerConfig(
        enable_llm_sso_extraction=True,
        enable_yasa=False,
        max_artifacts=600,
        max_total_text_bytes=2_000_000,
    ),
    "benchmark_no_cross_artifact_resolution": AnalyzerConfig(enable_llm_sso_extraction=True, enable_cross_artifact_resolution=False, max_artifacts=600, max_total_text_bytes=2_000_000),
    "benchmark_static_only": AnalyzerConfig(
        enable_llm_sso_extraction=False,
        enable_llm_object_analysis=False,
        enable_yasa=False,
        enable_cross_artifact_resolution=False,
        reasoning_mode="formal",
        max_artifacts=600,
        max_total_text_bytes=2_000_000,
    ),
}


def _baseline_runners():
    return {
        "masb_baseline": run_masb_baseline,
        "skill_security_audit_baseline": run_skill_security_audit_baseline,
        "skill_security_scan_baseline": run_skill_security_scan_baseline,
        "skills_security_audit_baseline": run_skills_security_audit_baseline,
        "caterpillar_baseline": run_caterpillar_baseline,
        "clawscan_baseline": run_clawscan_baseline,
        "skill_scanner_baseline": run_skill_scanner_baseline,
        "nova_proximity_baseline": run_nova_proximity_baseline,
        "snyk_agent_scan_baseline": run_snyk_agent_scan_baseline,
        "ai_infra_guard_baseline": run_ai_infra_guard_baseline,
        "agentguard_baseline": run_agentguard_baseline,
        "skillspector_baseline": run_skillspector_baseline,
        "agentverus_baseline": run_agentverus_baseline,
        "skilltotal_baseline": run_skilltotal_baseline,
        "clawvet_baseline": run_clawvet_baseline,
        "razin_baseline": run_razin_baseline,
        "openclaw_clawscan_baseline": run_openclaw_clawscan_baseline,
        "skillsieve_baseline": run_skillsieve_baseline,
        "skillward_baseline": run_skillward_baseline,
        "runtime_skill_audit_baseline": run_runtime_skill_audit_baseline,
        "skillfortify_baseline": run_skillfortify_baseline,
        "skill_sentinel_baseline": run_skill_sentinel_baseline,
    }


BASELINE_CONFIGS = tuple(_baseline_runners())

for baseline_config in BASELINE_CONFIGS:
    VARIANTS[baseline_config] = baseline_config
    VARIANTS[f"benchmark_{baseline_config}"] = baseline_config

# The outer benchmark case timeout must exceed any baseline subprocess timeout.
# Otherwise the evaluator can kill only the worker process while a detached
# baseline subprocess (started in its own session) keeps running as an orphan.
BENCHMARK_CASE_TIMEOUT_BUFFER_SEC = 30
BENCHMARK_CASE_TIMEOUT_SEC = (
    max(
        DEFAULT_TIMEOUT_SEC,
        SKILL_SCANNER_TIMEOUT_SEC,
        LLM_BASELINE_TIMEOUT_SEC,
        MODERN_TOOLS_TIMEOUT_SEC,
        RESEARCH_BASELINE_TIMEOUT_SEC,
    )
    + BENCHMARK_CASE_TIMEOUT_BUFFER_SEC
)


def _analyze_case_worker(skill_path: str, case_output_dir: str, config: AnalyzerConfig | str, queue: multiprocessing.Queue) -> None:
    try:
        if isinstance(config, str):
            runner = _baseline_runners().get(config)
            if runner is None:
                raise ValueError(f"unknown baseline config: {config}")
            queue.put({"message_type": "result", **runner(skill_path, case_output_dir)})
            return
        analyzer = SkillAnalyzer()
        result = analyzer.analyze(
            skill_path,
            output_dir=case_output_dir,
            config=config,
            progress=lambda event, fields: queue.put(
                {
                    "message_type": "progress",
                    "event": event,
                    "fields": fields,
                }
            ),
        )
        queue.put(
            {
                "message_type": "result",
                "status": "ok",
                "predicted": result.verdict.label,
                "patterns": result.verdict.malicious_patterns,
                "finding_count": len(result.findings),
                "operand_count": len(result.operands),
                "operand_resolution_count": len(result.operand_resolutions),
                "sso_count": len(result.ssos),
            }
        )
    except Exception as exc:
        queue.put(
            {
                "message_type": "result",
                "status": "error",
                "error": f"{type(exc).__name__}: {exc}",
                "predicted": "error",
                "patterns": [],
                "finding_count": 0,
                "operand_count": 0,
                "operand_resolution_count": 0,
                "sso_count": 0,
            }
        )


def _run_case_direct(skill_path: str, case_output_dir: Path, config: str) -> dict[str, object]:
    runner = _baseline_runners().get(config)
    if runner is None:
        raise ValueError(f"unknown baseline config: {config}")
    return runner(skill_path, case_output_dir)


class Evaluator:
    def __init__(
        self,
        *,
        progress: bool = False,
        progress_interval_sec: float = 30.0,
        progress_stream: TextIO | None = None,
        color: str = "auto",
    ) -> None:
        self.progress = progress
        self.progress_interval_sec = max(0.0, progress_interval_sec)
        self.progress_stream = progress_stream or sys.stderr
        self.color = color

    def _colors_enabled(self) -> bool:
        if self.color == "always":
            return True
        if self.color == "never" or os.environ.get("NO_COLOR") is not None:
            return False
        return bool(getattr(self.progress_stream, "isatty", lambda: False)())

    def _paint(self, text: str, code: str) -> str:
        if not self._colors_enabled():
            return text
        return f"\033[{code}m{text}\033[0m"

    def _emit_progress(self, message: str, *, level: str = "INFO") -> None:
        if self.progress:
            level_colors = {
                "DEBUG": "36",
                "INFO": "34",
                "SUCCESS": "32",
                "WARNING": "33",
                "ERROR": "31;1",
            }
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            rendered_level = self._paint(f"{level:<7}", level_colors.get(level, "0"))
            rendered_time = self._paint(timestamp, "2")
            print(
                f"{rendered_time} | {rendered_level} | {message}",
                file=self.progress_stream,
                flush=True,
            )

    def _format_progress_fields(self, fields: object) -> str:
        if not isinstance(fields, dict):
            return ""
        rendered = []
        for key, value in fields.items():
            if isinstance(value, (dict, list)):
                text = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
            else:
                text = str(value)
            rendered.append(f"{key}={text}")
        return " ".join(rendered)

    def run(
        self,
        benchmark_path: str | Path,
        output_dir: str | Path,
        variant: str = "full",
        limit: int | None = None,
        datasets: list[str] | None = None,
        splits: list[str] | None = None,
        labels: list[str] | None = None,
    ) -> dict[str, object]:
        config = VARIANTS[variant]
        selected_entries = self._select_entries(benchmark_path, limit=limit, datasets=datasets, splits=splits, labels=labels)
        return self._run_variant(selected_entries, output_dir, variant, config, datasets=datasets, splits=splits, labels=labels)

    def run_suite(
        self,
        benchmark_path: str | Path,
        output_dir: str | Path,
        variants: list[str] | None = None,
        limit: int | None = None,
        datasets: list[str] | None = None,
        splits: list[str] | None = None,
        labels: list[str] | None = None,
    ) -> dict[str, object]:
        selected_entries = self._select_entries(benchmark_path, limit=limit, datasets=datasets, splits=splits, labels=labels)
        chosen = variants or list(VARIANTS)
        reports = []
        for variant in chosen:
            reports.append(
                self._run_variant(
                    selected_entries,
                    output_dir,
                    variant,
                    VARIANTS[variant],
                    datasets=datasets,
                    splits=splits,
                    labels=labels,
                )
            )
        payload = {
            "variants": [report["variant"] for report in reports],
            "filters": {"datasets": datasets or [], "splits": splits or [], "labels": labels or []},
            "reports": reports,
        }
        destination = Path(output_dir)
        ensure_dir(destination)
        (destination / "eval_suite.json").write_text(json.dumps(to_jsonable(payload), indent=2, sort_keys=True), encoding="utf-8")
        return payload

    def _select_entries(
        self,
        benchmark_path: str | Path,
        *,
        limit: int | None,
        datasets: list[str] | None,
        splits: list[str] | None,
        labels: list[str] | None,
    ) -> list[BenchmarkEntry]:
        entries = [entry for entry in load_benchmark_entries(benchmark_path) if entry.analyzable and entry.local_path]
        if datasets:
            allowed = set(datasets)
            entries = [entry for entry in entries if entry.dataset in allowed]
        if splits:
            allowed = set(splits)
            entries = [entry for entry in entries if entry.split in allowed]
        if labels:
            allowed = set(labels)
            entries = [entry for entry in entries if entry.label in allowed]
        if limit is not None:
            entries = entries[:limit]
        return entries

    def _run_variant(
        self,
        entries: list[BenchmarkEntry],
        output_dir: str | Path,
        variant: str,
        config: AnalyzerConfig | str,
        *,
        datasets: list[str] | None,
        splits: list[str] | None,
        labels: list[str] | None,
    ) -> dict[str, object]:
        destination = Path(output_dir)
        ensure_dir(destination)
        results = []
        total = len(entries)
        self._emit_progress(
            f"[eval {variant}] START cases={total} output={destination.resolve()}"
        )
        for index, entry in enumerate(entries, start=1):
            started_at = time.perf_counter()
            case_output_dir = destination / "cases" / variant / self._stable_case_directory_name(entry.entry_id)
            manifest_path = case_output_dir / "output_manifest.json"
            prefix = f"[eval {variant} {index}/{total}]"
            self._emit_progress(
                f"{prefix} START gold={entry.label} id={entry.entry_id}"
            )
            case_result = self._run_case(
                entry.local_path,
                case_output_dir,
                config,
                on_wait=lambda elapsed, prefix=prefix, entry_id=entry.entry_id: self._emit_progress(
                    f"{prefix} WAIT elapsed={elapsed:.0f}s id={entry_id}",
                    level="WARNING",
                ),
                on_event=lambda event, fields, prefix=prefix: self._emit_progress(
                    f"{prefix} {event.upper().replace('.', '_')} "
                    f"{self._format_progress_fields(fields)}".rstrip(),
                    level="SUCCESS" if event.endswith(".done") else "DEBUG",
                ),
            )
            runtime_sec = time.perf_counter() - started_at
            row = {
                "entry_id": entry.entry_id,
                "dataset": entry.dataset,
                "split": entry.split,
                "label": entry.label,
                "status": case_result["status"],
                "predicted": case_result["predicted"],
                "patterns": case_result["patterns"],
                "runtime_sec": round(runtime_sec, 4),
                "finding_count": case_result["finding_count"],
                "operand_count": case_result.get("operand_count", 0),
                "operand_resolution_count": case_result["operand_resolution_count"],
                "sso_count": case_result["sso_count"],
                "analysis_output_dir": str(case_output_dir.relative_to(destination)),
                "analysis_manifest_path": str(manifest_path.relative_to(destination)),
                "error": case_result.get("error", ""),
            }
            if "score" in case_result:
                row["score"] = case_result["score"]
            results.append(row)
            running = self._compute_metrics(entries[:index], results)
            pattern_text = ",".join(str(item) for item in row["patterns"]) or "none"
            excluded = row["predicted"] == "suspicious"
            correct = row["predicted"] == row["label"]
            correctness = "excluded" if excluded else ("yes" if correct else "no")
            self._emit_progress(
                f"{prefix} DONE status={row['status']} gold={row['label']} "
                f"pred={row['predicted']} correct={correctness} "
                f"time={runtime_sec:.1f}s findings={row['finding_count']} "
                f"ssos={row['sso_count']} operands={row['operand_count']} "
                f"resolutions={row['operand_resolution_count']} "
                f"patterns={pattern_text} tp={int(running['tp'])} tn={int(running['tn'])} "
                f"fp={int(running['fp'])} fn={int(running['fn'])} "
                f"output={row['analysis_output_dir']}",
                level=(
                    "WARNING"
                    if excluded
                    else ("SUCCESS" if correct and row["status"] == "ok" else "ERROR")
                ),
            )
            if row["error"]:
                self._emit_progress(f"{prefix} ERROR {row['error']}", level="ERROR")
        metrics = self._compute_metrics(entries, results)
        payload = {
            "variant": variant,
            "filters": {"datasets": datasets or [], "splits": splits or [], "labels": labels or []},
            "metrics": metrics,
            "results": results,
            "breakdown": {
                "by_dataset": self._compute_breakdown(entries, results, key="dataset"),
                "by_split": self._compute_breakdown(entries, results, key="split"),
                "by_label": self._compute_breakdown(entries, results, key="label"),
            },
        }
        case_outputs = {
            row["entry_id"]: {
                "analysis_output_dir": row["analysis_output_dir"],
                "analysis_manifest_path": row["analysis_manifest_path"],
            }
            for row in results
        }
        payload["case_outputs"] = case_outputs
        (destination / f"eval_{variant}.json").write_text(json.dumps(to_jsonable(payload), indent=2, sort_keys=True), encoding="utf-8")
        (destination / f"case_outputs_{variant}.json").write_text(json.dumps(to_jsonable(case_outputs), indent=2, sort_keys=True), encoding="utf-8")
        self._emit_progress(
            f"[eval {variant}] COMPLETE cases={total} tp={int(metrics['tp'])} "
            f"tn={int(metrics['tn'])} fp={int(metrics['fp'])} fn={int(metrics['fn'])} "
            f"precision={metrics['precision']:.4f} recall={metrics['recall']:.4f} "
            f"f1={metrics['f1']:.4f} errors={int(metrics['error_count'])} "
            f"timeouts={int(metrics['timeout_count'])} "
            f"report={(destination / f'eval_{variant}.json').resolve()}"
        )
        return payload

    def _stable_case_directory_name(self, entry_id: str) -> str:
        slug = re.sub(r"[^A-Za-z0-9]+", "_", entry_id).strip("_").lower()
        if not slug:
            slug = "case"
        digest = hashlib.sha1(entry_id.encode("utf-8")).hexdigest()[:10]
        return f"{slug}__{digest}"

    def _run_case(
        self,
        skill_path: str,
        case_output_dir: Path,
        config: AnalyzerConfig | str,
        *,
        on_wait: Callable[[float], None] | None = None,
        on_event: Callable[[str, dict[str, object]], None] | None = None,
    ) -> dict[str, object]:
        ensure_dir(case_output_dir)
        if isinstance(config, str):
            try:
                payload = dict(_run_case_direct(skill_path, case_output_dir, config))
            except Exception as exc:
                payload = {
                    "status": "error",
                    "predicted": "error",
                    "score": 0.0,
                    "patterns": [],
                    "finding_count": 0,
                    "operand_count": 0,
                    "operand_resolution_count": 0,
                    "sso_count": 0,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            (case_output_dir / "benchmark_case_status.json").write_text(
                json.dumps(payload, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            return payload

        queue: multiprocessing.Queue = multiprocessing.Queue()
        process = multiprocessing.Process(
            target=_analyze_case_worker,
            args=(skill_path, str(case_output_dir), config, queue),
            daemon=True,
        )
        process.start()
        wait_started_at = time.monotonic()
        last_heartbeat_at = wait_started_at
        result_payload: dict[str, object] | None = None

        def handle_message(message: object) -> None:
            nonlocal result_payload
            if not isinstance(message, dict):
                return
            if message.get("message_type") == "progress":
                fields = message.get("fields", {})
                if on_event is not None and isinstance(fields, dict):
                    on_event(str(message.get("event", "progress")), fields)
            elif message.get("message_type") == "result":
                result_payload = {
                    key: value
                    for key, value in message.items()
                    if key != "message_type"
                }

        def drain_messages() -> None:
            while True:
                try:
                    message = queue.get_nowait()
                except queue_module.Empty:
                    break
                handle_message(message)

        while process.is_alive():
            elapsed = time.monotonic() - wait_started_at
            remaining = BENCHMARK_CASE_TIMEOUT_SEC - elapsed
            if remaining <= 0:
                break
            wait_for = min(0.25, remaining)
            process.join(wait_for)
            drain_messages()
            now = time.monotonic()
            if (
                process.is_alive()
                and on_wait is not None
                and self.progress_interval_sec > 0
                and now - last_heartbeat_at >= self.progress_interval_sec
            ):
                on_wait(now - wait_started_at)
                last_heartbeat_at = now
        if process.is_alive():
            process.terminate()
            process.join(5)
            if process.is_alive():
                process.kill()
                process.join(5)
            payload = {
                "status": "timeout",
                "predicted": "timeout",
                "patterns": [],
                "finding_count": 0,
                "operand_count": 0,
                "operand_resolution_count": 0,
                "sso_count": 0,
                "error": f"case timed out after {BENCHMARK_CASE_TIMEOUT_SEC}s",
            }
            (case_output_dir / "benchmark_case_status.json").write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
            return payload
        drain_messages()
        result_deadline = time.monotonic() + 2.0
        while result_payload is None and time.monotonic() < result_deadline:
            try:
                handle_message(queue.get(timeout=0.1))
            except queue_module.Empty:
                pass
        if result_payload is not None:
            payload = result_payload
        else:
            payload = {
                "status": "error",
                "predicted": "error",
                "patterns": [],
                "finding_count": 0,
                "operand_count": 0,
                "operand_resolution_count": 0,
                "sso_count": 0,
                "error": "worker exited without result payload",
            }
        (case_output_dir / "benchmark_case_status.json").write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return payload

    def _compute_metrics(self, entries: list[BenchmarkEntry], results: list[dict[str, object]]) -> dict[str, float]:
        suspicious = {row["entry_id"] for row in results if row["predicted"] == "suspicious"}
        evaluated_entries = [entry for entry in entries if entry.entry_id not in suspicious]
        gold_positive = {entry.entry_id for entry in evaluated_entries if entry.label == "malicious"}
        gold_negative = {entry.entry_id for entry in evaluated_entries if entry.label != "malicious"}
        pred_positive = {row["entry_id"] for row in results if row["predicted"] == "malicious"}
        pred_strict_positive = {row["entry_id"] for row in results if row["predicted"] == "malicious"}
        tp = len(gold_positive & pred_positive)
        fp = len(gold_negative & pred_positive)
        fn = len(gold_positive - pred_positive)
        tn = len(gold_negative - pred_positive)
        strict_tp = len(gold_positive & pred_strict_positive)
        strict_fp = len(gold_negative & pred_strict_positive)
        strict_fn = len(gold_positive - pred_strict_positive)
        strict_tn = len(gold_negative - pred_strict_positive)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        strict_precision = strict_tp / (strict_tp + strict_fp) if strict_tp + strict_fp else 0.0
        strict_recall = strict_tp / (strict_tp + strict_fn) if strict_tp + strict_fn else 0.0
        strict_fpr = strict_fp / (strict_fp + strict_tn) if strict_fp + strict_tn else 0.0
        total_runtime = sum(float(row.get("runtime_sec", 0.0)) for row in results)
        avg_runtime = total_runtime / len(results) if results else 0.0
        throughput = len(results) / (total_runtime / 60.0) if total_runtime else 0.0
        avg_findings = sum(float(row.get("finding_count", 0.0)) for row in results) / len(results) if results else 0.0
        avg_operands = sum(float(row.get("operand_count", 0.0)) for row in results) / len(results) if results else 0.0
        avg_operand_resolutions = sum(float(row.get("operand_resolution_count", 0.0)) for row in results) / len(results) if results else 0.0
        avg_ssos = sum(float(row.get("sso_count", 0.0)) for row in results) / len(results) if results else 0.0
        timeout_count = sum(1 for row in results if row.get("status") == "timeout")
        error_count = sum(1 for row in results if row.get("status") == "error")
        suspicious_malicious_count = sum(
            1 for entry in entries if entry.entry_id in suspicious and entry.label == "malicious"
        )
        suspicious_benign_count = len(suspicious) - suspicious_malicious_count
        coverage = len(evaluated_entries) / len(entries) if entries else 0.0
        return {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "false_positive_rate": round(fpr, 4),
            "strict_malicious_precision": round(strict_precision, 4),
            "strict_malicious_recall": round(strict_recall, 4),
            "strict_malicious_false_positive_rate": round(strict_fpr, 4),
            "tp": float(tp),
            "fp": float(fp),
            "fn": float(fn),
            "tn": float(tn),
            "num_entries": float(len(evaluated_entries)),
            "total_entries": float(len(entries)),
            "suspicious_count": float(len(suspicious)),
            "suspicious_malicious_count": float(suspicious_malicious_count),
            "suspicious_benign_count": float(suspicious_benign_count),
            "coverage": round(coverage, 4),
            "avg_runtime_sec": round(avg_runtime, 4),
            "throughput_skills_per_min": round(throughput, 4),
            "avg_finding_count": round(avg_findings, 4),
            "avg_operand_count": round(avg_operands, 4),
            "avg_operand_resolution_count": round(avg_operand_resolutions, 4),
            "avg_sso_count": round(avg_ssos, 4),
            "timeout_count": float(timeout_count),
            "error_count": float(error_count),
        }

    def _compute_breakdown(self, entries: list[BenchmarkEntry], results: list[dict[str, object]], *, key: str) -> dict[str, dict[str, float]]:
        entry_by_id = {entry.entry_id: entry for entry in entries}
        groups: dict[str, list[dict[str, object]]] = {}
        for row in results:
            group = str(row.get(key) or getattr(entry_by_id[row["entry_id"]], key))
            groups.setdefault(group, []).append(row)
        breakdown: dict[str, dict[str, float]] = {}
        for group, group_results in groups.items():
            group_entries = [entry_by_id[row["entry_id"]] for row in group_results]
            breakdown[group] = self._compute_metrics(group_entries, group_results)
        return breakdown


def render_results(results_dir: str | Path) -> Path:
    root = Path(results_dir)
    ensure_dir(root)
    reports = sorted(report for report in root.glob("eval_*.json") if report.name != "eval_suite.json")
    lines = ["# Evaluation Summary", ""]
    for report in reports:
        payload = json.loads(report.read_text(encoding="utf-8"))
        metrics = payload["metrics"]
        lines.append(f"## {payload['variant']}")
        lines.append("")
        filters = payload.get("filters", {})
        if any(filters.values()):
            lines.append(f"- Filters: datasets={filters.get('datasets', [])}, splits={filters.get('splits', [])}, labels={filters.get('labels', [])}")
        lines.append(f"- Precision: {metrics['precision']}")
        lines.append(f"- Recall: {metrics['recall']}")
        lines.append(f"- F1: {metrics['f1']}")
        lines.append(f"- False positive rate: {metrics['false_positive_rate']}")
        lines.append(f"- Strict malicious precision: {metrics.get('strict_malicious_precision', 0.0)}")
        lines.append(f"- Strict malicious recall: {metrics.get('strict_malicious_recall', 0.0)}")
        lines.append(f"- Strict malicious false positive rate: {metrics.get('strict_malicious_false_positive_rate', 0.0)}")
        lines.append(f"- Avg runtime (s): {metrics.get('avg_runtime_sec', 0.0)}")
        lines.append(f"- Throughput (skills/min): {metrics.get('throughput_skills_per_min', 0.0)}")
        lines.append(f"- Avg findings count: {metrics.get('avg_finding_count', 0.0)}")
        lines.append(f"- Avg operand count: {metrics.get('avg_operand_count', 0.0)}")
        lines.append(f"- Avg operand resolution count: {metrics.get('avg_operand_resolution_count', 0.0)}")
        lines.append(f"- Avg SSO count: {metrics.get('avg_sso_count', 0.0)}")
        if all(key in metrics for key in ("tp", "fp", "fn", "tn")):
            lines.append(f"- Confusion: TP={int(metrics['tp'])}, FP={int(metrics['fp'])}, FN={int(metrics['fn'])}, TN={int(metrics['tn'])}")
        lines.append(f"- Entries: {int(metrics['num_entries'])}")
        by_split = payload.get("breakdown", {}).get("by_split", {})
        if by_split:
            lines.append("- Split breakdown:")
            for split, split_metrics in sorted(by_split.items()):
                lines.append(
                    f"  - {split}: recall={split_metrics['recall']}, precision={split_metrics['precision']}, entries={int(split_metrics['num_entries'])}"
                )
        lines.append("")
    output = root / "summary.md"
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return output
