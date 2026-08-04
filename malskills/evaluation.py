from __future__ import annotations

import hashlib
import json
import multiprocessing
import re
import time
from pathlib import Path

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
    "full": AnalyzerConfig(enable_llm_sso_extraction=True),
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
    "benchmark_full": AnalyzerConfig(enable_llm_sso_extraction=True, max_artifacts=600, max_total_text_bytes=2_000_000),
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
            queue.put(runner(skill_path, case_output_dir))
            return
        analyzer = SkillAnalyzer()
        result = analyzer.analyze(skill_path, output_dir=case_output_dir, config=config)
        queue.put(
            {
                "status": "ok",
                "predicted": result.verdict.label,
                "score": result.verdict.score,
                "patterns": result.verdict.malicious_patterns,
                "finding_count": len(result.findings),
                "operand_resolution_count": len(result.operand_resolutions),
                "sso_count": len(result.ssos),
            }
        )
    except Exception as exc:
        queue.put(
            {
                "status": "error",
                "error": f"{type(exc).__name__}: {exc}",
                "predicted": "error",
                "score": 0.0,
                "patterns": [],
                "finding_count": 0,
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
    def __init__(self) -> None:
        pass

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
        for entry in entries:
            started_at = time.perf_counter()
            case_output_dir = destination / "cases" / variant / self._stable_case_directory_name(entry.entry_id)
            runtime_sec = time.perf_counter() - started_at
            manifest_path = case_output_dir / "output_manifest.json"
            case_result = self._run_case(entry.local_path, case_output_dir, config)
            runtime_sec = time.perf_counter() - started_at
            results.append({
                "entry_id": entry.entry_id,
                "dataset": entry.dataset,
                "split": entry.split,
                "label": entry.label,
                "status": case_result["status"],
                "predicted": case_result["predicted"],
                "score": case_result["score"],
                "patterns": case_result["patterns"],
                "runtime_sec": round(runtime_sec, 4),
                "finding_count": case_result["finding_count"],
                "operand_resolution_count": case_result["operand_resolution_count"],
                "sso_count": case_result["sso_count"],
                "analysis_output_dir": str(case_output_dir.relative_to(destination)),
                "analysis_manifest_path": str(manifest_path.relative_to(destination)),
                "error": case_result.get("error", ""),
            })
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
        return payload

    def _stable_case_directory_name(self, entry_id: str) -> str:
        slug = re.sub(r"[^A-Za-z0-9]+", "_", entry_id).strip("_").lower()
        if not slug:
            slug = "case"
        digest = hashlib.sha1(entry_id.encode("utf-8")).hexdigest()[:10]
        return f"{slug}__{digest}"

    def _run_case(self, skill_path: str, case_output_dir: Path, config: AnalyzerConfig | str) -> dict[str, object]:
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
        process.join(BENCHMARK_CASE_TIMEOUT_SEC)
        if process.is_alive():
            process.terminate()
            process.join(5)
            if process.is_alive():
                process.kill()
                process.join(5)
            payload = {
                "status": "timeout",
                "predicted": "timeout",
                "score": 0.0,
                "patterns": [],
                "finding_count": 0,
                "operand_resolution_count": 0,
                "sso_count": 0,
                "error": f"case timed out after {BENCHMARK_CASE_TIMEOUT_SEC}s",
            }
            (case_output_dir / "benchmark_case_status.json").write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
            return payload
        if not queue.empty():
            payload = dict(queue.get())
        else:
            payload = {
                "status": "error",
                "predicted": "error",
                "score": 0.0,
                "patterns": [],
                "finding_count": 0,
                "operand_resolution_count": 0,
                "sso_count": 0,
                "error": "worker exited without result payload",
            }
        (case_output_dir / "benchmark_case_status.json").write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return payload

    def _compute_metrics(self, entries: list[BenchmarkEntry], results: list[dict[str, object]]) -> dict[str, float]:
        gold_positive = {entry.entry_id for entry in entries if entry.label == "malicious"}
        gold_negative = {entry.entry_id for entry in entries if entry.label != "malicious"}
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
        avg_operand_resolutions = sum(float(row.get("operand_resolution_count", 0.0)) for row in results) / len(results) if results else 0.0
        avg_ssos = sum(float(row.get("sso_count", 0.0)) for row in results) / len(results) if results else 0.0
        timeout_count = sum(1 for row in results if row.get("status") == "timeout")
        error_count = sum(1 for row in results if row.get("status") == "error")
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
            "num_entries": float(len(entries)),
            "avg_runtime_sec": round(avg_runtime, 4),
            "throughput_skills_per_min": round(throughput, 4),
            "avg_finding_count": round(avg_findings, 4),
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
