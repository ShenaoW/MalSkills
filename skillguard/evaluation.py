from __future__ import annotations

import json
import time
from pathlib import Path

from .benchmark import load_benchmark_entries
from .models import BenchmarkEntry, to_jsonable
from .pipeline import AnalyzerConfig, SkillAnalyzer
from .utils import ensure_dir


VARIANTS = {
    "full": AnalyzerConfig(enable_intent=True),
    "static_only": AnalyzerConfig(enable_intent=False),
    "intent_only": AnalyzerConfig(enable_static=False, enable_intent=True),
    "no_formal_reasoning": AnalyzerConfig(enable_intent=True, reasoning_mode="heuristic"),
    "no_cross_artifact_resolution": AnalyzerConfig(enable_intent=True, enable_cross_artifact_resolution=False),
    "no_capability_mismatch": AnalyzerConfig(enable_intent=True, enable_capability_mismatch=False),
    "benchmark_full": AnalyzerConfig(enable_intent=True, enable_yasa=False),
    "benchmark_static_only": AnalyzerConfig(enable_intent=False, enable_yasa=False),
    "benchmark_no_formal_reasoning": AnalyzerConfig(enable_intent=True, enable_yasa=False, reasoning_mode="heuristic"),
    "benchmark_no_cross_artifact_resolution": AnalyzerConfig(enable_intent=True, enable_yasa=False, enable_cross_artifact_resolution=False),
    "benchmark_no_capability_mismatch": AnalyzerConfig(enable_intent=True, enable_yasa=False, enable_capability_mismatch=False),
}


class Evaluator:
    def __init__(self) -> None:
        self.analyzer = SkillAnalyzer()

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
        config: AnalyzerConfig,
        *,
        datasets: list[str] | None,
        splits: list[str] | None,
        labels: list[str] | None,
    ) -> dict[str, object]:
        results = []
        for entry in entries:
            started_at = time.perf_counter()
            result = self.analyzer.analyze(entry.local_path, config=config)
            runtime_sec = time.perf_counter() - started_at
            results.append({
                "entry_id": entry.entry_id,
                "dataset": entry.dataset,
                "split": entry.split,
                "label": entry.label,
                "predicted": result.verdict.label,
                "score": result.verdict.score,
                "patterns": result.verdict.malicious_patterns + result.verdict.suspicious_patterns,
                "runtime_sec": round(runtime_sec, 4),
                "evidence_count": len(result.evidence),
                "primitive_count": len(result.primitives),
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
        destination = Path(output_dir)
        ensure_dir(destination)
        (destination / f"eval_{variant}.json").write_text(json.dumps(to_jsonable(payload), indent=2, sort_keys=True), encoding="utf-8")
        return payload

    def _compute_metrics(self, entries: list[BenchmarkEntry], results: list[dict[str, object]]) -> dict[str, float]:
        gold_positive = {entry.entry_id for entry in entries if entry.label == "malicious"}
        gold_negative = {entry.entry_id for entry in entries if entry.label != "malicious"}
        pred_positive = {row["entry_id"] for row in results if row["predicted"] in {"malicious", "suspicious"}}
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
        avg_evidence = sum(float(row.get("evidence_count", 0.0)) for row in results) / len(results) if results else 0.0
        avg_primitives = sum(float(row.get("primitive_count", 0.0)) for row in results) / len(results) if results else 0.0
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
            "avg_evidence_count": round(avg_evidence, 4),
            "avg_primitive_count": round(avg_primitives, 4),
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
        lines.append(f"- Avg evidence count: {metrics.get('avg_evidence_count', 0.0)}")
        lines.append(f"- Avg primitive count: {metrics.get('avg_primitive_count', 0.0)}")
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
