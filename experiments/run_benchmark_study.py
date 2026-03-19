from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from skillguard.evaluation import Evaluator, render_results
from skillguard.models import BenchmarkEntry, to_jsonable
from skillguard.benchmark import load_benchmark_entries
from skillguard.utils import ensure_dir


DEFAULT_ABLATIONS = [
    "benchmark_full",
    "benchmark_static_only",
    "benchmark_no_formal_reasoning",
    "benchmark_no_cross_artifact_resolution",
    "benchmark_no_capability_mismatch",
]


def select_entries(
    entries: list[BenchmarkEntry],
    *,
    splits: Iterable[str],
    sample_size: int | None = None,
    seed: int = 1337,
) -> list[BenchmarkEntry]:
    selected = [entry for entry in entries if entry.analyzable and entry.local_path and entry.split in set(splits)]
    if sample_size is not None and len(selected) > sample_size:
        rng = random.Random(seed)
        selected = rng.sample(selected, sample_size)
        selected.sort(key=lambda item: item.entry_id)
    return selected


def write_subset(path: Path, entries: list[BenchmarkEntry]) -> None:
    path.write_text(json.dumps([to_jsonable(entry) for entry in entries], indent=2, sort_keys=True), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--benchmark", default="/tmp/skillguard_bench.json")
    parser.add_argument("--output", required=True)
    parser.add_argument("--ecosystem-sample", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--ablations", nargs="*", default=DEFAULT_ABLATIONS)
    args = parser.parse_args()

    entries = load_benchmark_entries(args.benchmark)
    output_dir = Path(args.output).resolve()
    ensure_dir(output_dir)

    recall_entries = select_entries(entries, splits=["confirmed_malicious", "mixed_malicious"])
    ecosystem_entries = select_entries(entries, splits=["mixed_ecosystem"], sample_size=args.ecosystem_sample, seed=args.seed)
    ablation_pool = sorted({entry.entry_id: entry for entry in (recall_entries + ecosystem_entries)}.values(), key=lambda item: item.entry_id)

    recall_path = output_dir / "benchmark_recall.json"
    ecosystem_path = output_dir / "benchmark_ecosystem_sample.json"
    ablation_path = output_dir / "benchmark_ablation_pool.json"
    write_subset(recall_path, recall_entries)
    write_subset(ecosystem_path, ecosystem_entries)
    write_subset(ablation_path, ablation_pool)

    evaluator = Evaluator()
    recall_report = evaluator.run(recall_path, output_dir / "recall_eval", variant="benchmark_full")
    ecosystem_report = evaluator.run(ecosystem_path, output_dir / "ecosystem_eval", variant="benchmark_full")
    ablation_report = evaluator.run_suite(ablation_path, output_dir / "ablation_eval", variants=args.ablations)
    recall_summary = render_results(output_dir / "recall_eval")
    ecosystem_summary = render_results(output_dir / "ecosystem_eval")
    ablation_summary = render_results(output_dir / "ablation_eval")

    overview = {
        "recall_entries": len(recall_entries),
        "ecosystem_sample_entries": len(ecosystem_entries),
        "ablation_entries": len(ablation_pool),
        "reports": {
            "recall": recall_report,
            "ecosystem": ecosystem_report,
            "ablations": ablation_report,
        },
        "summaries": {
            "recall": str(recall_summary),
            "ecosystem": str(ecosystem_summary),
            "ablations": str(ablation_summary),
        },
    }
    (output_dir / "study_overview.json").write_text(json.dumps(to_jsonable(overview), indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({
        "recall_entries": len(recall_entries),
        "ecosystem_sample_entries": len(ecosystem_entries),
        "ablation_entries": len(ablation_pool),
        "recall_strict_malicious_recall": recall_report["metrics"].get("strict_malicious_recall"),
        "ecosystem_false_positive_rate": ecosystem_report["metrics"].get("false_positive_rate"),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
