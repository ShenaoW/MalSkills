from __future__ import annotations

import argparse
from pathlib import Path

import json

from .benchmark import BenchmarkBuilder
from .evaluation import VARIANTS, Evaluator, render_results
from .mutate import MutationGenerator
from .pipeline import AnalyzerConfig, SkillAnalyzer


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="skillguard")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze-skill")
    analyze.add_argument("path")
    analyze.add_argument("--output", required=True)
    analyze.add_argument("--disable-intent", action="store_true")
    analyze.add_argument("--disable-static", action="store_true")
    analyze.add_argument("--no-souffle-export", action="store_true")
    analyze.add_argument("--disable-semgrep", action="store_true")
    analyze.add_argument("--disable-yasa", action="store_true")
    analyze.add_argument("--disable-cross-artifact-resolution", action="store_true")
    analyze.add_argument("--disable-capability-mismatch", action="store_true")
    analyze.add_argument("--reasoning-mode", choices=["formal", "heuristic"], default="formal")

    benchmark = subparsers.add_parser("build-benchmark-index")
    benchmark.add_argument("--output", required=True)
    benchmark.add_argument("--root", default=".")

    evaluate = subparsers.add_parser("run-eval")
    evaluate.add_argument("--benchmark", required=True)
    evaluate.add_argument("--output", required=True)
    evaluate.add_argument("--variant", choices=sorted(list(VARIANTS) + ["all"]), default="full")
    evaluate.add_argument("--limit", type=int)
    evaluate.add_argument("--dataset", action="append", dest="datasets")
    evaluate.add_argument("--split", action="append", dest="splits")
    evaluate.add_argument("--label", action="append", dest="labels")

    mutate = subparsers.add_parser("gen-mutations")
    mutate.add_argument("--input-skill", required=True)
    mutate.add_argument("--output", required=True)

    render = subparsers.add_parser("render-report")
    render.add_argument("--results", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "analyze-skill":
        analyzer = SkillAnalyzer()
        result = analyzer.analyze(
            args.path,
            output_dir=args.output,
            config=AnalyzerConfig(
                enable_static=not args.disable_static,
                enable_intent=not args.disable_intent,
                export_souffle=not args.no_souffle_export,
                enable_semgrep=not args.disable_semgrep,
                enable_yasa=not args.disable_yasa,
                enable_cross_artifact_resolution=not args.disable_cross_artifact_resolution,
                enable_capability_mismatch=not args.disable_capability_mismatch,
                reasoning_mode=args.reasoning_mode,
            ),
        )
        print(f"{result.verdict.label}\t{result.verdict.score:.2f}\t{result.skill_path}")
        return 0
    if args.command == "build-benchmark-index":
        builder = BenchmarkBuilder(args.root)
        entries = builder.build()
        builder.write(args.output, entries)
        summary = builder.summarize(entries)
        print(f"wrote {len(entries)} benchmark entries to {Path(args.output).resolve()}")
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    if args.command == "run-eval":
        evaluator = Evaluator()
        if args.variant == "all":
            payload = evaluator.run_suite(
                args.benchmark,
                args.output,
                limit=args.limit,
                datasets=args.datasets,
                splits=args.splits,
                labels=args.labels,
            )
            print(f"variants={','.join(payload['variants'])} reports={len(payload['reports'])}")
        else:
            payload = evaluator.run(
                args.benchmark,
                args.output,
                variant=args.variant,
                limit=args.limit,
                datasets=args.datasets,
                splits=args.splits,
                labels=args.labels,
            )
            print(f"variant={payload['variant']} recall={payload['metrics']['recall']} precision={payload['metrics']['precision']}")
        return 0
    if args.command == "gen-mutations":
        generator = MutationGenerator()
        outputs = generator.generate(args.input_skill, args.output)
        print("generated mutations:")
        for path in outputs:
            print(path)
        return 0
    if args.command == "render-report":
        output = render_results(args.results)
        print(output)
        return 0
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
