from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .benchmark import BenchmarkBuilder
from .corpus_scan import CorpusScanner
from .evaluation import VARIANTS, Evaluator, render_results
from .llm_runtime import describe_llm_runtime
from .pipeline import AnalyzerConfig, SkillAnalyzer
from .rule_learning.registry import RuleRegistry
from .rule_learning.validation import HeldOutRuleValidator
from .utils import load_env_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="malskills")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze-skill")
    analyze.add_argument("path")
    analyze.add_argument("--output", required=True)
    analyze.add_argument("--disable-llm-sso-extraction", action="store_true")
    analyze.add_argument("--disable-llm-object-analysis", action="store_true")
    analyze.add_argument("--disable-semgrep", action="store_true")
    analyze.add_argument("--disable-yasa", action="store_true")
    analyze.add_argument("--disable-cross-artifact-resolution", action="store_true")
    analyze.add_argument("--reasoning-mode", choices=["hybrid", "formal", "llm"])
    analyze.add_argument("--rule-store")
    analyze.add_argument("--collect-rule-candidates", action="store_true")
    analyze.add_argument("--rule-group-id")
    analyze.add_argument("--llm-config")

    benchmark = subparsers.add_parser("build-benchmark-index")
    benchmark.add_argument("--output", required=True)
    benchmark.add_argument("--root", default=".")

    scan = subparsers.add_parser("scan-corpus")
    scan.add_argument("--corpus-root", required=True)
    scan.add_argument("--output", required=True)
    scan.add_argument("--sample-size", type=int, required=True)
    scan.add_argument("--seed", type=int, default=1337)
    scan.add_argument("--workers", type=int, default=min(8, os.cpu_count() or 1))
    scan.add_argument("--source", action="append", dest="sources")
    scan.add_argument("--profile", choices=["static", "full"], default="static")
    scan.add_argument("--rule-store")
    scan.add_argument("--retain", choices=["malicious", "all", "none"], default="malicious")
    scan.add_argument("--resume", action="store_true")
    scan.add_argument("--keep-content-duplicates", action="store_true")
    scan.add_argument("--disable-yasa", action="store_true")
    scan.add_argument("--disable-cross-artifact-resolution", action="store_true")
    scan.add_argument("--max-artifacts", type=int, default=600)
    scan.add_argument("--max-total-text-bytes", type=int, default=2_000_000)
    scan.add_argument("--progress-every", type=int, default=1)
    scan.add_argument("--quiet", action="store_true")
    scan.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    scan.add_argument("--llm-config")

    evaluate = subparsers.add_parser("run-eval")
    evaluate.add_argument("--benchmark", required=True)
    evaluate.add_argument("--output", required=True)
    evaluate.add_argument("--variant", choices=sorted(list(VARIANTS) + ["all"]), default="full")
    evaluate.add_argument("--limit", type=int)
    evaluate.add_argument("--dataset", action="append", dest="datasets")
    evaluate.add_argument("--split", action="append", dest="splits")
    evaluate.add_argument("--label", action="append", dest="labels")
    evaluate.add_argument("--llm-config")
    evaluate.add_argument(
        "--progress-interval",
        type=float,
        default=30.0,
        help="seconds between per-case heartbeat messages; use 0 to disable heartbeats",
    )
    evaluate.add_argument(
        "--quiet",
        action="store_true",
        help="suppress per-case progress and print only the final summary",
    )
    evaluate.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default="auto",
        help="control ANSI colors in progress output",
    )

    render = subparsers.add_parser("render-report")
    render.add_argument("--results", required=True)

    show_llm = subparsers.add_parser("show-llm-config")
    show_llm.add_argument("--llm-config")

    rules = subparsers.add_parser("rules")
    rule_commands = rules.add_subparsers(dest="rules_command", required=True)

    rules_list = rule_commands.add_parser("list")
    rules_list.add_argument("--store", required=True)
    rules_list.add_argument("--status")

    rules_show = rule_commands.add_parser("show")
    rules_show.add_argument("candidate_id")
    rules_show.add_argument("--store", required=True)

    rules_validate = rule_commands.add_parser("validate")
    rules_validate.add_argument("candidate_id")
    rules_validate.add_argument("--store", required=True)
    rules_validate.add_argument("--manifest", required=True)
    rules_validate.add_argument("--corpus-root")

    rules_promote = rule_commands.add_parser("promote")
    rules_promote.add_argument("candidate_id")
    rules_promote.add_argument("--store", required=True)
    rules_promote.add_argument("--approved-by", required=True)

    rules_reject = rule_commands.add_parser("reject")
    rules_reject.add_argument("candidate_id")
    rules_reject.add_argument("--store", required=True)
    rules_reject.add_argument("--reason", required=True)

    rules_deactivate = rule_commands.add_parser("deactivate")
    rules_deactivate.add_argument("candidate_id")
    rules_deactivate.add_argument("--store", required=True)
    rules_deactivate.add_argument("--approved-by", required=True)

    rules_rollback = rule_commands.add_parser("rollback")
    rules_rollback.add_argument("bundle_digest")
    rules_rollback.add_argument("--store", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    load_env_file(Path(__file__).resolve().parents[1])
    parser = build_parser()
    args = parser.parse_args(argv)
    llm_config = getattr(args, "llm_config", None)
    if llm_config:
        os.environ["MALSKILLS_CONFIG"] = str(Path(llm_config).expanduser().resolve())
    if args.command == "analyze-skill":
        analyzer = SkillAnalyzer()
        result = analyzer.analyze(
            args.path,
            output_dir=args.output,
            config=AnalyzerConfig(
                enable_semgrep=not args.disable_semgrep,
                enable_llm_sso_extraction=(
                    False if args.disable_llm_sso_extraction else None
                ),
                enable_llm_object_analysis=(
                    False if args.disable_llm_object_analysis else None
                ),
                enable_yasa=not args.disable_yasa,
                enable_cross_artifact_resolution=not args.disable_cross_artifact_resolution,
                reasoning_mode=args.reasoning_mode,
                rule_store_dir=args.rule_store,
                collect_rule_candidates=(
                    True if args.collect_rule_candidates else None
                ),
                rule_learning_group_id=args.rule_group_id,
            ),
        )
        print(f"{result.verdict.label}\t{result.skill_path}")
        return 0
    if args.command == "build-benchmark-index":
        builder = BenchmarkBuilder(args.root)
        entries = builder.build()
        builder.write(args.output, entries)
        summary = builder.summarize(entries)
        print(f"wrote {len(entries)} benchmark entries to {Path(args.output).resolve()}")
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    if args.command == "scan-corpus":
        scanner = CorpusScanner(
            progress=not args.quiet,
            progress_every=args.progress_every,
            color=args.color,
        )
        summary = scanner.run(
            args.corpus_root,
            args.output,
            sample_size=args.sample_size,
            seed=args.seed,
            workers=args.workers,
            sources=args.sources,
            deduplicate_content=not args.keep_content_duplicates,
            retain=args.retain,
            resume=args.resume,
            profile=args.profile,
            rule_store_dir=args.rule_store,
            enable_yasa=not args.disable_yasa,
            enable_cross_artifact_resolution=not args.disable_cross_artifact_resolution,
            max_artifacts=args.max_artifacts,
            max_total_text_bytes=args.max_total_text_bytes,
        )
        print(
            f"scanned={summary['completed']} malicious={summary['verdicts'].get('malicious', 0)} "
            f"benign={summary['verdicts'].get('benign', 0)} errors={summary['statuses'].get('error', 0)} "
            f"report={Path(args.output).resolve() / 'scan_summary.json'}"
        )
        return 0
    if args.command == "run-eval":
        evaluator = Evaluator(
            progress=not args.quiet,
            progress_interval_sec=args.progress_interval,
            color=args.color,
        )
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
    if args.command == "render-report":
        output = render_results(args.results)
        print(output)
        return 0
    if args.command == "show-llm-config":
        print(json.dumps(describe_llm_runtime(), indent=2, sort_keys=True))
        return 0
    if args.command == "rules":
        registry = RuleRegistry(args.store)
        if args.rules_command == "list":
            print(json.dumps(registry.list_candidates(status=args.status), indent=2, sort_keys=True))
            return 0
        if args.rules_command == "show":
            print(json.dumps(registry.get_candidate(args.candidate_id), indent=2, sort_keys=True))
            return 0
        if args.rules_command == "validate":
            validation = HeldOutRuleValidator(registry).validate(
                args.candidate_id,
                args.manifest,
                corpus_root=args.corpus_root,
            )
            print(json.dumps(validation, indent=2, sort_keys=True))
            return 0
        if args.rules_command == "promote":
            snapshot = registry.promote(args.candidate_id, approved_by=args.approved_by)
            print(json.dumps(snapshot.manifest, indent=2, sort_keys=True))
            return 0
        if args.rules_command == "reject":
            registry.reject(args.candidate_id, reason=args.reason)
            print(json.dumps(registry.get_candidate(args.candidate_id), indent=2, sort_keys=True))
            return 0
        if args.rules_command == "deactivate":
            snapshot = registry.deactivate(
                args.candidate_id,
                approved_by=args.approved_by,
            )
            print(json.dumps(snapshot.manifest, indent=2, sort_keys=True))
            return 0
        if args.rules_command == "rollback":
            snapshot = registry.rollback(args.bundle_digest)
            print(json.dumps(snapshot.manifest, indent=2, sort_keys=True))
            return 0
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
