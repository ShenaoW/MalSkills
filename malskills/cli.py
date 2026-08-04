from __future__ import annotations

import argparse
from pathlib import Path

import json

from .benchmark import BenchmarkBuilder
from .evaluation import VARIANTS, Evaluator, render_results
from .llm_runtime import describe_llm_runtime
from .pipeline import AnalyzerConfig, SkillAnalyzer
from .rule_learning.registry import RuleRegistry
from .rule_learning.validation import HeldOutRuleValidator


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="malskills")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze-skill")
    analyze.add_argument("path")
    analyze.add_argument("--output", required=True)
    analyze.add_argument("--no-souffle-export", action="store_true")
    analyze.add_argument("--disable-llm-sso-extraction", action="store_true")
    analyze.add_argument("--disable-llm-object-analysis", action="store_true")
    analyze.add_argument("--disable-semgrep", action="store_true")
    analyze.add_argument("--disable-yasa", action="store_true")
    analyze.add_argument("--disable-cross-artifact-resolution", action="store_true")
    analyze.add_argument("--reasoning-mode", choices=["hybrid", "formal", "llm"], default="hybrid")
    analyze.add_argument("--rule-store")
    analyze.add_argument("--collect-rule-candidates", action="store_true")
    analyze.add_argument("--rule-group-id")

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

    render = subparsers.add_parser("render-report")
    render.add_argument("--results", required=True)

    subparsers.add_parser("show-llm-config")

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
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "analyze-skill":
        analyzer = SkillAnalyzer()
        result = analyzer.analyze(
            args.path,
            output_dir=args.output,
            config=AnalyzerConfig(
                export_souffle=not args.no_souffle_export,
                enable_semgrep=not args.disable_semgrep,
                enable_llm_sso_extraction=not args.disable_llm_sso_extraction,
                enable_llm_object_analysis=not args.disable_llm_object_analysis,
                enable_yasa=not args.disable_yasa,
                enable_cross_artifact_resolution=not args.disable_cross_artifact_resolution,
                reasoning_mode=args.reasoning_mode,
                rule_store_dir=args.rule_store,
                collect_rule_candidates=args.collect_rule_candidates,
                rule_learning_group_id=args.rule_group_id,
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
