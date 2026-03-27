# SkillGuard

SkillGuard is a static, neuro-symbolic analysis pipeline for malicious agent skills.

It parses heterogeneous skill artifacts, extracts structured evidence, synthesizes
capability primitives, and applies formal rules to produce explainable security
verdicts.

## CLI

- `python3 -m skillguard.cli analyze-skill <path> --output <dir>`
- `python3 -m skillguard.cli build-benchmark-index --output <file>`
- `python3 -m skillguard.cli run-eval --benchmark <file> --output <dir>`
- `python3 -m skillguard.cli gen-mutations --input-skill <path> --output <dir>`
- `python3 -m skillguard.cli render-report --results <dir>`

## Output

Each analyzed skill emits:

- `verdict.json`
- `evidence_graph.json`
- `primitives.json`
- `proofs.json`
- `human_report.md`

## Notes

- The analyzer is static-only by design.
- The reasoning engine exports Souffle-compatible facts and rules, and also
  includes a Python executor so the pipeline works even when `souffle` is not
  installed.


## Baselines

- `python3 -m skillguard.cli run-eval --benchmark experiments/benchmark_study/benchmark_recall.json --output output/codex_agent_baseline --variant benchmark_codex_agent_baseline`
- `python3 -m skillguard.cli run-eval --benchmark experiments/benchmark_study/benchmark_recall.json --output output/skill_security_audit_baseline --variant benchmark_skill_security_audit_baseline`
- `python3 -m skillguard.cli run-eval --benchmark experiments/benchmark_study/benchmark_recall.json --output output/skill_security_scan_baseline --variant benchmark_skill_security_scan_baseline`
- `python3 -m skillguard.cli run-eval --benchmark experiments/benchmark_study/benchmark_recall.json --output output/skills_security_audit_baseline --variant benchmark_skills_security_audit_baseline`
- `python3 -m skillguard.cli run-eval --benchmark experiments/benchmark_study/benchmark_recall.json --output output/caterpillar_baseline --variant benchmark_caterpillar_baseline`
- `python3 -m skillguard.cli run-eval --benchmark experiments/benchmark_study/benchmark_recall.json --output output/clawscan_baseline --variant benchmark_clawscan_baseline`
- `python3 -m skillguard.cli run-eval --benchmark experiments/benchmark_study/benchmark_recall.json --output output/skill_scanner_baseline --variant benchmark_skill_scanner_baseline`
- `python3 -m skillguard.cli run-eval --benchmark experiments/benchmark_study/benchmark_recall.json --output output/nova_proximity_baseline --variant benchmark_nova_proximity_baseline`
