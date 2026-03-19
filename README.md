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
