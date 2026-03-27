# MalSkills

MalSkills is a neuro-symbolic system for detecting malicious agent skills from heterogeneous skill artifacts.

It works in three stages:

1. **Security-Sensitive Operation extraction**: identify security-relevant operations from code, prompts, manifests, configuration files, and setup instructions.
2. **Skill Dependency Graph generation**: recover the operands of those operations and connect them through object identity and value-flow relations.
3. **Neuro-symbolic reasoning**: detect malicious behavior patterns or suspicious workflows from the graph.

![MalSkills pipeline](assets/malskills.pdf)

## What the repository contains

- `skillguard/`: main implementation
- `experiments/`: experiment drivers
- `data/`: benchmark and analysis inputs
- `output/`: generated results
- `baseline/`: baseline integrations
- `tests/`: regression tests
- `assets/`: figures used in this artifact

## Requirements

- Python `>= 3.9`
- optional `semgrep` for parsing-based extraction
- optional LLM API credentials in `.env` for full runs

The project metadata is in `pyproject.toml`.

## How to run MalSkills

Analyze a single skill:

```bash
python3 -m skillguard.cli analyze-skill <skill-dir> --output <output-dir>
```

Run the full benchmark pipeline:

```bash
python3 -m skillguard.cli run-eval \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/ground_truth_eval \
  --variant benchmark_full
```

Render a readable report:

```bash
python3 -m skillguard.cli render-report --results output/ground_truth_eval
```

Inspect the resolved LLM runtime:

```bash
python3 -m skillguard.cli show-llm-config
```

## Main outputs

Each analyzed skill produces:

- `verdict.json`: final label and score
- `all_evidence.json`: extracted security-sensitive operations
- `pattern_summary.json`: matched malicious or suspicious patterns
- `evidence_graph.json`: graph representation of recovered dependencies
- `proofs.json`: reasoning traces
- `human_report.md`: readable explanation

## Reproducing the benchmark experiments

### Main benchmark

The main labeled benchmark is:

- `output/ground_truth_final_benchmark.json`

Run the full system:

```bash
python3 -m skillguard.cli run-eval \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/rq1_malskills \
  --variant benchmark_full
```

### Ablation variants

The evaluation variants are defined in `skillguard/evaluation.py`.

Examples:

```bash
python3 -m skillguard.cli run-eval \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/rq2_no_neuro_reasoning \
  --variant benchmark_formal_reasoning_only
```

```bash
python3 -m skillguard.cli run-eval \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/rq2_no_symbolic_extractor \
  --variant benchmark_llm_evidence_only
```

```bash
python3 -m skillguard.cli run-eval \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/rq2_no_neuro_extractor \
  --variant benchmark_semgrep_evidence_only
```

### LLM comparison

Use the dedicated RQ3 driver:

```bash
python3 experiments/run_rq3_llm_comparison.py \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/rq3_llm_comparison \
  --profile claude \
  --profile gemini \
  --profile qwen \
  --profile deepseek \
  --timeout-sec 180
```

The script reads model-specific settings from `.env`, runs each model separately, and writes per-model outputs plus summary CSV/JSON files.

## LLM environment variables

General runtime variables:

- `SKILLGUARD_LLM_MODE`
- `SKILLGUARD_LLM_MODEL`
- `SKILLGUARD_LLM_API_KEY`
- `SKILLGUARD_LLM_BASE_URL`
- `SKILLGUARD_LLM_TIMEOUT_SEC`

RQ3 model-specific variables:

- `RQ3_CLAUDE_MODEL`, `RQ3_CLAUDE_API_KEY`, `CLAUDE_API_URL`
- `RQ3_GEMINI_MODEL`, `RQ3_GEMINI_API_KEY`, `GEMINI_API_URL`
- `RQ3_QWEN_MODEL`, `RQ3_QWEN_API_KEY`, `QWEN_API_URL`
- `RQ3_DEEPSEEK_MODEL`, `RQ3_DEEPSEEK_API_KEY`, `DEEPSEEK_API_URL`

## Baselines

Example baseline commands:

```bash
python3 -m skillguard.cli run-eval \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/codex_agent_baseline \
  --variant benchmark_codex_agent_baseline
```

```bash
python3 -m skillguard.cli run-eval \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/caterpillar_baseline \
  --variant benchmark_caterpillar_baseline
```

```bash
python3 -m skillguard.cli run-eval \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/skill_scanner_baseline \
  --variant benchmark_skill_scanner_baseline
```