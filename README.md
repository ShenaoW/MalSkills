# MalSkills

MalSkills is a neuro-symbolic system for detecting malicious agent skills from heterogeneous skill artifacts.

It works in three stages:

1. **Security-Sensitive Operation extraction**: identify security-relevant operations from code, prompts, manifests, configuration files, and setup instructions.
2. **Skill Dependency Graph generation**: recover the operands of those operations and connect them through object identity and value-flow relations.
3. **Neuro-symbolic reasoning**: detect malicious behavior patterns or suspicious workflows from the graph.

![MalSkills pipeline](assets/malskills.png)

## What the repository contains

- `malskills/`: main implementation
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

## Installation

```bash
git clone https://github.com/ShenaoW/MalSkills.git
cd MalSkills
python3 -m pip install -e .
```

## How to run MalSkills

Analyze a single skill:

```bash
malskills analyze-skill <skill-dir> --output <output-dir>
```

Run a single-skill static smoke test without LLM calls:

```bash
malskills analyze-skill <skill-dir> --output <output-dir> \
  --disable-llm-evidence \
  --disable-llm-object-analysis \
  --disable-yasa \
  --reasoning-mode formal
```

Run the full benchmark pipeline:

```bash
malskills run-eval \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/ground_truth_eval \
  --variant benchmark_full
```

Render a readable report:

```bash
malskills render-report --results output/ground_truth_eval
```

Inspect the resolved LLM runtime:

```bash
malskills show-llm-config
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

Generate it from the checked-in ground-truth CSV if it is not present:

```bash
malskills build-benchmark-index \
  --root . \
  --output output/ground_truth_final_benchmark.json
```

Run the full system:

```bash
malskills run-eval \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/rq1_malskills \
  --variant benchmark_full
```

### Ablation variants

The evaluation variants are defined in `malskills/evaluation.py`.

Examples:

```bash
malskills run-eval \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/rq2_no_neuro_reasoning \
  --variant benchmark_formal_reasoning_only
```

```bash
malskills run-eval \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/rq2_no_symbolic_extractor \
  --variant benchmark_llm_evidence_only
```

```bash
malskills run-eval \
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

- `MALSKILLS_LLM_MODE`
- `MALSKILLS_LLM_MODEL`
- `MALSKILLS_LLM_API_KEY`
- `MALSKILLS_LLM_BASE_URL`
- `MALSKILLS_LLM_TIMEOUT_SEC`

RQ3 model-specific variables:

- `RQ3_CLAUDE_MODEL`, `RQ3_CLAUDE_API_KEY`, `CLAUDE_API_URL`
- `RQ3_GEMINI_MODEL`, `RQ3_GEMINI_API_KEY`, `GEMINI_API_URL`
- `RQ3_QWEN_MODEL`, `RQ3_QWEN_API_KEY`, `QWEN_API_URL`
- `RQ3_DEEPSEEK_MODEL`, `RQ3_DEEPSEEK_API_KEY`, `DEEPSEEK_API_URL`

## Baselines

Example baseline commands:

```bash
malskills run-eval \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/codex_agent_baseline \
  --variant benchmark_codex_agent_baseline
```

```bash
malskills run-eval \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/caterpillar_baseline \
  --variant benchmark_caterpillar_baseline
```

```bash
malskills run-eval \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/skill_scanner_baseline \
  --variant benchmark_skill_scanner_baseline
```
