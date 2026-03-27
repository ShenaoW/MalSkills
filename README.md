# MalSkills Artifact

This repository contains the research artifact for **MalSkills**, a neuro-symbolic framework for **malicious skill detection** in the emerging **agentic supply chain**.

In the paper, MalSkills is organized as a three-stage pipeline:

1. **Security-Sensitive Operation (SSO) extraction**
2. **Skill Dependency Graph (SDG) generation**
3. **Neuro-symbolic reasoning**

The implementation in this repository follows the same high-level design, while exposing a practical CLI and experiment scripts for artifact evaluation.

## What MalSkills Does

MalSkills analyzes a skill package as a collection of heterogeneous artifacts, including:

- source code
- prompts and markdown instructions
- manifests and configuration files
- setup and installation scripts

Instead of directly asking whether a skill is malicious, MalSkills first extracts **security-sensitive operations**, then links operations, operands, and value flows into an **operand-centric SDG**, and finally performs **neuro-symbolic reasoning** to detect malicious patterns or previously unseen suspicious workflows.

This design follows the paper’s core claim: malicious skill detection is fundamentally a **cross-artifact, context-dependent reasoning problem**, and cannot be solved well by code-only scanning, free-form LLM judgments, or isolated dynamic checks alone.

## Repository Layout

- [paper/main.tex](/home/shenaow/AgentSkill/paper/main.tex): paper source
- [paper/Chapters/4.methodology.tex](/home/shenaow/AgentSkill/paper/Chapters/4.methodology.tex): methodology
- [paper/Chapters/5.evaluation.tex](/home/shenaow/AgentSkill/paper/Chapters/5.evaluation.tex): evaluation and research questions
- [MalSkills/](/home/shenaow/AgentSkill/MalSkills): main implementation
- [experiments/](/home/shenaow/AgentSkill/experiments): experiment drivers, including RQ3 LLM comparison
- [data/](/home/shenaow/AgentSkill/data): benchmark and evaluation inputs
- [output/](/home/shenaow/AgentSkill/output): generated experiment results
- [baseline/](/home/shenaow/AgentSkill/baseline): baseline tools used in evaluation
- [tests/](/home/shenaow/AgentSkill/tests): regression tests

For readers cross-referencing the paper and code:

- **SSO extraction** is primarily implemented under [MalSkills/evidence](/home/shenaow/AgentSkill/MalSkills/evidence)
- **SDG generation** is implemented through operand recovery, object binding, and cross-artifact linking under [MalSkills/primitive](/home/shenaow/AgentSkill/MalSkills/primitive)
- **Neuro-symbolic reasoning** is implemented under [MalSkills/reasoning](/home/shenaow/AgentSkill/MalSkills/reasoning)

## Artifact Scope

The artifact supports the four research questions described in the paper:

- **RQ1: Effectiveness** on the labeled malicious/benign benchmark
- **RQ2: Ablation Study** for major MalSkills components
- **RQ3: Impact of LLMs** under different model backends
- **RQ4: Practicality** for large-scale registry scanning

The benchmark used for the main comparison is the paper’s balanced 200-skill benchmark, exposed in this repository as [output/ground_truth_final_benchmark.json](/home/shenaow/AgentSkill/output/ground_truth_final_benchmark.json).

## Environment

The artifact requires:

- Python `>= 3.9`
- a working `python3` environment
- optional external analyzers such as `semgrep`
- optional LLM credentials in `.env` for full neuro-symbolic experiments

The project metadata is declared in [pyproject.toml](/home/shenaow/AgentSkill/pyproject.toml).

For LLM-backed runs, MalSkills reads runtime configuration from `.env`. The most commonly used variables are:

- `MalSkills_LLM_MODE`
- `MalSkills_LLM_MODEL`
- `MalSkills_LLM_API_KEY`
- `MalSkills_LLM_BASE_URL`
- `MalSkills_LLM_TIMEOUT_SEC`

For the RQ3 script, model-specific environment variables are used instead, such as:

- `RQ3_CLAUDE_MODEL`, `RQ3_CLAUDE_API_KEY`, `CLAUDE_API_URL`
- `RQ3_GEMINI_MODEL`, `RQ3_GEMINI_API_KEY`, `GEMINI_API_URL`
- `RQ3_QWEN_MODEL`, `RQ3_QWEN_API_KEY`, `QWEN_API_URL`
- `RQ3_DEEPSEEK_MODEL`, `RQ3_DEEPSEEK_API_KEY`, `DEEPSEEK_API_URL`

You can inspect the resolved runtime with:

```bash
python3 -m MalSkills.cli show-llm-config
```

## Quick Start

Analyze a single skill:

```bash
python3 -m MalSkills.cli analyze-skill <path-to-skill> --output <output-dir>
```

Run the full paper-style pipeline on the main benchmark:

```bash
python3 -m MalSkills.cli run-eval \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/ground_truth_eval \
  --variant benchmark_full
```

Render a human-readable summary for an evaluation directory:

```bash
python3 -m MalSkills.cli render-report --results output/ground_truth_eval
```

## Output Artifacts

For each analyzed skill, MalSkills emits machine-readable and human-readable outputs, including:

- `verdict.json`: final label and reasoning summary
- `all_evidence.json`: extracted SSO-level evidence from heterogeneous artifacts
- `pattern_summary.json`: matched malicious or suspicious behavior patterns
- `evidence_graph.json`: graph view of the recovered dependency structure
- `proofs.json`: reasoning traces
- `human_report.md`: readable explanation for manual inspection

These files correspond to the paper’s pipeline stages:

- extracted **SSOs**
- recovered **operands/value flows**
- inferred **malicious or suspicious workflows**

## Reproducing the Main Experiments

### RQ1: Effectiveness

Run the full MalSkills pipeline on the 200-skill benchmark:

```bash
python3 -m MalSkills.cli run-eval \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/rq1_MalSkills \
  --variant benchmark_full
```

This is the closest CLI entry point to the paper’s full system:

- parsing-based symbolic extraction
- LLM-assisted SSO extraction
- operand recovery and SDG construction
- neuro-symbolic reasoning

### RQ2: Ablation Study

The ablation variants are exposed through `run-eval` variants in [MalSkills/evaluation.py](/home/shenaow/AgentSkill/MalSkills/evaluation.py). Representative examples:

```bash
python3 -m MalSkills.cli run-eval \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/rq2_no_neuro_reasoning \
  --variant benchmark_formal_reasoning_only
```

```bash
python3 -m MalSkills.cli run-eval \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/rq2_no_symbolic_extractor \
  --variant benchmark_llm_evidence_only
```

```bash
python3 -m MalSkills.cli run-eval \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/rq2_no_neuro_extractor \
  --variant benchmark_semgrep_evidence_only
```

### RQ3: Impact of LLMs

Use the dedicated driver:

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

This script resolves the model-specific API settings from `.env`, runs MalSkills separately for each LLM, and writes per-model reports plus a summary CSV/JSON.

### RQ4: Practicality

The repository also includes large-scale outputs and scripts used for broader ecosystem scanning. The paper’s large-scale practicality study is based on scanning a large unlabeled corpus from public registries after deduplication. In this artifact, the same pipeline is reused; the main difference is the benchmark/input file size.

## Baselines

The artifact includes baseline integrations used in the evaluation. Example commands:

```bash
python3 -m MalSkills.cli run-eval \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/codex_agent_baseline \
  --variant benchmark_codex_agent_baseline
```

```bash
python3 -m MalSkills.cli run-eval \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/caterpillar_baseline \
  --variant benchmark_caterpillar_baseline
```

```bash
python3 -m MalSkills.cli run-eval \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/skill_scanner_baseline \
  --variant benchmark_skill_scanner_baseline
```

Additional baseline variants are defined in [MalSkills/evaluation.py](/home/shenaow/AgentSkill/MalSkills/evaluation.py).

## Paper-Aligned Terminology

Some implementation identifiers predate the final paper wording. For artifact readers, the paper terminology should be treated as authoritative:

- **Security-Sensitive Operation (SSO)**: the paper-level abstraction for operational evidence recovered from code, prompts, and manifests
- **Skill Dependency Graph (SDG)**: the operand-centric graph connecting artifacts, SSOs, operands, and value flows
- **Neuro-symbolic reasoning**: the final stage that combines pattern-based symbolic reasoning with LLM-assisted semantic interpretation

When navigating the implementation, you may still encounter lower-level engineering terms introduced during development. They are artifact-internal and should be interpreted through the paper’s final presentation.

## Minimal Validation

Quick syntax check:

```bash
python3 -m py_compile \
  experiments/run_rq3_llm_comparison.py \
  MalSkills/*.py \
  MalSkills/evidence/*.py \
  MalSkills/primitive/*.py \
  MalSkills/reasoning/*.py \
  tests/*.py
```

Example regression test:

```bash
pytest -q tests/test_yasa_object_binding.py
```

## Reference Results

The paper reports the following main findings on the 200-skill benchmark:

- MalSkills achieves the best overall F1 in RQ1
- neuro reasoning is the most important component in the ablation study
- the choice of LLM materially affects the precision/recall trade-off

See:

- [paper/Chapters/5.evaluation.tex](/home/shenaow/AgentSkill/paper/Chapters/5.evaluation.tex)
- [paper/Chapters/4.methodology.tex](/home/shenaow/AgentSkill/paper/Chapters/4.methodology.tex)
- [paper/Chapters/0.abstract.tex](/home/shenaow/AgentSkill/paper/Chapters/0.abstract.tex)

## Citation

If you use this artifact, please cite the corresponding paper and explicitly reference the MalSkills artifact repository in your evaluation or reproduction notes.
