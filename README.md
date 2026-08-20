# MalSkills

MalSkills is a neuro-symbolic system for detecting malicious agent skills from heterogeneous skill artifacts.

> [!IMPORTANT]
> **Extended baseline reproduction notice.** The paper's RQ1 evaluated
> MalSkills against five baselines (Cisco Skill Scanner, Nova-Proximity,
> Skill-Sec-Scan, Caterpillar, and MASB) using
> `gpt-5.3-codex-medium` for LLM-backed analysis. This repository now includes
> a substantially larger baseline suite and defaults MalSkills and all
> Codex-backed baselines to the newer `gpt-5.6-luna` model. Consequently,
> newly generated baseline metrics and rankings are updated extended-study
> results and are not expected to match the values in the paper's RQ1 table
> exactly. When reporting results, keep the paper and current settings
> separate and record the model, baseline revision, enabled analysis mode,
> `suspicious`/error policy, and evaluated coverage. Selecting the paper model
> alone does not guarantee exact reproduction because the baseline adapters
> and supported execution paths have also been expanded since the paper.

It works in three stages:

1. **Security-Sensitive Operation extraction**: identify security-relevant operations from code, prompts, manifests, configuration files, and setup instructions.
2. **Skill Dependency Graph generation**: recover the operands of those operations and connect them through object identity and value-flow relations.
3. **Neuro-symbolic reasoning**: detect malicious behavior patterns from the graph and produce a binary `malicious` or `benign` verdict.

![MalSkills pipeline](assets/malskills.png)

## What the repository contains

- `malskills/`: main implementation
- `experiments/`: experiment drivers
- `data/`: benchmark and analysis inputs
- `output/`: generated results
- `baseline/`: baseline integrations
- `assets/`: figures used in this artifact

## Requirements

- Python `>= 3.9`
- optional `semgrep` for parsing-based extraction
- Codex CLI installed and authenticated (`codex login`) for full LLM runs
- baseline-specific Python, Node.js, Go, Docker, and API dependencies as listed below

The project metadata is in `pyproject.toml`.

## Installation

```bash
git clone --recurse-submodules https://github.com/ShenaoW/MalSkills.git
cd MalSkills
python3 -m pip install -e .
```

For an existing checkout, synchronize and initialize every pinned baseline and
the YASA engine:

```bash
git submodule sync --recursive
git submodule update --init --recursive
git submodule status --recursive
```

## How to run MalSkills

Analyze a single skill:

```bash
malskills analyze-skill <skill-dir> --output <output-dir>
```

Run a single-skill static smoke test without LLM calls:

```bash
malskills analyze-skill <skill-dir> --output <output-dir> \
  --disable-llm-sso-extraction \
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

Scan a deterministic sample from a large, unlabeled corpus:

```bash
malskills scan-corpus \
  --corpus-root /path/to/skills \
  --output output/corpus-scan-2000 \
  --sample-size 2000 \
  --seed 1337 \
  --workers 4 \
  --profile full \
  --llm-config malskills.toml
```

`scan-corpus` treats each source's first-level directory as one logical Skill,
selects one primary version tree, and removes exact duplicate primary
`SKILL.md` content before sampling. The `full` profile enables Semgrep, LLM SSO
and operand extraction, YASA, cross-artifact resolution, hybrid graph
reasoning, and rule-candidate collection. Its rule store defaults to
`<output>/learned_rules`. The static profile disables every LLM stage and uses
formal graph reasoning.

Results are appended to `scan_results.jsonl` as cases complete. Re-run the same
command with `--resume` after an interruption. `sample_manifest.json` records
the exact sample, `scan_config.json` prevents incompatible resume settings, and
`scan_summary.json` reports throughput, flag rate, behavior distribution, and
rule-candidate observations. Because corpus entries are unlabeled, flag rate is
not reported as precision or malware prevalence. By default, complete evidence
directories are retained only for malicious results and errors; use
`--retain all` or `--retain none` to change that policy.

Evaluation prints colored stage events for every case: ingest, SSO extraction,
SDG compilation, behavior reasoning, and result writing. It also prints a
`WAIT` heartbeat every 30 seconds while a stage is running. The completed-case
line includes the prediction, runtime, finding/SSO/operand counts, matched
behavior patterns, the running confusion matrix, and its output directory.
Change the heartbeat cadence with `--progress-interval SECONDS`, use
`--color always` to preserve colors through a pipe such as `tee`, or use
`--quiet` when only the final summary is needed. `NO_COLOR` disables ANSI color
when `--color auto` is active.

Render a readable report:

```bash
malskills render-report --results output/ground_truth_eval
```

Inspect the resolved LLM runtime:

```bash
malskills show-llm-config
```

The default [malskills.toml](malskills.toml) routes every MalSkills LLM stage
and every LLM-backed baseline through the authenticated Codex CLI, using
`gpt-5.6-luna`. The original paper experiments used
`gpt-5.3-codex-medium` consistently; selecting that model is one required
setting when attempting to reproduce the original paper experiment. Use
another file for a local or deployment-specific configuration:

```bash
malskills show-llm-config --llm-config /path/to/malskills.toml
malskills analyze-skill <skill-dir> --output <output-dir> \
  --llm-config /path/to/malskills.toml
```

The file supports global defaults and per-stage overrides:

```toml
[llm]
mode = "codex_cli"
model = "gpt-5.6-luna"
reasoning_effort = "low"
timeout_sec = 300

[llm.sso_extraction]
enabled = true
model = "gpt-5.6-luna"

[llm.object_analysis]
enabled = true
model = "gpt-5.6-luna"

[llm.pattern_reasoning]
enabled = true
model = "gpt-5.6-luna"

[llm.rule_feedback]
enabled = false
model = "gpt-5.6-luna"
```

Disabling `pattern_reasoning` makes the analyzer use formal reasoning unless
`--reasoning-mode hybrid` or `--reasoning-mode llm` is supplied explicitly.
Enabling `rule_feedback` also requires a rule store because that stage persists
candidate observations.

## Main outputs

Each analyzed skill produces:

- `verdict.json`: final binary label, matched malicious patterns, and decision chain
- `sso_findings.json`: source-grounded extractor findings used to form security-sensitive operations
- `ssos.json`: normalized security-sensitive operations, with supporting Finding IDs and Operand IDs
- `operands.json`: role-bearing objects used by SSOs, such as endpoint, command, payload, and path operands
- `values.json`: literal, symbolic, and program values bound to or propagated into Operands
- `operand_resolutions.json`: binding provenance and analyzer-proven value-flow steps
- `pattern_summary.json`: matched malicious patterns
- `sdg.json`: the Artifact/SSO/Operand/Value dependency graph
- `sdg.dot`: Graphviz rendering of the same dependency graph
- `proofs.json`: reasoning traces
- `human_report.md`: readable explanation
- `workflow_discoveries.json`: LLM-nominated reusable workflow candidates
- `analysis_metadata.json`: extractor status and the content-addressed ruleset digest

The canonical analysis path is `SSOFinding -> SSO -> Operand -> Value -> Pattern -> Verdict`.
`SSOFinding` records are source-grounded extractor outputs and are not SDG nodes.
The canonical SDG path is `Artifact -> SSO -> Operand -> Value`; proven assignment
or call propagation is represented by directional `Value -> Value` edges.

SSO extraction uses a behavior-neutral taxonomy: code rules report atomic
execution, network, file, sensitive-data, cryptographic, installation, process,
and system-configuration operations rather than malicious tactics. The default
code corpus contains 2,665 Semgrep rules across 10 languages; Markdown and Shell
artifact rules are counted separately. See [the SSO taxonomy](docs/SSO_TAXONOMY.md).
Formal behavior reasoning uses nine declarative, connected SDG queries rather
than ATT&CK tactic labels or command-text matching. See
[the behavior rules](docs/BEHAVIOR_RULES.md).

## Guarded rule learning

LLM-only SSO discoveries and uncovered connected workflows can be accumulated in a persistent rule store. Collection is opt-in and never changes the active rules during the scan that produced a candidate:

```bash
malskills analyze-skill <skill-dir> \
  --output <output-dir> \
  --rule-store output/learned-rules \
  --collect-rule-candidates \
  --rule-group-id <dedupe-or-campaign-id>
```

Inspect, validate, and explicitly promote a candidate:

```bash
malskills rules list --store output/learned-rules
malskills rules validate <candidate-id> \
  --store output/learned-rules \
  --manifest held-out.json
malskills rules promote <candidate-id> \
  --store output/learned-rules \
  --approved-by <reviewer>
```

Future scans reuse the promoted Semgrep and graph rules by passing the same `--rule-store`, including when LLM analysis is disabled. See [the rule-learning guide](docs/RULE_LEARNING.md) for validation manifests, default gates, rollback, and poisoning controls. The detailed [paper alignment audit](docs/PAPER_ALIGNMENT.md) records what is aligned and what remains incomplete.

Use `malskills rules deactivate <candidate-id> --store <store> --approved-by <reviewer>` to withdraw one active rule while retaining unrelated active rules.

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
  --variant benchmark_llm_findings_only
```

```bash
malskills run-eval \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/rq2_no_neuro_extractor \
  --variant benchmark_semgrep_findings_only
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

- `MALSKILLS_CONFIG`
- `MALSKILLS_LLM_ENABLED`
- `MALSKILLS_LLM_MODE`
- `MALSKILLS_LLM_MODEL`
- `MALSKILLS_LLM_API_KEY`
- `MALSKILLS_LLM_BASE_URL`
- `MALSKILLS_LLM_TIMEOUT_SEC`
- `MALSKILLS_LLM_REASONING_EFFORT`

Each stage also supports `MODE`, `MODEL`, `TIMEOUT_SEC`, and
`REASONING_EFFORT` overrides using these prefixes. The corresponding
`*_ENABLED` variable overrides the TOML `enabled` value:

- `MALSKILLS_LLM_SSO_EXTRACTION_*`
- `MALSKILLS_LLM_OBJECT_ANALYSIS_*`
- `MALSKILLS_LLM_PATTERN_REASONING_*`
- `MALSKILLS_LLM_RULE_FEEDBACK_*`

The precedence is stage environment variable, global environment variable,
stage TOML setting, global TOML setting, then the built-in default.

## LLM execution strategy

The default pipeline minimizes repeated model context:

1. Semgrep extracts static SSO findings first.
2. One batched semantic pass supplements SSO findings and resolves operands in
   the same response.
3. YASA results take precedence over LLM operand bindings.
4. The standalone object model is only a fallback for sinks not covered by
   YASA when the combined semantic pass did not run.
5. Hybrid pattern reasoning invokes the LLM only when formal reasoning found
   no pattern and the SDG still contains an uncovered connected multi-SSO
   workflow.

Code-oriented fallback prompts use a bounded source window around findings;
Markdown and prompt artifacts retain their full text because operation meaning
often depends on surrounding instructions. Semantic call counts and result
counts are recorded under `analysis_metadata.json.llm_semantic`.
The combined pass uses the `sso_extraction` model setting; `object_analysis`
configures only the standalone fallback.

RQ3 model-specific variables:

- `RQ3_CLAUDE_MODEL`, `RQ3_CLAUDE_API_KEY`, `CLAUDE_API_URL`
- `RQ3_GEMINI_MODEL`, `RQ3_GEMINI_API_KEY`, `GEMINI_API_URL`
- `RQ3_QWEN_MODEL`, `RQ3_QWEN_API_KEY`, `QWEN_API_URL`
- `RQ3_DEEPSEEK_MODEL`, `RQ3_DEEPSEEK_API_KEY`, `DEEPSEEK_API_URL`

## Baselines

The paper's RQ1 comparison contained five baselines. The current artifact
extends that comparison to the 22 adapters listed below, including newer
static, LLM-assisted, and sandbox-backed scanners. This expanded suite is
intended to evaluate the current tool landscape; it should be described as an
updated baseline study rather than a verbatim reproduction of the original RQ1
table. The current default model is `gpt-5.6-luna`, while the paper used
`gpt-5.3-codex-medium` consistently for LLM-backed tools.

Every adapter writes the upstream report, a normalized `output_manifest.json`,
and the common benchmark fields (`predicted`, `score`, and `patterns`). The
`benchmark_` prefix selects the same adapter while preserving the naming used
by benchmark experiments.

The default benchmark study includes the following baseline adapters. Several
of these tools now run their full upstream LLM-assisted path through the shared
Codex configuration rather than a reduced static-only mode:

| Variant suffix | Tool | Runtime |
|---|---|---|
| `skill_security_audit_baseline` | skill-security-audit | Python |
| `skill_security_scan_baseline` | skill-security-scan | Python |
| `skills_security_audit_baseline` | skills_security_audit | Python |
| `caterpillar_baseline` | Caterpillar | Node.js + authenticated Codex CLI |
| `clawscan_baseline` | ClawScan by ClawGuard | Node.js |
| `skill_scanner_baseline` | Cisco AI Defense skill-scanner | Python + authenticated Codex CLI |
| `nova_proximity_baseline` | Nova Proximity | Python + authenticated Codex CLI |
| `agentguard_baseline` | GoPlus AgentGuard | Node.js |
| `skillspector_baseline` | NVIDIA SkillSpector | Python + authenticated Codex CLI |
| `agentverus_baseline` | AgentVerus Scanner | Node.js 22+ |
| `skilltotal_baseline` | SkillTotal | Python 3.10+ |
| `clawvet_baseline` | ClawVet offline scanner | Node.js 22+ |
| `razin_baseline` | Razin | Python 3.12+ |
| `openclaw_clawscan_baseline` | OpenClaw ClawScan static scanner | Go |
| `skillfortify_baseline` | SkillFortify | Python 3.11+ |

The following integrations remain opt-in because they require an external
service, sandboxed execution, or substantially heavier runtime setup.
Codex-backed adapters in both tables reuse the same Codex CLI authentication
and `[llm]` model as MalSkills; they do not require separate OpenAI or LiteLLM
credentials. Set `model` in `malskills.toml` or `MALSKILLS_LLM_MODEL` to
override it for both MalSkills and these baselines.

| Variant suffix | Tool | Additional requirement |
|---|---|---|
| `masb_baseline` | MaliciousAgentSkillsBench | Authenticated Codex CLI; `codex-skill-sandbox` for dynamic execution |
| `snyk_agent_scan_baseline` | Snyk Agent Scan | `SNYK_TOKEN` |
| `ai_infra_guard_baseline` | Tencent AI-Infra-Guard | Authenticated Codex CLI |
| `skillsieve_baseline` | SkillSieve | Authenticated Codex CLI |
| `skillward_baseline` | SkillWard | Authenticated Codex CLI, Docker, and its sandbox image |
| `runtime_skill_audit_baseline` | Runtime Skill Audit | Authenticated Codex CLI, OpenClaw, Docker, and `rsa_sandbox` |
| `skill_sentinel_baseline` | Enkrypt AI Skill Sentinel | Authenticated Codex CLI; `VIRUSTOTAL_API_KEY` is optional |

Snyk Agent Scan is not an LLM baseline and continues to call the Snyk service
with its own `SNYK_TOKEN`. The Codex compatibility bridge is local and
short-lived: it translates each baseline's OpenAI-, Anthropic-, or
Ollama-compatible request into `codex exec` using the shared model setting.

Submodules pin source revisions but do not install upstream dependencies. Use
an isolated environment for each Python tool and follow the corresponding
`baseline/<tool>/README*`; build Node.js tools in their own submodule. This
avoids dependency conflicts between research prototypes.

Run one baseline directly:

```bash
malskills run-eval \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/skillspector_baseline \
  --variant benchmark_skillspector_baseline
```

Run the study with MalSkills ablations and the default baseline set:

```bash
python3 experiments/run_benchmark_study.py \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/benchmark_study
```

Include every optional baseline only after its external requirements are ready:

```bash
python3 experiments/run_benchmark_study.py \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/benchmark_study_all \
  --include-optional-baselines
```

Third-party code remains under each upstream project's license. In particular,
review the current AgentVerus licensing terms and SkillFortify's Elastic License
2.0 before redistribution or commercial use; a git submodule does not relicense
its contents under MalSkills.
