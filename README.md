# MalSkills

MalSkills is a neuro-symbolic analyzer for detecting malicious agent Skills
across prompts, source code, manifests, configuration files, and setup scripts.
It produces a binary `malicious` or `benign` verdict together with the
Security-Sensitive Operations (SSOs), dependency graph, matched behavior rules,
and reasoning proofs behind the decision.

![MalSkills pipeline](assets/malskills.png)

> [!IMPORTANT]
> **Extended baseline reproduction notice.** The paper's RQ1 compared MalSkills
> with five baselines using `gpt-5.3-codex-medium`. The current repository
> integrates 22 baseline adapters and defaults all LLM-backed analysis to
> `gpt-5.6-luna`. Results produced by the current setup are an updated extended
> study and are not expected to match the original RQ1 table exactly. Record the
> model, baseline revision, enabled mode, `suspicious`/error policy, and coverage
> when reporting new results.

## How it works

1. **SSO extraction** identifies behavior-neutral sensitive operations. The
   code extractor uses 2,665 Semgrep rules across 10 languages; Markdown and
   Shell rules and a batched LLM semantic pass cover non-code and implicit
   operations.
2. **SDG construction** builds a Skill Dependency Graph over Artifacts, SSOs,
   Operands, and Values. YASA and cross-artifact resolution recover object
   identity and directional value flow.
3. **Behavior reasoning** executes 10 connected SDG workflow rules covering 9
   malicious behavior classes. In hybrid mode, the LLM is called only for an
   uncovered connected multi-SSO workflow.

The built-in behavior classes are Data Exfiltration, Credential Theft, Remote
Code Execution, Malware Delivery, Persistence, Reverse Shell, Ransomware,
Resource Abuse, and Privilege Escalation. Malware Delivery has two built-in
workflow rules, which is why there are 10 rules for 9 classes.

See [SSO taxonomy](docs/SSO_TAXONOMY.md) and
[SDG behavior rules](docs/BEHAVIOR_RULES.md) for the formal definitions.

## Requirements

- Python `>= 3.10` for the complete setup (the core package supports 3.9, but
  current Semgrep releases require 3.10)
- Semgrep for default analysis, `full` corpus scans, and benchmark reproduction
- Either Codex CLI authenticated with `codex login`, or an OpenAI-compatible
  API endpoint and key, for LLM stages
- Git submodules for the YASA engine and baseline implementations
- Baseline-specific Python, Node.js, Go, Docker, sandbox, or API dependencies
  when running those tools

Semgrep is a soft dependency at runtime only to support deliberate reduced
analysis. If it is unavailable while enabled, MalSkills records
`semgrep.status=unavailable` in `analysis_metadata.json` and continues without
code-rule findings. Such a run is not the complete pipeline and is not a valid
paper benchmark reproduction.

## Installation

```bash
git clone --recurse-submodules https://github.com/ShenaoW/MalSkills.git
cd MalSkills

python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/pip install semgrep
.venv/bin/semgrep --version
# Codex CLI mode only:
codex login
```

For an existing checkout, synchronize the pinned dependencies:

```bash
git submodule sync --recursive
git submodule update --init --recursive
git submodule status --recursive
```

Third-party baseline dependencies are not installed by the root package. Use an
isolated environment for each Python baseline and follow its upstream README.

## Quick start

Run the complete analyzer on one Skill:

```bash
.venv/bin/malskills analyze-skill path/to/skill \
  --output output/example \
  --llm-config malskills.toml
```

Run Semgrep and formal graph reasoning without LLM or deep value-flow analysis:

```bash
.venv/bin/malskills analyze-skill path/to/skill \
  --output output/example-static \
  --disable-llm-sso-extraction \
  --disable-llm-object-analysis \
  --disable-yasa \
  --disable-cross-artifact-resolution \
  --reasoning-mode formal
```

Use `--disable-semgrep` only for an intentional reduced run. It removes the
2,665 code-rule corpus from the analysis.

Render an existing result directory:

```bash
.venv/bin/malskills render-report --results output/example
```

## LLM configuration

The checked-in [malskills.toml](malskills.toml) routes MalSkills and all
LLM-backed baselines through one shared runtime. It defaults to the
authenticated Codex CLI. Global settings are in `[llm]`; each MalSkills stage
can override `enabled`, `mode`, `model`, `reasoning_effort`, `enable_thinking`,
and `timeout_sec`.

```toml
[llm]
mode = "codex_cli"
model = "gpt-5.6-luna"
reasoning_effort = "low"
timeout_sec = 300
enable_thinking = false

[llm.sso_extraction]
enabled = true

[llm.object_analysis]
enabled = true

[llm.pattern_reasoning]
enabled = true

[llm.rule_feedback]
enabled = false
```

To use an OpenAI-compatible API instead, change only the global mode and model
in TOML. Keep credentials out of the file:

```toml
[llm]
mode = "api"
model = "gpt-5.6-luna"
timeout_sec = 300
```

```bash
cp .env.example .env
chmod 600 .env
# Edit .env and set MALSKILLS_LLM_BASE_URL and MALSKILLS_LLM_API_KEY.
```

`OPENAI_BASE_URL` and `OPENAI_API_KEY` are accepted as compatibility aliases.
The `MALSKILLS_*` names take precedence. In API mode, the URL and key are
required environment variables; `show-llm-config` reports only whether a key
is configured and never prints its value. The same global backend and model
are used by every LLM-backed baseline adapter.

Keep persistent environment-specific values in `.env`; do not duplicate them
in shell startup files. The committed [.env.example](.env.example) contains all
supported long-lived settings:

| Group | Variables |
|---|---|
| Shared LLM API | `MALSKILLS_LLM_BASE_URL`, `MALSKILLS_LLM_API_KEY` |
| External baselines | `SNYK_TOKEN`, `VIRUSTOTAL_API_KEY` |
| Local tools | `MALSKILLS_CODEX_CLI`, `MALSKILLS_CLAUDE_CLI`, `MALSKILLS_YASA_UAST_SDK` |
| RQ3 profiles | `RQ3_*_MODEL`, `RQ3_*_API_KEY`, and the corresponding `*_API_URL` |
| Performance tuning | LLM batch/worker/prompt limits and Semgrep timeout |

Mode, model, timeout, reasoning effort, and stage enablement belong in
`malskills.toml`. Per-run paths such as `MALSKILLS_CONFIG`, cache directories,
and internal bridge credentials are generated or supplied by the CLI and
should not be stored in `.env`.

| Stage | Purpose | Current default |
|---|---|---:|
| `sso_extraction` | Supplement static SSO findings and batch operand bindings | enabled |
| `object_analysis` | Resolve remaining sink operands as a fallback | enabled |
| `pattern_reasoning` | Review uncovered connected SDG workflows | enabled |
| `rule_feedback` | Review LLM-only findings for reusable rules | disabled |

Inspect the effective configuration before a long run:

```bash
.venv/bin/malskills show-llm-config --llm-config malskills.toml
```

Environment variables override TOML settings. Use `MALSKILLS_LLM_*` globally or
the stage prefixes `MALSKILLS_LLM_SSO_EXTRACTION_*`,
`MALSKILLS_LLM_OBJECT_ANALYSIS_*`, `MALSKILLS_LLM_PATTERN_REASONING_*`, and
`MALSKILLS_LLM_RULE_FEEDBACK_*`. The precedence order is stage environment,
global environment, stage TOML, global TOML, then the built-in default.

## Analysis outputs

The canonical analysis path is:

```text
SSOFinding -> SSO -> Operand -> Value -> Pattern -> Verdict
```

`SSOFinding` is a source-grounded extractor record, not an SDG node. The SDG
contains `Artifact -> SSO -> Operand -> Value` relations plus directional
`Value -> Value` propagation edges.

| Output | Contents |
|---|---|
| `verdict.json` | Binary verdict, matched behaviors, and decision chain |
| `human_report.md` | Human-readable result summary |
| `artifacts.json` | Normalized artifact inventory |
| `sso_findings.json`, `ssos.json` | Source findings and normalized SSOs |
| `operands.json`, `values.json` | Operation objects and bound values |
| `operand_resolutions.json` | Binding provenance and proven flow steps |
| `sdg.json`, `sdg.dot` | Machine-readable and Graphviz SDG |
| `pattern_summary.json`, `proofs.json` | Matched graph rules and reasoning traces |
| `workflow_discoveries.json` | LLM-nominated reusable workflows |
| `feedback_loop.json` | Rule-feedback observations and candidates |
| `analysis_metadata.json` | Stage status, model use, and ruleset digest |
| `output_manifest.json` | Output schema version and file map |

## Large-corpus scanning

`scan-corpus` deterministically samples a registry-style corpus, supports
parallel workers and resume, and retains detailed results according to policy.
The expected layout is `<corpus-root>/<source>/<package>/.../SKILL.md`.

```bash
.venv/bin/malskills scan-corpus \
  --corpus-root /path/to/skills \
  --output output/corpus-scan-2000 \
  --sample-size 2000 \
  --seed 1337 \
  --workers 4 \
  --profile full \
  --llm-config malskills.toml
```

| Profile | Extraction | Reasoning | Rule candidates |
|---|---|---|---|
| `static` | Semgrep and built-in static extraction | formal SDG rules | disabled |
| `full` | Static extraction plus batched LLM semantics | hybrid | collected in the rule store |

The `full` profile explicitly enables all four LLM stages, including
`rule_feedback`, regardless of the per-stage `enabled` values in the checked-in
configuration. It uses the configured model and stores learned-rule state under
`<output>/learned_rules` unless `--rule-store` is provided.

The scanner selects one primary Skill tree per package and removes exact
duplicate primary `SKILL.md` content unless `--keep-content-duplicates` is
used. Results are appended to `scan_results.jsonl`; rerun with `--resume` after
an interruption. `sample_manifest.json` records the exact sample,
`scan_config.json` protects resume compatibility, and `scan_summary.json`
reports throughput, verdicts, behavior distribution, and candidate counts.

By default, complete per-Skill outputs are retained for malicious results and
errors. Change this with `--retain all` or `--retain none`. Because the corpus is
unlabeled, flag rate must not be reported as precision or malware prevalence.

## Benchmark reproduction

The labeled benchmark contains 100 malicious and 100 benign Skills. Generate
its index from the checked-in ground truth when needed:

```bash
.venv/bin/malskills build-benchmark-index \
  --root . \
  --output output/ground_truth_final_benchmark.json
```

Run the current full configuration:

```bash
.venv/bin/malskills run-eval \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/rq1_malskills_current \
  --variant benchmark_full \
  --llm-config malskills.toml
```

The evaluator prints colored ingest, SSO, SDG, reasoning, and result events for
every sample, with a `WAIT` heartbeat every 30 seconds. Use
`--progress-interval`, `--color`, or `--quiet` to control the output.

Malicious is the positive class. A baseline prediction of `suspicious` is
excluded from TP/TN/FP/FN, and coverage is the non-suspicious fraction. An
`error` remains in the evaluated set as a non-malicious prediction: it is an FN
for a malicious sample and a TN for a benign sample. Always report coverage,
`suspicious` count, and error count beside precision, recall, FPR, and F1.

Available MalSkills variants:

| Variant | Change from the full pipeline |
|---|---|
| `benchmark_full` | Complete benchmark configuration |
| `benchmark_semgrep_findings_only` | Disable LLM SSO extraction |
| `benchmark_llm_findings_only` | Disable Semgrep findings |
| `benchmark_formal_reasoning_only` | Force formal graph reasoning |
| `benchmark_llm_reasoning_only` | Force LLM behavior reasoning |
| `benchmark_no_yasa` | Disable YASA value-flow analysis |
| `benchmark_no_cross_artifact_resolution` | Disable cross-artifact resolution |
| `benchmark_static_only` | Disable LLM, YASA, and cross-artifact resolution |

The RQ3 driver is [experiments/run_rq3_llm_comparison.py](experiments/run_rq3_llm_comparison.py).
Paper-reproduction guidance is in
[docs/DEMO_REPRODUCTION.md](docs/DEMO_REPRODUCTION.md).

## Baseline integrations

Every adapter preserves the upstream report and writes a normalized
`output_manifest.json` with `predicted`, `score`, and `patterns`. LLM-backed
adapters share the backend and model configured in `malskills.toml`.

The default benchmark driver includes these 15 adapters:

| Variant suffix | Tool | Runtime |
|---|---|---|
| `skill_security_audit_baseline` | skill-security-audit | Python |
| `skill_security_scan_baseline` | skill-security-scan | Python |
| `skills_security_audit_baseline` | skills_security_audit | Python |
| `caterpillar_baseline` | Caterpillar | Node.js + configured LLM |
| `clawscan_baseline` | ClawScan by ClawGuard | Node.js |
| `skill_scanner_baseline` | Cisco AI Defense Skill Scanner | Python + configured LLM |
| `nova_proximity_baseline` | Nova Proximity | Python + configured LLM |
| `agentguard_baseline` | GoPlus AgentGuard | Node.js |
| `skillspector_baseline` | NVIDIA SkillSpector | Python + configured LLM |
| `agentverus_baseline` | AgentVerus Scanner | Node.js 22+ |
| `skilltotal_baseline` | SkillTotal | Python 3.10+ |
| `clawvet_baseline` | ClawVet | Node.js 22+ |
| `razin_baseline` | Razin | Python 3.12+ |
| `openclaw_clawscan_baseline` | OpenClaw ClawScan | Go |
| `skillfortify_baseline` | SkillFortify | Python 3.11+ |

These 7 adapters are opt-in because they require an external service, sandbox,
or heavier runtime setup:

| Variant suffix | Tool | Additional requirement |
|---|---|---|
| `masb_baseline` | MaliciousAgentSkillsBench | Configured LLM and `codex-skill-sandbox` dynamic validation |
| `snyk_agent_scan_baseline` | Snyk Agent Scan | `SNYK_TOKEN` |
| `ai_infra_guard_baseline` | Tencent AI-Infra-Guard | Configured LLM |
| `skillsieve_baseline` | SkillSieve | Configured LLM |
| `skillward_baseline` | SkillWard | Configured LLM, Docker, and its sandbox image |
| `runtime_skill_audit_baseline` | Runtime Skill Audit | Configured LLM, OpenClaw, Docker, and `rsa_sandbox` |
| `skill_sentinel_baseline` | Enkrypt AI Skill Sentinel | Configured LLM; optional `VIRUSTOTAL_API_KEY` |

Run one baseline on the complete benchmark:

```bash
.venv/bin/malskills run-eval \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/skillspector_baseline \
  --variant benchmark_skillspector_baseline \
  --llm-config malskills.toml
```

Run MalSkills ablations and the default baseline set:

```bash
.venv/bin/python experiments/run_benchmark_study.py \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/benchmark_study
```

Add the opt-in adapters only after their dependencies are ready:

```bash
.venv/bin/python experiments/run_benchmark_study.py \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/benchmark_study_all \
  --include-optional-baselines
```

Snyk Agent Scan continues to call the Snyk service. Other LLM-backed adapters
use a short-lived local compatibility bridge. In Codex mode it translates
OpenAI-, Anthropic-, or Ollama-compatible requests into `codex exec` calls; in
API mode it forwards them to the configured upstream without exposing the
upstream key to baseline command arguments or reports. MASB uses the same
backend for both its static audit and its monitored dynamic sandbox agent.

## Guarded rule learning

Rule learning is opt-in. It accumulates LLM-only SSO findings and uncovered
connected workflows without changing the active rules during the scan that
produced them.

```bash
.venv/bin/malskills analyze-skill path/to/skill \
  --output output/example-learning \
  --rule-store output/learned-rules \
  --collect-rule-candidates \
  --rule-group-id campaign-or-dedup-id

.venv/bin/malskills rules list --store output/learned-rules
.venv/bin/malskills rules validate <candidate-id> \
  --store output/learned-rules \
  --manifest held-out.json
.venv/bin/malskills rules promote <candidate-id> \
  --store output/learned-rules \
  --approved-by <reviewer>
```

Promotion, deactivation, and rollback are explicit, validated, and retained in
the content-addressed rule store. See
[docs/RULE_LEARNING.md](docs/RULE_LEARNING.md) for validation gates and
poisoning controls.

## Repository layout

- `malskills/`: analyzer, CLI, SDG compiler, reasoning, and adapters
- `semgrep_rules/`: 2,665 neutral code-level SSO rules
- `malskills/rules/`: Markdown/Shell SSO rules and SDG workflow rules
- `experiments/`: benchmark, ablation, and LLM-comparison drivers
- `data/`: benchmark source data and analysis inputs
- `baseline/`: pinned third-party baseline implementations
- `vendor/yasa/`: pinned YASA value-flow engine
- `docs/`: taxonomy, behavior rules, rule learning, and reproduction notes
- `assets/`: paper artifacts and figures
- `output/`: generated indexes, scan outputs, and evaluation results

## Further documentation

- [Paper-to-implementation alignment](docs/PAPER_ALIGNMENT.md)
- [SSO taxonomy](docs/SSO_TAXONOMY.md)
- [SDG behavior rules](docs/BEHAVIOR_RULES.md)
- [Guarded rule learning](docs/RULE_LEARNING.md)
- [Reproduction and delivery guide](docs/DEMO_REPRODUCTION.md)

Third-party code remains under each upstream project's license. In particular,
review the current AgentVerus licensing terms and SkillFortify's Elastic License
2.0 before redistribution or commercial use; a submodule does not relicense its
contents under MalSkills.
