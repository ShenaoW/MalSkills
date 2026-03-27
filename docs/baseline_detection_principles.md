# Baseline Detection Principles for Table `baseline-tool-comparison`

## Purpose

This note explains the detection principles behind the seven baselines used in Table `baseline-tool-comparison`:

- `AI-Infra-Guard`
- `AgentScan`
- `Skill Scanner`
- `Nova-Proximity`
- `Skill-Sec-Scan`
- `Caterpillar`
- `MASB`

The goal is not to restate marketing claims, but to clarify what each baseline is actually doing for Skill security scanning, and why it was labeled as full, partial, or limited in the comparison table.

## Reading Guide

- `Artifact Cov.` means how broadly the tool can inspect Skill-related artifacts such as `SKILL.md`, scripts, references, config files, and other package files.
- `Static` means the tool has an explicit static-analysis path, such as rules, regex, AST, taint-like reasoning, or code audit without execution.
- `LLM` means the tool contains a real LLM-backed analysis path for Skill security.
- `Dynamic` means the tool executes the target or monitors runtime behavior.
- `Cross-artifact` means explicit reasoning across multiple artifacts, not just recursively scanning many files.

## 1. AI-Infra-Guard

### Detection principle

The Skill-related part of `AI-Infra-Guard` in this repository is mainly `baseline/AI-Infra-Guard/agent-scan`.

Its core pipeline is implemented in [`agent-scan/core/agent.py`](/home/shenaow/AgentSkill/baseline/AI-Infra-Guard/agent-scan/core/agent.py). The pipeline has three stages:

1. Information collection
2. Parallel vulnerability detection with multiple detection skills
3. Final review and classification

The important design choice is that the detector is not primarily a regex engine. Instead, it is an LLM-driven multi-agent audit framework. The second stage runs several dedicated detection skills in parallel, including:

- `data-leakage-detection`
- `tool-abuse-detection`
- `indirect-injection-detection`
- `authorization-bypass-detection`

These skills are stored under [`agent-scan/prompt/skills/`](/home/shenaow/AgentSkill/baseline/AI-Infra-Guard/agent-scan/prompt/skills).

### Why it is marked `Static = full`

Its Skill audit prompt explicitly requires static code audit only. In [`prompt/system/agents/code_audit.md`](/home/shenaow/AgentSkill/baseline/AI-Infra-Guard/agent-scan/prompt/system/agents/code_audit.md), the system instructs the worker to use file reading, search, and shell-based inspection for code review, while forbidding dynamic execution.

That means the main analysis mode for Skill repositories is static review, even though the implementation is LLM-driven.

### Why it is marked `LLM = full`

The pipeline itself is built around LLM agents. The detector loads prompts, dispatches worker agents, merges findings, and then lets a reviewer consolidate and classify results. So the LLM is not optional decoration here; it is the main analysis engine.

### Why it is marked `Dynamic = none`

For Skill scanning in `agent-scan`, the audit path is static. The code audit prompt explicitly frames the process as static-only, and there is no dedicated runtime execution engine for Skill repositories in this module.

### Why it is marked `Cross-artifact = partial`

`AI-Infra-Guard` can jointly inspect `SKILL.md`, scripts, and repository code, and the workers are encouraged to reason over their consistency. In particular, its Skill audit mode is triggered by the presence of `SKILL.md`, and then compares declared functionality with real implementation.

However, it does not expose a structured cross-artifact reasoning engine like an object graph, dataflow graph, or fact compiler. The cross-artifact capability comes from holistic LLM review rather than explicit program analysis structures. Therefore `partial` is more accurate than `full`.

## 2. AgentScan

### Detection principle

The relevant implementation is `baseline/agent-scan`, especially [`src/agent_scan/skill_client.py`](/home/shenaow/AgentSkill/baseline/agent-scan/src/agent_scan/skill_client.py).

Its Skill handling works by converting a Skill package into a structured representation:

- `SKILL.md` becomes a base prompt
- other `.md` files become prompts
- `.py`, `.js`, `.ts`, `.sh` files become tools
- all remaining files become resources

This representation is then sent into the broader AgentScan analysis pipeline, which relies on local checks plus remote verification and analysis through the Agent Scan service.

### Why it is marked `Artifact Cov. = partial`

It does inspect more than a single file, but its typing model is relatively coarse:

- Markdown files are treated as prompts
- a small set of script files are treated as tools
- everything else is treated as generic resources

So it sees multiple artifact kinds, but not with the same depth as a scanner that explicitly models scripts, references, assets, binaries, and hidden files with dedicated logic.

### Why `Static`, `LLM`, and `Cross-artifact` are marked `partial`

Its Skill analysis is not a strong local static analyzer in the same sense as `skill-scanner` or `skill-security-scan`. Instead, it mainly packages the Skill into structured descriptions for downstream analysis.

- `Static = partial`: it does parse and structure the repository, but local code reasoning is limited.
- `LLM = partial`: the platform depends on service-side analysis, but the local Skill path is not an explicit LLM code auditor.
- `Cross-artifact = partial`: the remote analyzer can see multiple prompts/tools/resources together, but there is no explicit local cross-artifact malicious-chain engine.

### Why `Dynamic = none`

There is no Skill-specific runtime execution monitor in the code path used for Skill scanning.

## 3. Skill Scanner

### Detection principle

`Skill Scanner` is the most complete standalone baseline in this set. Its core pieces are:

- [`core/loader.py`](/home/shenaow/AgentSkill/baseline/skill-scanner/skill_scanner/core/loader.py)
- [`core/analyzers/static.py`](/home/shenaow/AgentSkill/baseline/skill-scanner/skill_scanner/core/analyzers/static.py)
- [`core/analyzers/behavioral_analyzer.py`](/home/shenaow/AgentSkill/baseline/skill-scanner/skill_scanner/core/analyzers/behavioral_analyzer.py)
- [`core/analyzers/llm_analyzer.py`](/home/shenaow/AgentSkill/baseline/skill-scanner/skill_scanner/core/analyzers/llm_analyzer.py)
- [`core/static_analysis/interprocedural/cross_file_analyzer.py`](/home/shenaow/AgentSkill/baseline/skill-scanner/skill_scanner/core/static_analysis/interprocedural/cross_file_analyzer.py)

It combines several analysis layers:

- static rules and YARA
- bytecode and pipeline analyzers
- optional LLM analysis
- behavioral static dataflow analysis
- cross-file correlation

### Why it is marked `Artifact Cov. = full`

Its loader recursively discovers the entire Skill package and retains a broad set of files, not only `SKILL.md` and scripts. It can also process markdown code blocks and keep binary files as analyzability inputs.

### Why it is marked `Static = full`

This is the core strength of the tool. It has:

- rule-based static analysis
- YARA scanning
- AST and behavioral analysis
- script and markdown code-block inspection

### Why it is marked `LLM = full`

It contains an explicit LLM analyzer and optional meta-analysis path. LLM analysis is a first-class component, not an external wrapper.

### Why `Dynamic = none`

Its behavioral analyzer is still static. It does not execute the target Skill repository to observe runtime behavior.

### Why `Cross-artifact = partial`

It does have explicit cross-file reasoning. In particular, [`cross_file_analyzer.py`](/home/shenaow/AgentSkill/baseline/skill-scanner/skill_scanner/core/static_analysis/interprocedural/cross_file_analyzer.py) looks for multi-file patterns such as:

- collection in one file and exfiltration in another
- credential access separated from network usage
- environment harvesting plus network transmission

However, this capability is strongest for script-level contexts, especially Python and Bash. It is not a general cross-artifact reasoning engine over heterogeneous artifacts like Markdown instructions, references, assets, and scripts all at once. So `partial` is more precise than `full`.

## 4. Nova-Proximity

### Detection principle

Skill scanning is implemented in [`lib/skill_scanner_lib.py`](/home/shenaow/AgentSkill/baseline/nova-proximity/lib/skill_scanner_lib.py).

The scanner:

- parses `SKILL.md`
- scans `scripts/`
- reads `references/`
- inventories `assets/`
- checks `allowed-tools`
- detects suspicious code patterns and imports
- checks whether code capabilities are undeclared in the manifest

Optional LLM-backed semantic evaluation is added through NOVA rules in:

- [`lib/nova_evaluator_lib.py`](/home/shenaow/AgentSkill/baseline/nova-proximity/lib/nova_evaluator_lib.py)
- [`skill_rules.nov`](/home/shenaow/AgentSkill/baseline/nova-proximity/skill_rules.nov)

### Why it is marked `Artifact Cov. = partial`

It covers multiple artifact categories, but the analysis depth is not uniform:

- scripts receive most of the real security checks
- references are mostly read as content
- assets are mostly inventoried as metadata

So coverage is broader than a script-only tool, but not fully uniform across all artifact types.

### Why it is marked `Static = full`

It has explicit static checks for:

- dangerous permissions
- suspicious script patterns
- suspicious imports
- manifest/code inconsistency

### Why it is marked `LLM = full`

The optional NOVA evaluator uses LLM-backed rule evaluation, so it has a real semantic analysis path.

### Why `Dynamic = none`

There is no runtime execution or sandbox monitoring path for Skill repositories.

### Why `Cross-artifact = none`

The tool scans multiple artifact classes, but it does not explicitly reason over relations among them. There is no cross-file dataflow or artifact-chain inference stage.

## 5. Skill-Sec-Scan

### Detection principle

This refers to `baseline/skill-security-scan`. The core pieces are:

- [`src/scanner/parser.py`](/home/shenaow/AgentSkill/baseline/skill-security-scan/src/scanner/parser.py)
- [`src/scanner/analyzer.py`](/home/shenaow/AgentSkill/baseline/skill-security-scan/src/scanner/analyzer.py)
- [`config/rules.yaml`](/home/shenaow/AgentSkill/baseline/skill-security-scan/config/rules.yaml)

The tool first collects a whitelist of file extensions, then applies a set of configurable regex-style rules to each file independently.

### Why it is marked `Artifact Cov. = partial`

It supports a reasonable set of text-like Skill files:

- markdown
- text
- Python/JavaScript/TypeScript
- shell
- YAML/JSON/TOML

But it does not model richer artifact classes or perform differentiated treatment of references, assets, binaries, or package structure beyond file collection.

### Why it is marked `Static = full`

This is a straightforward static scanner. The full detection capability comes from rule matching over collected files.

### Why `LLM`, `Dynamic`, and `Cross-artifact` are marked `none`

- No LLM path exists in the scanner
- No runtime execution path exists
- No file-relation or cross-artifact reasoning stage exists

## 6. Caterpillar

### Detection principle

The critical components are:

- [`core/src/lib/collector.ts`](/home/shenaow/AgentSkill/baseline/caterpillar/core/src/lib/collector.ts)
- [`core/src/lib/pattern-scanner.ts`](/home/shenaow/AgentSkill/baseline/caterpillar/core/src/lib/pattern-scanner.ts)
- [`core/src/lib/llm-judge.ts`](/home/shenaow/AgentSkill/baseline/caterpillar/core/src/lib/llm-judge.ts)
- [`core/src/lib/scan-skill.ts`](/home/shenaow/AgentSkill/baseline/caterpillar/core/src/lib/scan-skill.ts)

The collector walks the Skill directory, keeps artifacts, and concatenates readable text files into one large content blob. Then:

- offline mode runs pattern-based detection
- local AI mode runs LLM judge plus pattern scan
- server mode can send content to a service

VirusTotal is also optionally used for binaries and archives.

### Why it is marked `Artifact Cov. = full`

It supports broad text intake and also keeps binary/archive artifacts for VT checks. In practice it can observe most files that matter in a Skill package.

### Why it is marked `Static = full`

It has a real local pattern scanner over the collected content.

### Why it is marked `LLM = full`

The local AI mode runs an explicit LLM judge over the merged Skill content.

### Why `Dynamic = none`

It does not execute the target Skill repository to observe runtime behavior.

### Why `Cross-artifact = partial`

Because all readable text files are merged into one context, the LLM or pattern logic can notice cross-file evidence. This is stronger than purely file-local scanning.

But it still lacks an explicit relation model, dataflow graph, or source-sink chain reasoner. Therefore the cross-artifact support is partial rather than full.

## 7. MASB

### Detection principle

This refers to the code component under `baseline/MASB`, which is explicitly described in its README as a complete pipeline with:

1. static scan
2. CC analysis
3. dynamic execution

The relevant components are:

- [`scanner/scanner.py`](/home/shenaow/AgentSkill/baseline/MASB/scanner/scanner.py)
- [`scanner/skill-security-scan/src/scanner/analyzer.py`](/home/shenaow/AgentSkill/baseline/MASB/scanner/skill-security-scan/src/scanner/analyzer.py)
- [`analyzer/cc_analyzer.sh`](/home/shenaow/AgentSkill/baseline/MASB/analyzer/cc_analyzer.sh)
- executor modules under [`executor/`](/home/shenaow/AgentSkill/baseline/MASB/executor)

### Why it is marked `Artifact Cov. = partial`

Its static scanner is derived from `skill-security-scan`-style file collection and rule matching, so its direct artifact handling is still mainly text-like repository files rather than a fully typed artifact graph.

### Why it is marked `Static = full`

The static stage applies rules to repository files and assigns a risk level.

### Why it is marked `LLM = full`

The `CC Analysis` stage in [`cc_analyzer.sh`](/home/shenaow/AgentSkill/baseline/MASB/analyzer/cc_analyzer.sh) runs Codex or an OpenAI-compatible model over the Skill directory and asks for JSON-only audit output. This is a genuine LLM auditing phase.

### Why it is marked `Dynamic = full`

This is the major distinction of MASB. The pipeline includes monitored execution in Docker, with:

- sandboxed execution
- system call tracing
- network capture
- filesystem change monitoring

So dynamic analysis is a first-class capability rather than an afterthought.

### Why `Cross-artifact = partial`

The LLM audit can inspect the whole Skill directory and dynamic execution can observe effects spanning multiple files and behaviors. That gives MASB some cross-artifact visibility.

But the implementation does not present an explicit structured cross-artifact reasoning module comparable to a fact-based multi-artifact inference system. Therefore `partial` is safer than `full`.

## Overall Takeaway

These baselines fall into three broad families:

- **Rule-centric static scanners**:
  - `Skill-Sec-Scan`
  - parts of `Nova-Proximity`
  - parts of `Caterpillar`

- **LLM-centric repository reviewers**:
  - `AI-Infra-Guard`
  - `AgentScan`
  - `Caterpillar`
  - `MASB` CC analysis

- **Hybrid systems with stronger structure or runtime**:
  - `Skill Scanner` for stronger static and cross-file script analysis
  - `MASB` for end-to-end static + LLM + dynamic execution

Among these baselines:

- `Skill Scanner` is the strongest on explicit cross-file static reasoning
- `MASB` is the strongest on runtime-backed analysis
- `AI-Infra-Guard` is strongest as an LLM-driven multi-agent audit workflow
- `Caterpillar` is a practical merged-context hybrid
- `Nova-Proximity` is a lightweight but structured manifest-and-script analyzer
