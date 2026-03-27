# Baseline Skill Scanner Comparison

## Scope

This document compares the Skill scanning implementations under `baseline/` from the following dimensions:

- Number of supported Skill file types
- Whether static analysis is supported
- Whether LLM analysis is supported
- Whether dynamic analysis is supported
- Whether cross-file malicious logic analysis is supported

Important comparison rules:

- If a repository contains multiple product lines, only its Skill scanning part is considered.
- The comparison is based on the implementation in this repository, not only README claims.
- "Cross-file malicious logic analysis" means the tool can reason about a malicious chain across files or artifacts, such as read in Markdown and exfiltration in Python. Merely scanning multiple files recursively does not count.
- For tools without an explicit extension whitelist, the "file type count" column is marked as `No fixed whitelist`.

## Comparison Table

| Tool | Directory | Supported Skill file types | Static | LLM | Dynamic | Cross-file malicious logic | Notes |
|---|---|---|---|---|---|---|---|
| `skill-security-scan` | `baseline/skill-security-scan` | `11` explicit extensions, plus special-cased `SKILL.md` | Yes | No | No | No | Regex/rule scan over collected files; no repo-level correlation stage |
| `skill-security-audit` | `baseline/skill-security-audit` | `35` text extensions | Yes | No | No | No | Broad text pattern scanning, but still line/file-local |
| `skills_security_audit` | `baseline/skills_security_audit` | `6` explicit extensions, plus special-cased `SKILLS.md` | Yes | Yes | Yes | No | Supports `static/prompt/runtime/llm/all`, but scoring is still file-centric |
| `caterpillar` | `baseline/caterpillar` | `44` text extensions + `10` text filenames, but only `52` unique explicit text patterns because `.env` and `.cursorrules` appear in both sets; MIME fallback can include additional text files | Yes | Yes | No | Partial | Concatenates all text files into one context for pattern scan or LLM judge; can see multi-file context but has no explicit cross-file dataflow engine |
| `clawscan` | `baseline/clawscan` | About `19` file patterns in the combined analyzers, plus `SKILL.md` fenced code blocks | Yes | No | No | Weak | Global analyzer findings are combined for scoring, but there is no structured cross-file source-sink reasoning |
| `skill-scanner` | `baseline/skill-scanner` | No fixed whitelist; recursively discovers the whole package, with explicit typing for `15` common extensions and separate binary handling | Yes | Yes | No | Yes, mainly for script-level chains | The strongest baseline here: static rules + YARA + bytecode/pipeline + behavioral static dataflow + cross-file correlation |
| `AI-Infra-Guard` | `baseline/AI-Infra-Guard` | No fixed whitelist in Skill scan mode; Skill mode is triggered by `SKILL.md` and then audits repository files via agent tools | Yes | Yes | No | Partial | Multi-agent LLM-driven static audit. It can reason over `SKILL.md`, `scripts/`, and other repository files, but lacks a structured cross-file analysis engine |
| `SlowMist-AgentSec` | `baseline/slowmist-agent-security` | Not applicable | No | No | No | No | This is a review framework Skill and report template set, not an automated scanner implementation |
| `Nova-Proximity` | `baseline/nova-proximity` | No global extension whitelist; practical coverage is `SKILL.md`, `scripts/`, `references/`, and `assets` metadata | Yes | Yes, via NOVA evaluator | No | No | Uses manifest checks, regex on scripts, suspicious imports, and optional NOVA rule evaluation |

## Per-Tool Notes

### `skill-security-scan`

- Skill file collection is defined in `src/scanner/parser.py`.
- The implementation scans `.md`, `.txt`, `.py`, `.js`, `.ts`, `.sh`, `.bash`, `.yml`, `.yaml`, `.json`, `.toml`, and also accepts `SKILL.md`.
- Analysis is done by applying rules to each file independently.
- It does not build file relationships, object bindings, or cross-file attack chains.

### `skill-security-audit`

- Text extensions are defined directly in `scripts/skill_audit.py`.
- The implementation contains many detectors, but they still operate by scanning content in a file or line.
- There is no dedicated LLM, runtime, or cross-file correlation stage.

### `skills_security_audit`

- Supported modes are declared in `__main__.py` and executed in `orchestrator.py`.
- Static analysis includes regex and Python AST checks.
- Dynamic analysis is implemented by runtime hooks in `scanners/runtime_scanner.py`.
- LLM analysis is file-level intent classification.
- Despite multiple modes, the orchestration model remains file-based, so it does not perform explicit cross-file malicious chain detection.

### `caterpillar`

- File collection and text-type support are implemented in `core/src/lib/collector.ts`.
- Strict counting note:
  - `TEXT_EXTENSIONS` contains `44` entries.
  - `TEXT_FILENAMES` contains `10` entries.
  - But `.env` and `.cursorrules` are duplicated across both sets.
  - So the number of unique explicit text patterns is `52`, not `54`.
- All text files are concatenated into a single content blob for offline pattern scan or LLM judge.
- In addition, `isTextFile()` also accepts files by MIME type when `mime.startsWith('text/')` or MIME is `application/json` / `application/yaml`, so real practical coverage can exceed the fixed explicit list.
- This gives it partial cross-file visibility.
- However, it does not explicitly model source-sink paths, interprocedural calls, or artifact-level chains.

### `clawscan`

- Separate analyzers scan scripts, network indicators, credentials, obfuscation, and prompt injection.
- `SKILL.md` fenced code blocks are extracted and rescanned as temporary scripts.
- Final risk scoring includes "dangerous combinations" across findings.
- This is still heuristic aggregation, not true cross-file malicious logic reasoning.

### `skill-scanner`

- The loader recursively discovers the package and keeps all files, including hidden files and binaries.
- Static analysis includes rules and YARA.
- Optional analyzers include LLM, VirusTotal, AI Defense, Trigger, and Behavioral.
- `BehavioralAnalyzer` explicitly performs cross-file static correlation for script contexts, including cases like credential access in one file and network transmission in another.
- Markdown code blocks are also analyzed, but cross-artifact reasoning is still strongest on script-level contexts rather than full heterogeneous artifact graphs.

### `AI-Infra-Guard`

- The relevant Skill scanning part in this repository is `baseline/AI-Infra-Guard/agent-scan`.
- Its core pipeline is in `agent-scan/core/agent.py`: information collection, parallel vulnerability detection through detection skills, and final review.
- Skill mode is explicitly mentioned in prompts such as `prompt/system/agents/code_audit.md`, where the presence of `SKILL.md` triggers a dedicated Skill consistency audit.
- The implementation is clearly static-analysis-oriented: it instructs workers to use file reading and search tools for code audit, not dynamic execution.
- It is LLM-driven rather than regex-engine-driven.
- It can inspect `SKILL.md`, `scripts/`, and other repository code together, so it has partial cross-file reasoning capability through the agent's holistic review.
- It does not expose a structured dataflow/object-graph engine, so its cross-file capability is weaker and less explicit than `skill-scanner`.

### `SlowMist-AgentSec`

- The repository mainly contains `SKILL.md`, review guides, pattern libraries, and output templates.
- It is meant to guide an external agent to perform security review.
- There is no parser, rule engine, LLM client, runtime monitor, or cross-file analysis module implemented as an automated scanner.

### `Nova-Proximity`

- Skill scanning is implemented in `lib/skill_scanner_lib.py`.
- It parses `SKILL.md`, scans `scripts/`, reads `references/`, and inventories `assets/`.
- Static checks include dangerous `allowed-tools`, suspicious code patterns, suspicious imports, and manifest-code mismatch.
- Optional NOVA evaluation adds LLM-backed semantic matching through `.nov` rules.
- The analysis is still artifact-wise and rule-wise; it does not model cross-file malicious logic chains.

## Interpretation Notes

- `Yes` in the `LLM` column means the implementation contains a real LLM-backed analysis path, even if the current benchmark wiring in this repository may not always enable it.
- `Partial` in the `Cross-file malicious logic` column means the tool can reason across multiple files through merged context or holistic review, but it does not implement explicit inter-file source-sink or object-level correlation.
- `Weak` means the tool only aggregates independent findings from multiple files and does not truly analyze a malicious logic chain.

## Recommended Reading Order

- For classic rule-based baselines: `skill-security-scan`, `skill-security-audit`, `clawscan`
- For hybrid or stronger baselines: `caterpillar`, `skill-scanner`, `AI-Infra-Guard`, `Nova-Proximity`
- For non-automated review framework baselines: `SlowMist-AgentSec`
