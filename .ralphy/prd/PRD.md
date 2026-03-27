# SkillGuard Taxonomy Refactor PRD

## Ground Rules

- [x] Re-read `docs/taxonomy.md`, `PLANS.md`, and `AGENTS.md` before changing code
- [x] Keep the pipeline order fixed as `ingest -> evidence -> primitive -> reasoning -> reports`
- [x] Treat the graph built after object extraction as the main intermediate representation for downstream reasoning
- [x] Update tests together with any taxonomy, schema, primitive, or reasoning change

## Stage 0: Current State Audit

- [x] Inventory the current evidence subtypes emitted by `skillguard/evidence/semgrep.py`
- [x] Inventory the current evidence subtypes emitted by `skillguard/evidence/llm.py`
- [x] Inventory the current primitive types emitted by `skillguard/primitive/compiler.py`
- [x] Inventory the current pattern names emitted by `skillguard/reasoning/reasoner.py`
- [x] Inventory the taxonomy in `docs/taxonomy.md`
- [x] Inventory all current compiler-side heuristic object extraction and relation construction logic
- [x] Inventory all current YASA outputs used by `skillguard/primitive/compiler.py`
- [x] Inventory all current LLM object-analysis outputs used by `skillguard/primitive/compiler.py`

## Stage 1: Evidence Taxonomy in Code

- [x] Replace legacy evidence family definitions in `skillguard/evidence/schema.py`
- [x] Add explicit code-level definitions for evidence `category` and `subtype`
- [x] Ensure every normalized evidence record carries taxonomy-aligned `category`, `subtype`, `matched_text`, `span`, `producer`, and provenance fields
- [x] Remove schema assumptions that privilege legacy semantic-only subtype names
- [x] Remove evidence-stage requirements for extracted operand fields such as `value`, `path`, `url`, `command`, `env_key`, `config_key`, or inferred attributes
- [x] Make `matched_text` the canonical evidence payload captured from both Semgrep and LLM producers
- [x] Define which legacy subtypes are transitional aliases and which are removed
- [x] Update evidence schema tests to assert taxonomy-aligned fields

## Stage 2: Semgrep Evidence Producer Refactor

- [x] Audit all existing Semgrep rules under `skillguard/rules/semgrep/`
- [x] Group existing Semgrep rules by the new evidence taxonomy categories
- [x] Rewrite Python Semgrep rule metadata to emit taxonomy-aligned category/subtype values
- [x] Rewrite JavaScript Semgrep rule metadata to emit taxonomy-aligned category/subtype values
- [x] Rewrite generic text Semgrep rule metadata to emit taxonomy-aligned category/subtype values
- [x] Update `skillguard/evidence/semgrep.py` to consume the new rule metadata format and emit only taxonomy-aligned sensitive-operation hits plus `matched_text`
- [x] Remove evidence-stage operand extraction and attribute inference from `skillguard/evidence/semgrep.py`
- [x] Update Semgrep-specific tests to assert taxonomy-aligned outputs

## Stage 3: LLM Evidence Producer Refactor

- [x] Replace legacy allowed subtype definitions in `skillguard/evidence/llm.py`
- [x] Rewrite the LLM system prompt to follow `docs/taxonomy.md` evidence taxonomy
- [x] Rewrite the artifact prompt to request only sensitive-operation recognition with exact `matched_text`, not operand extraction or semantic conclusions
- [x] Update LLM record validation to enforce taxonomy-aligned `category`, `subtype`, `matched_text`, and `span`
- [x] Remove evidence-stage operand hints and inferred attributes from LLM output handling
- [x] Update LLM evidence tests to assert taxonomy-aligned outputs

## Stage 4: Evidence Fusion and Compatibility

- [x] Update evidence fusion keys to be taxonomy-aware
- [x] Ensure evidence fusion preserves producer provenance after category/subtype migration
- [x] Make evidence fusion operate on taxonomy fields plus `matched_text` and `span`, not inferred operand fields
- [x] Add compatibility handling for mixed old/new evidence records during migration
- [x] Add regression tests for cross-producer fusion under the new taxonomy

## Stage 4A: Feedback Loop for Rule Hardening

- [x] Add a mechanism to identify `LLM-only` evidence hits after cross-producer fusion
- [x] Aggregate `LLM-only` hits by `category`, `subtype`, and `artifact_type`
- [x] Define a decision rule for when an `LLM-only` sensitive operation should become a new `Semgrep` rule
- [x] Define a decision rule for when an `LLM-only` code-side object or flow gap should become a new `YASA` rule
- [x] Add an output artifact or report section that summarizes taxonomy gaps discovered from `LLM-only` hits
- [x] Ensure benchmark miss analysis records whether each miss is due to evidence taxonomy coverage, object extraction coverage, or reasoning coverage
- [x] Add tests or fixtures for at least one `LLM-only -> Semgrep rule hardening` path

## Stage 5: Primitive Role Redesign

- [x] Define the post-evidence object-analysis flow as `evidence -> YASA/LLM object extraction -> graph assembly -> reasoning`
- [x] Define the target graph-centered primitive model in code comments or a local design note before editing compiler logic
- [x] Separate operation detections, object bindings, and relation facts into distinct internal representations
- [x] Preserve the current object identity graph machinery only where it supports the new graph-centered design
- [x] Preserve YASA parameter-binding and taint-flow integration points
- [x] Remove or demote semantic-only primitive outputs such as setup or prompt-intent primitives from the core primitive space
- [x] Move all operand extraction, target extraction, and relation construction fully out of evidence extraction
- [x] Remove compiler-side heuristic object recovery as a source of truth
- [x] Make primitive compilation preserve upstream behavior taxonomy instead of inventing a parallel top-level behavior taxonomy

## Stage 6: Object Extraction Refactor

- [x] Refactor YASA outputs so that code-object extraction results are emitted in a stable object-binding schema
- [x] Refactor LLM object-analysis outputs so that all-artifact object extraction results are emitted in the same schema as YASA-compatible bindings where possible
- [x] Ensure YASA is the only code-side structural source of object extraction for code artifacts
- [x] Ensure LLM is the main source of object extraction and cross-artifact relation extraction for all artifacts
- [x] Ensure object extraction outputs can represent concrete command, script, module, endpoint, credential, file, service, policy, process, and remote-node objects
- [x] Ensure object extraction outputs can represent unresolved or unknown objects explicitly instead of relying on compiler heuristics
- [x] Ensure every extracted operation can explain “what exact object is being operated on” when analysis succeeds

## Stage 7: Dependency Graph Builder Refactor

- [x] Define the `skill_dependency_graph` schema before rewriting compiler logic
- [x] Define graph node types for at least artifacts, operations, and objects
- [x] Define graph edge types for at least containment, binding, flow, enablement, resolution, and same-object relations
- [x] Refactor `skillguard/primitive/compiler.py` into a graph assembler or graph builder role
- [x] Merge YASA and LLM object-analysis outputs into a unified dependency graph
- [x] Remove compiler-side heuristic object recovery and heuristic cross-artifact linking
- [x] Ensure taint-flow evidence is mapped into graph edges instead of ad hoc primitive params
- [x] Ensure parameter bindings from YASA and LLM are mapped into graph edges instead of ad hoc primitive params
- [x] Add tests for same-object linking across artifacts in the graph
- [x] Add tests for source-to-sink linking across artifacts in the graph
- [x] Add tests for graph assembly provenance preservation

## Stage 8: Reasoning Taxonomy Migration

- [x] Remove the legacy overlapping reasoning pattern list from `skillguard/reasoning/reasoner.py`
- [x] Introduce the target reasoning classes from `docs/taxonomy.md`
- [x] Define the exact rule boundary for `Execution_and_Delivery`
- [x] Define the exact rule boundary for `Persistence`
- [x] Define the exact rule boundary for `Privilege_Escalation_and_Identity_Abuse`
- [x] Define the exact rule boundary for `Injection_and_Covert_Residency`
- [x] Define the exact rule boundary for `Information_Theft`
- [x] Define the exact rule boundary for `Command_and_Control`
- [x] Define the exact rule boundary for `Lateral_Movement`
- [x] Define the exact rule boundary for `Defense_Evasion_and_Anti_Forensics`
- [x] Define the exact rule boundary for `Destruction_and_Ransomware`

## Stage 9: Reasoning Rule Rewrite

- [x] Make reasoning consume the dependency graph as the main intermediate representation
- [x] Implement graph-based rules for `Execution_and_Delivery`
- [x] Implement graph-based rules for `Persistence`
- [x] Implement graph-based rules for `Privilege_Escalation_and_Identity_Abuse`
- [x] Implement graph-based rules for `Injection_and_Covert_Residency`
- [x] Implement graph-based rules for `Information_Theft`
- [x] Implement graph-based rules for `Command_and_Control`
- [x] Implement graph-based rules for `Lateral_Movement`
- [x] Implement graph-based rules for `Defense_Evasion_and_Anti_Forensics`
- [x] Implement graph-based rules for `Destruction_and_Ransomware`
- [x] Remove rules that directly depend on legacy setup-language or prompt-semantic pattern names
- [x] Update heuristic reasoning mode to align with the new graph-centered primitive and reasoning taxonomy

## Stage 10: Souffle and Fact Export Refactor

- [x] Audit all current exported relations in `skillguard/reasoning/souffle.py`
- [x] Add or rename exported relations to reflect the new graph-centered primitive and relation model
- [x] Ensure object identity is exported as first-class fact data
- [x] Ensure source-to-sink, enablement, and resolution relations are exported as first-class fact data
- [x] Export dependency-graph node and edge relations in a stable format
- [x] Update `skillguard/rules/skillguard.dl` to align with the new exported fact layout
- [x] Add tests that assert the expected exported fact relations for representative cases

## Stage 11: Report and Verdict Refactor

- [x] Replace legacy pattern names in `skillguard/reasoning/verdict.py`
- [x] Rework severity grouping for the new reasoning taxonomy
- [x] Update `skillguard/report.py` to summarize final security consequence classes
- [x] Update graph payload generation to reflect the new reasoning taxonomy
- [x] Update proof output to describe object-linked primitive chains instead of legacy semantic labels
- [x] Update human-readable report sections to use the new taxonomy terminology

## Stage 12: Test Migration

- [x] Update evidence schema tests for the new evidence taxonomy
- [x] Update extractor tests for the new primitive outputs
- [x] Update object identity tests for the new primitive naming and relation model
- [x] Update reasoning tests for the new final consequence taxonomy
- [x] Add regression tests for representative evidence categories from `docs/taxonomy.md`
- [x] Add regression tests for representative reasoning classes from `docs/taxonomy.md`
- [x] Remove or rewrite tests that assert deprecated legacy pattern names

## Stage 13: Benchmark and Quality Gates

- [x] Run targeted syntax checks after each major code stage
- [x] Run the malicious benchmark gate after the evidence, primitive, and reasoning migration stabilizes
- [x] Record major false negatives introduced by the migration and map them to evidence, primitive, or reasoning gaps

## Finalization

- [x] Verify `docs/taxonomy.md`, `PLANS.md`, and `AGENTS.md` still match the implemented taxonomy
- [x] Verify no new code path introduces a parallel top-level behavior taxonomy outside the documented one
- [x] Verify reports, facts, and verdict outputs remain reproducible and machine-readable
- [x] Summarize the migration impact, changed files, and benchmark outcomes in the final review note

## Current Hardening Tasks

- [ ] Remove or quarantine legacy `skillguard/static/` modules that still emit `taint_flow` or old flow-only taxonomy values
- [ ] Add regression tests for YASA `object_binding / parameter_binding` on representative JavaScript and Python sink cases
- [ ] Add regression tests that assert `benchmark_full` enables YASA and hybrid reasoning
- [ ] Re-run a malicious sample end-to-end and confirm `primitive_support_evidence.json` contains only `parameter_binding`
- [ ] Re-audit benchmark scripts and docs so no entrypoint references removed variants such as `heuristic`, `no_capability_mismatch`, or old benchmark report names
