# Paper-to-Implementation Alignment

This audit uses `assets/ase25_malskills.pdf`. The PDF is the ASE 2026 paper despite the local filename.

## Paper Requirements

Sections 4.1-4.3 and Figure 3 describe three stages:

1. SSO extraction from heterogeneous artifacts with static rules and a finding-only LLM extractor.
2. SDG construction with Artifact, SSO, Operand, and Value nodes plus operand and value-flow dependencies.
3. Static connected-subgraph reasoning complemented by LLM reasoning over normalized graph facts.

Section 4.1, pages 5-6, describes the SSO feedback loop as repeated cross-package discovery, specification generation, normalization, deduplication, held-out validation, and incorporation into an online symbolic rule base.

Section 4.3, page 7, only says that recurring LLM-only workflows are recorded as candidate subgraphs, operation sequences, and dependencies. It does not define their rule language, validation thresholds, promotion, or rollback. This repository adds basic engineering gates, but does not claim a complete poisoning defense.

## Alignment Status

| Area | Paper | Current implementation | Status |
|---|---|---|---|
| LLM SSO output | Finding facts in a fixed taxonomy, no verdict | Schema-constrained `SSOFinding` with type, subtype, confidence, span, and matched text; Install/Crypto coverage and span grounding remain incomplete | Structurally aligned; taxonomy partial |
| SSO feedback | First identify recurrence across packages, then generate a normalized specification from repeated findings, validate, and reuse it | Per-hit specifications are fingerprinted across scans; persistent lifecycle, content-bound held-out validation, approval, tamper-evident content-addressed bundles, and learned Semgrep loading are implemented. Clustering multiple findings before specification generation is not | Partial |
| Workflow feedback | Record recurring uncovered connected workflows | LLM candidates are deterministically reduced to a restricted connected graph DSL, then validated, promoted, and loaded. Operand constraints, operation order, and concrete proof paths are incomplete | Partial / experimental |
| Candidate support | Repeated across packages | Byte-identical samples and explicitly grouped campaign members count once; automatic near-clone/campaign clustering is not implemented | Partial |
| Validation isolation | Held-out corpus | Duplicate content and exact discovery-sample/group overlap are rejected; isolation still depends on explicit grouping for near clones and campaigns | Partial |
| SSO compilation | Extracted SSOs feed graph/reasoning | `SSOFinding` records at the same operation callsite are merged into one `SSORecord`; every canonical operation subtype is compiled | Fixed |
| Connected reasoning | Match operand/value-flow-connected SDG findings | Built-in formal rules no longer join unrelated candidates; learned workflow rules require `same_object` or bounded directional `value_flow`. Explicit and fallback LLM nominations are filtered against existing symbolic coverage before persistence | Improved; still partial |
| LLM reasoning context | SDG plus existing symbolic matches | Hybrid reasoning now computes symbolic matches first and supplies them to the LLM | Fixed |
| SDG schema | Artifact, SSO, Operand, Value; `contains`, `has_operand`, `value_flow` | The graph emits only canonical Artifact/SSO/Operand/Value nodes (plus verdict/pattern report nodes). `SSOFinding` and operand-resolution records remain outside the graph. YASA proof paths emit directional Value-to-Value propagation; syntax-only findings stop at Operand-to-Value binding | Structurally aligned; flow coverage partial |
| Operand resolution | Points-to/value flow across assignments, calls, wrappers, and files | YASA produces `OperandBinding` records with proof steps; the LLM produces schema-constrained bindings without inventing SSOs. Callsite-nearest alignment reduces same-API mixing but remains a line-distance heuristic | Partial |
| Static rule scale | 2,665 Semgrep rules, 10 languages | The runtime canonical rule set is much smaller. The legacy `semgrep_rules/` corpus is not directly usable because it lacks canonical subtype metadata | Not aligned |
| Declarative reasoner | Relational facts and declarative graph patterns | Built-in rules remain Python; Souffle output is exported but `malskills.dl` has declarations only and is not executed | Not aligned |
| LLM failure telemetry | Not specified | Semgrep failures and ruleset digest are reported; LLM invocation failure is still represented as an empty result in several call sites | Remaining gap |

## Important Remaining Work

The guarded registry lifecycle and static reuse path are usable, but the learning loop and analyzer are not identical to the paper artifact. The core representation is now:

```text
Artifact --contains--> SSO --has_operand--> Operand --value_flow--> Value
                                                              Value --value_flow--> Value
```

`SSOFinding` is a source-grounded extractor result used to form an SSO and is not
a graph node. `OperandBinding` is an internal analyzer result, while
`OperandResolution` is its stable output representation. The end-to-end analysis
flow is `SSOFinding -> SSO -> Operand -> Value -> Pattern -> Verdict`.

1. Persist and cluster raw recurring LLM findings before specification generation, then generate one rule from multiple variants. The current implementation instead aggregates independently generated drafts by semantic fingerprint.
2. Expand directional value-flow coverage from YASA across every supported language and wrapper. Value nodes always represent bindings, but propagation edges are emitted only where the analyzer supplies a proof path.
3. Expand callsite-aware operand roles beyond endpoint/command/payload and retain source-to-sink proof paths and operation order in learned workflow rules.
4. Port the legacy 2,664-rule corpus into the canonical taxonomy, review broad crypto/obfuscation mappings, and regression-test it before loading it. Blindly assigning those rules to malicious subtypes would create false semantics.
5. Either implement an executable declarative rule engine consistent with the paper or describe the Python graph matcher as the formal reasoner. Exporting facts alone is not declarative reasoning.
6. Add structured LLM invocation status (`ok`, `empty`, `timeout`, `backend_error`, `schema_error`) so an empty neural result cannot hide a failed model call.
7. Add automatic near-clone/campaign clustering, finding-level span annotations, and a separate end-to-end regression corpus. Current fixture-level validation is executed locally, but full verdict-level FPR/F1 regression remains a reviewer responsibility.
8. Evaluate the feedback loop itself: learned-rule precision/recall, time-split generalization, rule survival, reduction in LLM calls, and poisoning resistance. The paper reports no isolated experiment for this loop.

The safest order is SSO rules first, then operand/value-flow quality, then workflow rules. A workflow rule should not become active if its dependency path relies only on weak same-file co-occurrence or an ambiguous operand binding.
