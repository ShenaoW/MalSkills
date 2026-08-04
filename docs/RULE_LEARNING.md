# Guarded Neuro-to-Symbolic Rule Learning

MalSkills keeps extraction rules and reasoning rules separate:

- SSO candidates compile to Semgrep rules that emit one canonical SSO-finding subtype.
- Workflow candidates compile to graph rules over connected SSOs and operands.

An LLM discovery never becomes active during the scan that produced it. Candidate collection, held-out validation, and promotion are separate operations.

## Lifecycle

The persistent store uses these states:

```text
observed -> eligible -> validated -> active -> retired
                         |             |
                         +-> rejected  +-> deactivate / rollback
```

Support is `COUNT(DISTINCT dedupe_group_id)`. Repeated findings in one package, byte-identical packages, and samples explicitly assigned to the same campaign group count once. The default eligibility threshold is three independent discovery groups. Near-clone and campaign clustering is not automatic, so callers must provide a stable `--rule-group-id` where appropriate.

The store contains:

```text
<rule-store>/
  candidates.sqlite3
  current
  activation.json              # transient during activation; retained after interruption
  bundles/<sha256>/
    manifest.json
    semgrep/*.yml
    workflows/*.json
    validation/*.json
```

Bundles are content-addressed and tamper-evident. Promotion and deactivation transitions, including the reviewer identity, are covered by the bundle digest. The `current` file is switched atomically after the new bundle has been validated and registry state committed. A short-lived activation journal reconciles the database and pointer after an interrupted process. Every active rule and validation report is checksum-verified when a scan starts; unlisted files, non-regular files, and symbolic links are rejected. Active Semgrep bundles are also compiled with `semgrep --validate`; an invalid or timed-out validation fails closed.

The rule store is trusted local administrative state. These checks detect inconsistent or directly modified bundle files, but an attacker who can coherently rewrite the SQLite registry, bundle, and `current` pointer is outside this trust boundary. Production deployments should protect the store with filesystem ownership and access controls; signed bundles would be required for an untrusted store.

## Collect Candidates

Candidate collection is opt-in so ordinary analysis and benchmark runs do not mutate the rule base:

```bash
malskills analyze-skill <skill-dir> \
  --output <output-dir> \
  --rule-store output/learned-rules \
  --collect-rule-candidates \
  --rule-group-id <dedupe-or-campaign-id>
```

The same store must be used across scans. `--rule-group-id` should identify an independent package family or campaign, not an artifact or individual finding record.

If the rule store is inside the scanned skill, it is excluded from ingestion and sample hashing. The store cannot be the skill root itself or one of its ancestors.

Inspect candidates:

```bash
malskills rules list --store output/learned-rules
malskills rules show <candidate-id> --store output/learned-rules
```

SSO fingerprints exclude generated rule ids, messages, YAML formatting, and Semgrep metavariable names. They retain the canonical finding category/subtype, languages, match structure, lexical/API anchors, argument structure, and context constraints. At present, the specification generator runs per LLM-only hit and the registry aggregates normalized drafts; clustering several raw finding variants before generation remains future work.

Workflow fingerprints use a restricted JSON DSL. A rule must contain two to six SSO roles that form one connected graph through:

- `same_object`
- directed `value_flow` with a maximum path length of eight

Disconnected SSO co-occurrence is not a valid workflow candidate.

## Validate

Validation manifests contain independently reviewed cases:

```json
{
  "corpus_id": "wrapper-occurrences-v1",
  "annotations_version": "reviewed-v1",
  "cases": [
    {
      "path": "fixtures/positive-wrapper",
      "expected": true,
      "dedupe_group_id": "held-out-positive-1"
    },
    {
      "path": "fixtures/hard-negative-wrapper",
      "expected": false,
      "dedupe_group_id": "held-out-negative-1"
    }
  ]
}
```

Run the candidate only on that corpus and record the result:

```bash
malskills rules validate <candidate-id> \
  --store output/learned-rules \
  --manifest held-out.json
```

Case paths are restricted to the manifest directory by default. Use `--corpus-root <reviewed-root>` when fixtures live elsewhere. Discovery and validation content hashes/group ids must be disjoint; duplicate held-out content is rejected even when given different group ids.

SSO cases are reviewed fixture-level annotations: each fixture is positive when the candidate should match at least once. A benign skill can legitimately contain a security-sensitive operation, so a package's benign/malicious label is not sufficient SSO ground truth. The default SSO gate requires:

- 3 independent discovery groups
- valid Semgrep compilation
- 5 held-out positive groups, at least 1 hard-negative group, and 20 reviewed fixtures with a rule hit
- precision >= 0.98 and recall >= 0.80
- fixture-level false-positive rate <= 0.01

The default workflow gate requires:

- a connected dependency path
- 3 held-out target-pattern groups
- 100 held-out non-target/benign groups
- precision >= 0.95 and recall >= 0.70
- at least one true-positive fixture and no false-positive fixture

Validation metrics are computed by `rules validate`; arbitrary metric reports cannot be imported through the CLI. The content-bound corpus digest and validation report are retained in the content-addressed bundle. Full verdict-level FPR/F1 regression and finding-level span accuracy are not inferred from fixture labels and remain separate release reviews.

Workflow validation records its analyzer profile, Semgrep identity, per-case YASA setting, active ruleset digest, and active learned SSO candidate ids. Promotion requires the same active ruleset digest. A learned SSO cannot be deactivated while a retained workflow validation names it as a base dependency; deactivate that workflow first.

## Promote, Deactivate, And Roll Back

Promotion always requires an explicit reviewer identity:

```bash
malskills rules promote <candidate-id> \
  --store output/learned-rules \
  --approved-by <reviewer>
```

Subsequent scans load the active bundle by using the same store, including with all LLM stages disabled:

```bash
malskills analyze-skill <skill-dir> \
  --output <output-dir> \
  --rule-store output/learned-rules \
  --disable-llm-sso-extraction \
  --disable-llm-object-analysis \
  --reasoning-mode formal
```

The exact `ruleset_digest` is written to `analysis_metadata.json` and learned rule ids appear in findings or pattern proofs.

Deactivate, reject, or roll back rules with:

```bash
malskills rules reject <candidate-id> --store output/learned-rules --reason <reason>
malskills rules deactivate <candidate-id> \
  --store output/learned-rules \
  --approved-by <reviewer>
malskills rules rollback <older-bundle-digest> --store output/learned-rules
```

`deactivate` creates a new bundle without the selected rule while retaining the other active rules. Use `malskills rules rollback none --store output/learned-rules` to deactivate the entire first bundle and return to an empty learned ruleset. After a rule has been deactivated or rolled out of the current bundle and explicitly rejected, rollback will not reactivate a bundle containing it.

Promotion is deliberately not automatic. Repetition alone is not findings of correctness and can be manipulated through cloned or attacker-published packages.
