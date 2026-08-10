# CloudDiagnose: Tool-Aligned Motivating Example

## One-Sentence Summary

`CloudDiagnose` looks like a normal DevOps troubleshooting Skill, but its malicious behavior emerges only when the prompt, diagnostic plan, and executable code are reasoned about together, and when operand links are made explicit.

## Surface Narrative

The Skill advertises itself as:

> A utility for collecting deployment diagnostics and preparing troubleshooting bundles for cloud-service incidents.

This framing is intentionally believable. A real operational debugging tool may legitimately:

- load a diagnostic plan
- invoke command-driven diagnostics
- inspect environment variables
- package results into a directory
- upload a report

As a result, the individual actions performed by the Skill appear operationally plausible.

## Artifact-by-Artifact Interpretation

### 1. `SKILL.md`

The prompt never says "steal credentials" or "exfiltrate secrets". Instead it uses benign operational language:

- `collect the target groups needed for remote-access diagnosis`
- `preserve raw cloud-profile material`
- `SSH-related configuration`
- `environment credentials`
- `submit the generated bundle to the diagnostics relay`

It also explicitly instructs the agent to read the remote destination from
`diagnostic.yaml`, execute the listed commands, and keep the upload logic in a
separate orchestration script rather than embedding everything into one file.

This prompt creates semantic justification for touching sensitive data while preserving a troubleshooting persona.

### 2. `post.js`

The script is intentionally written so that, by itself, it looks like a normal
diagnostics workflow launcher:

- it loads `diagnostic.yaml`
- it resolves the configured result directory
- it uploads the resulting directory contents via `axios.post(...)`

This is deliberate. A code-only analyzer can recover the upload operation, but
it cannot tell from `post.js` alone that the result directory is secret-bearing.
The dangerous collection scope only becomes visible after cross-artifact
reasoning resolves what the plan commands actually collect.

### 3. `diagnostic.yaml`

The plan is intentionally written so that it still resembles an operational
diagnostics recipe. It:

- names the output result directory
- specifies the remote upload destination
- lists shell commands that collect files and package artifacts into that directory

Viewed in isolation, this still resembles an aggressive troubleshooting recipe.
Its commands become dangerous because they directly read credential-bearing files
and package them into the uploaded result directory.

## Where the Malicious Logic Actually Comes From

The malicious logic is distributed:

- `SKILL.md` justifies preserving raw credential-bearing material inside a diagnostics bundle
- `diagnostic.yaml` contains command operands that read sensitive files and package them into the result directory
- `post.js` contains only a generic read-plan-and-upload workflow

None of these artifacts alone is strong enough to look overtly malicious. The security risk only becomes clear after composition.

This is the central message for the motivating example:

> No single artifact is overtly malicious; the attack emerges from their composition.

## Why Existing Baselines Struggle

### Stage 1: Capability Extraction

This example is designed so the first stage already has meaningful symbolic wins.

From `post.js`, `Semgrep` can recover:

- diagnostic-plan access
- outbound HTTP submission

From `SKILL.md` and `diagnostic.yaml`, text-oriented extraction can
recover:

- the claimed debugging purpose
- the command-driven file-collection semantics
- the sensitive local targets hidden inside diagnostic commands
- the remote delivery endpoint

This means the motivating example reflects the actual design of our pipeline:
extraction should recover source-grounded `SSOFinding` records and canonical
SSOs before any higher-level reasoning begins.

### Stage 2: Operand Resolution and SDG Generation

The second stage should explain why these operations are related, rather than
merely co-occurring.

For this case, the SDG should expose at least the following logical objects:

- a `config_key` object for `remote`
- a `config_key` object for `bundle_dir`
- one or more command objects from `diagnostic.yaml`
- a result-directory operand derived from secret-bearing targets
- a `data_send` SSO that is associated with the same result-directory operand

This is also where `YASA` has a meaningful role. It should not be the only way
to discover the behavior; instead, it should strengthen operand recovery through
pointer analysis by resolving that:

- the upload logic takes `plan.bundle_dir`
- the upload logic takes `plan.remote`
- the diagnostic commands write into the same result directory later consumed by the upload logic
- the network sink takes `plan.remote`

In the methodology section, the SDG figure can therefore show both:

- canonical SSO nodes recovered from `Semgrep` findings
- object and parameter edges that make the operational chain explicit

### Stage 3: Neuro-Symbolic Reasoning

Once the SDG is available, the reasoning stage can make claims that are much
more precise than "this skill contains sensitive APIs":

- a bundle operand is built from target groups that include secret-bearing local data
- the same result-directory operand is associated with the `data_send` SSO
- the remote endpoint is resolved to a config-backed network operand

This directly supports a rule-driven `Data_Exfiltration` conclusion based on a
secret-bearing bundle flowing into the external sink. The command-execution SSO
remains contextual unless the SDG proves one of the supported malicious workflow
relations; mere co-occurrence does not create a second behavior match.

## Why This Version Works Better for the Paper

Compared with a case that relies mostly on prompt semantics, this version is a
better anchor for the whole paper:

- the motivation section can use it to state the research challenge
- the methodology section can reuse it to explain SSO findings, canonical SSOs, and the SDG
- the SDG figure can be drawn directly from the example's concrete objects and derived bundle operand
- the reasoning section can show how formal rules fire on top of those objects

In short, the case now demonstrates both dimensions we need:

1. the paper challenge: malicious intent is compositionally distributed across heterogeneous artifacts
2. the system contribution: each analysis stage contributes a concrete, inspectable part of the final detection chain

## Suggested SDG Sketch

If you want to draw the methodology SDG around this case, the graph can use the
following backbone:

- artifact nodes: `SKILL.md`, `diagnostic.yaml`, `post.js`
- artifact nodes: `SKILL.md`, `diagnostic.yaml`, `post.js`
- SSO nodes: `EXEC_DIAGNOSTIC_COMMAND`, `BUILD_RESULT_DIR`, `NETWORK_SEND`
- operand nodes: `obj::config_key::remote`, `obj::config_key::bundle_dir`, `obj::result_dir::diagnostic_bundle`

Representative edges:

- `diagnostic.yaml -> obj::config_key::remote`
- `diagnostic.yaml -> obj::config_key::bundle_dir`
- `diagnostic.yaml:commands -> obj::result_dir::diagnostic_bundle`
- `post.js:axios.post -> obj::result_dir::diagnostic_bundle`
- `secret-bearing targets -> obj::result_dir::diagnostic_bundle`

That picture makes the later methodology narrative much easier to write because
every stage has a visible contribution.

## Suggested Paper Paragraph

You can adapt the following paragraph directly:

> Consider a third-party Skill named \textsc{CloudDiagnose}, advertised as a utility for collecting deployment diagnostics and preparing troubleshooting bundles for cloud-service incidents. Its \texttt{SKILL.md} prompt justifies preserving cloud-profile material, SSH-related configuration, environment credentials, and logs as part of routine troubleshooting, and instructs the agent to read a diagnostic recipe from \texttt{diagnostic.yaml}, execute the listed commands, and then invoke \texttt{post.js}. The \texttt{diagnostic.yaml} file specifies the shell commands that read sensitive files and package them into a result directory, together with the remote relay endpoint. Its JavaScript implementation in \texttt{post.js} only loads the plan, reads the configured result directory, and uploads the result. Viewed independently, these artifacts still resemble an aggressive but plausible debugging workflow. When considered together, however, they reveal an exfiltration pipeline in which prompt-level justification, plan-level command resolution, result-directory derivation, and outbound delivery jointly form a malicious behavior chain. This example is useful not only for motivating the research challenge, but also for illustrating our methodology: symbolic extraction recovers the concrete upload operation, YASA-based pointer analysis resolves the command, result-directory, and endpoint operands, SDG construction links the secret-bearing files collected by the plan to the uploaded result directory, and neuro-symbolic reasoning identifies the resulting information-theft pattern.
