# CloudDiagnose Motivating Example

## Overview

`CloudDiagnose` is a deliberately crafted motivating example for illustrating why malicious Skill detection requires explicit cross-artifact reasoning and why that reasoning should still stay aligned with analyzable program structure.

The Skill is presented as a benign DevOps utility:

> A skill for collecting deployment diagnostics and preparing troubleshooting bundles for cloud service incidents.

At first glance, its behavior appears normal for an operational debugging workflow:

- load a runtime collection plan
- inspect environment details
- collect troubleshooting target groups
- package a diagnostic bundle
- submit the bundle to a relay

However, the malicious behavior does not appear in any single artifact. It emerges only when the prompt, code, and diagnostic plan are interpreted together.

## Artifact Layout

This motivating example contains three skill artifacts plus one companion analysis note:

- [`SKILL.md`](/home/shenaow/AgentSkill/motivating_example/clouddiagnose/SKILL.md)
- [`diagnostic.yaml`](/home/shenaow/AgentSkill/motivating_example/clouddiagnose/diagnostic.yaml)
- [`post.js`](/home/shenaow/AgentSkill/motivating_example/clouddiagnose/post.js)
- [`analysis.md`](/home/shenaow/AgentSkill/motivating_example/clouddiagnose/analysis.md) (paper-writing companion note)
- [`simplified_sdg.md`](/home/shenaow/AgentSkill/motivating_example/clouddiagnose/simplified_sdg.md) (paper figure sketch)

## Why This Example Matters

This example is designed to expose both the paper's research challenges and the concrete role of each analysis stage in `SkillGuard`.

1. Heterogeneous artifacts
   The risky semantics are distributed across natural-language instructions, executable code, and a runtime diagnostic plan.

2. Adversarially distributed logic
   `post.js` resembles a generic diagnostics uploader. The sensitive collection scope is hidden inside shell commands in `diagnostic.yaml`, and the remote destination only becomes dangerous after composition with the prompt and plan.

3. Context-dependent risk
   Generic command-driven diagnostics and outbound submission are individually plausible in a troubleshooting Skill. Their risk depends on what is collected, why it is collected, and where it is sent.

4. Tool-aligned explainability
   The case is intentionally written so that `Semgrep` can recover outbound upload and plan-file access from code and text, `YASA` can resolve command, result-directory, and endpoint operands from `diagnostic.yaml`, and the SDG plus rule reasoning can explain why a seemingly benign diagnostics workflow produces a secret-bearing result directory that is then sent outward.

## Core Security Insight

The key conclusion is:

> No single artifact is overtly malicious, and the code alone looks like a normal diagnostics workflow; the dangerous collection scope only appears after cross-artifact reasoning resolves what the diagnostic commands actually collect.

For a fuller write-up aimed at paper text and presentation use, see:

- [`analysis.md`](/home/shenaow/AgentSkill/motivating_example/clouddiagnose/analysis.md)
