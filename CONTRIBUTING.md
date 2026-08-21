# Contributing to MalSkills

Thank you for improving MalSkills. Contributions should strengthen detection
quality and generalization without tuning behavior to individual benchmark
samples.

## Before You Start

Open an issue before a large architectural change, a new baseline integration,
or a taxonomy change. Bug fixes and focused documentation improvements can go
directly to a pull request.

Report vulnerabilities through the private process in [SECURITY.md](SECURITY.md),
not through a public issue.

## Development Setup

```bash
git clone --recurse-submodules https://github.com/security-pride/MalSkills.git
cd MalSkills
python3 -m venv .venv
.venv/bin/pip install -e '.[analysis]'
.venv/bin/malskills --help
```

Keep credentials in an ignored `.env`, using `.env.example` as the template.
Do not commit API keys, scan outputs, caches, downloaded corpora, or local tool
environments.

## Design Rules

- SSO extraction rules describe behavior-neutral sensitive operations. They
  must not encode a malicious verdict or sample-specific indicator.
- Behavior rules must match connected SDG operations through value flow or
  justified object identity. File co-occurrence and benchmark-specific strings
  are not acceptable substitutes for data flow.
- New heuristics need a general threat model, positive and negative examples,
  and held-out evaluation that demonstrates the precision/recall tradeoff.
- Preserve output schemas or document intentional schema changes.
- Keep baseline attribution and licensing intact. Compatibility changes to a
  third-party submodule belong in a maintained fork pinned to an exact commit,
  not as an uncommitted local patch.

## Validation

Run checks proportional to the change. At minimum:

```bash
.venv/bin/python -m compileall -q malskills scripts experiments
.venv/bin/malskills --help
.venv/bin/malskills show-llm-config --llm-config malskills.toml
git diff --check
```

Rule and reasoning changes should also run the relevant held-out corpus or
benchmark variant. Include the command, model/backend, sample coverage, and
result summary in the pull request. Do not commit generated output directories.

## Pull Requests

Keep each pull request focused. Explain the problem, the reasoning behind the
change, validation performed, and any remaining limitations. Update README or
the machine-readable rule files when user-visible behavior changes.
