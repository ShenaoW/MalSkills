# Security Policy

## Supported Versions

MalSkills is research software under active development. Security fixes are
applied to the latest revision of the default branch; older commits and locally
modified baseline revisions are not supported.

| Version | Supported |
|---|---|
| Latest `master` | Yes |
| Older revisions | No |

## Reporting a Vulnerability

Do not open a public issue for a vulnerability. Use
[GitHub private vulnerability reporting](https://github.com/security-pride/MalSkills/security/advisories/new).
If that channel is unavailable, email `shenaowang@hust.edu.cn` with the subject
`[MalSkills Security]`.

Include the affected revision, environment, impact, reproduction steps, and a
minimal proof of concept when it is safe to share. Do not include real secrets,
personal data, or an active malicious package. Reports will be acknowledged and
triaged privately; disclosure timing will be coordinated after a fix is ready.

Relevant issues include unsafe handling of untrusted Skill files, command or
path injection, credential disclosure, LLM bridge authentication bypass,
rule-store poisoning, and sandbox boundary violations caused by MalSkills.
Vulnerabilities that exist only in an unchanged third-party baseline should be
reported to that upstream project, while adapter or integration flaws should be
reported here.

MalSkills is a static analysis research prototype. Running optional baselines,
containers, or dynamic validation may execute third-party tooling; use isolated
environments and review their upstream security guidance.
