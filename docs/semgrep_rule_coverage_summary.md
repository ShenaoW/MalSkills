# Semgrep Rule Coverage Summary

## Scope

This note summarizes how many sensitive Semgrep rules currently exist under `semgrep_rules/`, grouped by language and behavior.

Count date: `2026-03-26`

## Counting Method

- Count unit: one Semgrep rule `id`
- Primary grouping:
  - language: inferred from `semgrep_rules/<language>/...`
  - behavior: inferred from `semgrep_rules/<language>/<behavior>/...`
- Special case:
  - `semgrep_rules/special/special.yaml` currently contains one obfuscation rule declared for both `javascript` and `typescript`
  - this summary counts that rule once under `javascript / obfuscation` and once under `typescript / obfuscation`

## Rules by Language and Behavior

| Language | command_execution | cryptography | dynamic_execution | file_or_system_operation | insecure_deserialization | network_access | obfuscation | sensitive_data | Total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| c | 20 | 58 | 5 | 83 | 0 | 64 | 9 | 0 | 239 |
| cpp | 40 | 90 | 37 | 101 | 0 | 78 | 23 | 0 | 369 |
| csharp | 27 | 42 | 14 | 50 | 0 | 51 | 16 | 0 | 200 |
| go | 11 | 28 | 11 | 64 | 0 | 45 | 27 | 0 | 186 |
| java | 27 | 33 | 16 | 39 | 0 | 33 | 17 | 0 | 165 |
| javascript | 94 | 72 | 13 | 194 | 0 | 141 | 38 | 0 | 552 |
| php | 17 | 32 | 1 | 25 | 0 | 30 | 29 | 0 | 134 |
| python | 40 | 16 | 6 | 73 | 8 | 65 | 4 | 14 | 226 |
| ruby | 14 | 34 | 17 | 74 | 0 | 39 | 36 | 0 | 214 |
| typescript | 55 | 69 | 2 | 131 | 0 | 85 | 38 | 0 | 380 |
| Total | 345 | 474 | 122 | 834 | 8 | 631 | 237 | 14 | 2665 |

## Totals by Language

| Language | Rule Count |
| --- | ---: |
| javascript | 552 |
| typescript | 380 |
| cpp | 369 |
| c | 239 |
| python | 226 |
| ruby | 214 |
| csharp | 200 |
| go | 186 |
| java | 165 |
| php | 134 |

## Totals by Behavior

| Behavior | Rule Count |
| --- | ---: |
| file_or_system_operation | 834 |
| network_access | 631 |
| cryptography | 474 |
| command_execution | 345 |
| obfuscation | 237 |
| dynamic_execution | 122 |
| sensitive_data | 14 |
| insecure_deserialization | 8 |

## Observations

- `file_or_system_operation` is the largest rule family, with `834` rules.
- `javascript` has the largest language-specific rule inventory, with `552` rules.
- `python` is the only language that currently includes `insecure_deserialization` and `sensitive_data` rule groups.
