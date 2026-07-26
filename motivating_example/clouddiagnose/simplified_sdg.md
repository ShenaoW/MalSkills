# Simplified SDG

Graph sources:

- [`sdg.dot`](sdg.dot)
- [`motivating_figure.dot`](motivating_figure.dot)

Core reasoning chain:

- `Semgrep` extracts diagnostic-plan access and outbound upload from `post.js`.
- `YASA` resolves the command, result-directory, and endpoint operands from `diagnostic.yaml`.
- SDG construction links the secret-bearing command targets to the uploaded diagnostic result directory.
- Formal reasoning uses the derived result-directory relation plus the outbound sink to trigger `Information_Theft`.
