# Simplified SDG

Generated sources:

- [`sdg.dot`](/home/shenaow/AgentSkill/motivating_example/clouddiagnose/sdg.dot)
- [`sdg.svg`](/home/shenaow/AgentSkill/motivating_example/clouddiagnose/sdg.svg)
- [`motivating_figure.dot`](/home/shenaow/AgentSkill/motivating_example/clouddiagnose/motivating_figure.dot)
- [`motivating_figure.svg`](/home/shenaow/AgentSkill/motivating_example/clouddiagnose/motivating_figure.svg)

Core reasoning chain:

- `Semgrep` extracts diagnostic-plan access and outbound upload from `post.js`.
- `YASA` resolves the command, result-directory, and endpoint operands from `diagnostic.yaml`.
- SDG construction links the secret-bearing command targets to the uploaded diagnostic result directory.
- Formal reasoning uses the derived result-directory relation plus the outbound sink to trigger `Information_Theft`.
