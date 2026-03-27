# Ground Truth Baseline Scans

This repository now includes a batch runner for scanning `data/ground_truth` with the `baseline/nova-proximity` and `baseline/AI-Infra-Guard` tools.

## Dataset Layout

The runner expects the malicious ground-truth samples under:

```bash
data/ground_truth/malicious/<source>/<sample>
```

Each immediate child under `clawhub/`, `skills_directory/`, `skillsmp/`, and `skillsrest/` is treated as one scan target.

## Nova-Proximity

Static skill scan across the full malicious ground truth:

```bash
pip install -r baseline/nova-proximity/requirements.txt
python3 scripts/scan_ground_truth_batch.py \
  --tool nova-proximity \
  --output-dir output/baseline/nova_proximity_ground_truth
```

Enable NOVA LLM analysis as well:

```bash
export OPENAI_API_KEY=...
python3 scripts/scan_ground_truth_batch.py \
  --tool nova-proximity \
  --nova-scan \
  --nova-evaluator openai \
  --nova-rule baseline/nova-proximity/skill_rules.nov
```

## AI-Infra-Guard

`AI-Infra-Guard` skill scanning is driven through `baseline/AI-Infra-Guard/agent-scan`.

```bash
pip install -r baseline/AI-Infra-Guard/agent-scan/requirements.txt
export OPENROUTER_API_KEY=...
python3 scripts/scan_ground_truth_batch.py \
  --tool ai-infra-guard \
  --output-dir output/baseline/ai_infra_guard_ground_truth
```

Optional overrides:

```bash
python3 scripts/scan_ground_truth_batch.py \
  --tool ai-infra-guard \
  --model deepseek/deepseek-v3.2-exp \
  --base-url https://openrouter.ai/api/v1 \
  --language en
```

If you need a custom provider config for the internal `agent-scan` workflow:

```bash
python3 scripts/scan_ground_truth_batch.py \
  --tool ai-infra-guard \
  --agent-provider baseline/AI-Infra-Guard/agent-scan/providers.yaml
```

## Output Structure

Each run writes to `output/baseline/<tool>_ground_truth/` by default:

```bash
output/baseline/<tool>_ground_truth/
  run_summary.json
  cases/<source>/<sample>/
    stdout.log
    stderr.log
    summary.json
    ...
```

Tool-specific reports:

- `nova-proximity`: `nova_proximity_*.json`
- `ai-infra-guard`: `ai_infra_guard_report.json`

## Useful Filters

Only scan one source:

```bash
python3 scripts/scan_ground_truth_batch.py \
  --tool nova-proximity \
  --source clawhub
```

Only scan a small smoke subset:

```bash
python3 scripts/scan_ground_truth_batch.py \
  --tool ai-infra-guard \
  --limit 5
```

Resume an interrupted run:

```bash
python3 scripts/scan_ground_truth_batch.py \
  --tool nova-proximity \
  --resume
```
