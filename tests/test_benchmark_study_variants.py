from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.run_benchmark_study import DEFAULT_ABLATIONS, OPTIONAL_BASELINES
from malskills.evaluation import BASELINE_CONFIGS, VARIANTS, _baseline_runners


def test_benchmark_study_variants_are_registered() -> None:
    configured = DEFAULT_ABLATIONS + OPTIONAL_BASELINES
    configured_baselines = {item.removeprefix("benchmark_") for item in configured if item.endswith("_baseline")}

    assert len(configured) == len(set(configured))
    assert set(configured) <= set(VARIANTS)
    assert configured_baselines == set(BASELINE_CONFIGS)
    assert set(BASELINE_CONFIGS) == set(_baseline_runners())
    assert all(VARIANTS[name] == name for name in BASELINE_CONFIGS)
    assert all(VARIANTS[f"benchmark_{name}"] == name for name in BASELINE_CONFIGS)


def test_default_benchmark_baselines_do_not_include_external_runtime_tools() -> None:
    assert "benchmark_nova_proximity_baseline" in DEFAULT_ABLATIONS
    assert "benchmark_openclaw_clawscan_baseline" in DEFAULT_ABLATIONS
    assert "benchmark_masb_baseline" in OPTIONAL_BASELINES
    assert "benchmark_skillward_baseline" in OPTIONAL_BASELINES
