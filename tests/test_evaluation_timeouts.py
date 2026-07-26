from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from malskills.baselines.external_tools import DEFAULT_TIMEOUT_SEC, SKILL_SCANNER_TIMEOUT_SEC
from malskills.evaluation import BENCHMARK_CASE_TIMEOUT_BUFFER_SEC, BENCHMARK_CASE_TIMEOUT_SEC


def test_benchmark_case_timeout_exceeds_baseline_subprocess_timeouts() -> None:
    max_baseline_timeout = max(
        DEFAULT_TIMEOUT_SEC,
        SKILL_SCANNER_TIMEOUT_SEC,
    )

    assert BENCHMARK_CASE_TIMEOUT_BUFFER_SEC > 0
    assert BENCHMARK_CASE_TIMEOUT_SEC > max_baseline_timeout
