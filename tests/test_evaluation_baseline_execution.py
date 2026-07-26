from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from malskills.evaluation import Evaluator


def test_baseline_run_case_executes_directly_without_outer_worker(monkeypatch, tmp_path: Path) -> None:
    import malskills.evaluation as evaluation

    called: dict[str, object] = {}

    class UnexpectedProcess:
        def __init__(self, *args: object, **kwargs: object) -> None:
            raise AssertionError("baseline case should not create an outer multiprocessing worker")

    def fake_run_skill_scanner_baseline(skill_path: str, case_output_dir: Path) -> dict[str, object]:
        called["skill_path"] = skill_path
        called["case_output_dir"] = str(case_output_dir)
        return {
            "status": "ok",
            "predicted": "benign",
            "score": 0.0,
            "patterns": [],
            "evidence_count": 0,
            "derived_evidence_count": 0,
            "combined_evidence_count": 0,
            "primitive_count": 0,
        }

    monkeypatch.setattr(evaluation.multiprocessing, "Process", UnexpectedProcess)
    monkeypatch.setattr(evaluation, "run_skill_scanner_baseline", fake_run_skill_scanner_baseline)

    evaluator = Evaluator()
    case_output_dir = tmp_path / "case"
    result = evaluator._run_case("/tmp/fake-skill", case_output_dir, "skill_scanner_baseline")

    assert result["status"] == "ok"
    assert called["skill_path"] == "/tmp/fake-skill"
    assert called["case_output_dir"] == str(case_output_dir)
    assert (case_output_dir / "benchmark_case_status.json").exists()
