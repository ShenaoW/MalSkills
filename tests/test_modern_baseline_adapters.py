from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from malskills.baselines.modern_tools import (
    run_agentverus_baseline,
    run_clawvet_baseline,
    run_openclaw_clawscan_baseline,
    run_razin_baseline,
    run_skillspector_baseline,
    run_skilltotal_baseline,
)


class _FakeProcess:
    def __init__(self, stdout: str = "", returncode: int = 0, stderr: str = "") -> None:
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode
        self.pid = 4321

    def communicate(self, timeout: int | None = None) -> tuple[str, str]:
        return self._stdout, self._stderr

    def wait(self, timeout: int | None = None) -> int:
        return self.returncode

    def terminate(self) -> None:
        return None

    def kill(self) -> None:
        return None


def _install_json_process(
    monkeypatch: Any,
    commands: list[list[str]],
    payload: dict[str, Any],
    *,
    returncode: int = 0,
) -> None:
    def fake_popen(command: list[str], **kwargs: object) -> _FakeProcess:
        commands.append(command)
        return _FakeProcess(json.dumps(payload), returncode=returncode)

    monkeypatch.setattr(subprocess, "Popen", fake_popen)


def _assert_artifacts(output_dir: Path, artifact_name: str, manifest_key: str) -> None:
    assert (output_dir / artifact_name).exists()
    manifest_path = output_dir / "output_manifest.json"
    assert manifest_path.exists()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["files"][manifest_key] == artifact_name


def test_skillspector_adapter_uses_static_json_and_accepts_findings_exit(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    output_dir = tmp_path / "out"
    commands: list[list[str]] = []
    payload = {
        "risk_assessment": {
            "score": 91,
            "severity": "CRITICAL",
            "recommendation": "DO_NOT_INSTALL",
        },
        "issues": [{"id": "SKSP-01", "severity": "CRITICAL"}],
    }
    _install_json_process(monkeypatch, commands, payload, returncode=1)

    result = run_skillspector_baseline(skill_dir, output_dir)

    assert result == {
        "status": "ok",
        "predicted": "malicious",
        "score": 0.91,
        "patterns": ["SKSP-01"],
        "evidence_count": 0,
        "derived_evidence_count": 0,
        "combined_evidence_count": 0,
        "primitive_count": 0,
    }
    assert commands[0][-5:] == [
        "scan",
        str(skill_dir.resolve()),
        "--format",
        "json",
        "--no-llm",
    ]
    _assert_artifacts(output_dir, "skillspector_report.json", "skillspector_report")


def test_agentverus_adapter_handles_wrapped_reports_and_inverts_trust_score(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    output_dir = tmp_path / "out"
    commands: list[list[str]] = []
    payload = {
        "reports": [
            {
                "target": str(skill_dir),
                "report": {
                    "overall": 40,
                    "badge": "conditional",
                    "findings": [{"id": "ASST-02", "severity": "high"}],
                },
            }
        ],
        "failures": [],
    }
    _install_json_process(monkeypatch, commands, payload)

    result = run_agentverus_baseline(skill_dir, output_dir)

    assert result["status"] == "ok"
    assert result["predicted"] == "suspicious"
    assert result["score"] == 0.6
    assert result["patterns"] == ["ASST-02"]
    assert commands[0][-3:] == ["scan", str(skill_dir.resolve()), "--json"]
    _assert_artifacts(output_dir, "agentverus_report.json", "agentverus_report")


def test_skilltotal_adapter_maps_schema_1_5_malicious_verdict(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    output_dir = tmp_path / "out"
    commands: list[list[str]] = []
    payload = {
        "risk_score": 88,
        "risk_level": "critical",
        "verdict": {
            "level": "malicious",
            "has_malicious_indicators": True,
            "headline": "Malicious indicators detected",
        },
        "findings": [{"id": "ST-COMBO-EXFIL", "severity": "critical"}],
    }
    _install_json_process(monkeypatch, commands, payload)

    result = run_skilltotal_baseline(skill_dir, output_dir)

    assert result["status"] == "ok"
    assert result["predicted"] == "malicious"
    assert result["score"] == 0.88
    assert result["patterns"] == ["ST-COMBO-EXFIL"]
    assert commands[0][-3:] == ["scan", str(skill_dir.resolve()), "--json"]
    assert commands[0][commands[0].index("-m") + 1] == "skilltotal"
    _assert_artifacts(output_dir, "skilltotal_report.json", "skilltotal_report")

    review_output = tmp_path / "review-out"
    review_payload = {
        "risk_score": 0,
        "risk_level": "low",
        "verdict": {
            "level": "low",
            "has_malicious_indicators": False,
            "headline": "Manual review required",
        },
        "findings": [],
        "needs_review": [{"category": "sensitive_path"}],
    }
    _install_json_process(monkeypatch, commands, review_payload)

    review_result = run_skilltotal_baseline(skill_dir, review_output)

    assert review_result["predicted"] == "suspicious"
    assert review_result["score"] == 0.4
    assert review_result["patterns"] == ["sensitive_path"]


def test_clawvet_adapter_maps_camel_case_warning_result(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    output_dir = tmp_path / "out"
    commands: list[list[str]] = []
    payload = {
        "status": "complete",
        "riskScore": 47,
        "riskGrade": "C",
        "recommendation": "warn",
        "findings": [{"id": "CV-NET-01", "severity": "high"}],
    }
    _install_json_process(monkeypatch, commands, payload)

    result = run_clawvet_baseline(skill_dir, output_dir)

    assert result["status"] == "ok"
    assert result["predicted"] == "suspicious"
    assert result["score"] == 0.47
    assert result["patterns"] == ["CV-NET-01"]
    assert commands[0][-4:] == [
        "scan",
        str(skill_dir.resolve()),
        "--format",
        "json",
    ]
    _assert_artifacts(output_dir, "clawvet_report.json", "clawvet_report")


def test_razin_adapter_collects_native_summary_and_findings(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    output_dir = tmp_path / "out"
    commands: list[list[str]] = []

    def fake_popen(command: list[str], **kwargs: object) -> _FakeProcess:
        commands.append(command)
        native_output = Path(command[command.index("--output-dir") + 1])
        report_dir = native_output / "demo"
        report_dir.mkdir(parents=True)
        (report_dir / "summary.json").write_text(
            json.dumps(
                {
                    "review_priority": 84,
                    "review_priority_level": "high",
                    "evidence_verdict": "review-required",
                    "counts_by_rule": {"RZN-DATA-EXFIL": 1},
                    "top_risks": [],
                }
            ),
            encoding="utf-8",
        )
        (report_dir / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "d34db33f",
                        "rule_id": "RZN-DATA-EXFIL",
                        "severity": "high",
                    }
                ]
            ),
            encoding="utf-8",
        )
        return _FakeProcess()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)

    result = run_razin_baseline(skill_dir, output_dir)

    assert result["status"] == "ok"
    assert result["predicted"] == "suspicious"
    assert result["score"] == 0.74
    assert result["patterns"] == ["RZN-DATA-EXFIL"]
    scan_args = commands[0][commands[0].index("scan") :]
    assert scan_args == [
        "scan",
        "--root",
        str(skill_dir.resolve()),
        "--output-dir",
        str((output_dir / "razin_native").resolve()),
        "--output-format",
        "json",
        "--no-cache",
        "--no-stdout",
    ]
    _assert_artifacts(output_dir, "razin_report.json", "razin_report")


def test_openclaw_clawscan_adapter_reads_nested_static_artifact(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    output_dir = tmp_path / "out"
    commands: list[list[str]] = []
    payload = {
        "schemaVersion": "clawscan-run-v1",
        "scanners": {
            "clawscan-static": {
                "status": "completed",
                "raw": {
                    "schemaVersion": "clawscan-static-v1",
                    "findings": [
                        {
                            "id": "static.credential_exfiltration",
                            "severity": "high",
                        }
                    ],
                },
            }
        },
    }
    _install_json_process(monkeypatch, commands, payload)

    result = run_openclaw_clawscan_baseline(skill_dir, output_dir)

    assert result["status"] == "ok"
    assert result["predicted"] == "malicious"
    assert result["score"] == 0.9
    assert result["patterns"] == ["static.credential_exfiltration"]
    assert commands[0][-4:] == [
        str(skill_dir.resolve()),
        "--scanner",
        "clawscan-static",
        "--json",
    ]
    _assert_artifacts(
        output_dir,
        "openclaw_clawscan_report.json",
        "openclaw_clawscan_report",
    )
