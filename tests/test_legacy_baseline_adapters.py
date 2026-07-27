from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from malskills.baselines.legacy_tools import (
    run_agentguard_baseline,
    run_ai_infra_guard_baseline,
    run_snyk_agent_scan_baseline,
)


class _FakeProcess:
    def __init__(self, stdout: str = "", returncode: int = 0, stderr: str = "") -> None:
        self.stdout_text = stdout
        self.stderr_text = stderr
        self.returncode = returncode
        self.pid = 4321

    def communicate(self, timeout: int | None = None) -> tuple[str, str]:
        return self.stdout_text, self.stderr_text

    def wait(self, timeout: int | None = None) -> int:
        return self.returncode

    def terminate(self) -> None:
        return None

    def kill(self) -> None:
        return None


def test_snyk_agent_scan_maps_high_issue(monkeypatch, tmp_path: Path) -> None:
    from malskills.baselines import legacy_tools

    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    output_dir = tmp_path / "out"
    payload = {
        str(skill_dir): {
            "path": str(skill_dir),
            "servers": [],
            "issues": [
                {
                    "code": "E101",
                    "message": "credential exfiltration",
                    "reference": None,
                    "extra_data": {"severity": "high"},
                }
            ],
            "labels": [],
            "error": None,
        }
    }

    monkeypatch.setattr(legacy_tools, "_resolve_tool_python", lambda _root: sys.executable)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: _FakeProcess(json.dumps(payload), 1))

    result = run_snyk_agent_scan_baseline(skill_dir, output_dir)

    assert result["predicted"] == "malicious"
    assert result["patterns"] == ["E101"]
    assert (output_dir / "snyk_agent_scan_report.json").exists()


def test_snyk_agent_scan_does_not_treat_total_failure_as_benign(monkeypatch, tmp_path: Path) -> None:
    from malskills.baselines import legacy_tools

    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    payload = {
        str(skill_dir): {
            "path": str(skill_dir),
            "servers": None,
            "issues": [],
            "error": {"message": "analysis API unavailable"},
        }
    }
    monkeypatch.setattr(legacy_tools, "_resolve_tool_python", lambda _root: sys.executable)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: _FakeProcess(json.dumps(payload)))

    try:
        run_snyk_agent_scan_baseline(skill_dir, tmp_path / "out")
        assert False, "expected a failed Snyk scan to raise"
    except RuntimeError as exc:
        assert "analysis API unavailable" in str(exc)


def test_ai_infra_guard_reads_sarif_output(monkeypatch, tmp_path: Path) -> None:
    from malskills.baselines import legacy_tools

    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    output_dir = tmp_path / "out"

    def fake_popen(command: list[str], **kwargs: object) -> _FakeProcess:
        report_path = Path(command[command.index("--output") + 1])
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            json.dumps(
                {
                    "version": "2.1.0",
                    "runs": [
                        {
                            "results": [
                                {
                                    "ruleId": "T04",
                                    "level": "error",
                                    "properties": {"severity": "High"},
                                }
                            ]
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        return _FakeProcess()

    monkeypatch.setattr(legacy_tools, "_resolve_tool_python", lambda _root: sys.executable)
    monkeypatch.setattr(subprocess, "Popen", fake_popen)

    result = run_ai_infra_guard_baseline(skill_dir, output_dir)

    assert result["predicted"] == "malicious"
    assert result["patterns"] == ["T04"]
    assert (output_dir / "ai_infra_guard_report.json").exists()


def test_agentguard_tolerates_findings_exit_code(monkeypatch, tmp_path: Path) -> None:
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    output_dir = tmp_path / "out"
    payload = {
        "risk_level": "critical",
        "risk_tags": ["PROMPT_INJECTION", "READ_SSH_KEYS"],
        "evidence": [{"tag": "PROMPT_INJECTION", "file": "SKILL.md", "line": 2}],
        "summary": "critical findings",
    }
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: _FakeProcess(json.dumps(payload), 2))

    result = run_agentguard_baseline(skill_dir, output_dir)

    assert result["predicted"] == "malicious"
    assert result["patterns"] == ["PROMPT_INJECTION", "READ_SSH_KEYS"]
    assert (output_dir / "agentguard_report.json").exists()
