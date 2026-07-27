from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from malskills.baselines.research_tools import (
    run_runtime_skill_audit_baseline,
    run_skill_sentinel_baseline,
    run_skillfortify_baseline,
    run_skillsieve_baseline,
    run_skillward_baseline,
)


class _FakeProcess:
    def __init__(self, stdout: str = "", returncode: int = 0, stderr: str = "", *, pid: int = 4321) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode
        self.pid = pid

    def communicate(self, timeout: int | None = None) -> tuple[str, str]:
        return self._stdout, self._stderr

    def wait(self, timeout: int | None = None) -> int:
        return self.returncode

    def terminate(self) -> None:
        pass

    def kill(self) -> None:
        pass


def _make_skill(tmp_path: Path) -> Path:
    skill_dir = tmp_path / "demo-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("---\nname: demo-skill\n---\n", encoding="utf-8")
    return skill_dir


def test_skillsieve_baseline_maps_malicious_confidence(monkeypatch, tmp_path: Path) -> None:
    skill_dir = _make_skill(tmp_path)
    output_dir = tmp_path / "out"
    payload = {
        "skill_name": "demo-skill",
        "final_verdict": "malicious",
        "final_confidence": 0.93,
        "layer_stopped": 1,
        "layer_results": [
            {
                "layer": 1,
                "verdict": "malicious",
                "confidence": 0.93,
                "evidence": ["credential theft chain"],
                "details": {"attack_type": "credential_theft"},
            }
        ],
        "report": "Detected a credential theft chain.",
    }

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: _FakeProcess(json.dumps(payload)))
    result = run_skillsieve_baseline(skill_dir, output_dir)

    assert result["status"] == "ok"
    assert result["predicted"] == "malicious"
    assert result["score"] == pytest.approx(0.93)
    assert result["patterns"] == ["credential theft chain", "credential_theft"]
    assert (output_dir / "skillsieve_report.json").exists()
    assert (output_dir / "output_manifest.json").exists()


def test_skillward_baseline_reads_native_guardian_report(monkeypatch, tmp_path: Path) -> None:
    skill_dir = _make_skill(tmp_path)
    output_dir = tmp_path / "out"

    def fake_popen(*args: object, **kwargs: object) -> _FakeProcess:
        command = list(args[0])
        native_output = Path(command[command.index("-o") + 1])
        native_output.mkdir(parents=True, exist_ok=True)
        report = {
            "prescan": {
                skill_dir.name: {
                    "safety_verdict": "SAFE",
                    "safety_confidence": 0.45,
                    "needs_sandbox": True,
                    "max_severity": "HIGH",
                    "findings": [{"rule_id": "NET001", "severity": "HIGH"}],
                    "key_threats": [],
                }
            },
            "runtime": {
                skill_dir.name: {
                    "status": "High Risk",
                    "blacklist_hits": 1,
                    "blocks": 1,
                    "content_risks": 1,
                    "agent_crashed": False,
                    "details": ["Blacklist hit: curl"],
                }
            },
            "timestamp": "2026-07-27T12:00:00",
        }
        (native_output / "guardian_report.json").write_text(json.dumps(report), encoding="utf-8")
        return _FakeProcess()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    result = run_skillward_baseline(skill_dir, output_dir)

    assert result["status"] == "ok"
    assert result["predicted"] == "malicious"
    assert result["score"] == pytest.approx(0.95)
    assert result["patterns"] == ["Blacklist hit: curl", "NET001"]
    assert (output_dir / "skillward_report.json").exists()
    assert (output_dir / "output_manifest.json").exists()


def test_runtime_skill_audit_maps_harmful_blocked_to_malicious(monkeypatch, tmp_path: Path) -> None:
    from malskills.baselines import research_tools

    skill_dir = _make_skill(tmp_path)
    output_dir = tmp_path / "out"
    payload = {
        "skill_path": str(skill_dir),
        "skill_name": skill_dir.name,
        "run_dir": "/tmp/runtime-audit-run",
        "profile": {
            "static_risk_targets": [
                {"file": "run.py", "file_function": "main", "risk_signals": ["credential_access"]}
            ]
        },
        "summary": {"skill": skill_dir.name, "completed": True},
        "run_results": [
            {
                "task_id": "task-1",
                "status": "defended",
                "harmfulness_assessment": {
                    "is_attack_asset": True,
                    "malicious_behavior_observed": False,
                    "harmfulness_label": "harmful",
                    "verdict": "harmful_blocked",
                    "confidence": "high",
                    "evidence": ["credential exfiltration path was refused"],
                },
            }
        ],
    }

    def fake_popen(*args: object, **kwargs: object) -> _FakeProcess:
        local_bin = research_tools._BASELINE_ROOT / "runtime-skill-audit" / ".openclaw" / "tools" / "node_modules" / ".bin"
        assert str(kwargs["env"]["PATH"]).split(os.pathsep)[0] == str(local_bin)
        return _FakeProcess(json.dumps(payload))

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    result = run_runtime_skill_audit_baseline(skill_dir, output_dir)

    assert result["status"] == "ok"
    assert result["predicted"] == "malicious"
    assert result["score"] == pytest.approx(0.95)
    assert result["patterns"] == ["credential exfiltration path was refused", "credential_access"]
    assert (output_dir / "runtime_skill_audit_report.json").exists()
    assert (output_dir / "output_manifest.json").exists()


def test_skillfortify_baseline_accepts_findings_exit_code(monkeypatch, tmp_path: Path) -> None:
    skill_dir = _make_skill(tmp_path)
    output_dir = tmp_path / "out"
    staged_roots: list[Path] = []
    payload = [
        {
            "skill_name": skill_dir.name,
            "is_safe": False,
            "findings_count": 1,
            "max_severity": "HIGH",
            "inferred_capabilities": [{"resource": "network", "access": "WRITE"}],
            "findings": [
                {
                    "severity": "HIGH",
                    "attack_type": "A3_CREDENTIAL_THEFT",
                    "attack_class": "credential_theft",
                    "finding_type": "pattern_match",
                    "evidence": "reads ~/.ssh/id_rsa",
                }
            ],
        }
    ]

    def fake_popen(*args: object, **kwargs: object) -> _FakeProcess:
        command = list(args[0])
        staged_root = Path(command[2])
        staged_skill = staged_root / ".claude" / "skills" / f"{skill_dir.name}.md"
        assert staged_root != skill_dir
        assert staged_skill.read_text(encoding="utf-8") == (skill_dir / "SKILL.md").read_text(encoding="utf-8")
        staged_roots.append(staged_root)
        return _FakeProcess(json.dumps(payload), returncode=1)

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    result = run_skillfortify_baseline(skill_dir, output_dir)

    assert result["status"] == "ok"
    assert result["predicted"] == "malicious"
    assert result["score"] == pytest.approx(0.95)
    assert result["patterns"] == ["A3_CREDENTIAL_THEFT"]
    assert (output_dir / "skillfortify_report.json").exists()
    assert (output_dir / "output_manifest.json").exists()
    assert len(staged_roots) == 1
    assert not staged_roots[0].exists()


def test_skill_sentinel_baseline_reads_requested_report(monkeypatch, tmp_path: Path) -> None:
    skill_dir = _make_skill(tmp_path)
    output_dir = tmp_path / "out"

    def fake_popen(*args: object, **kwargs: object) -> _FakeProcess:
        command = list(args[0])
        report_path = Path(command[command.index("-o") + 1])
        report = {
            "skill_name": skill_dir.name,
            "validated_findings": [
                {
                    "id": "prompt_injection_override",
                    "category": "prompt_injection",
                    "severity": "MEDIUM",
                }
            ],
            "false_positives": [],
            "overall_risk_assessment": {
                "risk_level": "MEDIUM",
                "skill_verdict": "SUSPICIOUS",
                "verdict_reasoning": "The instruction boundary is ambiguous.",
            },
            "scan_duration": {"seconds": 12.0, "display": "0m 12s"},
        }
        report_path.write_text(json.dumps(report), encoding="utf-8")
        return _FakeProcess()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    result = run_skill_sentinel_baseline(skill_dir, output_dir)

    assert result["status"] == "ok"
    assert result["predicted"] == "suspicious"
    assert result["score"] == pytest.approx(0.65)
    assert result["patterns"] == ["prompt_injection_override"]
    assert (output_dir / "skill_sentinel_report.json").exists()
    assert (output_dir / "output_manifest.json").exists()


def test_skill_sentinel_missing_report_is_not_benign(monkeypatch, tmp_path: Path) -> None:
    skill_dir = _make_skill(tmp_path)
    output_dir = tmp_path / "out"

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: _FakeProcess())

    with pytest.raises(FileNotFoundError, match="Skill Sentinel report not found"):
        run_skill_sentinel_baseline(skill_dir, output_dir)
