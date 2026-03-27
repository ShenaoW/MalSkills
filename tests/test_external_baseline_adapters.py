from __future__ import annotations

import subprocess
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from skillguard.baselines.external_tools import (
    run_masb_baseline,
    run_caterpillar_baseline,
    run_nova_proximity_baseline,
    run_skill_scanner_baseline,
    run_skill_security_audit_baseline,
    run_skill_security_scan_baseline,
    run_skills_security_audit_baseline,
)


class _FakeProcess:
    def __init__(self, stdout: str, returncode: int = 0, stderr: str = "", *, pid: int = 4321) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode
        self.pid = pid
        self.wait_calls = 0
        self.terminated = False
        self.killed = False

    def communicate(self, timeout: int | None = None) -> tuple[str, str]:
        return self._stdout, self._stderr

    def wait(self, timeout: int | None = None) -> int:
        self.wait_calls += 1
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True


def test_skill_security_scan_baseline_parses_prefixed_json(monkeypatch, tmp_path: Path) -> None:
    skill_dir = tmp_path / 'skill'
    skill_dir.mkdir()
    output_dir = tmp_path / 'out'

    payload = '\n'.join([
        'Scanning: /tmp/skill',
        '{',
        '  "risk_level": "CRITICAL",',
        '  "issues": [{"rule_id": "CMD001"}],',
        '  "summary": {"CRITICAL": 1}',
        '}',
    ])

    def fake_popen(*args: object, **kwargs: object) -> _FakeProcess:
        return _FakeProcess(payload)

    monkeypatch.setattr(subprocess, 'Popen', fake_popen)
    result = run_skill_security_scan_baseline(skill_dir, output_dir)

    assert result['status'] == 'ok'
    assert result['predicted'] == 'malicious'
    assert result['patterns'] == ['CMD001']
    assert (output_dir / 'skill_security_scan_report.json').exists()
    assert (output_dir / 'output_manifest.json').exists()


def test_masb_baseline_maps_thresholded_risk_score(monkeypatch, tmp_path: Path) -> None:
    skill_dir = tmp_path / 'skill'
    skill_dir.mkdir()
    output_dir = tmp_path / 'out'
    from skillguard.baselines import external_tools

    runtime_root = output_dir / "masb_runtime"

    def fake_prepare(skill_path: Path, destination: Path) -> Path:
        runtime_root.mkdir(parents=True, exist_ok=True)
        return runtime_root

    def fake_run(runtime: Path, commands: list[list[str]]) -> list[dict[str, Any]]:
        return [{"command": command, "returncode": 0, "stdout": "", "stderr": ""} for command in commands]

    def fake_collect_static(runtime: Path, skill_path: Path) -> dict[str, Any]:
        return {"risk_level": "CRITICAL", "skills_reports": [{"skill_name": skill_path.name, "risk_level": "CRITICAL"}]}

    def fake_collect_runtime(runtime: Path, skill_path: Path, static_payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "skill_path": str(skill_path),
            "risk_level": "MALICIOUS",
            "audit_reports": [
                {
                    "skill_name": "skill",
                    "skill_path": str(skill_path),
                    "repo_id": "repo",
                    "category": "MALICIOUS",
                    "report_path": str(runtime / "runtime_scan_results" / "MALICIOUS" / "repo_skill_audit.json"),
                    "audit_summary": {"intent_alignment_status": "MALICIOUS"},
                }
            ],
            "vulnerabilities": [{"pattern_id": "NET001"}],
            "execution_artifacts": ["runtime_execution_logs/MALICIOUS/repo/skill/final_message.txt"],
        }

    monkeypatch.setattr(external_tools, "_prepare_masb_runtime", fake_prepare)
    monkeypatch.setattr(external_tools, "_run_masb_native_pipeline", fake_run)
    monkeypatch.setattr(external_tools, "_collect_masb_static_payload", fake_collect_static)
    monkeypatch.setattr(external_tools, "_collect_masb_runtime_payload_from_static", fake_collect_runtime)
    result = run_masb_baseline(skill_dir, output_dir)

    assert result['status'] == 'ok'
    assert result['predicted'] == 'malicious'
    assert result['patterns'] == ['NET001']
    assert (output_dir / 'masb_report.json').exists()
    assert (output_dir / 'output_manifest.json').exists()


def test_skills_security_audit_baseline_maps_review_to_suspicious(monkeypatch, tmp_path: Path) -> None:
    skill_dir = tmp_path / 'skill'
    skill_dir.mkdir()
    output_dir = tmp_path / 'out'

    def fake_popen(*args: object, **kwargs: object) -> _FakeProcess:
        return _FakeProcess('{"files": [{"decision": "review", "findings": [{"category": "network_access"}]}], "summary": {"review": 1}}')

    monkeypatch.setattr(subprocess, 'Popen', fake_popen)
    result = run_skills_security_audit_baseline(skill_dir, output_dir)

    assert result['status'] == 'ok'
    assert result['predicted'] == 'suspicious'
    assert result['patterns'] == ['network_access']
    assert (output_dir / 'skills_security_audit_report.json').exists()


def test_skill_security_audit_baseline_tolerates_nonzero_exit_with_json(monkeypatch, tmp_path: Path) -> None:
    skill_dir = tmp_path / 'skill'
    skill_dir.mkdir()
    output_dir = tmp_path / 'out'

    payload = '{"skills": {"skill": [{"severity": "CRITICAL", "category": "credential_theft"}]}, "summary": {"skills_scanned": 1}}'

    def fake_popen(*args: object, **kwargs: object) -> _FakeProcess:
        return _FakeProcess(payload, returncode=3)

    monkeypatch.setattr(subprocess, 'Popen', fake_popen)
    result = run_skill_security_audit_baseline(skill_dir, output_dir)

    assert result['status'] == 'ok'
    assert result['predicted'] == 'malicious'
    assert result['patterns'] == ['credential_theft']
    assert (output_dir / 'skill_security_audit_report.json').exists()


def test_caterpillar_baseline_tolerates_nonzero_exit_with_json(monkeypatch, tmp_path: Path) -> None:
    skill_dir = tmp_path / 'skill'
    skill_dir.mkdir()
    output_dir = tmp_path / 'out'

    payload = (
        '{"success": true, "data": {"skill": "demo", "grade": "F", "score": 0, '
        '"findings": [{"severity": "critical", "category": "Credential Theft"}], "summary": "bad"}}'
    )

    def fake_popen(*args: object, **kwargs: object) -> _FakeProcess:
        return _FakeProcess(payload, returncode=1)

    monkeypatch.setattr(subprocess, 'Popen', fake_popen)
    result = run_caterpillar_baseline(skill_dir, output_dir)

    assert result['status'] == 'ok'
    assert result['predicted'] == 'malicious'
    assert result['patterns'] == ['Credential Theft']
    assert (output_dir / 'caterpillar_report.json').exists()


def test_skill_scanner_baseline_maps_high_severity(monkeypatch, tmp_path: Path) -> None:
    skill_dir = tmp_path / 'skill'
    skill_dir.mkdir()
    output_dir = tmp_path / 'out'

    payload = (
        '{"skill_name": "demo", "skill_path": "/tmp/demo", "is_safe": false, '
        '"max_severity": "HIGH", "findings_count": 1, '
        '"findings": [{"rule_id": "PIPELINE_TAINT_FLOW"}]}'
    )

    def fake_popen(*args: object, **kwargs: object) -> _FakeProcess:
        return _FakeProcess(payload, returncode=1)

    monkeypatch.setattr(subprocess, 'Popen', fake_popen)
    result = run_skill_scanner_baseline(skill_dir, output_dir)

    assert result['status'] == 'ok'
    assert result['predicted'] == 'malicious'
    assert result['patterns'] == ['PIPELINE_TAINT_FLOW']
    assert (output_dir / 'skill_scanner_report.json').exists()


def test_nova_proximity_baseline_maps_high_severity(monkeypatch, tmp_path: Path) -> None:
    skill_dir = tmp_path / 'skill'
    skill_dir.mkdir()
    output_dir = tmp_path / 'out'

    payload = {
        "scan_results": {
            "total_skills": 1,
            "skills": [
                {
                    "name": "demo",
                    "security_flags": [
                        {"type": "undeclared_tool", "severity": "high"},
                    ],
                }
            ],
        },
        "nova_analysis": {"flagged_count": 0},
    }

    def fake_popen(*args: object, **kwargs: object) -> _FakeProcess:
        prefix = Path(str(args[0][-1]))
        report_path = prefix.parent / f"{prefix.name}_20260326_120000.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(__import__("json").dumps(payload), encoding="utf-8")
        return _FakeProcess("")

    monkeypatch.setattr(subprocess, 'Popen', fake_popen)
    result = run_nova_proximity_baseline(skill_dir, output_dir)

    assert result['status'] == 'ok'
    assert result['predicted'] == 'malicious'
    assert result['patterns'] == ['undeclared_tool']
    assert (output_dir / 'nova_proximity_report.json').exists()

def test_external_baseline_timeout_kills_process_group(monkeypatch, tmp_path: Path) -> None:
    from skillguard.baselines import external_tools

    skill_dir = tmp_path / 'skill'
    skill_dir.mkdir()
    output_dir = tmp_path / 'out'

    fake_process = _FakeProcess("", pid=2468)

    def fake_communicate(timeout: int | None = None) -> tuple[str, str]:
        raise subprocess.TimeoutExpired(cmd=["python3"], timeout=timeout or 0)

    fake_process.communicate = fake_communicate  # type: ignore[method-assign]

    killpg_calls: list[tuple[int, Any]] = []

    def fake_popen(*args: object, **kwargs: object) -> _FakeProcess:
        return fake_process

    def fake_killpg(pid: int, sig: Any) -> None:
        killpg_calls.append((pid, sig))

    monkeypatch.setattr(subprocess, 'Popen', fake_popen)
    monkeypatch.setattr(external_tools.os, 'killpg', fake_killpg)

    try:
        run_skill_scanner_baseline(skill_dir, output_dir)
        assert False, "expected TimeoutExpired"
    except subprocess.TimeoutExpired:
        pass

    assert killpg_calls
    assert killpg_calls[0][0] == 2468
    assert fake_process.wait_calls >= 1
