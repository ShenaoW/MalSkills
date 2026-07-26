from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from malskills.evidence.semgrep import SemgrepEvidenceExtractor
from malskills.ingest import SkillIngestor


def _extract_semgrep_subtypes(skill: Path) -> list[tuple[str, str, str]]:
    artifacts = SkillIngestor().ingest(skill)
    evidence = SemgrepEvidenceExtractor().extract(skill, artifacts)
    return [
        (
            item.subtype,
            str(item.attributes.get("rule_id", "")),
            str(item.attributes.get("matched_text", "")),
        )
        for item in evidence
    ]


def test_markdown_persistence_rule_no_longer_matches_natural_language_or_examples() -> None:
    skill = Path("data/ground_truth/malicious/clawhub/zaycv_linkedin-job-application")
    matches = _extract_semgrep_subtypes(skill)

    assert matches
    assert not any(subtype == "scheduled_persistence" for subtype, _, _ in matches)
    assert any(
        subtype == "shell_interpreter_execution"
        and "encoded_shell_payload_echo" in rule_id
        for subtype, rule_id, _ in matches
    )


def test_markdown_base64_to_bash_chain_is_detected_in_real_malicious_skill() -> None:
    skill = Path("data/ground_truth/malicious/clawhub/sakaen736jih_nano-banana-pro-oinrw3")
    matches = _extract_semgrep_subtypes(skill)

    assert any(
        subtype == "shell_interpreter_execution"
        and "encoded_shell_payload_echo" in rule_id
        and "base64 -D | bash" in matched_text
        for subtype, rule_id, matched_text in matches
    )
