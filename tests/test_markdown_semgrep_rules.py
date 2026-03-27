from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from skillguard.evidence.semgrep import SemgrepEvidenceExtractor
from skillguard.ingest import SkillIngestor


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
    skill = Path("data/malicious_confirmed/zaycv/linkedin-job-application")
    matches = _extract_semgrep_subtypes(skill)

    assert matches
    assert not any(subtype == "scheduled_persistence" for subtype, _, _ in matches)
    assert any(
        subtype == "shell_interpreter_execution"
        and "encoded_shell_payload_echo" in rule_id
        for subtype, rule_id, _ in matches
    )


def test_markdown_base64_to_bash_chain_is_detected_in_real_malicious_skill() -> None:
    skill = Path("data/clawsec_malskills/extracted__sakaen736jih__nano-banana-pro-oinrw3__latest_124fb20ce8a9")
    matches = _extract_semgrep_subtypes(skill)

    assert any(
        subtype == "shell_interpreter_execution"
        and "encoded_shell_payload_echo" in rule_id
        and "base64 -D | bash" in matched_text
        for subtype, rule_id, matched_text in matches
    )
