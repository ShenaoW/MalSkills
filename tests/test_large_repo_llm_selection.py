from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from skillguard.evidence.extractor import EvidenceExtractor
from skillguard.models import ArtifactRecord, EvidenceRecord


def _artifact(relative_path: str, content: str = "content\n") -> ArtifactRecord:
    return ArtifactRecord(
        artifact_id=relative_path.replace("/", "_"),
        relative_path=relative_path,
        artifact_type="markdown" if relative_path.lower().endswith(".md") else "javascript",
        content_hash=f"hash:{relative_path}",
        size_bytes=len(content.encode("utf-8")),
        line_count=content.count("\n") + (1 if content else 0),
        is_text=True,
        content=content,
    )


def _semgrep_hit(artifact_path: str) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=f"hit:{artifact_path}",
        producer="semgrep",
        artifact_id=artifact_path.replace("/", "_"),
        artifact_path=artifact_path,
        evidence_type="network_and_remote_communication",
        subtype="outbound_connection",
        value="",
        confidence=0.9,
    )


def test_large_repo_llm_selection_uses_semgrep_hits_parent_docs_and_top_level_docs() -> None:
    artifacts = [_artifact(f"misc/file_{index:02d}.js") for index in range(18)]
    artifacts.extend(
        [
            _artifact("README.md", "# root\n"),
            _artifact("AGENTS.md", "# root agent\n"),
            _artifact("scripts/exfiltrate.js", "fetch('https://example.test')\n"),
            _artifact("scripts/SKILL.md", "# local skill\n"),
            _artifact("scripts/README.md", "# local readme\n"),
            _artifact("scripts/notes.md", "# ignore\n"),
        ]
    )

    extractor = EvidenceExtractor()
    seen_paths: list[str] = []

    def fake_semgrep_extract(skill_root: str | Path, received: list[ArtifactRecord]) -> list[EvidenceRecord]:
        assert len(received) == len(artifacts)
        return [_semgrep_hit("scripts/exfiltrate.js")]

    def fake_llm_extract(received: list[ArtifactRecord]):
        nonlocal seen_paths
        seen_paths = [artifact.relative_path for artifact in received]
        return type("Result", (), {"evidence": []})()

    extractor.semgrep.extract = fake_semgrep_extract  # type: ignore[method-assign]
    extractor.llm.extract = fake_llm_extract  # type: ignore[method-assign]

    extractor.extract("/tmp/skill", artifacts, enable_semgrep=True, enable_llm_evidence=True)

    assert seen_paths == [
        "AGENTS.md",
        "README.md",
        "scripts/README.md",
        "scripts/SKILL.md",
        "scripts/exfiltrate.js",
    ]


def test_large_repo_llm_selection_falls_back_to_all_instruction_docs_when_semgrep_has_no_hits() -> None:
    artifacts = [_artifact(f"misc/file_{index:02d}.js") for index in range(18)]
    artifacts.extend(
        [
            _artifact("README.md", "# root\n"),
            _artifact("AGENTS.md", "# root agent\n"),
            _artifact("nested/SKILL.md", "# nested skill\n"),
            _artifact("nested/CLAUDE.md", "# nested claude\n"),
            _artifact("nested/notes.md", "# ignore\n"),
            _artifact("scripts/exfiltrate.js", "fetch('https://example.test')\n"),
        ]
    )

    extractor = EvidenceExtractor()
    seen_paths: list[str] = []

    def fake_semgrep_extract(skill_root: str | Path, received: list[ArtifactRecord]) -> list[EvidenceRecord]:
        assert len(received) == len(artifacts)
        return []

    def fake_llm_extract(received: list[ArtifactRecord]):
        nonlocal seen_paths
        seen_paths = [artifact.relative_path for artifact in received]
        return type("Result", (), {"evidence": []})()

    extractor.semgrep.extract = fake_semgrep_extract  # type: ignore[method-assign]
    extractor.llm.extract = fake_llm_extract  # type: ignore[method-assign]

    extractor.extract("/tmp/skill", artifacts, enable_semgrep=True, enable_llm_evidence=True)

    assert seen_paths == [
        "AGENTS.md",
        "README.md",
        "nested/CLAUDE.md",
        "nested/SKILL.md",
    ]
