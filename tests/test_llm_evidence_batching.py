from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from skillguard.evidence.llm import LlmEvidenceExtractor
from skillguard.models import ArtifactRecord


def _artifact(relative_path: str, content: str = "line1\nline2\n") -> ArtifactRecord:
    return ArtifactRecord(
        artifact_id=relative_path.replace("/", "_"),
        relative_path=relative_path,
        artifact_type="markdown" if relative_path.endswith(".md") else "javascript",
        content_hash=f"hash:{relative_path}",
        size_bytes=len(content.encode("utf-8")),
        line_count=content.count("\n") + (1 if content else 0),
        is_text=True,
        content=content,
    )


def test_llm_evidence_uses_single_artifact_requests_at_or_below_threshold(monkeypatch, tmp_path: Path) -> None:
    extractor = LlmEvidenceExtractor(cache_dir=tmp_path / "cache", batch_threshold=10, max_workers=2)
    seen = []

    def fake_invoke_structured_json(*, prompt: str, schema: dict[str, object], **_: object) -> dict[str, object]:
        seen.append((prompt, schema))
        return {
            "records": [
                {
                    "type": "credential_and_secret_access",
                    "subtype": "private_key_or_api_key_access",
                    "confidence": 0.9,
                    "start_line": 1,
                    "end_line": 1,
                    "attributes": {"matched_text": "OPENAI_API_KEY"},
                }
            ]
        }

    monkeypatch.setattr("skillguard.evidence.llm.invoke_structured_json", fake_invoke_structured_json)
    artifacts = [_artifact(f"file_{index}.md") for index in range(3)]
    result = extractor.extract(artifacts)

    assert len(seen) == 3
    assert all("Analyze the following single artifact" in prompt for prompt, _ in seen)
    assert {item.artifact_path for item in result.evidence} == {"file_0.md", "file_1.md", "file_2.md"}


def test_llm_evidence_uses_batched_request_above_threshold_and_maps_artifact_paths(monkeypatch, tmp_path: Path) -> None:
    extractor = LlmEvidenceExtractor(cache_dir=tmp_path / "cache", batch_threshold=10, max_workers=2)
    seen = []

    def fake_invoke_structured_json(*, prompt: str, schema: dict[str, object], **_: object) -> dict[str, object]:
        seen.append((prompt, schema))
        return {
            "records": [
                {
                    "artifact_path": "file_0.md",
                    "type": "credential_and_secret_access",
                    "subtype": "private_key_or_api_key_access",
                    "confidence": 0.9,
                    "start_line": 1,
                    "end_line": 1,
                    "attributes": {"matched_text": "OPENAI_API_KEY"},
                },
                {
                    "artifact_path": "dir/file_10.js",
                    "type": "network_and_remote_communication",
                    "subtype": "outbound_connection",
                    "confidence": 0.8,
                    "start_line": 2,
                    "end_line": 2,
                    "attributes": {"matched_text": "https://example.test"},
                },
            ]
        }

    monkeypatch.setattr("skillguard.evidence.llm.invoke_structured_json", fake_invoke_structured_json)
    artifacts = [_artifact(f"file_{index}.md") for index in range(10)] + [_artifact("dir/file_10.js", "a\nb\n")]
    result = extractor.extract(artifacts)

    assert len(seen) == 1
    prompt, schema = seen[0]
    assert "Analyze the following artifacts together" in prompt
    assert "=== Artifact: file_0.md ===" in prompt
    assert "=== Artifact: dir/file_10.js ===" in prompt
    record_schema = schema["properties"]["records"]["items"]
    assert "artifact_path" in record_schema["properties"]
    assert {item.artifact_path for item in result.evidence} == {"file_0.md", "dir/file_10.js"}
