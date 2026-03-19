from __future__ import annotations

from pathlib import Path

from .models import ArtifactRecord
from .taxonomy import IGNORE_DIRS, MARKDOWN_NAMES, NOISY_ROOT_DIRS, NOISY_SUBTREES, PRIORITY_ROOT_DIRS, PROMPT_NAMES, classify_artifact
from .utils import sha256_bytes, sha256_text, try_read_text


class SkillIngestor:
    def ingest(self, skill_path: str | Path) -> list[ArtifactRecord]:
        root = Path(skill_path).resolve()
        if not root.is_dir():
            raise FileNotFoundError(f"skill path is not a directory: {root}")
        artifacts: list[ArtifactRecord] = []
        index = 0
        candidates = [path for path in sorted(root.rglob("*")) if path.is_file() and not any(part in IGNORE_DIRS for part in path.parts)]
        large_repo = len(candidates) > 300
        for path in candidates:
            if not path.is_file():
                continue
            rel = path.relative_to(root)
            if self._should_skip(rel, large_repo=large_repo):
                continue
            artifact_type = classify_artifact(path)
            is_text, content = try_read_text(path)
            if is_text and content is not None:
                content_hash = sha256_text(content)
                line_count = content.count("\n") + (1 if content else 0)
                size_bytes = len(content.encode("utf-8", errors="ignore"))
            else:
                raw = path.read_bytes()
                content_hash = sha256_bytes(raw)
                line_count = 0
                size_bytes = len(raw)
                content = None
            artifacts.append(
                ArtifactRecord(
                    artifact_id=f"art_{index:04d}",
                    relative_path=str(rel),
                    artifact_type=artifact_type,
                    content_hash=content_hash,
                    size_bytes=size_bytes,
                    line_count=line_count,
                    is_text=is_text,
                    content=content if artifact_type != "binary" else None,
                )
            )
            index += 1
        return artifacts

    def _should_skip(self, rel: Path, *, large_repo: bool) -> bool:
        parts = rel.parts
        if not parts:
            return False
        if parts[0].lower() in NOISY_ROOT_DIRS:
            return True
        if len(parts) >= 2 and (parts[0].lower(), parts[1].lower()) in NOISY_SUBTREES:
            return True
        lower_name = rel.name.lower()
        suffix = rel.suffix.lower()
        if suffix in {".md", ".markdown", ".txt"} and len(parts) > 2:
            if lower_name not in MARKDOWN_NAMES and lower_name not in PROMPT_NAMES and "skill" not in lower_name and "prompt" not in lower_name:
                return True
        if large_repo:
            root_name = parts[0].lower()
            if len(parts) > 1 and root_name not in PRIORITY_ROOT_DIRS:
                return True
            if root_name in PRIORITY_ROOT_DIRS and len(parts) > 3:
                return True
        return False
