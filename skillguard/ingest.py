from __future__ import annotations

from pathlib import Path

from .models import ArtifactRecord
from .taxonomy import (
    EVIDENCE_TEXT_ARTIFACT_TYPES,
    FULLTEXT_MARKDOWN_NAMES,
    IGNORE_DIRS,
    MARKDOWN_NAMES,
    NOISY_ROOT_DIRS,
    NOISY_SUBTREES,
    PRIORITY_ROOT_DIRS,
    PROMPT_NAMES,
    classify_artifact,
)
from .utils import iter_code_fences, sha256_bytes, sha256_text, try_read_text


FENCE_LANGUAGE_ALIASES = {
    "py": ("python", ".py"),
    "python": ("python", ".py"),
    "python3": ("python", ".py"),
    "js": ("javascript", ".js"),
    "javascript": ("javascript", ".js"),
    "node": ("javascript", ".js"),
    "mjs": ("javascript", ".js"),
    "cjs": ("javascript", ".js"),
    "jsx": ("javascript", ".jsx"),
    "ts": ("javascript", ".ts"),
    "tsx": ("javascript", ".tsx"),
    "typescript": ("javascript", ".ts"),
    "sh": ("shell", ".sh"),
    "bash": ("shell", ".sh"),
    "zsh": ("shell", ".zsh"),
    "shell": ("shell", ".sh"),
}
LARGE_REPO_ARTIFACT_THRESHOLD = 20


class SkillIngestor:
    def ingest(
        self,
        skill_path: str | Path,
        *,
        max_artifacts: int | None = None,
        max_total_text_bytes: int | None = None,
    ) -> list[ArtifactRecord]:
        root = Path(skill_path).resolve()
        if not root.is_dir():
            raise FileNotFoundError(f"skill path is not a directory: {root}")
        artifacts: list[ArtifactRecord] = []
        index = 0
        total_text_bytes = 0
        candidates = [path for path in sorted(root.rglob("*")) if path.is_file() and not any(part in IGNORE_DIRS for part in path.parts)]
        large_repo = len(candidates) > LARGE_REPO_ARTIFACT_THRESHOLD
        for path in candidates:
            if not path.is_file():
                continue
            if max_artifacts is not None and len(artifacts) >= max_artifacts:
                break
            rel = path.relative_to(root)
            artifact_type = classify_artifact(path)
            lower_name = rel.name.lower()
            if self._should_skip(rel, artifact_type=artifact_type, large_repo=large_repo):
                continue
            is_text, content = try_read_text(path)
            if self._markdown_fences_only(rel, artifact_type=artifact_type, large_repo=large_repo):
                if is_text and content is not None:
                    for derived in self._derived_fence_artifacts(
                        ArtifactRecord(
                            artifact_id=f"art_{index:04d}",
                            relative_path=str(rel),
                            artifact_type=artifact_type,
                            content_hash=sha256_text(content),
                            size_bytes=len(content.encode("utf-8", errors="ignore")),
                            line_count=content.count("\n") + (1 if content else 0),
                            is_text=True,
                            content=content,
                        ),
                        content,
                        start_index=index,
                    ):
                        if max_artifacts is not None and len(artifacts) >= max_artifacts:
                            break
                        derived_size = len((derived.content or "").encode("utf-8", errors="ignore"))
                        if max_total_text_bytes is not None and total_text_bytes + derived_size > max_total_text_bytes:
                            continue
                        artifacts.append(derived)
                        total_text_bytes += derived_size
                        index += 1
                continue
            if is_text and content is not None:
                content_hash = sha256_text(content)
                line_count = content.count("\n") + (1 if content else 0)
                size_bytes = len(content.encode("utf-8", errors="ignore"))
                if max_total_text_bytes is not None and total_text_bytes + size_bytes > max_total_text_bytes:
                    continue
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
            if is_text and content is not None:
                total_text_bytes += size_bytes
            source_artifact = artifacts[-1]
            index += 1
            if is_text and content is not None and artifact_type in {"markdown", "prompt"}:
                for derived in self._derived_fence_artifacts(source_artifact, content, start_index=index):
                    if max_artifacts is not None and len(artifacts) >= max_artifacts:
                        break
                    derived_size = len((derived.content or "").encode("utf-8", errors="ignore"))
                    if max_total_text_bytes is not None and total_text_bytes + derived_size > max_total_text_bytes:
                        continue
                    artifacts.append(derived)
                    total_text_bytes += derived_size
                    index += 1
        return artifacts

    def _derived_fence_artifacts(self, source_artifact: ArtifactRecord, content: str, *, start_index: int) -> list[ArtifactRecord]:
        derived: list[ArtifactRecord] = []
        source_rel = Path(source_artifact.relative_path)
        stem = source_rel.stem or "artifact"
        parent = source_rel.parent
        counter = start_index
        for fence_index, (language_name, body, start_line, end_line) in enumerate(iter_code_fences(content)):
            normalized = FENCE_LANGUAGE_ALIASES.get(language_name.strip().lower())
            if normalized is None:
                continue
            artifact_type, suffix = normalized
            snippet = body.rstrip()
            if not snippet.strip():
                continue
            derived_rel = (parent / ".skillguard_fences" / f"{stem}__fence_{fence_index}{suffix}").as_posix()
            derived.append(
                ArtifactRecord(
                    artifact_id=f"art_{counter:04d}",
                    relative_path=derived_rel,
                    artifact_type=artifact_type,
                    content_hash=sha256_text(snippet),
                    size_bytes=len(snippet.encode("utf-8", errors="ignore")),
                    line_count=snippet.count("\n") + (1 if snippet else 0),
                    is_text=True,
                    content=snippet,
                    generated=True,
                    source_artifact_id=source_artifact.artifact_id,
                    source_artifact_path=source_artifact.relative_path,
                    source_start_line=start_line,
                    source_end_line=end_line,
                )
            )
            counter += 1
        return derived

    def _should_skip(self, rel: Path, *, artifact_type: str, large_repo: bool) -> bool:
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
            if artifact_type not in EVIDENCE_TEXT_ARTIFACT_TYPES and lower_name not in MARKDOWN_NAMES and lower_name not in PROMPT_NAMES and "skill" not in lower_name and "prompt" not in lower_name:
                return True
        if large_repo:
            root_name = parts[0].lower()
            if len(parts) > 1 and root_name not in PRIORITY_ROOT_DIRS:
                if artifact_type in EVIDENCE_TEXT_ARTIFACT_TYPES:
                    return False
                return True
            if root_name in PRIORITY_ROOT_DIRS and len(parts) > 3:
                return True
        return False

    def _markdown_fences_only(self, rel: Path, *, artifact_type: str, large_repo: bool) -> bool:
        if not large_repo or artifact_type != "markdown":
            return False
        return rel.name.lower() not in FULLTEXT_MARKDOWN_NAMES
