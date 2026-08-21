from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any, Iterable


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def try_read_text(path: Path) -> tuple[bool, str | None]:
    try:
        data = path.read_bytes()
    except OSError:
        return False, None
    if b"\x00" in data:
        return False, None
    try:
        return True, data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return True, data.decode("latin-1")
        except UnicodeDecodeError:
            return False, None


def flatten_mapping(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
    items: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            items.extend(flatten_mapping(child, child_prefix))
        return items
    if isinstance(value, list):
        for index, child in enumerate(value):
            child_prefix = f"{prefix}[{index}]"
            items.extend(flatten_mapping(child, child_prefix))
        return items
    items.append((prefix, value))
    return items


def iter_code_fences(text: str) -> Iterable[tuple[str, str, int, int]]:
    pattern = re.compile(r"```([A-Za-z0-9_+-]*)\r?\n(.*?)```", re.DOTALL)
    for match in pattern.finditer(text):
        language = match.group(1).strip().lower()
        body = _normalize_quoted_fence_body(text, match.start(), match.group(2))
        start_line = text.count("\n", 0, match.start()) + 1
        end_line = start_line + body.count("\n") + 1
        yield language, body, start_line, end_line


def _normalize_quoted_fence_body(text: str, fence_start: int, body: str) -> str:
    """Remove Markdown blockquote markers that wrap a complete code fence."""
    line_start = text.rfind("\n", 0, fence_start) + 1
    prefix = text[line_start:fence_start]
    quote_match = re.fullmatch(r"[ \t]*(?P<quotes>(?:>[ \t]*)+)", prefix)
    if quote_match is None:
        return body
    quote_depth = quote_match.group("quotes").count(">")
    quoted_line = re.compile(rf"^[ \t]*(?:>[ \t]*){{{quote_depth}}}")
    normalized: list[str] = []
    for line in body.splitlines(keepends=True):
        content = line.rstrip("\r\n")
        ending = line[len(content) :]
        match = quoted_line.match(content)
        normalized.append((content[match.end() :] if match else content) + ending)
    return "".join(normalized)


def dotted_name(node: Any) -> str | None:
    name_parts: list[str] = []
    while node is not None:
        if hasattr(node, "id"):
            name_parts.append(node.id)
            break
        if hasattr(node, "attr"):
            name_parts.append(node.attr)
            node = getattr(node, "value", None)
            continue
        if hasattr(node, "func"):
            node = node.func
            continue
        break
    if not name_parts:
        return None
    return ".".join(reversed(name_parts))


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def load_env_file(start: str | Path | None = None) -> dict[str, str]:
    base = Path(start).resolve() if start else Path.cwd().resolve()
    candidates = [base, *base.parents]
    for directory in candidates:
        env_path = directory / ".env"
        if not env_path.exists():
            continue
        values: dict[str, str] = {}
        for line in env_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            values[key.strip()] = value.strip().strip('"').strip("'")
        for key, value in values.items():
            os.environ.setdefault(key, value)
        return values
    return {}
