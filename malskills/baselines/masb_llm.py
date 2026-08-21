from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any
from urllib import request


MAX_SOURCE_CHARS = 500_000
TEXT_SUFFIXES = {
    ".bash",
    ".c",
    ".go",
    ".html",
    ".java",
    ".js",
    ".json",
    ".md",
    ".php",
    ".ps1",
    ".py",
    ".rb",
    ".sh",
    ".toml",
    ".ts",
    ".yaml",
    ".yml",
}


def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv[1:])
    if len(args) != 6:
        raise SystemExit(
            "usage: masb_llm SKILL_DIR PROMPT_FILE OUTPUT_FILE BASE_URL API_KEY MODEL"
        )
    skill_dir, prompt_file, output_file, base_url, api_key, model = args
    prompt = Path(prompt_file).read_text(encoding="utf-8")
    source = _render_skill(Path(skill_dir))
    payload = {
        "model": model,
        "temperature": 0,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": prompt},
            {
                "role": "user",
                "content": (
                    "Analyze the following skill using static analysis only. Return strict JSON only.\n\n"
                    + source
                ),
            },
        ],
    }
    endpoint = base_url.rstrip("/") + "/chat/completions"
    http_request = request.Request(
        endpoint,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with request.urlopen(http_request, timeout=900) as response:
        decoded: dict[str, Any] = json.loads(response.read().decode("utf-8"))
    content = decoded["choices"][0]["message"]["content"]
    Path(output_file).write_text(str(content), encoding="utf-8")
    return 0


def _render_skill(root: Path) -> str:
    chunks: list[str] = []
    size = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        remaining = MAX_SOURCE_CHARS - size
        if remaining <= 0:
            break
        content = content[:remaining]
        chunks.append(f"--- {path.relative_to(root)} ---\n{content}")
        size += len(content)
    return "\n\n".join(chunks)


if __name__ == "__main__":
    raise SystemExit(main())
