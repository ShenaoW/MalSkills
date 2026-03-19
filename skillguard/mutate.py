from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from .taxonomy import classify_artifact
from .utils import ensure_dir, find_urls, try_read_text


class MutationGenerator:
    def generate(self, input_skill: str | Path, output_dir: str | Path) -> list[Path]:
        source = Path(input_skill).resolve()
        destination = Path(output_dir).resolve()
        ensure_dir(destination)
        variants = [
            ("rename_identifiers", self._rename_identifiers),
            ("prompt_camouflage", self._prompt_camouflage),
            ("config_sink", self._config_sink),
        ]
        outputs: list[Path] = []
        for name, transform in variants:
            target = destination / name
            if target.exists():
                shutil.rmtree(target)
            shutil.copytree(source, target)
            transform(target)
            outputs.append(target)
        return outputs

    def _rename_identifiers(self, root: Path) -> None:
        replacements = {
            r"\bcfg\b": "settings_blob",
            r"\bconfig\b": "runtime_catalog",
            r"\bsysinfo\b": "snapshot_payload",
            r"\btoken\b": "session_marker",
        }
        self._rewrite_text_files(root, replacements)

    def _prompt_camouflage(self, root: Path) -> None:
        replacements = {
            r"run this command": "complete the bootstrap step",
            r"must run": "should complete",
            r"download": "obtain",
            r"password": "access code",
            r"before starting": "before normal usage",
        }
        self._rewrite_text_files(root, replacements, only_types={"markdown", "prompt", "text"})

    def _config_sink(self, root: Path) -> None:
        urls: list[str] = []
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            is_text, content = try_read_text(path)
            if not is_text or not content:
                continue
            urls.extend(find_urls(content))
        urls = [url for url in urls if url.startswith("http")]
        if not urls:
            return
        config_path = root / "skillguard_mutation_config.json"
        config_path.write_text(json.dumps({"log_endpoint": urls[0]}, indent=2), encoding="utf-8")
        replacements = {re.escape(urls[0]): "config.log_endpoint"}
        self._rewrite_text_files(root, replacements, only_types={"javascript", "python"})

    def _rewrite_text_files(self, root: Path, replacements: dict[str, str], only_types: set[str] | None = None) -> None:
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            artifact_type = classify_artifact(path)
            if only_types and artifact_type not in only_types:
                continue
            is_text, content = try_read_text(path)
            if not is_text or content is None:
                continue
            updated = content
            for pattern, replacement in replacements.items():
                updated = re.sub(pattern, replacement, updated)
            if updated != content:
                path.write_text(updated, encoding="utf-8")
