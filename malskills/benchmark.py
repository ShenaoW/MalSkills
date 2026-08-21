from __future__ import annotations

import csv
import json
from pathlib import Path

from .models import BenchmarkEntry, to_jsonable
from .utils import ensure_dir


class BenchmarkBuilder:
    def __init__(self, root: str | Path = ".") -> None:
        self.root = Path(root).resolve()

    def build(self) -> list[BenchmarkEntry]:
        entries: list[BenchmarkEntry] = []
        entries.extend(self._build_ground_truth_entries())
        entries.extend(self._build_clawsec_entries())
        entries.extend(self._build_malicious_confirmed_entries())
        entries.extend(self._build_masb_entries())
        entries.sort(key=lambda item: item.entry_id)
        return entries

    def write(self, output_path: str | Path, entries: list[BenchmarkEntry]) -> None:
        destination = Path(output_path)
        ensure_dir(destination.parent)
        payload = [to_jsonable(entry) for entry in entries]
        if destination.suffix == ".jsonl":
            destination.write_text("\n".join(json.dumps(row, sort_keys=True) for row in payload) + "\n", encoding="utf-8")
        else:
            destination.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def summarize(self, entries: list[BenchmarkEntry]) -> dict[str, object]:
        summary: dict[str, object] = {
            "total_entries": len(entries),
            "analyzable_entries": sum(1 for entry in entries if entry.analyzable),
            "by_dataset": {},
            "by_split": {},
            "by_label": {},
        }
        for entry in entries:
            dataset_info = summary["by_dataset"].setdefault(entry.dataset, {"total": 0, "analyzable": 0})
            dataset_info["total"] += 1
            dataset_info["analyzable"] += int(entry.analyzable)
            split_info = summary["by_split"].setdefault(entry.split, {"total": 0, "analyzable": 0})
            split_info["total"] += 1
            split_info["analyzable"] += int(entry.analyzable)
            label_info = summary["by_label"].setdefault(entry.label, {"total": 0, "analyzable": 0})
            label_info["total"] += 1
            label_info["analyzable"] += int(entry.analyzable)
        return summary

    def _portable_local_path(self, path: Path) -> str:
        resolved = path.resolve()
        try:
            return resolved.relative_to(self.root).as_posix()
        except ValueError as exc:
            raise ValueError(f"benchmark path escapes repository root: {resolved}") from exc

    def _build_ground_truth_entries(self) -> list[BenchmarkEntry]:
        ground_truth_root = self.root / "data" / "ground_truth"
        csv_path = ground_truth_root / "ground_truth_final.csv"
        if not csv_path.exists():
            return []
        entries: list[BenchmarkEntry] = []
        with csv_path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                source = row.get("Source", "")
                registry = row.get("Registry", "")
                skill_name = row.get("Skill_name", "")
                label = row.get("Label", "unknown")
                ground_truth_path = row.get("Ground_truth_path", "")
                local_dir = (self.root / ground_truth_path).resolve() if ground_truth_path else None
                local_path = self._portable_local_path(local_dir) if local_dir and local_dir.is_dir() else None
                owner, _, repo_name = skill_name.partition("/")
                entries.append(
                    BenchmarkEntry(
                        entry_id=f"ground_truth::{registry}::{skill_name}",
                        dataset="ground_truth",
                        source=source,
                        repo=owner or skill_name,
                        skill_name=repo_name or skill_name,
                        label=label,
                        local_path=local_path,
                        analyzable=local_path is not None,
                        split="confirmed_malicious" if label == "malicious" else "mixed_ecosystem",
                        label_source="ground_truth_final.csv",
                        metadata={
                            "registry": registry,
                            "ground_truth_path": ground_truth_path,
                        },
                    )
                )
        return entries

    def _build_clawsec_entries(self) -> list[BenchmarkEntry]:
        root = self.root / "data" / "clawsec_malskills"
        if not root.exists():
            return []
        entries: list[BenchmarkEntry] = []
        for path in sorted(root.iterdir()):
            if not path.is_dir():
                continue
            entries.append(
                BenchmarkEntry(
                    entry_id=f"clawsec::{path.name}",
                    dataset="clawsec_malskills",
                    source="clawsec",
                    repo=path.name,
                    skill_name=path.name,
                    label="malicious",
                    local_path=self._portable_local_path(path),
                    analyzable=True,
                    split="confirmed_malicious",
                    label_source="curated_dataset",
                    metadata={"kind": "confirmed_malicious"},
                )
            )
        return entries

    def _build_malicious_confirmed_entries(self) -> list[BenchmarkEntry]:
        root = self.root / "data" / "malicious_confirmed"
        if not root.exists():
            return []
        entries: list[BenchmarkEntry] = []
        for owner in sorted(root.iterdir()):
            if not owner.is_dir():
                continue
            for skill in sorted(owner.iterdir()):
                if not skill.is_dir():
                    continue
                entries.append(
                    BenchmarkEntry(
                        entry_id=f"confirmed::{owner.name}/{skill.name}",
                        dataset="malicious_confirmed",
                        source=owner.name,
                        repo=owner.name,
                        skill_name=skill.name,
                        label="malicious",
                        local_path=self._portable_local_path(skill),
                        analyzable=True,
                        split="confirmed_malicious",
                        label_source="curated_dataset",
                        metadata={"kind": "confirmed_malicious"},
                    )
                )
        return entries

    def _build_masb_entries(self) -> list[BenchmarkEntry]:
        dataset_root = self.root / "data" / "MaliciousAgentSkillsBench"
        state_csv = dataset_root / "skills_download_state.csv"
        malicious_csv = dataset_root / "malicious_skills.csv"
        if not state_csv.exists():
            return []
        pattern_map: dict[tuple[str, str, str], list[str]] = {}
        if malicious_csv.exists():
            with malicious_csv.open(newline="", encoding="utf-8") as handle:
                reader = csv.DictReader(handle)
                for row in reader:
                    key = (row["source"], row["repo"], row["skill_name"])
                    patterns = [item.strip() for item in row.get("Pattern", "").split(";") if item.strip()]
                    pattern_map[key] = patterns
        entries: list[BenchmarkEntry] = []
        with state_csv.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                source = row.get("source", "")
                repo = row.get("repo", "")
                skill_name = row.get("skill_name", "")
                label = row.get("classification", "unknown")
                download_status = row.get("download_status", "unknown")
                platform_dir = dataset_root / source / repo / skill_name
                local_path = self._portable_local_path(platform_dir) if platform_dir.exists() and platform_dir.is_dir() else None
                analyzable = local_path is not None and download_status == "downloaded"
                split = "metadata_only"
                if analyzable:
                    split = "mixed_malicious" if label == "malicious" else "mixed_ecosystem"
                label_source = "malicious_skills.csv" if (source, repo, skill_name) in pattern_map else "skills_download_state.csv"
                entries.append(
                    BenchmarkEntry(
                        entry_id=f"masb::{source}::{repo}::{skill_name}",
                        dataset="MaliciousAgentSkillsBench",
                        source=source,
                        repo=repo,
                        skill_name=skill_name,
                        label=label,
                        local_path=local_path,
                        analyzable=analyzable,
                        split=split,
                        label_source=label_source,
                        pattern_labels=pattern_map.get((source, repo, skill_name), []),
                        metadata={"download_status": download_status, "url": row.get("url", "")},
                    )
                )
        return entries


def _find_project_root(source: Path) -> Path:
    starts = [source.parent.resolve(), Path.cwd().resolve(), Path(__file__).resolve().parents[1]]
    visited: set[Path] = set()
    for start in starts:
        for candidate in (start, *start.parents):
            if candidate in visited:
                continue
            visited.add(candidate)
            if (candidate / "pyproject.toml").is_file() and (candidate / "malskills").is_dir():
                return candidate
    raise ValueError(f"cannot locate the MalSkills repository root for benchmark: {source}")


def _resolve_benchmark_local_path(project_root: Path, local_path: str) -> str:
    candidate = Path(local_path)
    if candidate.is_absolute():
        return str(candidate)
    resolved = (project_root / candidate).resolve()
    try:
        resolved.relative_to(project_root)
    except ValueError as exc:
        raise ValueError(f"benchmark local_path escapes repository root: {local_path}") from exc
    return str(resolved)


def load_benchmark_entries(path: str | Path) -> list[BenchmarkEntry]:
    source = Path(path).resolve()
    if source.suffix == ".jsonl":
        rows = [json.loads(line) for line in source.read_text(encoding="utf-8").splitlines() if line.strip()]
    else:
        rows = json.loads(source.read_text(encoding="utf-8"))
    entries: list[BenchmarkEntry] = []
    project_root: Path | None = None
    for row in rows:
        normalized = dict(row)
        local_path = normalized.get("local_path")
        if isinstance(local_path, str) and local_path:
            if not Path(local_path).is_absolute():
                project_root = project_root or _find_project_root(source)
                local_path = _resolve_benchmark_local_path(project_root, local_path)
                normalized["local_path"] = local_path
            if normalized.get("analyzable") and not Path(local_path).is_dir():
                normalized["analyzable"] = False
        entries.append(BenchmarkEntry(**normalized))
    return entries
