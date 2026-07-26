from __future__ import annotations

import json
from pathlib import Path

import pytest

from malskills.benchmark import BenchmarkBuilder, load_benchmark_entries


def _benchmark_row(local_path: str) -> dict[str, object]:
    return {
        "entry_id": "ground_truth::test::sample",
        "dataset": "ground_truth",
        "source": "test",
        "repo": "owner",
        "skill_name": "sample",
        "label": "malicious",
        "local_path": local_path,
        "analyzable": True,
    }


def _make_repo(tmp_path: Path) -> Path:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "pyproject.toml").write_text("[project]\nname = \"malskills\"\n", encoding="utf-8")
    (repo_root / "malskills").mkdir()
    return repo_root


def test_load_benchmark_resolves_repository_relative_paths_outside_repo_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_root = _make_repo(tmp_path)
    skill_dir = repo_root / "data" / "ground_truth" / "malicious" / "sample"
    skill_dir.mkdir(parents=True)
    benchmark_path = repo_root / "experiments" / "benchmark.json"
    benchmark_path.parent.mkdir()
    benchmark_path.write_text(
        json.dumps([_benchmark_row("data/ground_truth/malicious/sample")]),
        encoding="utf-8",
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.chdir(outside)

    entries = load_benchmark_entries(benchmark_path)

    assert entries[0].local_path == str(skill_dir.resolve())


def test_load_benchmark_rejects_relative_paths_outside_repository(tmp_path: Path) -> None:
    repo_root = _make_repo(tmp_path)
    benchmark_path = repo_root / "benchmark.json"
    benchmark_path.write_text(json.dumps([_benchmark_row("../outside")]), encoding="utf-8")

    with pytest.raises(ValueError, match="escapes repository root"):
        load_benchmark_entries(benchmark_path)


def test_load_benchmark_marks_missing_paths_unanalyzable(tmp_path: Path) -> None:
    repo_root = _make_repo(tmp_path)
    benchmark_path = repo_root / "benchmark.json"
    benchmark_path.write_text(json.dumps([_benchmark_row("data/missing")]), encoding="utf-8")

    entries = load_benchmark_entries(benchmark_path)

    assert entries[0].local_path == str((repo_root / "data" / "missing").resolve())
    assert entries[0].analyzable is False


def test_benchmark_builder_writes_repository_relative_paths(tmp_path: Path) -> None:
    repo_root = _make_repo(tmp_path)
    ground_truth_root = repo_root / "data" / "ground_truth"
    skill_dir = ground_truth_root / "malicious" / "sample"
    skill_dir.mkdir(parents=True)
    (ground_truth_root / "ground_truth_final.csv").write_text(
        "Source,Registry,Skill_name,Label,Ground_truth_path\n"
        "test,test,owner/sample,malicious,data/ground_truth/malicious/sample\n",
        encoding="utf-8",
    )

    entries = BenchmarkBuilder(repo_root).build()

    assert len(entries) == 1
    assert entries[0].local_path == "data/ground_truth/malicious/sample"
