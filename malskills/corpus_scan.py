from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import random
import re
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from .llm_runtime import LLM_STAGES, describe_llm_runtime
from .models import AnalysisResult, to_jsonable
from .pipeline import AnalyzerConfig, SkillAnalyzer
from .utils import ensure_dir


SAMPLE_SCHEMA_VERSION = 1
SCAN_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class CorpusSampleEntry:
    entry_id: str
    source: str
    package: str
    package_path: str
    scan_path: str
    skill_file: str
    skill_content_sha256: str


_WORKER_CONFIG: AnalyzerConfig | None = None
_WORKER_OUTPUT_DIR: Path | None = None
_WORKER_RETAIN = "malicious"


def _initialize_worker(config: dict[str, object], output_dir: str, retain: str) -> None:
    global _WORKER_CONFIG, _WORKER_OUTPUT_DIR, _WORKER_RETAIN
    _WORKER_CONFIG = AnalyzerConfig(**config)
    _WORKER_OUTPUT_DIR = Path(output_dir)
    _WORKER_RETAIN = retain


def _scan_entry_worker(entry_payload: dict[str, str]) -> dict[str, object]:
    entry = CorpusSampleEntry(**entry_payload)
    started_at = time.perf_counter()
    analyzer = SkillAnalyzer()
    try:
        assert _WORKER_CONFIG is not None
        config = replace(
            _WORKER_CONFIG,
            rule_learning_group_id=entry.entry_id,
        )
        result = analyzer.analyze(entry.scan_path, config=config)
        retained_output = ""
        if _should_retain(result, _WORKER_RETAIN):
            assert _WORKER_OUTPUT_DIR is not None
            case_dir = _WORKER_OUTPUT_DIR / "cases" / _stable_case_directory_name(entry.entry_id)
            analyzer.writer.write(result, case_dir)
            retained_output = case_dir.relative_to(_WORKER_OUTPUT_DIR).as_posix()
        metadata = result.analysis_metadata
        semgrep_metadata = metadata.get("semgrep", {})
        if not isinstance(semgrep_metadata, dict):
            semgrep_metadata = {}
        feedback_summary = metadata.get("rule_feedback_summary", {})
        if not isinstance(feedback_summary, dict):
            feedback_summary = {}
        rule_learning = metadata.get("rule_learning", {})
        if not isinstance(rule_learning, dict):
            rule_learning = {}
        return {
            **entry_payload,
            "status": "ok",
            "verdict": result.verdict.label,
            "patterns": sorted({pattern.name for pattern in result.patterns}),
            "pattern_matches": len(result.patterns),
            "artifact_count": len(result.artifacts),
            "finding_count": len(result.findings),
            "sso_count": len(result.ssos),
            "operand_count": len(result.operands),
            "operand_resolution_count": len(result.operand_resolutions),
            "semgrep_status": str(semgrep_metadata.get("status", "unknown")),
            "llm_only_finding_count": int(feedback_summary.get("llm_only_hit_count", 0)),
            "proposed_rule_count": int(feedback_summary.get("proposed_rule_count", 0)),
            "observed_candidate_count": int(rule_learning.get("observed_candidate_count", 0)),
            "runtime_sec": round(time.perf_counter() - started_at, 4),
            "retained_output": retained_output,
            "error": "",
        }
    except Exception as exc:
        retained_output = ""
        if _WORKER_RETAIN in {"all", "malicious"} and _WORKER_OUTPUT_DIR is not None:
            case_dir = _WORKER_OUTPUT_DIR / "cases" / _stable_case_directory_name(entry.entry_id)
            ensure_dir(case_dir)
            error_payload = {
                "entry_id": entry.entry_id,
                "scan_path": entry.scan_path,
                "error": f"{type(exc).__name__}: {exc}",
            }
            (case_dir / "scan_error.json").write_text(
                json.dumps(error_payload, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            retained_output = case_dir.relative_to(_WORKER_OUTPUT_DIR).as_posix()
        return {
            **entry_payload,
            "status": "error",
            "verdict": "error",
            "patterns": [],
            "pattern_matches": 0,
            "artifact_count": 0,
            "finding_count": 0,
            "sso_count": 0,
            "operand_count": 0,
            "operand_resolution_count": 0,
            "semgrep_status": "error",
            "llm_only_finding_count": 0,
            "proposed_rule_count": 0,
            "observed_candidate_count": 0,
            "runtime_sec": round(time.perf_counter() - started_at, 4),
            "retained_output": retained_output,
            "error": f"{type(exc).__name__}: {exc}",
        }


def _should_retain(result: AnalysisResult, retain: str) -> bool:
    if retain == "all":
        return True
    if retain == "none":
        return False
    return result.verdict.label == "malicious"


def _stable_case_directory_name(entry_id: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "_", entry_id).strip("_").lower() or "case"
    digest = hashlib.sha1(entry_id.encode("utf-8")).hexdigest()[:10]
    return f"{slug[:100]}__{digest}"


class CorpusSampler:
    def discover(
        self,
        corpus_root: str | Path,
        *,
        sources: list[str] | None = None,
        deduplicate_content: bool = True,
    ) -> tuple[list[CorpusSampleEntry], dict[str, int]]:
        root = Path(corpus_root).resolve()
        if not root.is_dir():
            raise FileNotFoundError(f"corpus root is not a directory: {root}")
        allowed_sources = set(sources or [])
        entries: list[CorpusSampleEntry] = []
        skipped_without_skill = 0
        duplicate_content = 0
        seen_content: set[str] = set()
        source_dirs = [path for path in sorted(root.iterdir()) if path.is_dir()]
        for source_dir in source_dirs:
            if allowed_sources and source_dir.name not in allowed_sources:
                continue
            for package_dir in sorted(path for path in source_dir.iterdir() if path.is_dir()):
                selected = self._select_skill_file(package_dir)
                if selected is None:
                    skipped_without_skill += 1
                    continue
                content_digest = hashlib.sha256(selected.read_bytes()).hexdigest()
                if deduplicate_content and content_digest in seen_content:
                    duplicate_content += 1
                    continue
                seen_content.add(content_digest)
                scan_root = self._scan_root(package_dir, selected)
                relative_package = package_dir.relative_to(root).as_posix()
                entries.append(
                    CorpusSampleEntry(
                        entry_id=f"{source_dir.name}::{package_dir.name}",
                        source=source_dir.name,
                        package=package_dir.name,
                        package_path=relative_package,
                        scan_path=str(scan_root),
                        skill_file=selected.relative_to(root).as_posix(),
                        skill_content_sha256=content_digest,
                    )
                )
        return entries, {
            "package_directories_without_skill": skipped_without_skill,
            "content_duplicates_removed": duplicate_content,
        }

    def sample(
        self,
        entries: list[CorpusSampleEntry],
        *,
        sample_size: int,
        seed: int,
    ) -> list[CorpusSampleEntry]:
        if sample_size <= 0:
            raise ValueError("sample_size must be positive")
        if sample_size > len(entries):
            raise ValueError(
                f"sample_size {sample_size} exceeds {len(entries)} eligible corpus entries"
            )
        selected = random.Random(seed).sample(entries, sample_size)
        return sorted(selected, key=lambda item: item.entry_id)

    def _select_skill_file(self, package_dir: Path) -> Path | None:
        candidates = [
            path
            for path in package_dir.rglob("*")
            if path.is_file() and path.name.lower() == "skill.md"
        ]
        if not candidates:
            return None
        primary = [path for path in candidates if not self._is_secondary_skill_file(path, package_dir)]
        return max(primary or candidates, key=lambda path: self._candidate_rank(path, package_dir))

    def _candidate_rank(self, path: Path, package_dir: Path) -> tuple[object, ...]:
        relative = path.relative_to(package_dir)
        lower_parts = [part.lower() for part in relative.parts]
        tree_rank = 2 if "canonical-tree-v1" in lower_parts else 1 if "tree" in lower_parts else 0
        exact_name = int(path.name == "SKILL.md")
        snapshot_name = relative.parts[0] if len(relative.parts) > 1 else ""
        try:
            modified_ns = path.stat().st_mtime_ns
        except OSError:
            modified_ns = 0
        return exact_name, modified_ns, snapshot_name, tree_rank, relative.as_posix()

    def _is_secondary_skill_file(self, path: Path, package_dir: Path) -> bool:
        parts = {part.lower() for part in path.relative_to(package_dir).parts[:-1]}
        return bool(parts & {"reference", "references", "docs", "examples", "fixtures", "test", "tests"})

    def _scan_root(self, package_dir: Path, skill_file: Path) -> Path:
        relative_parts = skill_file.relative_to(package_dir).parts
        lowered = [part.lower() for part in relative_parts]
        for marker in ("canonical-tree-v1", "tree"):
            if marker in lowered:
                index = lowered.index(marker)
                return package_dir.joinpath(*relative_parts[: index + 1]).resolve()
        return skill_file.parent.resolve()


class CorpusScanner:
    def __init__(
        self,
        *,
        progress: bool = True,
        progress_every: int = 1,
        color: str = "auto",
        progress_stream: TextIO | None = None,
    ) -> None:
        self.progress = progress
        self.progress_every = max(progress_every, 1)
        self.color = color
        self.progress_stream = progress_stream or sys.stderr

    def run(
        self,
        corpus_root: str | Path,
        output_dir: str | Path,
        *,
        sample_size: int,
        seed: int = 1337,
        workers: int = 8,
        sources: list[str] | None = None,
        deduplicate_content: bool = True,
        retain: str = "malicious",
        resume: bool = False,
        profile: str = "static",
        rule_store_dir: str | Path | None = None,
        enable_yasa: bool = True,
        enable_cross_artifact_resolution: bool = True,
        max_artifacts: int = 600,
        max_total_text_bytes: int = 2_000_000,
    ) -> dict[str, object]:
        if workers <= 0:
            raise ValueError("workers must be positive")
        if retain not in {"malicious", "all", "none"}:
            raise ValueError(f"unsupported retain policy: {retain}")
        if profile not in {"static", "full"}:
            raise ValueError(f"unsupported scan profile: {profile}")
        root = Path(corpus_root).resolve()
        destination = Path(output_dir).resolve()
        ensure_dir(destination)
        sample_path = destination / "sample_manifest.json"
        results_path = destination / "scan_results.jsonl"
        summary_path = destination / "scan_summary.json"
        scan_config_path = destination / "scan_config.json"
        resolved_rule_store = (
            Path(rule_store_dir).resolve()
            if rule_store_dir is not None
            else destination / "learned_rules"
        )
        if profile == "full":
            for stage in LLM_STAGES:
                os.environ[f"MALSKILLS_LLM_{stage.upper()}_ENABLED"] = "true"
            cache_paths = {
                "MALSKILLS_LLM_CACHE": destination / "llm_cache" / "sso_findings",
                "MALSKILLS_LLM_OBJECT_CACHE": destination / "llm_cache" / "objects",
                "MALSKILLS_LLM_REASONING_CACHE": destination / "llm_cache" / "reasoning",
                "MALSKILLS_LLM_FEEDBACK_CACHE": destination / "llm_cache" / "rule_feedback",
            }
            for name, path in cache_paths.items():
                os.environ[name] = str(path)
            llm_runtime = describe_llm_runtime()
        else:
            llm_runtime = None
        scan_config = {
            "schema_version": SCAN_SCHEMA_VERSION,
            "profile": profile,
            "retain": retain,
            "enable_yasa": enable_yasa,
            "enable_cross_artifact_resolution": enable_cross_artifact_resolution,
            "max_artifacts": max_artifacts,
            "max_total_text_bytes": max_total_text_bytes,
            "rule_store_dir": str(resolved_rule_store) if profile == "full" else None,
            "llm_runtime": llm_runtime,
        }

        if resume:
            if not sample_path.is_file():
                raise FileNotFoundError(f"resume requested but sample manifest is missing: {sample_path}")
            sample_payload = json.loads(sample_path.read_text(encoding="utf-8"))
            self._validate_resume_manifest(
                sample_payload,
                corpus_root=root,
                sample_size=sample_size,
                seed=seed,
            )
            if not scan_config_path.is_file():
                raise FileNotFoundError(f"resume requested but scan config is missing: {scan_config_path}")
            previous_scan_config = json.loads(scan_config_path.read_text(encoding="utf-8"))
            if previous_scan_config != scan_config:
                raise ValueError("resume arguments do not match scan_config.json")
            entries = [CorpusSampleEntry(**item) for item in sample_payload["entries"]]
        else:
            if sample_path.exists() or results_path.exists():
                raise FileExistsError(
                    f"scan output already exists in {destination}; use --resume or a new output directory"
                )
            discovered, discovery_stats = CorpusSampler().discover(
                root,
                sources=sources,
                deduplicate_content=deduplicate_content,
            )
            entries = CorpusSampler().sample(discovered, sample_size=sample_size, seed=seed)
            sample_payload = {
                "schema_version": SAMPLE_SCHEMA_VERSION,
                "corpus_root": str(root),
                "sample_size": sample_size,
                "seed": seed,
                "sources": sources or [],
                "deduplicate_content": deduplicate_content,
                "eligible_entries": len(discovered),
                "discovery": discovery_stats,
                "source_counts": dict(sorted(Counter(item.source for item in entries).items())),
                "entries": [asdict(item) for item in entries],
            }
            self._write_json_atomic(sample_path, sample_payload)
            self._write_json_atomic(scan_config_path, scan_config)

        checkpoint_results = self._load_checkpoint(results_path)
        completed = {
            entry_id: result
            for entry_id, result in checkpoint_results.items()
            if result.get("status") == "ok"
        }
        completed_before_run = len(completed)
        pending = [entry for entry in entries if entry.entry_id not in completed]
        self._emit(
            f"START sample={len(entries)} pending={len(pending)} resumed={len(completed)} "
            f"workers={workers} profile={profile} retain={retain} output={destination}"
        )
        scan_started_at = time.perf_counter()
        config = AnalyzerConfig(
            enable_llm_sso_extraction=profile == "full",
            enable_llm_object_analysis=profile == "full",
            enable_semgrep=True,
            enable_yasa=enable_yasa,
            enable_cross_artifact_resolution=enable_cross_artifact_resolution,
            reasoning_mode="hybrid" if profile == "full" else "formal",
            max_artifacts=max_artifacts,
            max_total_text_bytes=max_total_text_bytes,
            rule_store_dir=resolved_rule_store if profile == "full" else None,
            collect_rule_candidates=profile == "full",
        )

        context = multiprocessing.get_context("spawn")
        pool = context.Pool(
            processes=workers,
            initializer=_initialize_worker,
            initargs=(asdict(config), str(destination), retain),
        )
        checkpoint = results_path.open("a", encoding="utf-8")
        try:
            for result in pool.imap_unordered(
                _scan_entry_worker,
                (asdict(entry) for entry in pending),
                chunksize=1,
            ):
                checkpoint.write(json.dumps(to_jsonable(result), sort_keys=True) + "\n")
                checkpoint.flush()
                completed[str(result["entry_id"])] = result
                done_count = len(completed)
                if done_count % self.progress_every == 0 or done_count == len(entries):
                    pattern_text = ",".join(str(item) for item in result["patterns"]) or "none"
                    self._emit(
                        f"[{done_count}/{len(entries)}] {str(result['status']).upper()} "
                        f"verdict={result['verdict']} time={float(result['runtime_sec']):.1f}s "
                        f"findings={result['finding_count']} ssos={result['sso_count']} "
                        f"patterns={pattern_text} id={result['entry_id']}",
                        level="ERROR" if result["status"] != "ok" else (
                            "WARNING" if result["verdict"] == "malicious" else "SUCCESS"
                        ),
                    )
                if done_count % max(self.progress_every, 25) == 0:
                    summary = self._build_summary(
                        sample_payload,
                        completed,
                        workers=workers,
                        profile=profile,
                        retain=retain,
                        completed_this_run=len(completed) - completed_before_run,
                        elapsed_sec=time.perf_counter() - scan_started_at,
                    )
                    self._write_json_atomic(summary_path, summary)
            pool.close()
            pool.join()
        except BaseException:
            pool.terminate()
            pool.join()
            raise
        finally:
            checkpoint.close()

        summary = self._build_summary(
            sample_payload,
            completed,
            workers=workers,
            profile=profile,
            retain=retain,
            completed_this_run=len(completed) - completed_before_run,
            elapsed_sec=time.perf_counter() - scan_started_at,
        )
        self._write_json_atomic(summary_path, summary)
        self._emit(
            f"COMPLETE scanned={summary['completed']} malicious={summary['verdicts'].get('malicious', 0)} "
            f"benign={summary['verdicts'].get('benign', 0)} errors={summary['statuses'].get('error', 0)} "
            f"rate={summary['throughput_skills_per_min']:.2f}/min report={summary_path}"
        )
        return summary

    def _validate_resume_manifest(
        self,
        payload: dict[str, object],
        *,
        corpus_root: Path,
        sample_size: int,
        seed: int,
    ) -> None:
        expected = {
            "schema_version": SAMPLE_SCHEMA_VERSION,
            "corpus_root": str(corpus_root),
            "sample_size": sample_size,
            "seed": seed,
        }
        mismatches = [
            key for key, value in expected.items() if payload.get(key) != value
        ]
        if mismatches:
            raise ValueError(f"resume arguments do not match sample manifest: {', '.join(mismatches)}")

    def _load_checkpoint(self, path: Path) -> dict[str, dict[str, object]]:
        if not path.exists():
            return {}
        results: dict[str, dict[str, object]] = {}
        lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                if index == len(lines):
                    break
                raise ValueError(f"invalid checkpoint JSON at {path}:{index}")
            entry_id = str(row.get("entry_id", ""))
            if entry_id:
                results[entry_id] = row
        return results

    def _build_summary(
        self,
        sample_payload: dict[str, object],
        results: dict[str, dict[str, object]],
        *,
        workers: int,
        profile: str,
        retain: str,
        completed_this_run: int,
        elapsed_sec: float,
    ) -> dict[str, object]:
        rows = list(results.values())
        statuses = Counter(str(row.get("status", "unknown")) for row in rows)
        verdicts = Counter(str(row.get("verdict", "unknown")) for row in rows)
        patterns = Counter(
            str(pattern)
            for row in rows
            for pattern in row.get("patterns", [])
        )
        semgrep_statuses = Counter(str(row.get("semgrep_status", "unknown")) for row in rows)
        by_source: dict[str, dict[str, int]] = {}
        for row in rows:
            source = str(row.get("source", "unknown"))
            source_summary = by_source.setdefault(source, {"scanned": 0, "malicious": 0, "benign": 0, "errors": 0})
            source_summary["scanned"] += 1
            verdict = str(row.get("verdict", ""))
            if verdict in {"malicious", "benign"}:
                source_summary[verdict] += 1
            if row.get("status") != "ok":
                source_summary["errors"] += 1
        runtimes = sorted(float(row.get("runtime_sec", 0.0)) for row in rows)
        return {
            "schema_version": SCAN_SCHEMA_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "sample_size": int(sample_payload["sample_size"]),
            "completed": len(rows),
            "completed_this_run": completed_this_run,
            "remaining": max(int(sample_payload["sample_size"]) - len(rows), 0),
            "workers": workers,
            "profile": profile,
            "retain": retain,
            "rule_store": "learned_rules" if profile == "full" else None,
            "elapsed_sec_this_run": round(elapsed_sec, 4),
            "throughput_skills_per_min": round(completed_this_run / (elapsed_sec / 60.0), 4) if elapsed_sec else 0.0,
            "avg_runtime_sec": round(sum(runtimes) / len(runtimes), 4) if runtimes else 0.0,
            "p50_runtime_sec": self._percentile(runtimes, 0.50),
            "p95_runtime_sec": self._percentile(runtimes, 0.95),
            "statuses": dict(sorted(statuses.items())),
            "verdicts": dict(sorted(verdicts.items())),
            "malicious_rate": round(verdicts.get("malicious", 0) / max(statuses.get("ok", 0), 1), 4),
            "pattern_counts": dict(patterns.most_common()),
            "semgrep_statuses": dict(sorted(semgrep_statuses.items())),
            "llm_only_findings": sum(int(row.get("llm_only_finding_count", 0)) for row in rows),
            "proposed_rules": sum(int(row.get("proposed_rule_count", 0)) for row in rows),
            "candidate_observations": sum(int(row.get("observed_candidate_count", 0)) for row in rows),
            "by_source": dict(sorted(by_source.items())),
            "sample_manifest": "sample_manifest.json",
            "results": "scan_results.jsonl",
            "note": "Unlabeled corpus scan; malicious_rate is a flag rate, not precision or prevalence.",
        }

    def _percentile(self, values: list[float], quantile: float) -> float:
        if not values:
            return 0.0
        index = min(round((len(values) - 1) * quantile), len(values) - 1)
        return round(values[index], 4)

    def _write_json_atomic(self, path: Path, payload: object) -> None:
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(json.dumps(to_jsonable(payload), indent=2, sort_keys=True), encoding="utf-8")
        os.replace(temporary, path)

    def _colors_enabled(self) -> bool:
        if self.color == "always":
            return True
        if self.color == "never" or os.environ.get("NO_COLOR") is not None:
            return False
        return bool(getattr(self.progress_stream, "isatty", lambda: False)())

    def _emit(self, message: str, *, level: str = "INFO") -> None:
        if not self.progress:
            return
        colors = {"INFO": "34", "SUCCESS": "32", "WARNING": "33", "ERROR": "31;1"}
        timestamp = datetime.now().strftime("%H:%M:%S")
        label = f"{level:<7}"
        if self._colors_enabled():
            label = f"\033[{colors.get(level, '0')}m{label}\033[0m"
            timestamp = f"\033[2m{timestamp}\033[0m"
        print(f"{timestamp} | {label} | {message}", file=self.progress_stream, flush=True)
