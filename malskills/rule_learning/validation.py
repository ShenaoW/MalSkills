from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from ..findings import SSOFindingExtractor
from ..findings.semgrep import SemgrepSSOFindingExtractor, semgrep_timeout_sec
from ..ingest import SkillIngestor
from ..sdg import SDGCompiler
from .registry import (
    WORKFLOW_VALIDATION_PROFILE_VERSION,
    RuleRegistry,
    RuleSnapshot,
    RuleValidationError,
)
from .workflow import WorkflowRuleMatcher


class HeldOutRuleValidator:
    def __init__(self, registry: RuleRegistry) -> None:
        self.registry = registry
        self.ingestor = SkillIngestor()

    def validate(
        self,
        candidate_id: str,
        manifest_path: str | Path,
        *,
        corpus_root: str | Path | None = None,
    ) -> dict[str, Any]:
        path = Path(manifest_path).resolve()
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuleValidationError(f"invalid held-out manifest: {exc}") from exc
        if not isinstance(manifest, dict) or not isinstance(manifest.get("cases"), list):
            raise RuleValidationError("held-out manifest must contain a cases list")
        candidate = self.registry.get_candidate(candidate_id)
        allowed_root = Path(corpus_root).resolve() if corpus_root is not None else path.parent
        cases = self._resolve_cases(manifest["cases"], allowed_root)
        if not cases:
            raise RuleValidationError("held-out manifest contains no cases")
        validation_context: dict[str, Any] = {}
        if candidate["kind"] == "sso":
            metrics, group_ids = self._validate_sso(candidate, cases)
        elif candidate["kind"] == "workflow":
            snapshot = self.registry.snapshot()
            validation_context = {
                "profile_version": WORKFLOW_VALIDATION_PROFILE_VERSION,
                "base_ruleset_digest": snapshot.digest,
                "base_sso_candidate_ids": sorted(
                    str(entry["candidate_id"])
                    for entry in snapshot.manifest.get("entries", [])
                    if entry.get("kind") == "sso"
                ),
                "enable_llm_sso_extraction": False,
                "enable_llm_object_analysis": False,
                "enable_cross_artifact_resolution": True,
                "semgrep": self._semgrep_engine_identity(),
                "case_enable_yasa": [
                    {
                        "sample_id": str(case["sample_id"]),
                        "enabled": bool(case.get("enable_yasa", True)),
                    }
                    for case in cases
                ],
            }
            metrics, group_ids = self._validate_workflow(
                candidate,
                cases,
                snapshot,
            )
        else:
            raise RuleValidationError(f"unsupported candidate kind: {candidate['kind']}")
        corpus_payload = {
            "candidate_kind": candidate["kind"],
            "cases": [
                {
                    "path": case["corpus_path"],
                    "expected": case["expected"],
                    "dedupe_group_id": case["dedupe_group_id"],
                    "sample_id": case["sample_id"],
                    "enable_yasa": bool(case.get("enable_yasa", True)),
                }
                for case in cases
            ],
            "annotations_version": manifest.get("annotations_version", "unspecified"),
            "validation_context": validation_context,
        }
        corpus_digest = hashlib.sha256(_json(corpus_payload).encode("utf-8")).hexdigest()
        return self.registry._record_validation(
            candidate_id,
            corpus_id=str(manifest.get("corpus_id", path.stem)),
            corpus_digest=corpus_digest,
            validation_group_ids=group_ids,
            validation_sample_ids=[str(case["sample_id"]) for case in cases],
            metrics=metrics,
            validation_context=validation_context,
        )

    def _validate_sso(
        self,
        candidate: dict[str, Any],
        cases: list[dict[str, Any]],
    ) -> tuple[dict[str, Any], list[str]]:
        spec = candidate["spec"]
        with tempfile.TemporaryDirectory(prefix="malskills-sso-validation-") as temp_name:
            rules_dir = Path(temp_name)
            rule_path = rules_dir / "candidate.yml"
            rule_path.write_text(str(spec["rule_yaml"]), encoding="utf-8")
            extractor = SemgrepSSOFindingExtractor(rules_dir=rules_dir)
            engine_validated = self._validate_semgrep_engine(extractor, rule_path)
            outcomes: list[tuple[bool, bool, str]] = []
            for case in cases:
                artifacts = list(case["artifacts"])
                group_id = str(case["dedupe_group_id"])
                predicted = False
                if engine_validated:
                    findings = extractor.extract(case["path"], artifacts)
                    predicted = any(
                        item.subtype == spec["subtype"]
                        and str(item.attributes.get("rule_id", "")).endswith(str(spec["rule_id"]))
                        for item in findings
                    )
                outcomes.append((bool(case["expected"]), predicted, group_id))
        metrics = _classification_metrics(outcomes)
        metrics.update(
            {
                "engine_validated": engine_validated,
                "positive_groups": len({group for expected, _, group in outcomes if expected}),
                "negative_groups": len({group for expected, _, group in outcomes if not expected}),
                "reviewed_hits": sum(1 for _, predicted, _ in outcomes if predicted),
            }
        )
        return metrics, sorted({group for _, _, group in outcomes})

    def _validate_workflow(
        self,
        candidate: dict[str, Any],
        cases: list[dict[str, Any]],
        snapshot: RuleSnapshot,
    ) -> tuple[dict[str, Any], list[str]]:
        spec = candidate["spec"]
        matcher = WorkflowRuleMatcher()
        matcher.validate_rule(spec)
        extractor = SSOFindingExtractor()
        outcomes: list[tuple[bool, bool, str]] = []
        for case in cases:
            artifacts = list(case["artifacts"])
            group_id = str(case["dedupe_group_id"])
            extraction = extractor.extract(
                case["path"],
                artifacts,
                enable_semgrep=True,
                enable_llm_sso_extraction=False,
                additional_semgrep_rules_dirs=(
                    [snapshot.semgrep_dir] if snapshot.semgrep_dir is not None else []
                ),
                ruleset_digest=snapshot.digest,
            )
            compilation = SDGCompiler().synthesize(
                artifacts,
                extraction.findings,
                skill_root=case["path"],
                enable_llm_object_analysis=False,
                enable_yasa=bool(case.get("enable_yasa", True)),
                enable_cross_artifact_resolution=True,
            )
            predicted = bool(
                matcher.match(compilation.ssos, compilation.graph, [spec])
            )
            outcomes.append((bool(case["expected"]), predicted, group_id))
        metrics = _classification_metrics(outcomes)
        metrics.update(
            {
                "dependency_paths_valid": metrics["true_positives"] > 0,
                "positive_groups": len({group for expected, _, group in outcomes if expected}),
                "benign_groups": len({group for expected, _, group in outcomes if not expected}),
                "new_high_risk_false_positives": metrics["false_positives"],
            }
        )
        return metrics, sorted({group for _, _, group in outcomes})

    def _resolve_cases(self, raw_cases: list[object], corpus_root: Path) -> list[dict[str, Any]]:
        if not corpus_root.is_dir():
            raise RuleValidationError(f"held-out corpus root is not a directory: {corpus_root}")
        cases: list[dict[str, Any]] = []
        seen_samples: set[str] = set()
        for raw in raw_cases:
            if (
                not isinstance(raw, dict)
                or "path" not in raw
                or not isinstance(raw.get("expected"), bool)
            ):
                raise RuleValidationError("each held-out case requires path and expected")
            case_path = Path(str(raw["path"]))
            if not case_path.is_absolute():
                case_path = corpus_root / case_path
            case_path = case_path.resolve()
            try:
                corpus_path = case_path.relative_to(corpus_root).as_posix()
            except ValueError as exc:
                raise RuleValidationError(
                    f"held-out case escapes the allowed corpus root: {case_path}"
                ) from exc
            if not case_path.is_dir():
                raise RuleValidationError(f"held-out case is not a directory: {case_path}")
            artifacts = self.ingestor.ingest(
                case_path,
                exclude_roots=[self.registry.root],
            )
            if not artifacts:
                raise RuleValidationError(
                    f"held-out case contains no analyzable artifacts: {case_path}"
                )
            sample_id = _artifact_digest(artifacts)
            if sample_id in seen_samples:
                raise RuleValidationError(
                    "held-out manifest contains duplicate sample content"
                )
            seen_samples.add(sample_id)
            declared_group = str(raw.get("dedupe_group_id", "")).strip()
            cases.append(
                {
                    **raw,
                    "path": str(case_path),
                    "corpus_path": corpus_path,
                    "expected": bool(raw["expected"]),
                    "sample_id": sample_id,
                    "dedupe_group_id": declared_group or sample_id,
                    "artifacts": artifacts,
                }
            )
        return cases

    def _validate_semgrep_engine(self, extractor: SemgrepSSOFindingExtractor, rule_path: Path) -> bool:
        if extractor.binary is None:
            return False
        environment = os.environ.copy()
        with tempfile.TemporaryDirectory(prefix="malskills-semgrep-validate-") as home:
            environment["XDG_CONFIG_HOME"] = str(Path(home) / ".config")
            environment["SEMGREP_USER_HOME"] = str(Path(home) / ".semgrep")
            try:
                process = subprocess.run(
                    [
                        str(extractor.binary),
                        "scan",
                        "--validate",
                        "--config",
                        str(rule_path),
                        "--metrics=off",
                        "--disable-version-check",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                    env=environment,
                    timeout=semgrep_timeout_sec(),
                )
            except subprocess.TimeoutExpired:
                return False
        return process.returncode == 0

    def _semgrep_engine_identity(self) -> dict[str, str]:
        extractor = SemgrepSSOFindingExtractor()
        if extractor.binary is None:
            return {"binary": "", "version": "unavailable"}
        try:
            process = subprocess.run(
                [str(extractor.binary), "--version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=min(10.0, semgrep_timeout_sec()),
            )
        except subprocess.TimeoutExpired:
            return {"binary": str(extractor.binary), "version": "timeout"}
        version = (process.stdout or process.stderr).strip().splitlines()
        return {
            "binary": str(extractor.binary),
            "version": version[0][:200] if version else f"exit-{process.returncode}",
        }


def _classification_metrics(outcomes: list[tuple[bool, bool, str]]) -> dict[str, Any]:
    true_positives = sum(1 for expected, predicted, _ in outcomes if expected and predicted)
    false_positives = sum(1 for expected, predicted, _ in outcomes if not expected and predicted)
    false_negatives = sum(1 for expected, predicted, _ in outcomes if expected and not predicted)
    true_negatives = sum(1 for expected, predicted, _ in outcomes if not expected and not predicted)
    precision = true_positives / (true_positives + false_positives) if true_positives + false_positives else 0.0
    recall = true_positives / (true_positives + false_negatives) if true_positives + false_negatives else 0.0
    false_positive_rate = false_positives / (false_positives + true_negatives) if false_positives + true_negatives else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "true_negatives": true_negatives,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "false_positive_rate": round(false_positive_rate, 6),
        "f1": round(f1, 6),
    }


def _artifact_digest(artifacts: list[Any]) -> str:
    payload = sorted(
        (str(item.relative_path), str(item.content_hash))
        for item in artifacts
        if not bool(item.generated)
    )
    return hashlib.sha256(_json(payload).encode("utf-8")).hexdigest()


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
