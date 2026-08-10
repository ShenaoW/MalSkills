from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import sqlite3
import stat
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from ..findings.schema import SCHEMA_VERSION as FINDING_SCHEMA_VERSION
from ..findings.schema import SSO_CATEGORY_BY_SUBTYPE, canonical_sso_category
from ..findings.semgrep import SemgrepSSOFindingExtractor, semgrep_timeout_sec
from ..models import AnalysisResult, to_jsonable
from .workflow import (
    WorkflowRuleMatcher,
    build_workflow_spec,
    canonicalize_workflow_structure,
)

REGISTRY_SCHEMA_VERSION = 1
BUNDLE_SCHEMA_VERSION = "malskills-rule-bundle-v2"
ACTIVATION_JOURNAL_SCHEMA_VERSION = 1
WORKFLOW_VALIDATION_PROFILE_VERSION = "malskills-workflow-validation-v1"
ACTIVE_STATES = {"active"}
TERMINAL_STATES = {"rejected", "retired"}
_ENGINE_VALIDATED_DIGESTS: set[str] = set()


class RuleValidationError(ValueError):
    pass


@dataclass(frozen=True)
class RuleGatePolicy:
    min_discovery_groups: int = 3
    sso_min_positive_groups: int = 5
    sso_min_negative_groups: int = 1
    sso_min_reviewed_hits: int = 20
    sso_min_precision: float = 0.98
    sso_min_recall: float = 0.80
    sso_max_false_positive_rate: float = 0.01
    workflow_min_positive_groups: int = 3
    workflow_min_benign_groups: int = 100
    workflow_min_precision: float = 0.95
    workflow_min_recall: float = 0.70


@dataclass(frozen=True)
class RuleSnapshot:
    digest: str
    root: Path | None
    semgrep_dir: Path | None
    workflows_dir: Path | None
    manifest: dict[str, Any]


class RuleRegistry:
    def __init__(self, root: str | Path, *, policy: RuleGatePolicy | None = None) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.database_path = self.root / "candidates.sqlite3"
        self.bundles_dir = self.root / "bundles"
        self.bundles_dir.mkdir(parents=True, exist_ok=True)
        self.current_path = self.root / "current"
        self.activation_journal_path = self.root / "activation.json"
        self.policy = policy or RuleGatePolicy()
        self._initialize_database()
        with self._bundle_lock():
            self._reconcile_active_state()

    def observe_analysis(
        self,
        result: AnalysisResult,
        feedback_payload: dict[str, Any],
        *,
        dedupe_group_id: str | None = None,
    ) -> dict[str, Any]:
        sample_id = self.sample_id(result)
        group_id = dedupe_group_id or sample_id
        observed: list[str] = []
        for candidate in feedback_payload.get("semgrep_rule_candidates", []):
            if not isinstance(candidate, dict):
                continue
            try:
                spec = self._normalize_sso_spec(candidate)
            except RuleValidationError:
                continue
            candidate_id = self.observe_candidate(
                "sso",
                spec,
                sample_id=sample_id,
                dedupe_group_id=group_id,
                observation={
                    "skill_path": result.skill_path,
                    "examples": candidate.get("examples", []),
                    "confidence": candidate.get("confidence", 0.0),
                    "rationale": candidate.get("rationale", ""),
                    "generator": feedback_payload.get("llm_feedback_runtime", {}),
                },
            )
            observed.append(candidate_id)

        for discovery in result.workflow_discoveries:
            spec = build_workflow_spec(discovery, result.ssos, result.graph)
            if spec is None:
                continue
            candidate_id = self.observe_candidate(
                "workflow",
                spec,
                sample_id=sample_id,
                dedupe_group_id=group_id,
                observation={
                    "skill_path": result.skill_path,
                    "discovery": to_jsonable(discovery),
                },
            )
            observed.append(candidate_id)
        return {
            "registry_path": str(self.root),
            "sample_id": sample_id,
            "dedupe_group_id": group_id,
            "observed_candidate_ids": sorted(set(observed)),
            "observed_candidate_count": len(set(observed)),
            "ruleset_digest": str(result.analysis_metadata.get("ruleset_digest", "none")),
        }

    def observe_candidate(
        self,
        kind: str,
        spec: dict[str, Any],
        *,
        sample_id: str,
        dedupe_group_id: str,
        observation: dict[str, Any],
    ) -> str:
        if kind not in {"sso", "workflow"}:
            raise RuleValidationError(f"unsupported candidate kind: {kind}")
        normalized = self._normalize_sso_spec(spec) if kind == "sso" else self._normalize_workflow_spec(spec)
        fingerprint = str(normalized["semantic_fingerprint"])
        candidate_id = f"cand_{kind}_{fingerprint[:20]}"
        now = _utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO candidates (
                    candidate_id, kind, semantic_fingerprint, spec_json, status, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, 'observed', ?, ?)
                ON CONFLICT(semantic_fingerprint) DO UPDATE SET last_seen=excluded.last_seen
                """,
                (
                    candidate_id,
                    kind,
                    fingerprint,
                    _json(normalized),
                    now,
                    now,
                ),
            )
            row = connection.execute(
                "SELECT candidate_id, kind FROM candidates WHERE semantic_fingerprint=?",
                (fingerprint,),
            ).fetchone()
            if row is None or str(row["kind"]) != kind:
                raise RuleValidationError("semantic fingerprint collision across candidate kinds")
            candidate_id = str(row["candidate_id"])
            connection.execute(
                """
                INSERT OR IGNORE INTO observations (
                    candidate_id, sample_id, dedupe_group_id, payload_json, observed_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (candidate_id, sample_id, dedupe_group_id, _json(observation), now),
            )
            support = self._support_count(connection, candidate_id)
            status_row = connection.execute(
                "SELECT status FROM candidates WHERE candidate_id=?", (candidate_id,)
            ).fetchone()
            status = str(status_row["status"]) if status_row else "observed"
            if support >= self.policy.min_discovery_groups and status not in TERMINAL_STATES | ACTIVE_STATES | {"validated"}:
                connection.execute(
                    "UPDATE candidates SET status='eligible', last_seen=? WHERE candidate_id=?",
                    (now, candidate_id),
                )
            connection.commit()
        return candidate_id

    def list_candidates(self, *, status: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM candidates"
        values: tuple[object, ...] = ()
        if status:
            query += " WHERE status=?"
            values = (status,)
        query += " ORDER BY first_seen, candidate_id"
        with self._connect() as connection:
            rows = connection.execute(query, values).fetchall()
            return [self._candidate_payload(connection, row) for row in rows]

    def get_candidate(self, candidate_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM candidates WHERE candidate_id=?", (candidate_id,)
            ).fetchone()
            if row is None:
                raise KeyError(candidate_id)
            return self._candidate_payload(connection, row)

    def _record_validation(
        self,
        candidate_id: str,
        *,
        corpus_id: str,
        corpus_digest: str,
        validation_group_ids: list[str],
        metrics: dict[str, Any],
        validation_sample_ids: list[str],
        validation_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        validation_samples = sorted(set(validation_sample_ids))
        validation_groups = sorted(set(validation_group_ids))
        with self._bundle_lock():
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM candidates WHERE candidate_id=?", (candidate_id,)
                ).fetchone()
                if row is None:
                    raise KeyError(candidate_id)
                candidate = self._candidate_payload(connection, row)
                if candidate["status"] != "eligible":
                    raise RuleValidationError("only an eligible candidate can be validated")
                if candidate["support_count"] < self.policy.min_discovery_groups:
                    raise RuleValidationError(
                        "candidate has not reached the distinct discovery-group threshold"
                    )
                if not validation_groups or not validation_samples:
                    raise RuleValidationError(
                        "held-out validation requires content-bound groups and samples"
                    )
                group_overlap = set(candidate["dedupe_group_ids"]) & set(validation_groups)
                if group_overlap:
                    raise RuleValidationError(
                        "held-out validation overlaps discovery groups: "
                        + ", ".join(sorted(group_overlap))
                    )
                discovery_samples = {
                    str(item["sample_id"]) for item in candidate["observations"]
                }
                sample_overlap = discovery_samples & set(validation_samples)
                if sample_overlap:
                    raise RuleValidationError(
                        "held-out validation overlaps discovery samples: "
                        + ", ".join(sorted(sample_overlap))
                    )
                self._validate_validation_metrics(
                    str(candidate["kind"]),
                    metrics,
                    group_count=len(validation_groups),
                    sample_count=len(validation_samples),
                )
                passed, gate = self._evaluate_gate(str(candidate["kind"]), metrics)
                payload = {
                    "candidate_id": candidate_id,
                    "candidate_revision": candidate["revision"],
                    "corpus_id": corpus_id,
                    "corpus_digest": corpus_digest,
                    "validation_group_ids": validation_groups,
                    "validation_sample_ids": validation_samples,
                    "metrics": metrics,
                    "validation_context": validation_context or {},
                    "gate": gate,
                    "passed": passed,
                }
                validation_digest = hashlib.sha256(
                    _json(payload).encode("utf-8")
                ).hexdigest()
                validation_id = f"val_{validation_digest[:20]}"
                now = _utc_now()
                connection.execute(
                    """
                    INSERT OR REPLACE INTO validations (
                        validation_id, candidate_id, candidate_revision, corpus_id, corpus_digest,
                        report_json, passed, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        validation_id,
                        candidate_id,
                        int(candidate["revision"]),
                        corpus_id,
                        corpus_digest,
                        _json(payload),
                        int(passed),
                        now,
                    ),
                )
                if passed:
                    updated = connection.execute(
                        """
                        UPDATE candidates
                        SET status='validated', validation_id=?
                        WHERE candidate_id=? AND status='eligible' AND revision=?
                        """,
                        (validation_id, candidate_id, int(candidate["revision"])),
                    )
                    if updated.rowcount != 1:
                        raise RuleValidationError(
                            "candidate changed while validation was being recorded"
                        )
                connection.commit()
        return {**payload, "validation_id": validation_id}

    def promote(self, candidate_id: str, *, approved_by: str) -> RuleSnapshot:
        if not approved_by.strip():
            raise RuleValidationError("promotion requires an explicit approver identity")
        with self._bundle_lock():
            candidate = self.get_candidate(candidate_id)
            if candidate["status"] != "validated" or not candidate.get("validation_id"):
                raise RuleValidationError("only a validated candidate can be promoted")
            current = self.snapshot()
            if candidate["kind"] == "workflow":
                validation = self._validation_report(str(candidate["validation_id"]))
                context = validation.get("validation_context", {})
                if (
                    not isinstance(context, dict)
                    or context.get("profile_version")
                    != WORKFLOW_VALIDATION_PROFILE_VERSION
                    or context.get("base_ruleset_digest") != current.digest
                ):
                    raise RuleValidationError(
                        "workflow candidate must be revalidated against the current ruleset"
                    )
            entries = [
                {
                    **entry,
                    "spec": self.get_candidate(str(entry["candidate_id"]))["spec"],
                }
                for entry in current.manifest.get("entries", [])
            ]
            entries = [entry for entry in entries if entry.get("candidate_id") != candidate_id]
            entries.append(
                {
                    "candidate_id": candidate_id,
                    "kind": candidate["kind"],
                    "revision": candidate["revision"],
                    "validation_id": candidate["validation_id"],
                    "approved_by": approved_by.strip(),
                    "approved_at": _utc_now(),
                    "spec": candidate["spec"],
                }
            )
            snapshot = self._write_bundle(
                entries,
                parent_digest=current.digest,
                transition={
                    "operation": "promote",
                    "candidate_id": candidate_id,
                    "approved_by": approved_by.strip(),
                },
            )
            target_ids = {
                str(entry["candidate_id"])
                for entry in snapshot.manifest.get("entries", [])
            }
            affected_states: dict[str, tuple[str, object]] = {}
            journal_written = False
            try:
                with self._connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    current_candidate = connection.execute(
                        "SELECT status, revision, validation_id FROM candidates WHERE candidate_id=?",
                        (candidate_id,),
                    ).fetchone()
                    if (
                        current_candidate is None
                        or str(current_candidate["status"]) != "validated"
                        or int(current_candidate["revision"]) != int(candidate["revision"])
                        or str(current_candidate["validation_id"])
                        != str(candidate["validation_id"])
                    ):
                        raise RuleValidationError(
                            "candidate changed while it was being promoted"
                        )
                    affected_rows = connection.execute(
                        "SELECT candidate_id, status, active_bundle FROM candidates WHERE status='active'"
                    ).fetchall()
                    affected_states = {
                        str(row["candidate_id"]): (
                            str(row["status"]),
                            row["active_bundle"],
                        )
                        for row in affected_rows
                    }
                    for active_id in target_ids:
                        if active_id in affected_states:
                            continue
                        row = connection.execute(
                            "SELECT status, active_bundle FROM candidates WHERE candidate_id=?",
                            (active_id,),
                        ).fetchone()
                        if row is None:
                            raise RuleValidationError(
                                f"active bundle references unknown candidate: {active_id}"
                            )
                        affected_states[active_id] = (
                            str(row["status"]),
                            row["active_bundle"],
                        )
                    self._write_activation_journal(
                        operation="promote",
                        previous_digest=current.digest,
                        target_digest=snapshot.digest,
                        previous_states=affected_states,
                    )
                    journal_written = True
                    connection.execute(
                        "UPDATE candidates SET status='retired', active_bundle=NULL WHERE status='active'"
                    )
                    for active_id in target_ids:
                        connection.execute(
                            "UPDATE candidates SET status='active', active_bundle=? WHERE candidate_id=?",
                            (snapshot.digest, active_id),
                        )
                    connection.execute(
                        "INSERT OR REPLACE INTO bundles (digest, parent_digest, manifest_json, created_at) VALUES (?, ?, ?, ?)",
                        (
                            snapshot.digest,
                            current.digest,
                            _json(snapshot.manifest),
                            _utc_now(),
                        ),
                    )
                    connection.commit()
            except Exception:
                if journal_written:
                    self._recover_activation()
                raise
            try:
                self._switch_current(snapshot.digest)
            except Exception:
                self._recover_activation()
                raise
            self._clear_activation_journal()
        return snapshot

    def reject(self, candidate_id: str, *, reason: str) -> None:
        if not reason.strip():
            raise RuleValidationError("rejection requires a reason")
        with self._bundle_lock():
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT status FROM candidates WHERE candidate_id=?", (candidate_id,)
                ).fetchone()
                if row is None:
                    raise KeyError(candidate_id)
                if str(row["status"]) == "active":
                    raise RuleValidationError(
                        "active candidates must be removed through deactivation or rollback"
                    )
                connection.execute(
                    "UPDATE candidates SET status='rejected', rejection_reason=? WHERE candidate_id=?",
                    (reason.strip(), candidate_id),
                )
                connection.commit()

    def deactivate(self, candidate_id: str, *, approved_by: str) -> RuleSnapshot:
        if not approved_by.strip():
            raise RuleValidationError("deactivation requires an explicit approver identity")
        with self._bundle_lock():
            current = self.snapshot()
            candidate = self.get_candidate(candidate_id)
            if (
                candidate["status"] != "active"
                or candidate.get("active_bundle") != current.digest
            ):
                raise RuleValidationError(
                    "only a candidate in the current bundle can be deactivated"
                )
            retained = [
                {
                    **entry,
                    "spec": self.get_candidate(str(entry["candidate_id"]))["spec"],
                }
                for entry in current.manifest.get("entries", [])
                if str(entry.get("candidate_id", "")) != candidate_id
            ]
            if candidate["kind"] == "sso":
                dependent_workflows: list[str] = []
                for entry in retained:
                    if entry.get("kind") != "workflow":
                        continue
                    validation = self._validation_report(str(entry["validation_id"]))
                    context = validation.get("validation_context", {})
                    dependencies = (
                        context.get("base_sso_candidate_ids")
                        if isinstance(context, dict)
                        else None
                    )
                    if not isinstance(dependencies, list) or candidate_id in {
                        str(item) for item in dependencies
                    }:
                        dependent_workflows.append(str(entry["candidate_id"]))
                if dependent_workflows:
                    raise RuleValidationError(
                        "deactivate dependent workflow rules first: "
                        + ", ".join(sorted(dependent_workflows))
                    )
            snapshot = self._write_bundle(
                retained,
                parent_digest=current.digest,
                transition={
                    "operation": "deactivate",
                    "candidate_id": candidate_id,
                    "approved_by": approved_by.strip(),
                },
            )
            target_ids = {
                str(entry["candidate_id"])
                for entry in snapshot.manifest.get("entries", [])
            }
            affected_states: dict[str, tuple[str, object]] = {}
            journal_written = False
            try:
                with self._connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    current_candidate = connection.execute(
                        "SELECT status, active_bundle FROM candidates WHERE candidate_id=?",
                        (candidate_id,),
                    ).fetchone()
                    if (
                        current_candidate is None
                        or str(current_candidate["status"]) != "active"
                        or str(current_candidate["active_bundle"]) != current.digest
                    ):
                        raise RuleValidationError(
                            "candidate changed while it was being deactivated"
                        )
                    affected_rows = connection.execute(
                        "SELECT candidate_id, status, active_bundle FROM candidates WHERE status='active'"
                    ).fetchall()
                    affected_states = {
                        str(row["candidate_id"]): (
                            str(row["status"]),
                            row["active_bundle"],
                        )
                        for row in affected_rows
                    }
                    self._write_activation_journal(
                        operation="deactivate",
                        previous_digest=current.digest,
                        target_digest=snapshot.digest,
                        previous_states=affected_states,
                    )
                    journal_written = True
                    connection.execute(
                        "UPDATE candidates SET status='retired', active_bundle=NULL WHERE status='active'"
                    )
                    for active_id in target_ids:
                        connection.execute(
                            "UPDATE candidates SET status='active', active_bundle=? WHERE candidate_id=?",
                            (snapshot.digest, active_id),
                        )
                    if snapshot.digest != "none":
                        connection.execute(
                            "INSERT OR REPLACE INTO bundles (digest, parent_digest, manifest_json, created_at) VALUES (?, ?, ?, ?)",
                            (
                                snapshot.digest,
                                current.digest,
                                _json(snapshot.manifest),
                                _utc_now(),
                            ),
                        )
                    connection.commit()
            except Exception:
                if journal_written:
                    self._recover_activation()
                raise
            try:
                self._switch_current(snapshot.digest)
            except Exception:
                self._recover_activation()
                raise
            self._clear_activation_journal()
        return snapshot

    def rollback(self, bundle_digest: str) -> RuleSnapshot:
        with self._bundle_lock():
            current = self.snapshot()
            snapshot = (
                RuleSnapshot(
                    digest="none",
                    root=None,
                    semgrep_dir=None,
                    workflows_dir=None,
                    manifest={"entries": []},
                )
                if bundle_digest == "none"
                else self._load_snapshot(bundle_digest)
            )
            active_ids = {str(entry.get("candidate_id", "")) for entry in snapshot.manifest.get("entries", [])}
            affected_states: dict[str, tuple[str, object]] = {}
            journal_written = False
            try:
                with self._connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    if bundle_digest != "none":
                        registered = connection.execute(
                            "SELECT 1 FROM bundles WHERE digest=?", (bundle_digest,)
                        ).fetchone()
                        if registered is None:
                            raise RuleValidationError(
                                "rollback target is not a registered bundle"
                            )
                    affected_rows = connection.execute(
                        "SELECT candidate_id, status, active_bundle FROM candidates WHERE status='active'"
                    ).fetchall()
                    affected_states = {
                        str(row["candidate_id"]): (
                            str(row["status"]),
                            row["active_bundle"],
                        )
                        for row in affected_rows
                    }
                    for active_id in active_ids:
                        if active_id in affected_states:
                            continue
                        row = connection.execute(
                            "SELECT status, active_bundle FROM candidates WHERE candidate_id=?",
                            (active_id,),
                        ).fetchone()
                        if row is None:
                            raise RuleValidationError(
                                f"rollback bundle references unknown candidate: {active_id}"
                            )
                        if str(row["status"]) == "rejected":
                            raise RuleValidationError(
                                f"rollback bundle contains rejected candidate: {active_id}"
                            )
                        affected_states[active_id] = (
                            str(row["status"]),
                            row["active_bundle"],
                        )
                    self._write_activation_journal(
                        operation="rollback",
                        previous_digest=current.digest,
                        target_digest=bundle_digest,
                        previous_states=affected_states,
                    )
                    journal_written = True
                    connection.execute(
                        "UPDATE candidates SET status='retired', active_bundle=NULL WHERE status='active'"
                    )
                    for active_id in active_ids:
                        connection.execute(
                            "UPDATE candidates SET status='active', active_bundle=? WHERE candidate_id=?",
                            (bundle_digest, active_id),
                        )
                    connection.commit()
            except Exception:
                if journal_written:
                    self._recover_activation()
                raise
            try:
                self._switch_current(bundle_digest)
            except Exception:
                self._recover_activation()
                raise
            self._clear_activation_journal()
        return snapshot

    def snapshot(self) -> RuleSnapshot:
        digest = self._read_current_digest()
        if digest == "none":
            return RuleSnapshot(digest="none", root=None, semgrep_dir=None, workflows_dir=None, manifest={"entries": []})
        return self._load_snapshot(digest)

    @staticmethod
    def sample_id(result: AnalysisResult) -> str:
        payload = sorted(
            (artifact.relative_path, artifact.content_hash)
            for artifact in result.artifacts
            if not artifact.generated
        )
        return hashlib.sha256(_json(payload).encode("utf-8")).hexdigest()

    def _normalize_sso_spec(self, candidate: dict[str, Any]) -> dict[str, Any]:
        if candidate.get("kind") == "sso" and isinstance(candidate.get("spec"), dict):
            candidate = dict(candidate["spec"])
        artifact_type = str(candidate.get("artifact_type", "")).strip()
        subtype = str(candidate.get("subtype", "")).strip()
        category = canonical_sso_category(subtype, str(candidate.get("type", "")).strip())
        rule_yaml = str(candidate.get("rule_yaml", "")).strip()
        if not artifact_type or not subtype or not category or not rule_yaml:
            raise RuleValidationError("SSO candidate is missing taxonomy, artifact type, or rule YAML")
        if subtype not in SSO_CATEGORY_BY_SUBTYPE:
            raise RuleValidationError("SSO candidate uses an unsupported subtype")
        if category != SSO_CATEGORY_BY_SUBTYPE[subtype]:
            raise RuleValidationError("SSO candidate category is inconsistent with its subtype")
        try:
            payload = yaml.safe_load(rule_yaml)
        except yaml.YAMLError as exc:
            raise RuleValidationError(f"invalid Semgrep YAML: {exc}") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("rules"), list) or len(payload["rules"]) != 1:
            raise RuleValidationError("Semgrep candidate must contain exactly one rule")
        rule = payload["rules"][0]
        if not isinstance(rule, dict):
            raise RuleValidationError("Semgrep rule must be an object")
        metadata = rule.get("metadata")
        languages = rule.get("languages")
        if not isinstance(metadata, dict) or not isinstance(languages, list) or not languages:
            raise RuleValidationError("Semgrep rule requires metadata and languages")
        if str(metadata.get("malskills_subtype", "")) != subtype:
            raise RuleValidationError("Semgrep rule subtype metadata is inconsistent")
        metadata_type = canonical_sso_category(
            subtype, str(metadata.get("malskills_sso_category", ""))
        )
        if metadata_type != category:
            raise RuleValidationError("Semgrep rule SSO-category metadata is inconsistent")
        matcher_keys = {
            "pattern",
            "patterns",
            "pattern-either",
            "pattern-regex",
            "mode",
            "pattern-sources",
            "pattern-sinks",
            "pattern-propagators",
        }
        if not matcher_keys & set(rule):
            raise RuleValidationError("Semgrep rule has no supported matcher")
        canonical_rule = {
            key: value
            for key, value in rule.items()
            if key not in {"id", "message", "severity", "metadata"}
        }
        canonical_rule["languages"] = sorted(str(item) for item in languages)
        canonical_rule = _alpha_normalize_metavariables(canonical_rule)
        canonical = {
            "taxonomy_version": FINDING_SCHEMA_VERSION,
            "artifact_type": artifact_type,
            "category": category,
            "subtype": subtype,
            "rule": canonical_rule,
        }
        fingerprint = hashlib.sha256(_json(canonical).encode("utf-8")).hexdigest()
        rule_id = f"learned.sso.{artifact_type}.{subtype}.{fingerprint[:12]}"
        rule["id"] = rule_id
        rule["message"] = str(rule.get("message") or f"Learned MalSkills SSO: {subtype}")
        rule["severity"] = str(rule.get("severity") or "WARNING")
        metadata["malskills_subtype"] = subtype
        metadata["malskills_sso_category"] = category
        metadata["malskills_origin"] = "learned"
        return {
            "schema_version": "malskills-sso-rule-v1",
            "taxonomy_version": FINDING_SCHEMA_VERSION,
            "artifact_type": artifact_type,
            "category": category,
            "subtype": subtype,
            "rule_id": rule_id,
            "rule_yaml": yaml.safe_dump(payload, sort_keys=False),
            "semantic_fingerprint": fingerprint,
        }

    def _normalize_workflow_spec(self, spec: dict[str, Any]) -> dict[str, Any]:
        roles, relations = canonicalize_workflow_structure(spec)
        canonical = {
            "taxonomy_version": FINDING_SCHEMA_VERSION,
            "pattern_name": spec["pattern_name"],
            "roles": roles,
            "relations": relations,
        }
        fingerprint = hashlib.sha256(_json(canonical).encode("utf-8")).hexdigest()
        normalized = dict(spec)
        normalized["taxonomy_version"] = FINDING_SCHEMA_VERSION
        normalized["semantic_fingerprint"] = fingerprint
        normalized["roles"] = roles
        normalized["relations"] = relations
        normalized["severity"] = "high"
        normalized["decision_effect"] = "candidate"
        normalized["source"] = "learned"
        normalized["rule_id"] = f"learned.workflow.{spec['workflow_name']}.{fingerprint[:12]}"
        return normalized

    def _evaluate_gate(self, kind: str, metrics: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
        if kind == "sso":
            required = {
                "engine_validated": bool(metrics.get("engine_validated")),
                "positive_groups": int(metrics.get("positive_groups", 0)) >= self.policy.sso_min_positive_groups,
                "negative_groups": int(metrics.get("negative_groups", 0)) >= self.policy.sso_min_negative_groups,
                "reviewed_hits": int(metrics.get("reviewed_hits", 0)) >= self.policy.sso_min_reviewed_hits,
                "precision": float(metrics.get("precision", 0.0)) >= self.policy.sso_min_precision,
                "recall": float(metrics.get("recall", 0.0)) >= self.policy.sso_min_recall,
                "false_positive_rate": float(metrics.get("false_positive_rate", 1.0)) <= self.policy.sso_max_false_positive_rate,
            }
        elif kind == "workflow":
            required = {
                "dependency_paths_valid": bool(metrics.get("dependency_paths_valid")),
                "positive_groups": int(metrics.get("positive_groups", 0)) >= self.policy.workflow_min_positive_groups,
                "benign_groups": int(metrics.get("benign_groups", 0)) >= self.policy.workflow_min_benign_groups,
                "true_positives": int(metrics.get("true_positives", 0)) >= 1,
                "precision": float(metrics.get("precision", 0.0)) >= self.policy.workflow_min_precision,
                "recall": float(metrics.get("recall", 0.0)) >= self.policy.workflow_min_recall,
                "new_high_risk_false_positives": int(metrics.get("new_high_risk_false_positives", 1)) == 0,
            }
        else:
            raise RuleValidationError(f"unsupported candidate kind: {kind}")
        return all(required.values()), {"checks": required, "policy": asdict(self.policy)}

    def _validate_validation_metrics(
        self,
        kind: str,
        metrics: dict[str, Any],
        *,
        group_count: int,
        sample_count: int,
    ) -> None:
        count_keys = (
            "true_positives",
            "false_positives",
            "false_negatives",
            "true_negatives",
        )
        try:
            counts = {key: int(metrics[key]) for key in count_keys}
        except (KeyError, TypeError, ValueError) as exc:
            raise RuleValidationError(
                "validation metrics require a complete integer confusion matrix"
            ) from exc
        if any(value < 0 for value in counts.values()):
            raise RuleValidationError("validation confusion-matrix counts cannot be negative")
        if sum(counts.values()) != sample_count:
            raise RuleValidationError(
                "validation confusion matrix does not match content-bound sample count"
            )
        try:
            if kind == "sso":
                claimed_groups = int(metrics.get("positive_groups", -1)) + int(
                    metrics.get("negative_groups", -1)
                )
            elif kind == "workflow":
                claimed_groups = int(metrics.get("positive_groups", -1)) + int(
                    metrics.get("benign_groups", -1)
                )
            else:
                raise RuleValidationError(f"unsupported candidate kind: {kind}")
        except (TypeError, ValueError) as exc:
            raise RuleValidationError("validation group metrics must be integers") from exc
        try:
            reported_false_positives = int(
                metrics.get("new_high_risk_false_positives", -1)
            )
            reviewed_hits = int(metrics.get("reviewed_hits", -1))
        except (TypeError, ValueError) as exc:
            raise RuleValidationError("validation hit metrics must be integers") from exc
        if kind == "sso":
            if reviewed_hits != counts["true_positives"] + counts["false_positives"]:
                raise RuleValidationError(
                    "reviewed_hits does not match the candidate's observed hits"
                )
        else:
            if reported_false_positives != counts["false_positives"]:
                raise RuleValidationError(
                    "workflow false-positive metrics are inconsistent"
                )
        if claimed_groups != group_count:
            raise RuleValidationError(
                "validation group metrics do not match distinct held-out groups"
            )

        true_positives = counts["true_positives"]
        false_positives = counts["false_positives"]
        false_negatives = counts["false_negatives"]
        true_negatives = counts["true_negatives"]
        precision = (
            true_positives / (true_positives + false_positives)
            if true_positives + false_positives
            else 0.0
        )
        recall = (
            true_positives / (true_positives + false_negatives)
            if true_positives + false_negatives
            else 0.0
        )
        false_positive_rate = (
            false_positives / (false_positives + true_negatives)
            if false_positives + true_negatives
            else 0.0
        )
        for key, expected in (
            ("precision", precision),
            ("recall", recall),
            ("false_positive_rate", false_positive_rate),
        ):
            try:
                actual = float(metrics[key])
            except (KeyError, TypeError, ValueError) as exc:
                raise RuleValidationError(f"validation metric is missing or invalid: {key}") from exc
            if abs(actual - expected) > 0.00001:
                raise RuleValidationError(f"validation metric is inconsistent: {key}")

    def _write_bundle(
        self,
        entries: list[dict[str, Any]],
        *,
        parent_digest: str,
        transition: dict[str, str],
    ) -> RuleSnapshot:
        normalized_entries = sorted(entries, key=lambda item: (str(item["kind"]), str(item["candidate_id"])))
        with tempfile.TemporaryDirectory(prefix="malskills-bundle-", dir=self.bundles_dir) as temp_name:
            temp_root = Path(temp_name)
            semgrep_dir = temp_root / "semgrep"
            workflows_dir = temp_root / "workflows"
            validation_dir = temp_root / "validation"
            semgrep_dir.mkdir()
            workflows_dir.mkdir()
            validation_dir.mkdir()
            manifest_entries: list[dict[str, Any]] = []
            for entry in normalized_entries:
                candidate_id = str(entry["candidate_id"])
                kind = str(entry["kind"])
                spec = dict(entry["spec"])
                if kind == "sso":
                    relative_path = f"semgrep/{candidate_id}.yml"
                    content = str(spec["rule_yaml"])
                elif kind == "workflow":
                    WorkflowRuleMatcher().validate_rule(spec)
                    relative_path = f"workflows/{candidate_id}.json"
                    content = json.dumps(spec, indent=2, sort_keys=True) + "\n"
                else:
                    raise RuleValidationError(f"unsupported bundle entry kind: {kind}")
                target = temp_root / relative_path
                target.write_text(content, encoding="utf-8")
                _fsync_file(target)
                validation_id = str(entry["validation_id"])
                validation_content = json.dumps(
                    self._validation_report(validation_id), indent=2, sort_keys=True
                ) + "\n"
                validation_path = f"validation/{validation_id}.json"
                validation_target = temp_root / validation_path
                validation_target.write_text(validation_content, encoding="utf-8")
                _fsync_file(validation_target)
                manifest_entries.append(
                    {
                        key: value
                        for key, value in entry.items()
                        if key != "spec"
                    }
                    | {
                        "path": relative_path,
                        "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                        "rule_id": spec["rule_id"],
                        "validation_path": validation_path,
                        "validation_sha256": hashlib.sha256(
                            validation_content.encode("utf-8")
                        ).hexdigest(),
                    }
                )
            created_at = _utc_now()
            unsigned_manifest = {
                "schema_version": BUNDLE_SCHEMA_VERSION,
                "parent_digest": parent_digest,
                "transition": transition,
                "entries": manifest_entries,
                "created_at": created_at,
            }
            digest = hashlib.sha256(_json(unsigned_manifest).encode("utf-8")).hexdigest()
            manifest = {**unsigned_manifest, "digest": digest}
            manifest_target = temp_root / "manifest.json"
            manifest_target.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            _fsync_file(manifest_target)
            for directory in (semgrep_dir, workflows_dir, validation_dir, temp_root):
                _fsync_directory(directory)
            destination = self.bundles_dir / digest
            if not destination.exists():
                os.rename(temp_root, destination)
                _fsync_directory(self.bundles_dir)
        return self._load_snapshot(digest)

    def _load_snapshot(self, digest: str) -> RuleSnapshot:
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RuleValidationError("invalid active ruleset digest")
        root = self.bundles_dir / digest
        manifest_path = root / "manifest.json"
        if root.is_symlink() or manifest_path.is_symlink():
            raise RuleValidationError("active rule bundle may not contain symbolic links")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuleValidationError(f"cannot load active rule bundle {digest}: {exc}") from exc
        if manifest.get("schema_version") != BUNDLE_SCHEMA_VERSION or manifest.get("digest") != digest:
            raise RuleValidationError("active rule bundle manifest is inconsistent")
        entries = manifest.get("entries")
        if not isinstance(entries, list) or not all(isinstance(entry, dict) for entry in entries):
            raise RuleValidationError("active rule bundle entries are invalid")
        unsigned = {
            "schema_version": manifest["schema_version"],
            "parent_digest": manifest.get("parent_digest", "none"),
            "entries": entries,
            "created_at": manifest.get("created_at", ""),
        }
        transition = manifest.get("transition")
        if transition is not None:
            if (
                not isinstance(transition, dict)
                or transition.get("operation") not in {"promote", "deactivate"}
                or not str(transition.get("candidate_id", "")).strip()
                or not str(transition.get("approved_by", "")).strip()
            ):
                raise RuleValidationError("active rule bundle transition is invalid")
            unsigned["transition"] = transition
        if hashlib.sha256(_json(unsigned).encode("utf-8")).hexdigest() != digest:
            raise RuleValidationError("active rule bundle digest does not match its manifest")
        expected_files = {"manifest.json"}
        for entry in entries:
            kind = str(entry.get("kind", ""))
            relative_rule_path = str(entry.get("path", ""))
            if kind == "sso" and not (
                relative_rule_path.startswith("semgrep/")
                and relative_rule_path.endswith((".yml", ".yaml"))
            ):
                raise RuleValidationError("SSO bundle entry has an invalid rule path")
            if kind == "workflow" and not (
                relative_rule_path.startswith("workflows/")
                and relative_rule_path.endswith(".json")
            ):
                raise RuleValidationError("workflow bundle entry has an invalid rule path")
            if kind not in {"sso", "workflow"}:
                raise RuleValidationError(f"unsupported active rule kind: {kind}")
            path = self._safe_bundle_path(root, relative_rule_path)
            if relative_rule_path in expected_files:
                raise RuleValidationError("active rule bundle contains duplicate paths")
            expected_files.add(relative_rule_path)
            try:
                content = path.read_bytes()
            except OSError as exc:
                raise RuleValidationError(f"active rule bundle is missing {path.name}") from exc
            if hashlib.sha256(content).hexdigest() != entry.get("sha256"):
                raise RuleValidationError(f"active rule checksum mismatch: {path.name}")
            relative_validation_path = str(entry.get("validation_path", ""))
            if not (
                relative_validation_path.startswith("validation/")
                and relative_validation_path.endswith(".json")
            ):
                raise RuleValidationError("active rule has an invalid validation path")
            validation_path = self._safe_bundle_path(root, relative_validation_path)
            if relative_validation_path in expected_files:
                raise RuleValidationError("active rule bundle contains duplicate paths")
            expected_files.add(relative_validation_path)
            try:
                validation_content = validation_path.read_bytes()
            except OSError as exc:
                raise RuleValidationError(
                    f"active rule bundle is missing validation report for {path.name}"
                ) from exc
            if hashlib.sha256(validation_content).hexdigest() != entry.get("validation_sha256"):
                raise RuleValidationError(f"active validation checksum mismatch: {path.name}")
        expected_dirs = {"semgrep", "workflows", "validation"}
        actual_dirs: set[str] = set()
        actual_files: set[str] = set()
        for path in root.rglob("*"):
            try:
                mode = path.lstat().st_mode
            except OSError as exc:
                raise RuleValidationError(
                    f"cannot inspect active rule bundle entry: {path.name}"
                ) from exc
            if stat.S_ISLNK(mode):
                raise RuleValidationError("active rule bundle may not contain symbolic links")
            relative = path.relative_to(root).as_posix()
            if stat.S_ISDIR(mode):
                actual_dirs.add(relative)
                continue
            if not stat.S_ISREG(mode):
                raise RuleValidationError(
                    f"active rule bundle contains a non-regular file: {relative}"
                )
            if stat.S_ISREG(mode):
                actual_files.add(path.relative_to(root).as_posix())
        if actual_dirs != expected_dirs:
            unexpected = sorted(actual_dirs - expected_dirs)
            missing_dirs = sorted(expected_dirs - actual_dirs)
            if unexpected:
                raise RuleValidationError(
                    f"active rule bundle contains an unexpected directory: {unexpected[0]}"
                )
            raise RuleValidationError(
                f"active rule bundle is missing a required directory: {missing_dirs[0]}"
            )
        if actual_files != expected_files:
            unlisted = sorted(actual_files - expected_files)
            missing = sorted(expected_files - actual_files)
            if unlisted:
                raise RuleValidationError(
                    f"active rule bundle contains a file outside its manifest: {unlisted[0]}"
                )
            raise RuleValidationError(
                f"active rule bundle is missing a manifest file: {missing[0]}"
            )
        if (
            digest not in _ENGINE_VALIDATED_DIGESTS
            and any(entry.get("kind") == "sso" for entry in entries)
        ):
            self._validate_active_semgrep_bundle(root / "semgrep")
            _ENGINE_VALIDATED_DIGESTS.add(digest)
        WorkflowRuleMatcher().load_rules(root / "workflows")
        return RuleSnapshot(
            digest=digest,
            root=root,
            semgrep_dir=root / "semgrep",
            workflows_dir=root / "workflows",
            manifest=manifest,
        )

    def _safe_bundle_path(self, root: Path, relative_path: str) -> Path:
        if not relative_path or Path(relative_path).is_absolute():
            raise RuleValidationError("active rule bundle contains an invalid path")
        candidate = (root / relative_path).resolve()
        try:
            candidate.relative_to(root.resolve())
        except ValueError as exc:
            raise RuleValidationError("active rule bundle path escapes its root") from exc
        return candidate

    def _validate_active_semgrep_bundle(self, rules_dir: Path) -> None:
        extractor = SemgrepSSOFindingExtractor(rules_dir=rules_dir)
        if extractor.binary is None:
            raise RuleValidationError("cannot load learned SSO rules because Semgrep is unavailable")
        try:
            with tempfile.TemporaryDirectory(prefix="malskills-active-rules-") as temp_name:
                environment = os.environ.copy()
                environment["XDG_CONFIG_HOME"] = str(Path(temp_name) / ".config")
                environment["SEMGREP_USER_HOME"] = str(Path(temp_name) / ".semgrep")
                process = subprocess.run(
                    [
                        str(extractor.binary),
                        "scan",
                        "--validate",
                        "--config",
                        str(rules_dir),
                        "--metrics=off",
                        "--disable-version-check",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                    env=environment,
                    timeout=semgrep_timeout_sec(),
                )
        except subprocess.TimeoutExpired as exc:
            raise RuleValidationError(
                "learned Semgrep bundle validation timed out"
            ) from exc
        if process.returncode != 0:
            detail = (process.stderr or process.stdout)[-2000:].strip()
            raise RuleValidationError(f"learned Semgrep bundle failed validation: {detail}")

    def _read_current_digest(self) -> str:
        if self.current_path.is_symlink():
            raise RuleValidationError("active ruleset pointer may not be a symbolic link")
        if not self.current_path.exists():
            return "none"
        try:
            digest = self.current_path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise RuleValidationError("cannot read the active ruleset pointer") from exc
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RuleValidationError("invalid active ruleset digest")
        return digest

    def _write_activation_journal(
        self,
        *,
        operation: str,
        previous_digest: str,
        target_digest: str,
        previous_states: dict[str, tuple[str, object]],
    ) -> None:
        payload = {
            "schema_version": ACTIVATION_JOURNAL_SCHEMA_VERSION,
            "operation": operation,
            "previous_digest": previous_digest,
            "target_digest": target_digest,
            "previous_states": {
                candidate_id: {
                    "status": status,
                    "active_bundle": active_bundle,
                }
                for candidate_id, (status, active_bundle) in sorted(previous_states.items())
            },
        }
        handle, temp_name = tempfile.mkstemp(
            prefix="activation-",
            dir=self.root,
            text=True,
        )
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                stream.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, self.activation_journal_path)
            _fsync_directory(self.root)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    def _clear_activation_journal(self) -> None:
        try:
            self.activation_journal_path.unlink()
        except FileNotFoundError:
            return
        _fsync_directory(self.root)

    def _recover_activation(self) -> None:
        if self.activation_journal_path.is_symlink():
            raise RuleValidationError("activation journal may not be a symbolic link")
        if not self.activation_journal_path.exists():
            return
        try:
            payload = json.loads(
                self.activation_journal_path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise RuleValidationError("cannot recover interrupted rule activation") from exc
        if (
            not isinstance(payload, dict)
            or payload.get("schema_version") != ACTIVATION_JOURNAL_SCHEMA_VERSION
            or payload.get("operation") not in {"promote", "rollback", "deactivate"}
            or not isinstance(payload.get("previous_states"), dict)
        ):
            raise RuleValidationError("activation journal is invalid")
        previous_digest = str(payload.get("previous_digest", ""))
        target_digest = str(payload.get("target_digest", ""))
        if previous_digest != "none" and not re.fullmatch(r"[0-9a-f]{64}", previous_digest):
            raise RuleValidationError("activation journal has an invalid previous digest")
        if target_digest != "none" and not re.fullmatch(r"[0-9a-f]{64}", target_digest):
            raise RuleValidationError("activation journal has an invalid target digest")
        previous_states: dict[str, tuple[str, object]] = {}
        for candidate_id, raw_state in payload["previous_states"].items():
            if not isinstance(raw_state, dict) or not isinstance(raw_state.get("status"), str):
                raise RuleValidationError("activation journal has invalid candidate state")
            previous_states[str(candidate_id)] = (
                str(raw_state["status"]),
                raw_state.get("active_bundle"),
            )

        current_digest = self._read_current_digest()
        if current_digest == target_digest:
            if target_digest == "none":
                snapshot = RuleSnapshot(
                    digest="none",
                    root=None,
                    semgrep_dir=None,
                    workflows_dir=None,
                    manifest={"entries": []},
                )
            else:
                snapshot = self._load_snapshot(target_digest)
            active_ids = {
                str(entry["candidate_id"])
                for entry in snapshot.manifest.get("entries", [])
            }
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "UPDATE candidates SET status='retired', active_bundle=NULL WHERE status='active'"
                )
                for candidate_id in active_ids:
                    updated = connection.execute(
                        "UPDATE candidates SET status='active', active_bundle=? WHERE candidate_id=?",
                        (target_digest, candidate_id),
                    )
                    if updated.rowcount != 1:
                        raise RuleValidationError(
                            f"activation journal references unknown candidate: {candidate_id}"
                        )
                if target_digest != "none":
                    connection.execute(
                        "INSERT OR REPLACE INTO bundles (digest, parent_digest, manifest_json, created_at) VALUES (?, ?, ?, ?)",
                        (
                            target_digest,
                            str(snapshot.manifest.get("parent_digest", "none")),
                            _json(snapshot.manifest),
                            str(snapshot.manifest.get("created_at", _utc_now())),
                        ),
                    )
                connection.commit()
        elif current_digest == previous_digest:
            self._restore_candidate_states(previous_states)
            if payload["operation"] in {"promote", "deactivate"} and target_digest != "none":
                with self._connect() as connection:
                    connection.execute("DELETE FROM bundles WHERE digest=?", (target_digest,))
        else:
            raise RuleValidationError(
                "activation journal does not match the active ruleset pointer"
            )
        self._clear_activation_journal()

    def _reconcile_active_state(self) -> None:
        digest = self._read_current_digest()
        snapshot = self._load_snapshot(digest) if digest != "none" else None
        entries = snapshot.manifest.get("entries", []) if snapshot is not None else []
        active_ids = {str(entry["candidate_id"]) for entry in entries}
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if snapshot is not None:
                bundle = connection.execute(
                    "SELECT manifest_json FROM bundles WHERE digest=?",
                    (digest,),
                ).fetchone()
                if bundle is None or json.loads(str(bundle["manifest_json"])) != snapshot.manifest:
                    raise RuleValidationError(
                        "active ruleset is not registered consistently in the rule registry"
                    )
                for entry in entries:
                    candidate_id = str(entry["candidate_id"])
                    candidate = connection.execute(
                        "SELECT kind, revision, status, validation_id FROM candidates WHERE candidate_id=?",
                        (candidate_id,),
                    ).fetchone()
                    if candidate is None:
                        raise RuleValidationError(
                            f"active bundle references unknown candidate: {candidate_id}"
                        )
                    if str(candidate["status"]) == "rejected":
                        raise RuleValidationError(
                            f"active bundle contains rejected candidate: {candidate_id}"
                        )
                    if (
                        str(candidate["kind"]) != str(entry.get("kind", ""))
                        or int(candidate["revision"]) != int(entry.get("revision", -1))
                        or str(candidate["validation_id"])
                        != str(entry.get("validation_id", ""))
                        or not str(entry.get("approved_by", "")).strip()
                    ):
                        raise RuleValidationError(
                            f"active bundle candidate metadata is inconsistent: {candidate_id}"
                        )
                    validation = connection.execute(
                        "SELECT candidate_id, candidate_revision, passed FROM validations WHERE validation_id=?",
                        (str(entry["validation_id"]),),
                    ).fetchone()
                    if (
                        validation is None
                        or not bool(validation["passed"])
                        or str(validation["candidate_id"]) != candidate_id
                        or int(validation["candidate_revision"])
                        != int(entry.get("revision", -1))
                    ):
                        raise RuleValidationError(
                            f"active bundle lacks a matching passed validation: {candidate_id}"
                        )
            current_rows = connection.execute(
                "SELECT candidate_id, active_bundle FROM candidates WHERE status='active'"
            ).fetchall()
            current_ids = {str(row["candidate_id"]) for row in current_rows}
            bundles_match = all(
                str(row["active_bundle"]) == digest for row in current_rows
            )
            if current_ids != active_ids or not bundles_match:
                connection.execute(
                    "UPDATE candidates SET status='retired', active_bundle=NULL WHERE status='active'"
                )
                for candidate_id in active_ids:
                    connection.execute(
                        "UPDATE candidates SET status='active', active_bundle=? WHERE candidate_id=?",
                        (digest, candidate_id),
                    )
            connection.commit()

    def _switch_current(self, digest: str) -> None:
        if digest == "none":
            try:
                self.current_path.unlink()
            except FileNotFoundError:
                return
            _fsync_directory(self.root)
            return
        handle, temp_name = tempfile.mkstemp(prefix="current-", dir=self.root, text=True)
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                stream.write(digest + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, self.current_path)
            _fsync_directory(self.root)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    def _restore_candidate_states(
        self,
        states: dict[str, tuple[str, object]],
    ) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for candidate_id, (status, active_bundle) in states.items():
                connection.execute(
                    "UPDATE candidates SET status=?, active_bundle=? WHERE candidate_id=?",
                    (status, active_bundle, candidate_id),
                )
            connection.commit()

    @contextmanager
    def _bundle_lock(self):
        lock_path = self.root / ".promotion.lock"
        with lock_path.open("a+", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                self._recover_activation()
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _candidate_payload(self, connection: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
        candidate_id = str(row["candidate_id"])
        observations = connection.execute(
            "SELECT sample_id, dedupe_group_id, payload_json, observed_at FROM observations WHERE candidate_id=? ORDER BY observed_at",
            (candidate_id,),
        ).fetchall()
        return {
            "candidate_id": candidate_id,
            "kind": str(row["kind"]),
            "semantic_fingerprint": str(row["semantic_fingerprint"]),
            "revision": int(row["revision"]),
            "status": str(row["status"]),
            "spec": json.loads(str(row["spec_json"])),
            "first_seen": str(row["first_seen"]),
            "last_seen": str(row["last_seen"]),
            "support_count": len({str(item["dedupe_group_id"]) for item in observations}),
            "dedupe_group_ids": sorted({str(item["dedupe_group_id"]) for item in observations}),
            "observations": [
                {
                    "sample_id": str(item["sample_id"]),
                    "dedupe_group_id": str(item["dedupe_group_id"]),
                    "payload": json.loads(str(item["payload_json"])),
                    "observed_at": str(item["observed_at"]),
                }
                for item in observations
            ],
            "validation_id": row["validation_id"],
            "active_bundle": row["active_bundle"],
            "rejection_reason": row["rejection_reason"],
        }

    def _support_count(self, connection: sqlite3.Connection, candidate_id: str) -> int:
        row = connection.execute(
            "SELECT COUNT(DISTINCT dedupe_group_id) AS count FROM observations WHERE candidate_id=?",
            (candidate_id,),
        ).fetchone()
        return int(row["count"] if row else 0)

    def _validation_report(self, validation_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT report_json FROM validations WHERE validation_id=? AND passed=1",
                (validation_id,),
            ).fetchone()
        if row is None:
            raise RuleValidationError(f"missing passed validation report: {validation_id}")
        return json.loads(str(row["report_json"]))

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=30.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def _initialize_database(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS registry_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS candidates (
                    candidate_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL CHECK(kind IN ('sso', 'workflow')),
                    semantic_fingerprint TEXT NOT NULL UNIQUE,
                    revision INTEGER NOT NULL DEFAULT 1,
                    spec_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    validation_id TEXT,
                    active_bundle TEXT,
                    rejection_reason TEXT
                );
                CREATE TABLE IF NOT EXISTS observations (
                    observation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    candidate_id TEXT NOT NULL REFERENCES candidates(candidate_id),
                    sample_id TEXT NOT NULL,
                    dedupe_group_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    UNIQUE(candidate_id, sample_id)
                );
                CREATE INDEX IF NOT EXISTS observations_candidate_group
                    ON observations(candidate_id, dedupe_group_id);
                CREATE TABLE IF NOT EXISTS validations (
                    validation_id TEXT PRIMARY KEY,
                    candidate_id TEXT NOT NULL REFERENCES candidates(candidate_id),
                    candidate_revision INTEGER NOT NULL,
                    corpus_id TEXT NOT NULL,
                    corpus_digest TEXT NOT NULL,
                    report_json TEXT NOT NULL,
                    passed INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS bundles (
                    digest TEXT PRIMARY KEY,
                    parent_digest TEXT NOT NULL,
                    manifest_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            existing = connection.execute(
                "SELECT value FROM registry_meta WHERE key='schema_version'"
            ).fetchone()
            if existing is not None and int(existing["value"]) != REGISTRY_SCHEMA_VERSION:
                raise RuleValidationError("unsupported rule registry schema")
            connection.execute(
                "INSERT OR REPLACE INTO registry_meta (key, value) VALUES ('schema_version', ?)",
                (str(REGISTRY_SCHEMA_VERSION),),
            )


def _alpha_normalize_metavariables(value: Any) -> Any:
    mapping: dict[str, str] = {}

    def visit(item: Any) -> Any:
        if isinstance(item, dict):
            return {key: visit(item[key]) for key in sorted(item)}
        if isinstance(item, list):
            return [visit(child) for child in item]
        if isinstance(item, str):
            def replace(match: re.Match[str]) -> str:
                token = match.group(0)
                if token not in mapping:
                    mapping[token] = f"$VAR{len(mapping)}"
                return mapping[token]

            return re.sub(r"\$[A-Z_][A-Z0-9_]*", replace, item)
        return item

    return visit(value)


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _fsync_file(path: Path) -> None:
    handle = os.open(path, os.O_RDONLY)
    try:
        os.fsync(handle)
    finally:
        os.close(handle)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    handle = os.open(path, flags)
    try:
        os.fsync(handle)
    finally:
        os.close(handle)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
