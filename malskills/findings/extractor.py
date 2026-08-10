from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
from pathlib import Path

from ..ingest import LARGE_REPO_ARTIFACT_THRESHOLD
from ..models import ArtifactRecord, OperandBinding, SSOFinding
from .llm import LlmSSOFindingExtractor
from .semgrep import SemgrepSSOFindingExtractor
from .shell_semantics import extract_embedded_shell_findings


@dataclass
class SSOFindingExtractionResult:
    findings: list[SSOFinding]
    semgrep_findings: list[SSOFinding]
    static_findings: list[SSOFinding]
    llm_findings: list[SSOFinding]
    llm_operand_bindings: list[OperandBinding]
    semantic_analysis_performed: bool
    metadata: dict[str, object]


class SSOFindingExtractor:
    def __init__(self) -> None:
        self.semgrep = SemgrepSSOFindingExtractor()
        self.llm = LlmSSOFindingExtractor()

    def extract(
        self,
        skill_root: str | Path,
        artifacts: list[ArtifactRecord],
        *,
        enable_semgrep: bool = True,
        enable_llm_sso_extraction: bool = True,
        enable_llm_object_analysis: bool = True,
        additional_semgrep_rules_dirs: list[str | Path] | None = None,
        ruleset_digest: str = "none",
    ) -> SSOFindingExtractionResult:
        findings: list[SSOFinding] = []
        large_repo = len(artifacts) > LARGE_REPO_ARTIFACT_THRESHOLD
        semgrep_findings: list[SSOFinding] = []
        should_run_semgrep = enable_semgrep or (
            enable_llm_sso_extraction and large_repo and self.semgrep.available()
        )
        if should_run_semgrep:
            if additional_semgrep_rules_dirs or ruleset_digest != "none":
                semgrep_findings = self.semgrep.extract(
                    skill_root,
                    artifacts,
                    additional_rules_dirs=additional_semgrep_rules_dirs,
                    ruleset_digest=ruleset_digest,
                )
            else:
                semgrep_findings = self.semgrep.extract(skill_root, artifacts)
            if enable_semgrep:
                findings.extend(semgrep_findings)
        else:
            self.semgrep.last_run = {
                "status": "disabled",
                "ruleset_digest": ruleset_digest,
            }
        llm_findings: list[SSOFinding] = []
        llm_operand_bindings: list[OperandBinding] = []
        semantic_analysis_performed = False
        llm_artifact_count = 0
        if enable_llm_sso_extraction:
            llm_artifacts = self._select_llm_artifacts(artifacts, semgrep_findings)
            llm_artifact_count = len(llm_artifacts)
            semantic = self.llm.extract(
                llm_artifacts,
                existing_findings=semgrep_findings,
                include_operand_bindings=enable_llm_object_analysis,
            )
            semantic_analysis_performed = bool(llm_artifacts)
            llm_findings = semantic.findings
            llm_operand_bindings = semantic.operand_bindings
            findings.extend(llm_findings)
        static_findings = extract_embedded_shell_findings(artifacts)
        findings.extend(static_findings)
        findings = self._dedupe_findings(findings)
        findings.sort(key=lambda item: (item.artifact_path, item.span.start_line if item.span else 0, item.finding_id))
        return SSOFindingExtractionResult(
            findings=findings,
            semgrep_findings=semgrep_findings,
            static_findings=static_findings,
            llm_findings=llm_findings,
            llm_operand_bindings=llm_operand_bindings,
            semantic_analysis_performed=semantic_analysis_performed,
            metadata={
                "semgrep": dict(self.semgrep.last_run),
                "static_shell_semantics": {"finding_count": len(static_findings)},
                "llm_semantic": {
                    "performed": semantic_analysis_performed,
                    "artifact_count": llm_artifact_count,
                    "finding_count": len(llm_findings),
                    "operand_binding_count": len(llm_operand_bindings),
                    "backend": self.llm.runtime.backend,
                    "model": self.llm.runtime.model,
                },
                "ruleset_digest": ruleset_digest,
            },
        )

    def _select_llm_artifacts(
        self,
        artifacts: list[ArtifactRecord],
        semgrep_findings: list[SSOFinding],
    ) -> list[ArtifactRecord]:
        eligible = [artifact for artifact in artifacts if artifact.is_text and artifact.content and not artifact.generated]
        if not eligible:
            return []
        doc_names = {"skill.md", "agents.md", "claude.md", "readme.md"}
        artifact_by_path = {artifact.relative_path: artifact for artifact in eligible}
        artifact_lookup = {artifact.relative_path.lower(): artifact.relative_path for artifact in eligible}
        all_artifacts = {artifact.relative_path: artifact for artifact in artifacts}
        selected_paths: set[str] = set()

        def add_if_present(path: str) -> None:
            normalized = path.lstrip("./")
            actual_path = artifact_lookup.get(normalized.lower())
            if actual_path is not None:
                selected_paths.add(actual_path)

        hit_paths: set[str] = set()
        for item in semgrep_findings:
            artifact = all_artifacts.get(item.artifact_path)
            if artifact is None:
                continue
            if artifact.generated and artifact.source_artifact_path:
                add_if_present(artifact.source_artifact_path)
                hit_paths.add(artifact.source_artifact_path)
                continue
            add_if_present(artifact.relative_path)
            hit_paths.add(artifact.relative_path)

        if hit_paths:
            for hit_path in hit_paths:
                parent = Path(hit_path).parent
                for doc_name in doc_names:
                    candidate = Path(doc_name) if str(parent) == "." else parent / doc_name
                    add_if_present(candidate.as_posix())
            for doc_name in doc_names:
                add_if_present(doc_name)
        else:
            for artifact in eligible:
                if Path(artifact.relative_path).name.lower() in doc_names:
                    selected_paths.add(artifact.relative_path)
            code_types = {
                "python",
                "javascript",
                "shell",
                "java",
                "go",
                "c",
                "cpp",
                "csharp",
                "php",
                "ruby",
            }
            exploratory = [artifact for artifact in eligible if artifact.artifact_type in code_types]
            priority_roots = {"scripts", "src", "lib", "bin", "hooks"}
            exploratory.sort(
                key=lambda artifact: (
                    0
                    if Path(artifact.relative_path).parts
                    and Path(artifact.relative_path).parts[0].lower() in priority_roots
                    else 1,
                    artifact.relative_path,
                )
            )
            selected_paths.update(artifact.relative_path for artifact in exploratory[:12])

        selected = [artifact_by_path[path] for path in sorted(selected_paths)]
        return self._focus_llm_artifacts(selected, semgrep_findings)

    def _focus_llm_artifacts(
        self,
        artifacts: list[ArtifactRecord],
        findings: list[SSOFinding],
        *,
        context_lines: int = 40,
    ) -> list[ArtifactRecord]:
        findings_by_path: dict[str, list[SSOFinding]] = {}
        for finding in findings:
            findings_by_path.setdefault(finding.artifact_path, []).append(finding)
        focused: list[ArtifactRecord] = []
        for artifact in artifacts:
            relevant = [item for item in findings_by_path.get(artifact.relative_path, []) if item.span]
            if not relevant or artifact.artifact_type in {"markdown", "prompt"}:
                focused.append(artifact)
                continue
            lines = (artifact.content or "").splitlines()
            if not lines:
                continue
            start = max(1, min(item.span.start_line for item in relevant if item.span) - context_lines)
            end = min(
                len(lines),
                max(item.span.end_line for item in relevant if item.span) + context_lines,
            )
            if start == 1 and end == len(lines):
                focused.append(artifact)
                continue
            snippet = "\n".join(lines[start - 1 : end])
            focused.append(
                replace(
                    artifact,
                    content=snippet,
                    content_hash=hashlib.sha256(snippet.encode("utf-8")).hexdigest(),
                    size_bytes=len(snippet.encode("utf-8")),
                    line_count=max(1, end - start + 1),
                    source_start_line=start,
                    source_end_line=end,
                )
            )
        return focused

    def _dedupe_findings(self, findings: list[SSOFinding]) -> list[SSOFinding]:
        grouped: dict[tuple[object, ...], list[SSOFinding]] = {}
        for item in findings:
            matched_text = item.matched_text.strip()
            key = (
                item.artifact_id,
                item.artifact_path,
                item.category,
                item.subtype,
                matched_text,
                item.span.start_line if item.span else None,
                item.span.end_line if item.span else None,
            )
            grouped.setdefault(key, []).append(item)

        deduped: list[SSOFinding] = []
        for group in grouped.values():
            primary = max(
                group,
                key=lambda item: item.confidence if item.confidence is not None else -1.0,
            )
            merged_attributes = dict(primary.attributes)
            engines = sorted({str(item.attributes.get("engine", "")) for item in group if str(item.attributes.get("engine", "")).strip()})
            producers = sorted({item.producer for item in group if item.producer})
            rule_ids = sorted({str(item.attributes.get("rule_id", "")) for item in group if str(item.attributes.get("rule_id", "")).strip()})
            backends = sorted({str(item.attributes.get("backend", "")) for item in group if str(item.attributes.get("backend", "")).strip()})
            models = sorted({str(item.attributes.get("model", "")) for item in group if str(item.attributes.get("model", "")).strip()})
            rule_origins = sorted(
                {
                    str(item.attributes.get("rule_origin", ""))
                    for item in group
                    if str(item.attributes.get("rule_origin", "")).strip()
                }
            )
            learned_rule_ids = sorted(
                {
                    str(item.attributes.get("rule_id", ""))
                    for item in group
                    if str(item.attributes.get("rule_origin", "")) == "learned"
                    and str(item.attributes.get("rule_id", "")).strip()
                }
            )
            if engines:
                merged_attributes["engines"] = engines
            if producers:
                merged_attributes["producers"] = producers
            if rule_ids:
                merged_attributes["rule_ids"] = rule_ids
            if backends:
                merged_attributes["backends"] = backends
            if models:
                merged_attributes["models"] = models
            if rule_origins:
                merged_attributes["rule_origins"] = rule_origins
            if learned_rule_ids:
                merged_attributes["learned_rule_ids"] = learned_rule_ids
            deduped.append(
                SSOFinding(
                    finding_id=primary.finding_id,
                    producer=primary.producer,
                    artifact_id=primary.artifact_id,
                    artifact_path=primary.artifact_path,
                    category=primary.category,
                    subtype=primary.subtype,
                    matched_text=primary.matched_text,
                    confidence=max(
                        (item.confidence for item in group if item.confidence is not None),
                        default=None,
                    ),
                    span=primary.span,
                    attributes=merged_attributes,
                    provenance=dict(primary.provenance),
                )
            )
        return deduped
