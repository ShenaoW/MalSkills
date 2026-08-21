from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import re
from typing import Any

from ..models import ArtifactRecord, SSORecord


SOURCE_SUBTYPES = {
    "data_receive",
    "file_read",
    "file_access",
    "credential_data_access",
    "environment_access",
    "system_information_access",
    "process_information_access",
    "user_information_access",
}
TRANSFORM_SUBTYPES = {
    "decoding",
    "decryption",
    "encoding",
    "encryption",
    "hashing",
    "cryptographic_operation",
}
SINK_SUBTYPES = {
    "system_command_execution",
    "dynamic_code_execution",
    "external_file_execution",
    "unsafe_deserialization",
    "data_send",
    "file_create",
    "file_write",
}
EXECUTION_SUBTYPES = {
    "system_command_execution",
    "dynamic_code_execution",
    "external_file_execution",
    "unsafe_deserialization",
}


@dataclass(frozen=True)
class _CanonicalLine:
    path: str
    line: int


def build_shell_flow_edges(
    artifacts: list[ArtifactRecord],
    ssos: list[SSORecord],
) -> list[dict[str, Any]]:
    """Build operation flow only for explicit shell pipes or substitutions."""
    artifact_by_path = {item.relative_path: item for item in artifacts}
    source_by_path = {
        item.relative_path: item
        for item in artifacts
        if not item.generated and item.content is not None
    }
    ssos_by_line: dict[_CanonicalLine, list[SSORecord]] = defaultdict(list)

    for sso in ssos:
        for location in _canonical_lines(sso, artifact_by_path):
            ssos_by_line[location].append(sso)

    edges: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, int]] = set()
    for location, candidates in ssos_by_line.items():
        source_artifact = source_by_path.get(location.path)
        if source_artifact is None or source_artifact.content is None:
            continue
        lines = source_artifact.content.splitlines()
        if not 1 <= location.line <= len(lines):
            continue
        statement = lines[location.line - 1]
        if _shell_dataflow_count(statement) != 1:
            continue

        unique = {item.sso_id: item for item in candidates}
        sources = sorted(
            (item for item in unique.values() if item.subtype in SOURCE_SUBTYPES),
            key=lambda item: item.sso_id,
        )
        transforms = sorted(
            (item for item in unique.values() if item.subtype in TRANSFORM_SUBTYPES),
            key=lambda item: item.sso_id,
        )
        sinks = sorted(
            (item for item in unique.values() if item.subtype in SINK_SUBTYPES),
            key=lambda item: item.sso_id,
        )
        if not sinks or not (sources or transforms):
            continue

        if sources and transforms:
            _append_complete_layer(edges, seen, sources, transforms, location)
            _append_complete_layer(edges, seen, transforms, sinks, location)
        elif sources:
            _append_complete_layer(edges, seen, sources, sinks, location)
        else:
            _append_complete_layer(edges, seen, transforms, sinks, location)
    return edges


def build_explicit_text_flow_edges(
    artifacts: list[ArtifactRecord],
    ssos: list[SSORecord],
) -> list[dict[str, Any]]:
    """Build Markdown flow only for a statically proven download-then-execute clause."""
    artifact_by_path = {item.relative_path: item for item in artifacts}
    ssos_by_line: dict[_CanonicalLine, list[SSORecord]] = defaultdict(list)
    for sso in ssos:
        for location in _canonical_lines(sso, artifact_by_path):
            ssos_by_line[location].append(sso)

    edges: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, int]] = set()
    for location, candidates in ssos_by_line.items():
        sources = [item for item in candidates if item.subtype == "data_receive"]
        sinks = [
            item
            for item in candidates
            if item.subtype == "external_file_execution"
            and item.attributes.get("flow_hint") == "downloaded_payload"
        ]
        _append_complete_layer(
            edges,
            seen,
            sorted({item.sso_id: item for item in sources}.values(), key=lambda item: item.sso_id),
            sorted({item.sso_id: item for item in sinks}.values(), key=lambda item: item.sso_id),
            location,
            flow_kind="markdown_explicit_flow",
        )
    return edges


def build_embedded_shell_flow_edges(ssos: list[SSORecord]) -> list[dict[str, Any]]:
    """Connect a statically parsed fetch pipeline to its enclosing execution call."""
    edges: list[dict[str, Any]] = []
    for source in ssos:
        if source.attributes.get("flow_hint") != "embedded_shell_pipeline":
            continue
        source_start = int(source.attributes.get("source_start_line", 0) or 0)
        source_end = int(source.attributes.get("source_end_line", source_start) or source_start)
        for sink in ssos:
            if sink.subtype not in EXECUTION_SUBTYPES or sink.sso_id == source.sso_id:
                continue
            if not set(source.artifact_paths) & set(sink.artifact_paths):
                continue
            sink_start = int(sink.attributes.get("source_start_line", 0) or 0)
            sink_end = int(sink.attributes.get("source_end_line", sink_start) or sink_start)
            if source_start <= sink_end and sink_start <= source_end:
                edges.append(
                    {
                        "source": source.sso_id,
                        "target": sink.sso_id,
                        "type": "value_flow",
                        "flow_kind": "embedded_shell_pipeline",
                        "pipeline_group": source.attributes.get("pipeline_group", ""),
                    }
                )
    return edges


def build_explicit_archive_flow_edges(
    artifacts: list[ArtifactRecord],
    ssos: list[SSORecord],
) -> list[dict[str, Any]]:
    """Build flows for explicit password-protected download/extract/run instructions."""
    artifact_by_path = {item.relative_path: item for item in artifacts}
    sources: list[tuple[_CanonicalLine, SSORecord]] = []
    transforms: list[tuple[_CanonicalLine, SSORecord]] = []
    sinks: list[tuple[_CanonicalLine, SSORecord]] = []
    for sso in ssos:
        for location in _canonical_lines(sso, artifact_by_path):
            if sso.subtype == "data_receive":
                sources.append((location, sso))
            elif (
                sso.subtype == "decoding"
                and sso.attributes.get("operation_class") == "archive_extraction"
            ):
                transforms.append((location, sso))
            elif sso.subtype == "external_file_execution":
                sinks.append((location, sso))

    edges: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, int]] = set()
    for transform_location, transform in transforms:
        artifact = artifact_by_path.get(transform_location.path)
        if (
            artifact is None
            or artifact.artifact_type not in {"markdown", "prompt"}
            or not artifact.content
        ):
            continue
        lines = artifact.content.splitlines()
        if not 1 <= transform_location.line <= len(lines):
            continue
        transform_text = lines[transform_location.line - 1]
        if not _mentions_archive_password(transform_text):
            continue

        source_candidates = [item for item in sources if item[0].path == transform_location.path]
        sink_candidates = [item for item in sinks if item[0].path == transform_location.path]
        for source_location, source in source_candidates:
            for sink_location, sink in sink_candidates:
                same_line = source_location.line == transform_location.line == sink_location.line
                numbered_sequence = _is_numbered_archive_sequence(
                    lines,
                    source_location.line,
                    transform_location.line,
                    sink_location.line,
                )
                if not same_line and not numbered_sequence:
                    continue
                if same_line and not _is_explicit_archive_clause(transform_text):
                    continue
                _append_complete_layer(
                    edges,
                    seen,
                    [source],
                    [transform],
                    transform_location,
                    flow_kind="archive_instruction_flow",
                )
                _append_complete_layer(
                    edges,
                    seen,
                    [transform],
                    [sink],
                    transform_location,
                    flow_kind="archive_instruction_flow",
                )
    return edges


def _canonical_lines(
    sso: SSORecord,
    artifact_by_path: dict[str, ArtifactRecord],
) -> set[_CanonicalLine]:
    start = int(sso.attributes.get("source_start_line", 0) or 0)
    end = int(sso.attributes.get("source_end_line", start) or start)
    if start <= 0:
        return set()
    locations: set[_CanonicalLine] = set()
    for path in sso.artifact_paths:
        artifact = artifact_by_path.get(path)
        if artifact is None:
            continue
        if artifact.generated and artifact.source_artifact_path and artifact.source_start_line:
            for line in range(start, end + 1):
                locations.add(
                    _CanonicalLine(
                        artifact.source_artifact_path,
                        artifact.source_start_line + line,
                    )
                )
        elif artifact.artifact_type in {"shell", "markdown", "prompt"}:
            for line in range(start, end + 1):
                locations.add(_CanonicalLine(path, line))
    return locations


def _append_complete_layer(
    edges: list[dict[str, Any]],
    seen: set[tuple[str, str, str, str, int]],
    left: list[SSORecord],
    right: list[SSORecord],
    location: _CanonicalLine,
    *,
    flow_kind: str = "shell_pipeline",
) -> None:
    for source in left:
        for target in right:
            if source.sso_id == target.sso_id:
                continue
            key = (source.sso_id, target.sso_id, flow_kind, location.path, location.line)
            if key in seen:
                continue
            seen.add(key)
            edges.append(
                {
                    "source": source.sso_id,
                    "target": target.sso_id,
                    "type": "value_flow",
                    "flow_kind": flow_kind,
                    "artifact_path": location.path,
                    "source_line": location.line,
                }
            )


def _shell_dataflow_count(text: str) -> int:
    """Count independent shell clauses containing a pipe or command substitution."""
    clauses: list[bool] = [False]
    quote = ""
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if escaped:
            escaped = False
            index += 1
            continue
        if char == "\\" and quote != "'":
            escaped = True
            index += 1
            continue
        if char in {"'", '"'}:
            if not quote:
                quote = char
            elif quote == char:
                quote = ""
            index += 1
            continue
        if quote != "'" and char == "$" and next_char == "(":
            clauses[-1] = True
            index += 2
            continue
        if not quote and char == "|" and next_char != "|":
            clauses[-1] = True
            index += 1
            continue
        if not quote and (
            char == ";" or (char == "&" and next_char == "&") or (char == "|" and next_char == "|")
        ):
            clauses.append(False)
            index += 2 if next_char == char else 1
            continue
        index += 1
    return sum(clauses)


def _mentions_archive_password(text: str) -> bool:
    return re.search(r"(?i)\b(?:pass(?:word|phrase)?|pwd)\b", text) is not None


def _is_explicit_archive_clause(text: str) -> bool:
    lower = text.lower()
    positions = (
        _first_token_position(lower, ("download", "fetch", "get")),
        _first_token_position(lower, ("extract", "unzip", "decompress")),
        _first_token_position(lower, ("run", "open", "launch", "execute")),
    )
    return all(position >= 0 for position in positions) and positions[0] < positions[1] < positions[2]


def _first_token_position(text: str, tokens: tuple[str, ...]) -> int:
    positions = [match.start() for token in tokens if (match := re.search(rf"\b{token}\b", text))]
    return min(positions, default=-1)


def _is_numbered_archive_sequence(
    lines: list[str],
    source_line: int,
    transform_line: int,
    sink_line: int,
) -> bool:
    if not source_line < transform_line < sink_line:
        return False
    ordinals = [
        _markdown_ordinal(lines[line - 1])
        for line in (source_line, transform_line, sink_line)
    ]
    if any(value is None for value in ordinals):
        return False
    assert all(value is not None for value in ordinals)
    if not (ordinals[1] == ordinals[0] + 1 and ordinals[2] == ordinals[1] + 1):
        return False
    for line in lines[source_line:sink_line]:
        stripped = re.sub(r"^[ \t]*(?:>[ \t]*)*", "", line).strip()
        if stripped and _markdown_ordinal(line) is None:
            return False
    return True


def _markdown_ordinal(text: str) -> int | None:
    match = re.match(r"^[ \t]*(?:>[ \t]*)*(\d+)\.[ \t]+", text)
    return int(match.group(1)) if match else None
