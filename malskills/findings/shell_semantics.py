from __future__ import annotations

import ast
import base64
import binascii
import hashlib
import re
import shlex

from ..models import ArtifactRecord, SSOFinding, Span


_PYTHON_SHELL_APIS = {
    "commands.getoutput",
    "commands.getstatusoutput",
    "os.popen",
    "os.system",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
    "subprocess.run",
}
_FETCH_COMMANDS = {"curl", "wget"}
_SHELL_INTERPRETERS = {"bash", "dash", "ksh", "sh", "zsh"}
_URL_RE = re.compile(r"https?://[^\s'\"`|;&)]+", re.IGNORECASE)
_ENCODED_PIPELINE_RE = re.compile(
    r"(?i)\b(?:echo|printf)\s+(['\"])(?P<payload>[A-Za-z0-9+/=]{24,})\1"
    r"\s*\|\s*base64\s+(?:-d|-D|--decode)\b[^\n|]*\|\s*(?:bash|sh)\b"
)
_FETCH_SUBSTITUTION_RE = re.compile(
    r"(?is)\b(?:bash|dash|ksh|sh|zsh)\b[^\n]*\s-c\b[^\n]*"
    r"\$\(\s*(?:curl|wget)\b(?P<body>[^)]*)\)"
)


def extract_embedded_shell_findings(artifacts: list[ArtifactRecord]) -> list[SSOFinding]:
    """Find explicit fetch-to-shell flows inside constant Python commands."""
    findings: list[SSOFinding] = []
    for artifact in artifacts:
        if not artifact.content:
            continue
        if artifact.artifact_type == "python":
            findings.extend(_python_shell_findings(artifact))
        if artifact.artifact_type in {"markdown", "prompt"} or (
            artifact.artifact_type == "shell" and not artifact.generated
        ):
            findings.extend(_encoded_shell_findings(artifact))
    return findings


def _python_shell_findings(artifact: ArtifactRecord) -> list[SSOFinding]:
    try:
        tree = ast.parse(artifact.content or "")
    except SyntaxError:
        return []
    findings: list[SSOFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or _dotted_name(node.func) not in _PYTHON_SHELL_APIS:
            continue
        command = _constant_command(node)
        if not command or not _has_fetch_to_shell_pipeline(command):
            continue
        endpoint_match = _URL_RE.search(command)
        endpoint = endpoint_match.group(0) if endpoint_match else command
        start_line = int(getattr(node, "lineno", 1) or 1)
        end_line = int(getattr(node, "end_lineno", start_line) or start_line)
        findings.append(
            _network_finding(
                artifact,
                endpoint,
                start_line,
                end_line,
                engine="python_ast_shell",
                flow_hint="embedded_shell_pipeline",
            )
        )
    return findings


def _encoded_shell_findings(artifact: ArtifactRecord) -> list[SSOFinding]:
    findings: list[SSOFinding] = []
    for line_number, line in enumerate((artifact.content or "").splitlines(), start=1):
        for match in _ENCODED_PIPELINE_RE.finditer(line):
            payload = match.group("payload")
            if len(payload) > 131_072:
                continue
            try:
                decoded = base64.b64decode(payload, validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            endpoint = _executed_fetch_endpoint(decoded)
            if not endpoint:
                continue
            findings.append(
                _network_finding(
                    artifact,
                    endpoint,
                    line_number,
                    line_number,
                    engine="constant_base64_shell",
                    flow_hint="encoded_shell_pipeline",
                )
            )
    return findings


def _executed_fetch_endpoint(command: str) -> str:
    if _has_fetch_to_shell_pipeline(command):
        match = _URL_RE.search(command)
        return match.group(0) if match else ""
    substitution = _FETCH_SUBSTITUTION_RE.search(command)
    if substitution is None:
        return ""
    match = _URL_RE.search(substitution.group("body"))
    return match.group(0) if match else ""


def _network_finding(
    artifact: ArtifactRecord,
    endpoint: str,
    start_line: int,
    end_line: int,
    *,
    engine: str,
    flow_hint: str,
) -> SSOFinding:
    digest = hashlib.sha256(
        f"{artifact.artifact_id}\0{start_line}\0{endpoint}\0{flow_hint}".encode("utf-8")
    ).hexdigest()[:16]
    return SSOFinding(
        finding_id=f"static_shell_{digest}",
        producer="static_shell_semantics",
        artifact_id=artifact.artifact_id,
        artifact_path=artifact.relative_path,
        category="network_access",
        subtype="data_receive",
        matched_text=endpoint,
        confidence=None,
        span=Span(start_line, end_line),
        attributes={
            "analysis_stage": "sso_extraction",
            "analysis_component": "embedded_shell_semantics",
            "engine": engine,
            "flow_hint": flow_hint,
            "pipeline_group": digest,
        },
        provenance={
            "artifact": {"id": artifact.artifact_id, "path": artifact.relative_path},
            "span": {"start_line": start_line, "end_line": end_line},
            "producer": "static_shell_semantics",
        },
    )


def _dotted_name(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _constant_command(node: ast.Call) -> str:
    if not node.args:
        return ""
    value = node.args[0]
    return value.value if isinstance(value, ast.Constant) and isinstance(value.value, str) else ""


def _has_fetch_to_shell_pipeline(command: str) -> bool:
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars="|&;")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return False

    pipelines: list[list[list[str]]] = [[[]]]
    for token in tokens:
        if token == "|":
            pipelines[-1].append([])
        elif token in {";", "&&", "||", "&"}:
            pipelines.append([[]])
        else:
            pipelines[-1][-1].append(token)

    for stages in pipelines:
        fetch_indexes = [
            index for index, stage in enumerate(stages) if _command_name(stage) in _FETCH_COMMANDS
        ]
        shell_indexes = [
            index
            for index, stage in enumerate(stages)
            if _command_name(stage) in _SHELL_INTERPRETERS
        ]
        if any(source < sink for source in fetch_indexes for sink in shell_indexes):
            return True
    return False


def _command_name(stage: list[str]) -> str:
    index = 0
    while index < len(stage):
        token = stage[index]
        name = token.rsplit("/", 1)[-1]
        is_assignment = "=" in token and not token.startswith(("http://", "https://"))
        if name in {"command", "env", "sudo"} or is_assignment:
            index += 1
            continue
        return name
    return ""
