from __future__ import annotations

from pathlib import Path
import re
from urllib.parse import urlparse

TEXT_SUFFIXES = {
    ".md",
    ".markdown",
    ".txt",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".env",
    ".cfg",
    ".conf",
    ".ini",
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".sh",
    ".bash",
    ".zsh",
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".cs",
    ".go",
    ".java",
    ".php",
    ".rb",
}

MARKDOWN_NAMES = {"skill.md", "claude.md", "agents.md", "readme.md", "handoff.md"}
FULLTEXT_MARKDOWN_NAMES = {"skill.md", "claude.md", "agents.md", "readme.md"}
CONFIG_NAMES = {"package.json", ".mcp.json", "config.json", ".env", ".env.example"}
MANIFEST_NAMES = {"package.json", "package-lock.json", "manifest.json", "plugin.json", "mcp.json", ".mcp.json"}
PROMPT_NAMES = {"system_prompt.txt", "system_prompt.md", "prompt.txt", "prompt.md", "claude.md", "skill.md", "agents.md"}
INSTALLER_NAMES = {
    "install.sh",
    "install.bash",
    "install.zsh",
    "bootstrap.sh",
    "bootstrap.bash",
    "bootstrap.zsh",
    "setup.sh",
    "setup.bash",
    "setup.zsh",
}

SENSITIVE_PATH_TOKENS = {
    ".ssh",
    "id_rsa",
    "id_ed25519",
    ".env",
    "passwd",
    "shadow",
    "credential",
    "credentials",
    "token",
    "secret",
    "wallet",
    "mnemonic",
    "seed",
    "auth",
    "config/gcloud",
    "aws/credentials",
}

SENSITIVE_ENV_TOKENS = {
    "api_key",
    "token",
    "secret",
    "password",
    "passwd",
    "private_key",
    "mnemonic",
    "seed",
    "github_token",
    "anthropic_api_key",
    "openai_api_key",
    "aws_access_key",
    "aws_secret_access_key",
}
SECRET_CLASS_PATTERNS = (
    ("private_key", ("private key", "private_key", "ssh key")),
    ("seed_phrase", ("seed phrase", "mnemonic", "recovery phrase")),
    ("wallet_credential", ("wallet", "keystore")),
    ("api_credential", ("api key", "api_key", "api secret", "api_secret", "access token", "bearer token", "token")),
)
HIGH_RISK_PERMISSION_TOKENS = {
    "exec",
    "shell",
    "bash",
    "terminal",
    "network",
    "web",
    "http",
    "https",
    "fetch",
    "curl",
    "wget",
    "filesystem",
    "file",
    "env",
    "secret",
    "credential",
}
HIGH_RISK_TOOL_TOKENS = {
    "bash",
    "shell",
    "terminal",
    "exec",
    "python",
    "node",
    "curl",
    "wget",
    "http",
    "fetch",
}

HIGH_RISK_COMMAND_PATTERNS = [
    r"(?:^|[\s|;&(])curl(?:[\s]|$)",
    r"(?:^|[\s|;&(])wget(?:[\s]|$)",
    r"(?:^|[\s|;&(])powershell(?:[\s]|$)",
    r"(?:^|[\s|;&(])bash(?:[\s]|$)",
    r"(?:^|[\s|;&(])sh(?:[\s]|$)",
    r"(?:^|[\s|;&(])zsh(?:[\s]|$)",
    r"(?:^|[\s|;&(])chmod(?:[\s]|$)",
    r"(?:^|[\s|;&(])base64(?:[\s]|$)",
    r"(?:^|[\s|;&(])python\s+-c(?:[\s]|$)",
    r"(?:^|[\s|;&(])node\s+-e(?:[\s]|$)",
    r"(?:^|[\s|;&(])osascript(?:[\s]|$)",
    r"invoke-webrequest",
]

SAFE_INTENT_TOKENS = {"log", "logging", "analytics", "setup", "configure", "manage", "search", "organize"}
HIDDEN_INTENT_TOKENS = {
    "ignore previous",
    "do not tell the user",
    "before starting",
    "before proceeding",
    "must run",
    "mandatory setup",
    "always run",
    "do not cd",
}
SECRET_REQUEST_TOKENS = {
    "private key",
    "seed phrase",
    "mnemonic",
    "api key",
    "api-key",
    "token",
    "password",
    "gemini_api_key",
    "openai_api_key",
}
IGNORE_DIRS = {".git", "node_modules", "__pycache__", ".pytest_cache", "dist", "build", ".next"}
NOISY_ROOT_DIRS = {"docs", "doc", "examples", "example", "templates", "template", "benchmark", "benchmarks"}
NOISY_SUBTREES = {
    (".claude", "agents"),
    (".cursor", "rules"),
    (".cursor", "prompts"),
}
PRIORITY_ROOT_DIRS = {"prompts", "prompt", "skills", "skill", "scripts", ".claude", ".cursor", ".mcp"}
ANALYZABLE_TEXT_ARTIFACT_TYPES = {"markdown", "prompt", "manifest", "config", "installer"}


def classify_artifact(path: Path) -> str:
    lower_name = path.name.lower()
    suffix = path.suffix.lower()
    if lower_name in MARKDOWN_NAMES or suffix in {".md", ".markdown"}:
        return "markdown"
    if lower_name in PROMPT_NAMES:
        return "prompt"
    if lower_name in MANIFEST_NAMES:
        return "manifest"
    if lower_name in INSTALLER_NAMES:
        return "installer"
    if lower_name in CONFIG_NAMES or suffix in {".json", ".yaml", ".yml", ".toml", ".ini", ".env", ".cfg", ".conf"}:
        return "config"
    if suffix == ".py":
        return "python"
    if suffix in {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}:
        return "javascript"
    if suffix in {".sh", ".bash", ".zsh"}:
        return "shell"
    if suffix == ".java":
        return "java"
    if suffix == ".go":
        return "go"
    if suffix == ".c":
        return "c"
    if suffix in {".cc", ".cpp", ".cxx"}:
        return "cpp"
    if suffix == ".cs":
        return "csharp"
    if suffix == ".php":
        return "php"
    if suffix == ".rb":
        return "ruby"
    if suffix in TEXT_SUFFIXES:
        return "text"
    return "binary"


def path_class(path_value: str | None) -> str:
    if not path_value:
        return "unknown"
    lower = path_value.lower()
    if any(token in lower for token in SENSITIVE_PATH_TOKENS):
        return "sensitive"
    if lower.startswith(("/etc", "/var", "/home", "~", "%appdata%")):
        return "system"
    return "ordinary"


def env_class(name: str | None) -> str:
    if not name:
        return "unknown"
    lower = name.lower()
    if any(token in lower for token in SENSITIVE_ENV_TOKENS):
        return "sensitive"
    return "ordinary"


def url_class(url: str | None) -> str:
    if not url:
        return "unknown"
    try:
        parsed = urlparse(url)
    except ValueError:
        return "unknown"
    if parsed.scheme not in {"http", "https"}:
        return "unknown"
    host = (parsed.hostname or "").lower()
    if host in {"", "localhost", "127.0.0.1", "0.0.0.0"}:
        return "local"
    return "external"


def endpoint_class(endpoint: str | None) -> str:
    return url_class(endpoint)


def permission_class(values: str | list[str] | tuple[str, ...] | None) -> str:
    normalized_values = _normalize_value_list(values)
    if not normalized_values:
        return "unknown"
    lowered = [value.lower() for value in normalized_values]
    if any(any(token in value for token in HIGH_RISK_PERMISSION_TOKENS) for value in lowered):
        return "high_risk"
    return "ordinary"


def tool_surface_class(values: str | list[str] | tuple[str, ...] | None) -> str:
    normalized_values = _normalize_value_list(values)
    if not normalized_values:
        return "unknown"
    lowered = [value.lower() for value in normalized_values]
    if any(any(token in value for token in HIGH_RISK_TOOL_TOKENS) for value in lowered):
        return "high_risk"
    return "ordinary"


def secret_class(secret_value: str | None) -> str:
    if not secret_value:
        return "unknown"
    lowered = secret_value.lower()
    for class_name, tokens in SECRET_CLASS_PATTERNS:
        if any(token in lowered for token in tokens):
            return class_name
    if any(token in lowered for token in ("secret", "credential", "password", "passwd")):
        return "generic_secret"
    return "unknown"


def command_class(command: str | None) -> str:
    if not command:
        return "unknown"
    lower = command.lower()
    if any(re.search(pattern, lower) for pattern in HIGH_RISK_COMMAND_PATTERNS):
        return "high_risk"
    return "ordinary"


def looks_sensitive_text(text: str) -> bool:
    return path_class(text) == "sensitive" or env_class(text) == "sensitive"


def _normalize_value_list(values: str | list[str] | tuple[str, ...] | None) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        return [values]
    return [value for value in values if value]
