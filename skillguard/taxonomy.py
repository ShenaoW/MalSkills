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
}

MARKDOWN_NAMES = {"skill.md", "claude.md", "readme.md", "handoff.md"}
CONFIG_NAMES = {"package.json", ".mcp.json", "config.json", ".env", ".env.example"}
PROMPT_NAMES = {"system_prompt.txt", "system_prompt.md", "prompt.txt", "prompt.md", "claude.md", "skill.md"}

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


def classify_artifact(path: Path) -> str:
    lower_name = path.name.lower()
    suffix = path.suffix.lower()
    if lower_name in MARKDOWN_NAMES or suffix in {".md", ".markdown"}:
        return "markdown"
    if lower_name in CONFIG_NAMES or suffix in {".json", ".yaml", ".yml", ".toml", ".ini", ".env", ".cfg", ".conf"}:
        return "config"
    if suffix == ".py":
        return "python"
    if suffix in {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}:
        return "javascript"
    if suffix in {".sh", ".bash", ".zsh"}:
        return "shell"
    if lower_name in PROMPT_NAMES:
        return "prompt"
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


def command_class(command: str | None) -> str:
    if not command:
        return "unknown"
    lower = command.lower()
    if any(re.search(pattern, lower) for pattern in HIGH_RISK_COMMAND_PATTERNS):
        return "high_risk"
    return "ordinary"


def looks_sensitive_text(text: str) -> bool:
    return path_class(text) == "sensitive" or env_class(text) == "sensitive"
