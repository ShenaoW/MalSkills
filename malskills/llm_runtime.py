from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import error, request

from .utils import load_env_file


@dataclass(frozen=True)
class EnvValue:
    name: str | None
    value: str


@dataclass(frozen=True)
class LlmRuntimeConfig:
    requested_mode: str
    backend: str
    model: str
    timeout_sec: int
    codex_cli: str
    claude_cli: str
    codex_cli_path: str
    claude_cli_path: str
    base_url: str
    api_key: str
    api_provider: str
    resolved_env: dict[str, str | None]
    reasoning_effort: str = ""


DEFAULT_OPENAI_MODEL = "gpt-5.6-sol"
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-5"
DEFAULT_CODEX_REASONING_EFFORT = "low"
DEFAULT_TIMEOUT_SEC = 300
LLM_RUNTIME_PROTOCOL_VERSION = "2026-07-28-v1"


def build_llm_runtime_config() -> LlmRuntimeConfig:
    load_env_file(Path(__file__).resolve().parents[1])

    requested_mode = _env_value("MALSKILLS_LLM_MODE").value.lower() or "auto"
    model_env = _first_env("MALSKILLS_LLM_MODEL", "OPENAI_MODEL", "ANTHROPIC_MODEL", "LLM_MODEL")
    base_url_env = _first_env("MALSKILLS_LLM_BASE_URL", "OPENAI_BASE_URL", "PACKY_API_URL", "ANTHROPIC_BASE_URL")
    api_key_env = _first_env(
        "MALSKILLS_LLM_API_KEY",
        "OPENAI_API_KEY",
        "PACKY_API_KEY",
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
    )
    codex_cli_env = _first_env("MALSKILLS_CODEX_CLI")
    claude_cli_env = _first_env("MALSKILLS_CLAUDE_CLI")
    timeout_env = _first_env("MALSKILLS_LLM_TIMEOUT_SEC")
    reasoning_effort_env = _first_env("MALSKILLS_LLM_REASONING_EFFORT")

    codex_cli = codex_cli_env.value or "codex"
    claude_cli = claude_cli_env.value or "claude"
    codex_cli_path = shutil.which(codex_cli) or ""
    claude_cli_path = shutil.which(claude_cli) or ""

    api_provider = _infer_api_provider(requested_mode, model_env.value, base_url_env.value, api_key_env.name)
    default_model = DEFAULT_ANTHROPIC_MODEL if api_provider == "anthropic" else DEFAULT_OPENAI_MODEL
    model = model_env.value or default_model

    backend = _resolve_backend(
        requested_mode=requested_mode,
        codex_available=bool(codex_cli_path),
        claude_available=bool(claude_cli_path),
        api_available=bool(api_key_env.value),
        api_provider=api_provider,
    )
    reasoning_effort = _parse_reasoning_effort(reasoning_effort_env.value)
    if backend == "codex_cli" and not reasoning_effort:
        reasoning_effort = DEFAULT_CODEX_REASONING_EFFORT

    return LlmRuntimeConfig(
        requested_mode=requested_mode,
        backend=backend,
        model=model,
        timeout_sec=_parse_timeout(timeout_env.value),
        codex_cli=codex_cli,
        claude_cli=claude_cli,
        codex_cli_path=codex_cli_path,
        claude_cli_path=claude_cli_path,
        base_url=base_url_env.value,
        api_key=api_key_env.value,
        api_provider=api_provider,
        resolved_env={
            "mode": "MALSKILLS_LLM_MODE" if os.environ.get("MALSKILLS_LLM_MODE") else None,
            "model": model_env.name,
            "base_url": base_url_env.name,
            "api_key": api_key_env.name,
            "codex_cli": codex_cli_env.name,
            "claude_cli": claude_cli_env.name,
            "timeout_sec": timeout_env.name,
            "reasoning_effort": reasoning_effort_env.name,
        },
        reasoning_effort=reasoning_effort,
    )


def describe_llm_runtime(config: LlmRuntimeConfig | None = None) -> dict[str, Any]:
    runtime = config or build_llm_runtime_config()
    return {
        "requested_mode": runtime.requested_mode,
        "resolved_backend": runtime.backend,
        "model": runtime.model,
        "timeout_sec": runtime.timeout_sec,
        "reasoning_effort": runtime.reasoning_effort or None,
        "local_cli": {
            "codex_cli": runtime.codex_cli,
            "codex_cli_path": runtime.codex_cli_path or None,
            "claude_cli": runtime.claude_cli,
            "claude_cli_path": runtime.claude_cli_path or None,
        },
        "online_api": {
            "provider": runtime.api_provider,
            "base_url": runtime.base_url or None,
            "api_key_configured": bool(runtime.api_key),
        },
        "resolved_env": runtime.resolved_env,
        "environment_variables": {
            "selection": [
                "MALSKILLS_LLM_MODE",
                "MALSKILLS_LLM_MODEL",
                "MALSKILLS_LLM_TIMEOUT_SEC",
                "MALSKILLS_LLM_REASONING_EFFORT",
            ],
            "local_cli": ["MALSKILLS_CODEX_CLI", "MALSKILLS_CLAUDE_CLI"],
            "online_api": [
                "MALSKILLS_LLM_BASE_URL",
                "MALSKILLS_LLM_API_KEY",
                "OPENAI_BASE_URL",
                "OPENAI_API_KEY",
                "OPENAI_MODEL",
                "PACKY_API_URL",
                "PACKY_API_KEY",
                "ANTHROPIC_BASE_URL",
                "ANTHROPIC_API_KEY",
                "ANTHROPIC_AUTH_TOKEN",
                "ANTHROPIC_MODEL",
            ],
            "cache": [
                "MALSKILLS_LLM_CACHE",
                "MALSKILLS_LLM_OBJECT_CACHE",
                "MALSKILLS_LLM_REASONING_CACHE",
                "MALSKILLS_LLM_FEEDBACK_CACHE",
            ],
        },
    }


def invoke_structured_json(
    *,
    prompt: str,
    schema: dict[str, Any],
    system_prompt: str,
    cwd: str | Path | None = None,
    config: LlmRuntimeConfig | None = None,
) -> dict[str, Any] | None:
    runtime = config or build_llm_runtime_config()
    if runtime.backend == "codex_cli":
        return _invoke_codex_cli(
            runtime,
            prompt=prompt,
            schema=schema,
            system_prompt=system_prompt,
            cwd=cwd,
        )
    if runtime.backend == "claude_cli":
        return _invoke_claude_cli(runtime, prompt=prompt, schema=schema, system_prompt=system_prompt, cwd=cwd)
    if runtime.backend == "anthropic_api":
        return _invoke_anthropic_api(runtime, prompt=prompt, system_prompt=system_prompt)
    if runtime.backend == "openai_api":
        return _invoke_openai_api(runtime, prompt=prompt, system_prompt=system_prompt)
    return None


def _invoke_codex_cli(
    runtime: LlmRuntimeConfig,
    *,
    prompt: str,
    schema: dict[str, Any],
    system_prompt: str,
    cwd: str | Path | None,
) -> dict[str, Any] | None:
    with tempfile.TemporaryDirectory(prefix="malskills-codex-") as tmp_dir:
        schema_path = Path(tmp_dir) / "schema.json"
        output_path = Path(tmp_dir) / "result.json"
        schema_path.write_text(json.dumps(schema, indent=2, sort_keys=True), encoding="utf-8")
        command = [runtime.codex_cli_path]
        trusted_instructions = system_prompt.strip()
        if trusted_instructions:
            command.extend(
                ["--config", f"developer_instructions={json.dumps(trusted_instructions)}"]
            )
        if runtime.reasoning_effort:
            command.extend(
                ["--config", f"model_reasoning_effort={json.dumps(runtime.reasoning_effort)}"]
            )
        command.extend([
            "exec",
            "--skip-git-repo-check",
            "--sandbox",
            "read-only",
            "--color",
            "never",
            "--model",
            runtime.model,
            "--output-schema",
            str(schema_path),
            "--output-last-message",
            str(output_path),
            "-",
        ])
        try:
            subprocess.run(
                command,
                cwd=str(Path(cwd).resolve()) if cwd else None,
                check=True,
                capture_output=True,
                text=True,
                input=prompt,
                timeout=runtime.timeout_sec,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        try:
            return _coerce_json_payload(output_path.read_text(encoding="utf-8"))
        except OSError:
            return None


def _invoke_claude_cli(
    runtime: LlmRuntimeConfig,
    *,
    prompt: str,
    schema: dict[str, Any],
    system_prompt: str,
    cwd: str | Path | None,
) -> dict[str, Any] | None:
    command = [
        runtime.claude_cli_path,
        "--print",
        "--output-format",
        "json",
        "--permission-mode",
        "dontAsk",
        "--tools",
        "",
        "--model",
        runtime.model,
        "--system-prompt",
        system_prompt,
        "--json-schema",
        json.dumps(schema, sort_keys=True),
        prompt,
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=str(Path(cwd).resolve()) if cwd else None,
            check=True,
            capture_output=True,
            text=True,
            timeout=runtime.timeout_sec,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return _coerce_json_payload(completed.stdout)


def _invoke_openai_api(
    runtime: LlmRuntimeConfig,
    *,
    prompt: str,
    system_prompt: str,
) -> dict[str, Any] | None:
    if not runtime.api_key:
        return None
    endpoint = _resolve_openai_endpoint(runtime.base_url or "https://api.openai.com/v1")
    payload = {
        "model": runtime.model,
        "temperature": 0,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
    }
    try:
        response_payload = _post_json(
            endpoint,
            payload,
            {
                "Authorization": f"Bearer {runtime.api_key}",
                "Content-Type": "application/json",
            },
            timeout_sec=runtime.timeout_sec,
        )
        content = response_payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError, ValueError):
        return None
    return _coerce_json_payload(content)


def _resolve_openai_endpoint(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    if normalized.endswith("/chat/completions"):
        return normalized
    return normalized + "/chat/completions"


def _invoke_anthropic_api(
    runtime: LlmRuntimeConfig,
    *,
    prompt: str,
    system_prompt: str,
) -> dict[str, Any] | None:
    if not runtime.api_key:
        return None
    endpoint = (runtime.base_url or "https://api.anthropic.com").rstrip("/") + "/v1/messages"
    payload = {
        "model": runtime.model,
        "max_tokens": 1200,
        "temperature": 0,
        "system": system_prompt,
        "messages": [{"role": "user", "content": prompt}],
    }
    try:
        response_payload = _post_json(
            endpoint,
            payload,
            {
                "x-api-key": runtime.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            timeout_sec=runtime.timeout_sec,
        )
        blocks = response_payload["content"]
        text_blocks = [block.get("text", "") for block in blocks if isinstance(block, dict) and block.get("type") == "text"]
    except (KeyError, TypeError, ValueError):
        return None
    return _coerce_json_payload("\n".join(text_blocks))


def _post_json(endpoint: str, payload: dict[str, Any], headers: dict[str, str], *, timeout_sec: int) -> dict[str, Any]:
    http_request = request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with request.urlopen(http_request, timeout=timeout_sec) as response:
            return json.loads(response.read().decode("utf-8"))
    except (error.URLError, error.HTTPError, TimeoutError, json.JSONDecodeError) as exc:
        raise ValueError("request failed") from exc


def _coerce_json_payload(payload: str) -> dict[str, Any] | None:
    text = payload.strip()
    if not text:
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            return None
        try:
            parsed = json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return None
    if isinstance(parsed, dict) and isinstance(parsed.get("result"), str):
        return _coerce_json_payload(parsed["result"])
    return parsed if isinstance(parsed, dict) else None


def _infer_api_provider(requested_mode: str, model: str, base_url: str, api_key_name: str | None) -> str:
    if requested_mode in {"anthropic", "anthropic_api"}:
        return "anthropic"
    if requested_mode == "openai_api":
        return "openai"
    if "anthropic" in base_url.lower() or model.lower().startswith("claude"):
        return "anthropic"
    if api_key_name in {"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"}:
        return "anthropic"
    return "openai"


def _resolve_backend(
    *,
    requested_mode: str,
    codex_available: bool,
    claude_available: bool,
    api_available: bool,
    api_provider: str,
) -> str:
    explicit_map = {
        "codex": "codex_cli",
        "codex_cli": "codex_cli",
        "claude": "claude_cli",
        "claude_cli": "claude_cli",
        "api": f"{api_provider}_api",
        "openai_api": "openai_api",
        "anthropic_api": "anthropic_api",
    }
    explicit_backend = explicit_map.get(requested_mode, "")
    if explicit_backend == "codex_cli" and codex_available:
        return explicit_backend
    if explicit_backend == "claude_cli" and claude_available:
        return explicit_backend
    if explicit_backend in {"openai_api", "anthropic_api"} and api_available:
        return explicit_backend
    if codex_available:
        return "codex_cli"
    if claude_available:
        return "claude_cli"
    if api_available:
        return f"{api_provider}_api"
    return "unavailable"


def _first_env(*names: str) -> EnvValue:
    for name in names:
        value = os.environ.get(name)
        if value is not None and value.strip():
            return EnvValue(name=name, value=value.strip())
    return EnvValue(name=None, value="")


def _env_value(name: str) -> EnvValue:
    value = os.environ.get(name)
    return EnvValue(name=name if value is not None else None, value=(value or "").strip())


def _parse_timeout(value: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT_SEC
    return max(1, parsed)


def _parse_reasoning_effort(value: str) -> str:
    normalized = value.strip().lower()
    if normalized in {"minimal", "low", "medium", "high", "xhigh", "max", "ultra"}:
        return normalized
    return ""
