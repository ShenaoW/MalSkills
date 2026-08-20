from __future__ import annotations

import html
import json
import secrets
import subprocess
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlparse

from ..llm_runtime import build_llm_runtime_config


PAPER_BASELINE_MODEL = "gpt-5.3-codex-medium"
DEFAULT_BASELINE_MODEL = "gpt-5.6-luna"


@dataclass(frozen=True)
class BaselineCodexConfig:
    cli_path: str
    model: str
    reasoning_effort: str
    timeout_sec: int


@dataclass(frozen=True)
class CodexBridgeEndpoint:
    base_url: str
    docker_base_url: str
    api_key: str
    model: str

    @property
    def chat_completions_url(self) -> str:
        return f"{self.base_url}/chat/completions"

    @property
    def ollama_chat_url(self) -> str:
        return f"{self.base_url.removesuffix('/v1')}/api/chat"


def resolve_baseline_codex_config() -> BaselineCodexConfig:
    runtime = build_llm_runtime_config()
    if not runtime.codex_cli_path:
        raise FileNotFoundError(
            "LLM baselines require Codex CLI; configure MALSKILLS_CODEX_CLI or install `codex`"
        )
    return BaselineCodexConfig(
        cli_path=runtime.codex_cli_path,
        model=runtime.model or DEFAULT_BASELINE_MODEL,
        reasoning_effort=runtime.reasoning_effort or "low",
        timeout_sec=max(runtime.timeout_sec, 900),
    )


@contextmanager
def codex_cli_api_bridge(*, cwd: str | Path) -> Iterator[CodexBridgeEndpoint]:
    config = resolve_baseline_codex_config()
    # A leading '-' is parsed as another option by baselines that pass the key
    # as a CLI argument (for example AI-Infra-Guard).
    api_key = f"malskills_{secrets.token_urlsafe(32)}"
    server = _CodexBridgeServer(
        ("0.0.0.0", 0),
        config=config,
        cwd=Path(cwd).resolve(),
        api_key=api_key,
    )
    thread = threading.Thread(target=server.serve_forever, name="malskills-codex-bridge", daemon=True)
    thread.start()
    port = int(server.server_address[1])
    endpoint = CodexBridgeEndpoint(
        base_url=f"http://127.0.0.1:{port}/v1",
        docker_base_url=f"http://{_docker_bridge_gateway()}:{port}/v1",
        api_key=api_key,
        model=config.model,
    )
    try:
        yield endpoint
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class _CodexBridgeServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        *,
        config: BaselineCodexConfig,
        cwd: Path,
        api_key: str,
    ) -> None:
        super().__init__(address, _CodexBridgeHandler)
        self.config = config
        self.cwd = cwd
        self.api_key = api_key

    def invoke(self, payload: dict[str, Any]) -> dict[str, Any]:
        messages = _request_messages(payload)
        tools = payload.get("tools") if isinstance(payload.get("tools"), list) else []
        prompt = _render_messages(messages, [] if tools else tools)
        system_prompt = "\n\n".join(
            _content_text(message.get("content"))
            for message in messages
            if str(message.get("role", "")) in {"system", "developer"}
        ).strip()
        if tools:
            return _invoke_codex_for_tools(
                self.config,
                cwd=self.cwd,
                prompt=prompt,
                system_prompt=system_prompt,
                tools=tools,
            )
        return {
            "content": _invoke_codex_text(
                self.config,
                cwd=self.cwd,
                prompt=prompt,
                system_prompt=system_prompt,
            ),
            "tool_calls": [],
        }


class _CodexBridgeHandler(BaseHTTPRequestHandler):
    server: _CodexBridgeServer

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path.rstrip("/")
        if path in {"", "/health"}:
            self._json(HTTPStatus.OK, {"status": "ok", "backend": "codex_cli"})
            return
        if path == "/v1/models":
            if not self._authorized():
                return
            self._json(
                HTTPStatus.OK,
                {"object": "list", "data": [{"id": self.server.config.model, "object": "model"}]},
            )
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": {"message": "unknown endpoint"}})

    def do_POST(self) -> None:  # noqa: N802
        if not self._authorized():
            return
        try:
            payload = self._read_json()
            result = self.server.invoke(payload)
            path = urlparse(self.path).path.rstrip("/")
            if path.endswith("/chat/completions"):
                response = _chat_completion_response(self.server.config.model, result)
                if payload.get("stream") is True:
                    self._chat_completion_stream(response)
                else:
                    self._json(HTTPStatus.OK, response)
                return
            if path.endswith("/responses"):
                self._json(HTTPStatus.OK, _responses_api_response(self.server.config.model, result))
                return
            if path.endswith("/messages"):
                self._json(HTTPStatus.OK, _anthropic_response(self.server.config.model, result))
                return
            if path.endswith("/api/chat"):
                self._json(HTTPStatus.OK, _ollama_response(self.server.config.model, result))
                return
            self._json(HTTPStatus.NOT_FOUND, {"error": {"message": "unknown endpoint"}})
        except subprocess.TimeoutExpired:
            self._json(HTTPStatus.GATEWAY_TIMEOUT, {"error": {"message": "Codex CLI timed out"}})
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as exc:
            self._json(
                HTTPStatus.BAD_GATEWAY,
                {"error": {"message": f"Codex CLI bridge failed: {type(exc).__name__}: {exc}"}},
            )

    def log_message(self, format: str, *args: object) -> None:
        return

    def _authorized(self) -> bool:
        supplied = self.headers.get("Authorization", "")
        alternate = self.headers.get("x-api-key", "")
        if supplied == f"Bearer {self.server.api_key}" or alternate == self.server.api_key:
            return True
        self._json(HTTPStatus.UNAUTHORIZED, {"error": {"message": "invalid bridge API key"}})
        return False

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or 0)
        decoded = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(decoded, dict):
            raise ValueError("request body must be a JSON object")
        return decoded

    def _json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        try:
            self.wfile.write(encoded)
        except (BrokenPipeError, ConnectionResetError):
            return

    def _chat_completion_stream(self, response: dict[str, Any]) -> None:
        choice = response["choices"][0]
        message = choice["message"]
        delta = {key: value for key, value in message.items() if key != "role"}
        chunk = {
            "id": response["id"],
            "object": "chat.completion.chunk",
            "created": response["created"],
            "model": response["model"],
            "choices": [{"index": 0, "delta": delta, "finish_reason": choice["finish_reason"]}],
        }
        encoded = (
            f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n"
            "data: [DONE]\n\n"
        ).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def _invoke_codex_text(
    config: BaselineCodexConfig,
    *,
    cwd: Path,
    prompt: str,
    system_prompt: str,
) -> str:
    bridge_instruction = (
        "Complete the entire requested task in this single Codex invocation. Use your built-in "
        "read-only tools to inspect the working directory; do not ask the caller to execute "
        "intermediate read, list, grep, or analysis tools. If the caller defines a textual finish "
        "function format, end by invoking finish exactly once with the complete final result."
    )
    developer = "\n\n".join(part for part in (system_prompt, bridge_instruction) if part)
    with tempfile.TemporaryDirectory(prefix="malskills-baseline-codex-") as tmp_dir:
        output_path = Path(tmp_dir) / "result.txt"
        command = _codex_command(config, output_path=output_path, system_prompt=developer)
        _run_codex_command(
            command,
            cwd=str(cwd),
            input=prompt,
            timeout=config.timeout_sec,
        )
        result = output_path.read_text(encoding="utf-8").strip()
        declares_xml_finish = '<tool name="finish">' in system_prompt or "<function=finish>" in system_prompt
        if declares_xml_finish and "<function=finish" not in result:
            escaped = html.escape(result, quote=False)
            return f"<function=finish>\n<parameter=content>{escaped}</parameter>\n</function>"
        return result


def _invoke_codex_for_tools(
    config: BaselineCodexConfig,
    *,
    cwd: Path,
    prompt: str,
    system_prompt: str,
    tools: list[Any],
) -> dict[str, Any]:
    schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "content": {"type": "string"},
            "tool_calls": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "name": {"type": "string"},
                        "arguments": {"type": "object"},
                    },
                    "required": ["name", "arguments"],
                },
            },
        },
        "required": ["content", "tool_calls"],
    }
    tool_instruction = (
        "Complete the entire requested task in this single Codex invocation. Use your built-in "
        "read-only tools to inspect the working directory instead of calling supplied read, list, "
        "grep, or analysis functions. Return the complete final content with an empty tool_calls "
        "array; only request a supplied function when an unavoidable external side effect is required."
    )
    developer = "\n\n".join(part for part in (system_prompt, tool_instruction) if part)
    with tempfile.TemporaryDirectory(prefix="malskills-baseline-codex-") as tmp_dir:
        output_path = Path(tmp_dir) / "result.json"
        schema_path = Path(tmp_dir) / "schema.json"
        schema_path.write_text(json.dumps(schema), encoding="utf-8")
        command = _codex_command(
            config,
            output_path=output_path,
            system_prompt=developer,
            schema_path=schema_path,
        )
        _run_codex_command(
            command,
            cwd=str(cwd),
            input=prompt,
            timeout=config.timeout_sec,
        )
        decoded = json.loads(output_path.read_text(encoding="utf-8"))
    calls = decoded.get("tool_calls") if isinstance(decoded, dict) else []
    allowed = {_tool_name(item) for item in tools if isinstance(item, dict)}
    allowed.discard("")
    normalized_calls = [
        item
        for item in calls
        if isinstance(item, dict) and str(item.get("name", "")) in allowed
    ]
    return {
        "content": str(decoded.get("content", "")) if isinstance(decoded, dict) else "",
        "tool_calls": normalized_calls,
    }


def _run_codex_command(
    command: list[str],
    *,
    cwd: str,
    input: str,
    timeout: int,
) -> None:
    completed: subprocess.CompletedProcess[str] | None = None
    for _ in range(2):
        completed = subprocess.run(
            command,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            input=input,
            timeout=timeout,
        )
        if completed.returncode == 0:
            return
    assert completed is not None
    detail = (completed.stderr or completed.stdout).strip()[-4000:]
    raise RuntimeError(f"Codex CLI exited with status {completed.returncode}: {detail}")


def _codex_command(
    config: BaselineCodexConfig,
    *,
    output_path: Path,
    system_prompt: str,
    schema_path: Path | None = None,
) -> list[str]:
    command = [config.cli_path]
    if system_prompt:
        command.extend(["--config", f"developer_instructions={json.dumps(system_prompt)}"])
    if config.reasoning_effort:
        command.extend(["--config", f"model_reasoning_effort={json.dumps(config.reasoning_effort)}"])
    command.extend(
        [
            "exec",
            "--skip-git-repo-check",
            "--sandbox",
            "read-only",
            "--color",
            "never",
            "--model",
            config.model,
        ]
    )
    if schema_path is not None:
        command.extend(["--output-schema", str(schema_path)])
    command.extend(["--output-last-message", str(output_path), "-"])
    return command


def _request_messages(payload: dict[str, Any]) -> list[dict[str, Any]]:
    leading: list[dict[str, Any]] = []
    system = payload.get("system")
    if system not in (None, ""):
        leading.append({"role": "system", "content": system})
    instructions = payload.get("instructions")
    if instructions not in (None, ""):
        leading.append({"role": "developer", "content": instructions})
    messages = payload.get("messages")
    if isinstance(messages, list):
        return leading + [item for item in messages if isinstance(item, dict)]
    input_value = payload.get("input", "")
    if isinstance(input_value, str):
        return leading + [{"role": "user", "content": input_value}]
    if isinstance(input_value, list):
        return leading + [item for item in input_value if isinstance(item, dict)]
    return leading + [{"role": "user", "content": str(input_value)}]


def _tool_name(tool: dict[str, Any]) -> str:
    function = tool.get("function")
    if isinstance(function, dict):
        return str(function.get("name", ""))
    return str(tool.get("name", ""))


def _render_messages(messages: list[dict[str, Any]], tools: list[Any]) -> str:
    lines: list[str] = []
    for message in messages:
        role = str(message.get("role", "user")).upper()
        name = str(message.get("name", "")).strip()
        label = f"{role} ({name})" if name else role
        lines.append(f"[{label}]\n{_content_text(message.get('content'))}")
    if tools:
        lines.append(f"[AVAILABLE FUNCTIONS]\n{json.dumps(tools, ensure_ascii=False)}")
    return "\n\n".join(lines)


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                value = item.get("text") or item.get("content") or item.get("output")
                if value is not None:
                    parts.append(str(value))
        return "\n".join(parts)
    if content is None:
        return ""
    return json.dumps(content, ensure_ascii=False)


def _chat_completion_response(model: str, result: dict[str, Any]) -> dict[str, Any]:
    tool_calls = [
        {
            "id": f"call_{uuid.uuid4().hex}",
            "type": "function",
            "function": {
                "name": str(item["name"]),
                "arguments": json.dumps(item["arguments"], ensure_ascii=False),
            },
        }
        for item in result.get("tool_calls", [])
    ]
    message: dict[str, Any] = {"role": "assistant", "content": result.get("content") or None}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": message,
                "finish_reason": "tool_calls" if tool_calls else "stop",
            }
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


def _responses_api_response(model: str, result: dict[str, Any]) -> dict[str, Any]:
    output: list[dict[str, Any]] = []
    content = str(result.get("content", ""))
    if content:
        output.append(
            {
                "id": f"msg_{uuid.uuid4().hex}",
                "type": "message",
                "role": "assistant",
                "status": "completed",
                "content": [{"type": "output_text", "text": content, "annotations": []}],
            }
        )
    for item in result.get("tool_calls", []):
        output.append(
            {
                "id": f"fc_{uuid.uuid4().hex}",
                "type": "function_call",
                "call_id": f"call_{uuid.uuid4().hex}",
                "name": str(item["name"]),
                "arguments": json.dumps(item["arguments"], ensure_ascii=False),
                "status": "completed",
            }
        )
    return {
        "id": f"resp_{uuid.uuid4().hex}",
        "object": "response",
        "created_at": int(time.time()),
        "status": "completed",
        "model": model,
        "output": output,
        "output_text": content,
        "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
    }


def _anthropic_response(model: str, result: dict[str, Any]) -> dict[str, Any]:
    content: list[dict[str, Any]] = []
    if result.get("content"):
        content.append({"type": "text", "text": str(result["content"])})
    for item in result.get("tool_calls", []):
        content.append(
            {
                "type": "tool_use",
                "id": f"toolu_{uuid.uuid4().hex}",
                "name": str(item["name"]),
                "input": item["arguments"],
            }
        )
    return {
        "id": f"msg_{uuid.uuid4().hex}",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": "tool_use" if result.get("tool_calls") else "end_turn",
        "usage": {"input_tokens": 0, "output_tokens": 0},
    }


def _ollama_response(model: str, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "model": model,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "message": {"role": "assistant", "content": str(result.get("content", ""))},
        "done": True,
        "done_reason": "stop",
    }


def _docker_bridge_gateway() -> str:
    try:
        completed = subprocess.run(
            ["docker", "network", "inspect", "bridge", "--format", "{{(index .IPAM.Config 0).Gateway}}"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        gateway = completed.stdout.strip()
        if gateway:
            return gateway
    except (OSError, subprocess.SubprocessError):
        pass
    return "172.17.0.1"
