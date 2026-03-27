#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run AI-Infra-Guard agent-scan on one repository and write JSON output."
    )
    parser.add_argument("--repo", required=True, help="Repository path to scan")
    parser.add_argument("--output", required=True, help="Destination JSON report path")
    parser.add_argument("-p", "--prompt", default="", help="Additional scan prompt")
    parser.add_argument("-m", "--model", default=None, help="LLM model name override")
    parser.add_argument("-k", "--api-key", dest="api_key", default=None, help="LLM API key override")
    parser.add_argument("-u", "--base-url", dest="base_url", default=None, help="LLM base URL override")
    parser.add_argument("--agent-provider", default="", help="Agent provider YAML path")
    parser.add_argument("--language", default="zh", choices=["zh", "en"], help="Output language")
    return parser.parse_args()


def _load_agent_scan_modules(agent_scan_root: Path) -> tuple[object, object, object, object, object, object]:
    if str(agent_scan_root) not in sys.path:
        sys.path.insert(0, str(agent_scan_root))

    from core.agent import Agent  # type: ignore[import-not-found]
    from core.agent_adapter.adapter import AIProviderClient  # type: ignore[import-not-found]
    from core.agent_adapter.connectivity import connectivity  # type: ignore[import-not-found]
    from utils import config  # type: ignore[import-not-found]
    from utils.llm import LLM  # type: ignore[import-not-found]
    from utils.llm_manager import LLMManager  # type: ignore[import-not-found]

    import tools as _  # type: ignore[import-not-found]  # noqa: F401

    return Agent, AIProviderClient, connectivity, config, LLM, LLMManager


async def _run() -> int:
    args = parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    agent_scan_root = repo_root / "baseline" / "AI-Infra-Guard" / "agent-scan"
    Agent, AIProviderClient, connectivity, config, LLM, LLMManager = _load_agent_scan_modules(agent_scan_root)

    api_key = args.api_key or os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        print("OPENROUTER_API_KEY is required for AI-Infra-Guard agent-scan.", file=sys.stderr)
        return 2

    model = args.model or getattr(config, "DEFAULT_MODEL")
    base_url = args.base_url or getattr(config, "DEFAULT_BASE_URL")

    repo_path = Path(args.repo).resolve()
    if not repo_path.exists():
        print(f"Repository path does not exist: {repo_path}", file=sys.stderr)
        return 2
    if not repo_path.is_dir():
        print(f"Repository path is not a directory: {repo_path}", file=sys.stderr)
        return 2

    llm = LLM(model=model, api_key=api_key, base_url=base_url)
    llm_manager = LLMManager(api_key=api_key, base_url=base_url)
    specialized_llms = llm_manager.get_specialized_llms(["thinking", "coding"])

    agent_provider = args.agent_provider
    if agent_provider:
        default_client = AIProviderClient()
        if not connectivity(default_client, agent_provider):
            print(f"Agent provider is not valid: {agent_provider}", file=sys.stderr)
            return 2

    prompt = args.prompt
    if args.language == "en":
        prompt += " All responses should be in English."
    else:
        prompt += " 所有回复都应使用中文。"

    agent = Agent(
        llm=llm,
        specialized_llms=specialized_llms,
        debug=True,
        language=args.language,
        agent_provider=agent_provider,
    )
    result = await agent.scan(str(repo_path), prompt)

    output_path = Path(args.output).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False))
    return 0


def main() -> int:
    return asyncio.run(_run())


if __name__ == "__main__":
    raise SystemExit(main())
