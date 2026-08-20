from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 6:
        raise SystemExit(
            "usage: skillsieve_codex SKILL_PATH BASE_URL API_KEY MODEL MAX_LAYER"
        )
    skill_path = Path(sys.argv[1]).resolve()
    base_url, api_key, model = sys.argv[2:5]
    max_layer = int(sys.argv[5])

    from skillsieve.adapters.llm_adapter import MODEL_PROFILES
    from skillsieve.core.pipeline import Pipeline

    MODEL_PROFILES["malskills_codex_cli"] = {
        "base_url": f"{base_url.rstrip('/')}/chat/completions",
        "api_type": "openai",
        "model": model,
        "env_key": "",
    }
    pipeline = Pipeline(
        max_layer=max_layer,
        layer2_profile="malskills_codex_cli",
        layer3_profiles=["malskills_codex_cli"] * 3,
    )
    pipeline._l2._adapter.api_key = api_key
    for adapter in pipeline._l3._adapters:
        adapter.api_key = api_key
    result = asyncio.run(pipeline.scan(skill_path))
    print(result.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
