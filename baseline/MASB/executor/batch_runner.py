# -*- coding: utf-8 -*-
"""
Batch Execution Runner
Executes multiple skills concurrently in Docker containers
"""

import os
import sys
import subprocess
import time
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.config_loader import Config
from utils.api_key_pool import APIKeyPool


def run_task(line: str, config: Config, api_pool: APIKeyPool, ex_mode: bool = False) -> tuple:
    """
    Execute a single skill task

    Args:
        line: Task line (format: skill_name|skill_path|prompt|repo_id|risk_level|top_level)
        config: Configuration object
        api_pool: API key pool
        ex_mode: Extended mode flag

    Returns:
        Tuple of (success, message)
    """
    try:
        parts = line.strip().split('|')

        if len(parts) < 3:
            return False, f"Invalid format: {line}"

        skill_name = parts[0]
        skill_path = parts[1]
        prompt = parts[2]

        if ex_mode and len(parts) >= 6:
            repo_id = parts[3]
            risk_level = parts[4]
            top_level = parts[5]
        else:
            repo_id = "unknown"
            risk_level = "unknown"

        # Get API key from pool
        api_key = api_pool.get_next_key()

        print(f"\n{'='*60}")
        print(f"Starting: {skill_name} ({repo_id}/{risk_level})")
        if api_key:
            print(f"API Key: {api_key[:20]}...")
        print(f"{'='*60}")

        sys.stdout.flush()

        # Build command
        cmd = [
            str(Path(__file__).parent / "run_skill.sh"),
            skill_name,
            skill_path,
            prompt,
            repo_id,
            risk_level,
            "false"  # in_place_log
        ]

        # Set environment
        env = os.environ.copy()
        if api_key:
            env["ANTHROPIC_API_KEY"] = api_key

        base_url = config.get_with_env_fallback(
            'analyzer.api.base_url_env',
            'ANTHROPIC_BASE_URL',
            'https://api.anthropic.com'
        )
        env["ANTHROPIC_BASE_URL"] = base_url

        env["PROJECT_ROOT"] = str(config.root_dir)
        env["EXECUTION_LOGS_DIR"] = str(config.paths.execution_logs_dir)
        env["EXEC_TIMEOUT"] = str(config.get('executor.timeout', 900))

        # Execute
        result = subprocess.run(
            cmd,
            env=env,
            stdout=None,
            stderr=None,
            text=True
        )

        if result.returncode == 0:
            print(f"\nSuccess: {skill_name}")
            sys.stdout.flush()
            return True, f"[{skill_name}] Success"
        else:
            print(f"\nFailed: {skill_name} (exit code: {result.returncode})")
            sys.stdout.flush()
            return False, f"[{skill_name}] Failed (code {result.returncode})"

    except Exception as e:
        print(f"\nError: {str(e)}")
        sys.stdout.flush()
        return False, f"Exception: {str(e)}"


def main():
    parser = argparse.ArgumentParser(description="Batch Skill Execution Runner")
    parser.add_argument("task_file", help="Task queue file path")
    parser.add_argument("--workers", type=int, default=3, help="Concurrent workers (default: 3)")
    parser.add_argument("--sequential", action="store_true", help="Sequential mode")
    parser.add_argument("--config", default=None, help="Config file path")
    args = parser.parse_args()

    # Load configuration
    config = Config(args.config)

    task_file = Path(args.task_file)
    if not task_file.exists():
        print(f"Error: Task file not found: {task_file}")
        sys.exit(1)

    with open(task_file, 'r') as f:
        lines = [l.strip() for l in f if l.strip()]

    total = len(lines)
    workers = args.workers
    sequential = args.sequential

    print(f"\n{'='*60}")
    print(f"Batch Execution Runner")
    print(f"{'='*60}")
    print(f"Tasks: {total}")
    print(f"Mode: {'Sequential' if sequential else f'Concurrent (workers={workers})'}")
    print(f"{'='*60}\n")

    # Initialize API key pool
    api_pool = APIKeyPool(config.root_dir / "api_keys.conf")

    results = []

    if sequential:
        # Sequential execution
        for i, line in enumerate(lines, 1):
            print(f"\nProgress: [{i}/{total}]")
            success, msg = run_task(line, config, api_pool)
            results.append(success)
            time.sleep(1)
    else:
        # Concurrent execution
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = []
            for line in lines:
                futures.append(executor.submit(run_task, line, config, api_pool))
                time.sleep(2)  # Stagger submissions

            for future in as_completed(futures):
                success, msg = future.result()
                results.append(success)

    # Summary
    success_count = sum(results)
    print("\n" + "="*60)
    print("Execution Complete")
    print("="*60)
    print(f"Total: {total}")
    print(f"Success: {success_count}")
    print(f"Failed: {total - success_count}")
    print("="*60)

    if success_count < total:
        sys.exit(1)


if __name__ == "__main__":
    main()
