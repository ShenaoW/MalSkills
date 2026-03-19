# -*- coding: utf-8 -*-
"""
Path Helper Module
Provides path utilities for the project
"""

import os
from pathlib import Path
from typing import Optional


def get_project_root() -> Path:
    """Get project root directory"""
    # Start from current file and go up
    current = Path(__file__).resolve()
    for _ in range(3):  # Go up 3 levels: utils/ -> project/
        current = current.parent
        if (current / "config.yaml").exists():
            return current
    return Path.cwd()


def ensure_dir(path: Path) -> Path:
    """
    Ensure directory exists, create if not

    Args:
        path: Directory path

    Returns:
        Path object
    """
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_relative_path(path: Path, base: Optional[Path] = None) -> Path:
    """
    Get relative path from base

    Args:
        path: Absolute path
        base: Base directory (default: project root)

    Returns:
        Relative path
    """
    if base is None:
        base = get_project_root()
    try:
        return path.relative_to(base)
    except ValueError:
        return path


def find_skill_markdown(directory: Path) -> Optional[Path]:
    """
    Find SKILL.md in directory

    Args:
        directory: Directory to search

    Returns:
        Path to SKILL.md or None
    """
    skill_md = directory / "SKILL.md"
    if skill_md.exists():
        return skill_md
    return None


def is_skill_directory(directory: Path) -> bool:
    """
    Check if directory is a valid skill directory

    Args:
        directory: Directory to check

    Returns:
        True if directory contains skill indicators
    """
    indicators = [
        "SKILL.md",
        "skill.json",
        "api.json",
        "tool.json",
        "SKILL"
    ]

    for indicator in indicators:
        if (directory / indicator).exists():
            return True
    return False
