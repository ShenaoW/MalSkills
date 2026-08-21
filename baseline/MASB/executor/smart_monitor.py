#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Smart File System Monitor
Creates snapshots and analyzes file system changes
"""

import sys
import json
import os
from pathlib import Path
from typing import Dict, List, Any


def snapshot(output_path: str, target_dir: str) -> None:
    """
    Create a snapshot of the file system

    Args:
        output_path: Path to save snapshot JSON
        target_dir: Directory to snapshot
    """
    snapshot_data = {}
    target_path = Path(target_dir)

    if not target_path.exists():
        print(f"Error: Target directory does not exist: {target_dir}")
        return

    for item in target_path.rglob("*"):
        if item.is_file():
            try:
                stat = item.stat()
                rel_path = str(item.relative_to(target_path))
                snapshot_data[rel_path] = {
                    "size": stat.st_size,
                    "mode": stat.st_mode,
                    "mtime": stat.st_mtime,
                    "inode": stat.st_ino
                }
            except (OSError, ValueError):
                pass

    with open(output_path, 'w') as f:
        json.dump(snapshot_data, f, indent=2)

    print(f"Snapshot saved: {len(snapshot_data)} files")


def diff(snapshot_path: str, target_dir: str, output_dir: str) -> None:
    """
    Compare snapshot with current state and report changes

    Args:
        snapshot_path: Path to snapshot JSON
        target_dir: Directory to analyze
        output_dir: Directory to save diff report
    """
    target_path = Path(target_dir)

    if not target_path.exists():
        print(f"Error: Target directory does not exist: {target_dir}")
        return

    # Load snapshot
    with open(snapshot_path, 'r') as f:
        snapshot_data = json.load(f)

    # Get current state
    current_data = {}
    for item in target_path.rglob("*"):
        if item.is_file():
            try:
                stat = item.stat()
                rel_path = str(item.relative_to(target_path))
                current_data[rel_path] = {
                    "size": stat.st_size,
                    "mode": stat.st_mode,
                    "mtime": stat.st_mtime,
                    "inode": stat.st_ino
                }
            except (OSError, ValueError):
                pass

    # Analyze changes
    changes = {
        "created": [],
        "modified": [],
        "deleted": [],
        "unchanged": []
    }

    snapshot_files = set(snapshot_data.keys())
    current_files = set(current_data.keys())

    # Created files
    for path in current_files - snapshot_files:
        changes["created"].append({
            "path": path,
            "size": current_data[path]["size"]
        })

    # Deleted files
    for path in snapshot_files - current_files:
        changes["deleted"].append({"path": path})

    # Modified files
    for path in snapshot_files & current_files:
        old_stat = snapshot_data[path]
        new_stat = current_data[path]

        if (old_stat["size"] != new_stat["size"] or
            old_stat["mtime"] != new_stat["mtime"]):
            changes["modified"].append({
                "path": path,
                "old_size": old_stat["size"],
                "new_size": new_stat["size"]
            })
        else:
            changes["unchanged"].append(path)

    # Save report
    output_path = Path(output_dir) / "filesystem_changes.json"
    with open(output_path, 'w') as f:
        json.dump(changes, f, indent=2)

    print(f"File changes: {len(changes['created'])} created, {len(changes['modified'])} modified, {len(changes['deleted'])} deleted")
    print(f"Report saved: {output_path}")


def main():
    if len(sys.argv) < 3:
        print("Usage:")
        print("  Snapshot: python3 smart_monitor.py snapshot <output.json> <target_dir>")
        print("  Diff: python3 smart_monitor.py diff <snapshot.json> <target_dir> <output_dir>")
        sys.exit(1)

    command = sys.argv[1]

    if command == "snapshot":
        snapshot(sys.argv[2], sys.argv[3])
    elif command == "diff":
        diff(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
