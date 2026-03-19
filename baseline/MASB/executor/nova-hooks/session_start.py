#!/usr/bin/env python3
"""
NOVA Session Start Hook
Called when a Claude Code session begins
"""
import os
import sys
import json
from datetime import datetime

# Add NOVA to path if installed
NOVA_PATH = "/opt/nova-protector"
if os.path.exists(NOVA_PATH):
    sys.path.insert(0, NOVA_PATH)

def main():
    # Create session report
    session_id = os.environ.get("NOVA_SESSION_ID", f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    report_dir = os.environ.get("NOVA_REPORT_DIR", "/tmp/nova_reports")

    os.makedirs(report_dir, exist_ok=True)

    session_info = {
        "session_id": session_id,
        "start_time": datetime.now().isoformat(),
        "user": os.environ.get("USER", "unknown"),
        "home": os.environ.get("HOME", "unknown"),
    }

    session_file = os.path.join(report_dir, f"{session_id}_start.json")
    with open(session_file, "w") as f:
        json.dump(session_info, f, indent=2)

    print(f"[NOVA] Session started: {session_id}", file=sys.stderr)

if __name__ == "__main__":
    main()
