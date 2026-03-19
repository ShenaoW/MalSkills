#!/usr/bin/env python3
"""
NOVA Session End Hook
Called when a Claude Code session ends
Generates final security report
"""
import os
import sys
import json
from datetime import datetime

# Add NOVA to path if installed
NOVA_PATH = "/opt/nova-protector"
if os.path.exists(NOVA_PATH):
    sys.path.insert(0, NOVA_PATH)

def generate_summary(report_dir: str, session_id: str):
    """Generate summary report for the session"""
    tools_file = os.path.join(report_dir, f"{session_id}_tools.jsonl")

    summary = {
        "session_id": session_id,
        "end_time": datetime.now().isoformat(),
        "total_tool_calls": 0,
        "tools_used": {},
        "nova_alerts": 0,
    }

    if os.path.exists(tools_file):
        with open(tools_file, "r") as f:
            for line in f:
                if not line.strip():
                    continue
                entry = json.loads(line)
                summary["total_tool_calls"] += 1

                tool_name = entry.get("tool", "unknown")
                summary["tools_used"][tool_name] = summary["tools_used"].get(tool_name, 0) + 1

                if entry.get("matched_rules", 0) > 0:
                    summary["nova_alerts"] += 1

    summary_file = os.path.join(report_dir, f"{session_id}_summary.json")
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"[NOVA] Session ended: {session_id}", file=sys.stderr)
    print(f"[NOVA] Tool calls: {summary['total_tool_calls']}, Alerts: {summary['nova_alerts']}", file=sys.stderr)

def main():
    session_id = os.environ.get("NOVA_SESSION_ID", "unknown")
    report_dir = os.environ.get("NOVA_REPORT_DIR", "/tmp/nova_reports")

    generate_summary(report_dir, session_id)

if __name__ == "__main__":
    main()
