#!/usr/bin/env python3
"""
NOVA Post-Tool Use Hook
Called after Claude executes a tool
Logs tool usage for security analysis
"""
import os
import sys
import json
from datetime import datetime

# Add NOVA to path if installed
NOVA_PATH = "/opt/nova-protector"
if os.path.exists(NOVA_PATH):
    sys.path.insert(0, NOVA_PATH)

# Try to import NOVA for semantic analysis
try:
    from nova.core.parser import NovaParser
    from nova.core.matcher import NovaMatcher
    NOVA_AVAILABLE = True
except ImportError:
    NOVA_AVAILABLE = False

def analyze_with_nova(input_text: str) -> dict:
    """Use NOVA to analyze input for malicious patterns"""
    if not NOVA_AVAILABLE:
        return {"nova_analysis": "unavailable"}

    try:
        matcher = NovaMatcher()
        result = matcher.match(input_text)
        return {
            "nova_analysis": "completed",
            "matched_rules": len(result.get("matches", [])),
            "risk_score": result.get("risk_score", 0)
        }
    except Exception as e:
        return {"nova_analysis": f"error: {str(e)}"}

def log_tool_use(tool_name: str, tool_input: dict, result: str):
    """Log tool usage to report file"""
    report_dir = os.environ.get("NOVA_REPORT_DIR", "/tmp/nova_reports")
    os.makedirs(report_dir, exist_ok=True)

    session_id = os.environ.get("NOVA_SESSION_ID", "unknown")

    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "session_id": session_id,
        "tool": tool_name,
        "input": tool_input,
        "input_preview": str(tool_input)[:200],  # Truncated for readability
    }

    # Analyze with NOVA if available
    input_text = json.dumps(tool_input)
    nova_result = analyze_with_nova(input_text)
    log_entry.update(nova_result)

    log_file = os.path.join(report_dir, f"{session_id}_tools.jsonl")

    with open(log_file, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

def main():
    if len(sys.argv) < 3:
        sys.exit(0)

    tool_name = sys.argv[1]
    tool_input = json.loads(sys.argv[2])
    # tool_result = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}

    log_tool_use(tool_name, tool_input, "")

if __name__ == "__main__":
    main()
