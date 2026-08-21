#!/usr/bin/env python3
"""
NOVA Pre-Tool Use Hook
Called before Claude executes a tool
Can be used to block dangerous operations
"""
import os
import sys
import json

# Add NOVA to path if installed
NOVA_PATH = "/opt/nova-protector"
if os.path.exists(NOVA_PATH):
    sys.path.insert(0, NOVA_PATH)

# Dangerous command patterns to block
DANGEROUS_PATTERNS = [
    "rm -rf /",
    "mkfs",
    "dd if=",
    "chmod 000",
    "chattr +i",
    ":(){:|:&};:",  # fork bomb
    "curl | bash",
    "wget | bash",
    "eval $(",
    "exec $(",
]

BLOCK_MODE = os.environ.get("NOVA_BLOCK_MODE", "false") == "true"

def check_command(command: str) -> tuple[bool, str]:
    """Check if command contains dangerous patterns"""
    for pattern in DANGEROUS_PATTERNS:
        if pattern in command:
            return True, f"Dangerous pattern detected: {pattern}"
    return False, ""

def main():
    if len(sys.argv) < 2:
        sys.exit(0)

    tool_input = json.loads(sys.argv[1])
    command = ""

    # Extract command from common tools
    if tool_input.get("name") == "Bash":
        command = tool_input.get("input", {}).get("command", "")
    elif tool_input.get("name") == "Edit":
        command = tool_input.get("input", {}).get("old_string", "")

    if command:
        is_dangerous, reason = check_command(command)
        if is_dangerous and BLOCK_MODE:
            print(f"[NOVA] BLOCKED: {reason}", file=sys.stderr)
            sys.exit(1)  # Block the operation

if __name__ == "__main__":
    main()
