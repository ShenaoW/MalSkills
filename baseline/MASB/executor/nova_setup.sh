#!/bin/bash
#
# NOVA Protector Setup Script
# Configures NOVA hooks for Claude Code
#
# Usage: nova_setup.sh <appuser_home> [mode]
#   mode: "monitor" (default) - log only, don't block
#         "block"              - actively block dangerous operations
#

APPUSER_HOME="$1"
MODE="${2:-monitor}"  # monitor or block

if [ -z "$APPUSER_HOME" ]; then
    echo "Usage: $0 <appuser_home> [mode]"
    exit 1
fi

# Check if NOVA is installed
if [ ! -d "/opt/nova-protector/nova_hooks" ]; then
    echo "[NOVA] Not installed (NOVA_MODE=none)"
    exit 0
fi

CLAUDE_DIR="$APPUSER_HOME/.claude"
SETTINGS_FILE="$CLAUDE_DIR/settings.json"

mkdir -p "$CLAUDE_DIR"

# Create settings based on mode
if [ "$MODE" = "block" ]; then
    # Block mode: actively block dangerous operations
    cat > "$SETTINGS_FILE" <<EOF
{
  "hooks": {
    "SessionStart": "/opt/nova-protector/nova_hooks/session_start.py",
    "PreToolUse": "/opt/nova-protector/nova_hooks/pre_tool_use.py",
    "PostToolUse": "/opt/nova-protector/nova_hooks/post_tool_use.py",
    "SessionEnd": "/opt/nova-protector/nova_hooks/session_end.py"
  },
  "hookSettings": {
    "blockDangerousCommands": true,
    "alertOnSuspiciousActivity": true
  }
}
EOF
    export NOVA_BLOCK_MODE="true"
else
    # Monitor mode: only log, don't block
    cat > "$SETTINGS_FILE" <<EOF
{
  "hooks": {
    "SessionStart": "/opt/nova-protector/nova_hooks/session_start.py",
    "PostToolUse": "/opt/nova-protector/nova_hooks/post_tool_use.py",
    "SessionEnd": "/opt/nova-protector/nova_hooks/session_end.py"
  },
  "hookSettings": {
    "blockDangerousCommands": false,
    "alertOnSuspiciousActivity": true
  }
}
EOF
    export NOVA_BLOCK_MODE="false"
fi

chown -R appuser:appuser "$CLAUDE_DIR"

NOVA_MODE_INSTALLED=$(cat /opt/nova-protector/nova_mode 2>/dev/null || echo "unknown")
echo "[NOVA] Setup complete (mode: $MODE, installed: $NOVA_MODE_INSTALLED)"
