#!/bin/bash
#
# Shared library functions for scripts
#

# Colors
export GREEN='\033[0;32m'
export BLUE='\033[0;34m'
export RED='\033[0;31m'
export YELLOW='\033[1;33m'
export CYAN='\033[0;36m'
export NC='\033[0m'

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Paths (will be initialized)
DATA_DIR=""
WORKSPACE_DIR=""
SCAN_RESULTS_DIR=""
EXECUTION_LOGS_DIR=""
TASKS_DIR=""

# Initialize paths from config
init_config() {
    local config_file="$PROJECT_ROOT/config.yaml"

    if [ ! -f "$config_file" ]; then
        echo "Error: Config file not found: $config_file"
        exit 1
    fi

    # Parse paths from config (using Python for reliability)
    local paths_output=$(python3 -c "
import sys
sys.path.insert(0, '$PROJECT_ROOT')
from utils.config_loader import Config

config = Config('$config_file')
paths = config.paths

print(paths.data_dir)
print(paths.workspace_dir)
print(paths.scan_results_dir)
print(paths.execution_logs_dir)
print(paths.tasks_dir)
" 2>/dev/null)

    if [ -z "$paths_output" ]; then
        echo "Error: Failed to parse config"
        exit 1
    fi

    # Read paths
    DATA_DIR=$(echo "$paths_output" | sed -n '1p')
    WORKSPACE_DIR=$(echo "$paths_output" | sed -n '2p')
    SCAN_RESULTS_DIR=$(echo "$paths_output" | sed -n '3p')
    EXECUTION_LOGS_DIR=$(echo "$paths_output" | sed -n '4p')
    TASKS_DIR=$(echo "$paths_output" | sed -n '5p')

    # Export paths
    export DATA_DIR WORKSPACE_DIR SCAN_RESULTS_DIR EXECUTION_LOGS_DIR TASKS_DIR
    export PROJECT_ROOT

    # Create directories
    mkdir -p "$DATA_DIR" "$WORKSPACE_DIR" "$SCAN_RESULTS_DIR" "$EXECUTION_LOGS_DIR" "$TASKS_DIR"
    mkdir -p "$WORKSPACE_DIR/zip"
    mkdir -p "$WORKSPACE_DIR/repo"
    mkdir -p "$SCAN_RESULTS_DIR"/{SAFE,SUSPICIOUS,MALICIOUS,ERROR,logs}

    # Create risk directories
    for risk in critical high medium low safe; do
        mkdir -p "$WORKSPACE_DIR/$risk"
    done
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}
