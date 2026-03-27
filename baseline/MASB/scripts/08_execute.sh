#!/bin/bash
#
# Script 8: Execute skills dynamically
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

init_config

log_info "=========================================="
log_info "Step 8: Dynamic Execution"
log_info "=========================================="

QUEUE_FILE="$TASKS_DIR/run_queue.txt"

if [ ! -f "$QUEUE_FILE" ]; then
    log_error "Queue file not found: $QUEUE_FILE"
    log_error "Please run step 7 (generate execution queue) first"
    exit 1
fi

# Count tasks
task_count=$(wc -l < "$QUEUE_FILE")
log_info "Found $task_count execution tasks"

# Check Docker image
DOCKER_IMAGE="${DOCKER_IMAGE:-codex-skill-sandbox}"
if ! docker image inspect "$DOCKER_IMAGE" &>/dev/null; then
    log_warn "Docker image '$DOCKER_IMAGE' not found"
    log_info "Please build the image first: docker build -t $DOCKER_IMAGE -f Dockerfile ."
    log_info "Skipping execution..."
    exit 0
fi

# Run batch executor
python3 "$PROJECT_ROOT/executor/batch_runner.py" "$QUEUE_FILE" \
    --workers="${EXEC_WORKERS:-3}" \
    --config="$PROJECT_ROOT/config.yaml"

log_success "Dynamic execution complete!"
log_info "Execution logs in: $EXECUTION_LOGS_DIR/"
