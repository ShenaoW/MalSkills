#!/bin/bash
#
# Main Pipeline Script
# Runs the complete security analysis pipeline
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

init_config

log_info "=========================================="
log_info "Claude Skill Security Pipeline"
log_info "=========================================="
log_info ""
log_info "Project Root: $PROJECT_ROOT"
log_info "Config: $PROJECT_ROOT/config.yaml"
log_info ""

# Parse arguments
SKIP_TO="${1:-}"

# Pipeline steps
steps=(
    "01_crawl.sh"
    "02_generate_mapping.sh"
    "03_download.sh"
    "04_scan.sh"
    "05_gen_cc_queue.sh"
    "06_cc_analyze.sh"
    "07_gen_run_queue.sh"
    "08_execute.sh"
)

step_names=(
    "Crawl"
    "Generate Mapping"
    "Download"
    "Static Scan"
    "Generate CC Queue"
    "CC Analyze"
    "Generate Run Queue"
    "Dynamic Execute"
)

# Find starting step
start_index=0
if [ -n "$SKIP_TO" ]; then
    for i in "${!step_names[@]}"; do
        if [ "${step_names[$i]}" = "$SKIP_TO" ]; then
            start_index=$i
            break
        fi
    done
fi

log_info "Starting from: ${step_names[$start_index]} (${steps[$start_index]})"
log_info ""

# Run pipeline
for ((i=$start_index; i<${#steps[@]}; i++)); do
    step="${steps[$i]}"
    name="${step_names[$i]}"

    log_info ""
    log_info "=========================================="
    log_info "Step $((i+1))/${#steps[@]}: $name"
    log_info "=========================================="

    bash "$SCRIPT_DIR/$step"

    log_success "Step $((i+1)) complete: $name"
done

log_info ""
log_info "=========================================="
log_info "Pipeline Complete!"
log_info "=========================================="
log_info ""
log_info "Results:"
log_info "  Scan Reports: $WORKSPACE_DIR/{critical,high,medium,low,safe}/"
log_info "  CC Analysis: $SCAN_RESULTS_DIR/{SAFE,SUSPICIOUS,MALICIOUS}/"
log_info "  Execution Logs: $EXECUTION_LOGS_DIR/"
log_info ""
