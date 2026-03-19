#!/bin/bash
#
# Script 7: Generate execution queue from MALICIOUS skills
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

init_config

log_info "=========================================="
log_info "Step 7: Generate Execution Queue"
log_info "=========================================="

QUEUE_FILE="$TASKS_DIR/run_queue.txt"
MALICIOUS_DIR="$SCAN_RESULTS_DIR/MALICIOUS"

if [ ! -d "$MALICIOUS_DIR" ]; then
    log_error "MALICIOUS directory not found: $MALICIOUS_DIR"
    log_error "Please run step 6 (CC analyze) first"
    exit 1
fi

# Count malicious skills
malicious_count=$(ls -1 "$MALICIOUS_DIR"/*_audit.json 2>/dev/null | wc -l)
if [ "$malicious_count" -eq 0 ]; then
    log_warn "No malicious skills found"
    exit 0
fi

log_info "Found $malicious_count malicious skills"

# Generate execution queue
python3 -c "
import json
import sys
from pathlib import Path

malicious_dir = Path('$MALICIOUS_DIR')
queue_file = Path('$QUEUE_FILE')

tasks = []

for audit_file in malicious_dir.glob('*_audit.json'):
    try:
        with open(audit_file, 'r') as f:
            audit = json.load(f)

        # Parse filename: rest_1_skillname_audit.json
        filename = audit_file.stem  # remove _audit.json
        parts = filename.split('_')

        if len(parts) >= 3:
            repo_id = f'{parts[0]}_{parts[1]}'
            skill_name = '_'.join(parts[2:])

            # Get skill path from audit
            skill_path = audit.get('skill_path', '')
            if not skill_path:
                continue

            # Check if already executed
            log_dir = Path('$EXECUTION_LOGS_DIR') / 'MALICIOUS' / repo_id / skill_name
            if log_dir.exists():
                continue

            # Format: skill_name|skill_path|prompt|repo_id|risk_level|top_level
            tasks.append('|'.join([
                skill_name,
                skill_path,
                'Read and execute all instructions in this skill',
                repo_id,
                'MALICIOUS',
                'malicious'
            ]))

    except Exception as e:
        print(f'Error processing {audit_file.name}: {e}')

# Save queue
with open(queue_file, 'w') as f:
    for task in tasks:
        f.write(task + '\\n')

print(f'Generated {len(tasks)} execution tasks')
print(f'Output: {queue_file}')
"

log_success "Execution queue generated!"
log_info "Queue file: $QUEUE_FILE"
