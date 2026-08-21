#!/bin/bash
#
# Codex Security Analyzer v1.0
# Performs detailed security analysis on skills using Codex via an OpenAI-compatible API
#

set -e

# Configuration
OUTPUT_SUFFIX="_audit.json"
JOBS=${CC_JOBS:-10}
MAX_RETRIES=${CC_MAX_RETRIES:-3}

# Colors for output
export GREEN='\033[0;32m'
export BLUE='\033[0;34m'
export RED='\033[0;31m'
export YELLOW='\033[1;33m'
export CYAN='\033[0;36m'
export NC='\033[0m'

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SEARCH_DIR="$PROJECT_ROOT"
while [ "$SEARCH_DIR" != "/" ]; do
    ENV_FILE="$SEARCH_DIR/.env"
    if [ -f "$ENV_FILE" ]; then
        set -a
        source "$ENV_FILE"
        set +a
        break
    fi
    SEARCH_DIR="$(dirname "$SEARCH_DIR")"
done

# Source config loader
source "$PROJECT_ROOT/scripts/lib.sh"

# Initialize paths using config
init_config

# Output directories
OUTPUT_DIR="$SCAN_RESULTS_DIR"
mkdir -p "$OUTPUT_DIR"/{SAFE,SUSPICIOUS,MALICIOUS,ERROR,logs}

# Log file
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$OUTPUT_DIR/logs/cc_analyze_${TIMESTAMP}.log"

# Cache files
INDEX_FILE="$OUTPUT_DIR/index.cache"
TODO_FILE="$OUTPUT_DIR/todo.cache"
SKIPPED_LOG="$OUTPUT_DIR/logs/skipped.log"

# Command line arguments
QUEUE_FILE="${1:-}"
SKIP_CROSS_CHECK="${2:-false}"

log() {
    local msg="$1"
    echo -e "$msg"
    echo -e "$msg" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE"
}

# Core analysis function
analyze_single_skill() {
    local skill_dir="$1"
    local repo_id="$2"
    local skill_name="$3"

    local filename="${repo_id}_${skill_name}${OUTPUT_SUFFIX}"
    local tmp_out=$(mktemp)

    # Load prompt
    local prompt_file="$PROJECT_ROOT/analyzer/prompts/audit_prompt.txt"
    if [ ! -f "$prompt_file" ]; then
        log "${RED}Error: Prompt file not found: $prompt_file${NC}"
        echo "ERROR|$repo_id|$skill_name|PROMPT_NOT_FOUND"
        return
    fi

    local llm_model="${OPENAI_MODEL:-${LLM_MODEL:-gpt-5.6-luna}}"

    # The MalSkills adapter exposes one OpenAI-compatible endpoint for either
    # Codex CLI or a configured upstream API.
    "${MALSKILLS_MASB_PYTHON:-python3}" -m malskills.baselines.masb_llm \
        "$skill_dir" \
        "$prompt_file" \
        "$tmp_out" \
        "$MALSKILLS_MASB_LLM_BASE_URL" \
        "$MALSKILLS_MASB_LLM_API_KEY" \
        "$llm_model" > /dev/null 2>&1 < /dev/null

    local exit_code=$?

    if [ ! -s "$tmp_out" ]; then
        exit_code=1
    fi

    # Process result
    if [ $exit_code -eq 0 ]; then
        local raw=$(cat "$tmp_out")

        # Clean JSON response
        local clean_json=$(python3 -c "
import sys, json, re
try:
    raw_input = sys.stdin.read()
    start_index = raw_input.find('{')
    if start_index == -1:
        print(raw_input)
        sys.exit(0)
    json_text = raw_input[start_index:]

    # Parse wrapper
    try:
        wrapper = json.loads(json_text)
        if isinstance(wrapper, dict) and 'result' in wrapper:
            inner_content = wrapper['result']
        else:
            inner_content = json_text
    except:
        match = re.search(r'(\{.*\})', json_text, re.DOTALL)
        if match:
            inner_content = match.group(1)
        else:
            inner_content = json_text

    # Extract JSON from markdown
    match = re.search(r'\`\`\`(?:json)?\s*(\{.*?\})\s*\`\`\`', inner_content, re.DOTALL | re.IGNORECASE)
    if match:
        final_json = match.group(1)
    else:
        # Greedy match
        s = inner_content.find('{')
        e = inner_content.rfind('}')
        if s != -1 and e != -1:
            final_json = inner_content[s:e+1]
        else:
            final_json = inner_content

    json.loads(final_json)
    print(final_json)
except:
    print(raw_input)
" <<< "$raw")

        # Validate and save
        if echo "$clean_json" | jq . >/dev/null 2>&1; then
            local enriched_json
            enriched_json=$(echo "$clean_json" | jq \
                --arg skill_path "$skill_dir" \
                --arg repo_id "$repo_id" \
                --arg skill_name "$skill_name" \
                '. + {
                    skill_path: $skill_path,
                    repo_id: $repo_id,
                    skill_name: $skill_name
                }')

            local status=$(echo "$enriched_json" | jq -r '.audit_summary.intent_alignment_status' | tr -d '[:space:]')

            if [ -z "$status" ] || [ "$status" == "null" ]; then
                echo "$enriched_json" > "${OUTPUT_DIR}/ERROR/${filename}.status_missing.err"
                echo "ERROR|$repo_id|$skill_name|STATUS_MISSING"
            else
                local target_dir="$OUTPUT_DIR/ERROR"
                case "$status" in
                    "SAFE") target_dir="$OUTPUT_DIR/SAFE" ;;
                    "SUSPICIOUS") target_dir="$OUTPUT_DIR/SUSPICIOUS" ;;
                    "MALICIOUS") target_dir="$OUTPUT_DIR/MALICIOUS" ;;
                    *) target_dir="$OUTPUT_DIR/ERROR" ;;
                esac
                echo "$enriched_json" > "${target_dir}/${filename}"
                echo "DONE|$repo_id|$skill_name|$status"
            fi
        else
            echo "$raw" > "${OUTPUT_DIR}/ERROR/${filename}.parse_err"
            echo "ERROR|$repo_id|$skill_name|INVALID_JSON"
        fi
    else
        echo "ERROR|$repo_id|$skill_name|API_FAIL"
    fi

    rm -f "$tmp_out"
}

export OUTPUT_DIR OUTPUT_SUFFIX PROJECT_ROOT OPENAI_MODEL LLM_MODEL
export MALSKILLS_MASB_PYTHON MALSKILLS_MASB_LLM_BASE_URL MALSKILLS_MASB_LLM_API_KEY
export -f analyze_single_skill

# Main execution
main() {
    log "${BLUE}======================================${NC}"
    log "${BLUE}CC Security Analyzer v1.0${NC}"
    log "${BLUE}======================================${NC}"

    # Check queue file
    if [ -z "$QUEUE_FILE" ] || [ ! -f "$QUEUE_FILE" ]; then
        log "${RED}Error: Queue file not specified or not found${NC}"
        log "Usage: $0 <queue_file> [skip_cross_check]"
        exit 1
    fi

    TOTAL_COUNT=$(wc -l < "$QUEUE_FILE")
    log "Queue file: $QUEUE_FILE"
    log "Total tasks: ${GREEN}${TOTAL_COUNT}${NC}"
    log "Workers: $JOBS"

    # Generate TODO list (skip existing)
    log "${YELLOW}Generating TODO list...${NC}"

    python3 -c "
import os, sys

queue_file = '$QUEUE_FILE'
scan_dir = '$OUTPUT_DIR'
output_suffix = '$OUTPUT_SUFFIX'
skip_cross_check = '$SKIP_CROSS_CHECK'

# Load existing results
existing_files = set()
for subdir in ['SAFE', 'SUSPICIOUS', 'MALICIOUS', 'ERROR']:
    path = os.path.join(scan_dir, subdir)
    if os.path.exists(path):
        existing_files.update(os.listdir(path))

print(f'Existing results: {len(existing_files)}')

# Process queue
todo_count = 0
with open(queue_file, 'r') as f_in, open('$TODO_FILE', 'w') as f_out:
    for line in f_in:
        line = line.strip()
        if not line:
            continue

        parts = line.split('|')
        if len(parts) < 4:
            continue

        skill_name = parts[0]
        repo_id = parts[3]
        target_name = f'{repo_id}_{skill_name}{output_suffix}'

        # Skip if already exists
        if target_name in existing_files:
            continue

        f_out.write(line + '\\n')
        todo_count += 1

print(f'TODO count: {todo_count}')
"

    TOTAL_TODO=$(wc -l < "$TODO_FILE")

    if [ "$TOTAL_TODO" -eq 0 ]; then
        log "${GREEN}All tasks already completed!${NC}"
        exit 0
    fi

    log "Tasks to process: ${GREEN}${TOTAL_TODO}${NC}"
    log "----------------------------------------"

    # Process queue
    COUNT_SAFE=0
    COUNT_SUSP=0
    COUNT_MAL=0
    COUNT_ERR=0
    PROCESSED=0

    cat "$TODO_FILE" | xargs -P "$JOBS" -I {} bash -c '
        IFS="|" read -r skill_name skill_path prompt repo_id risk_level rest <<< "{}"
        analyze_single_skill "$skill_path" "$repo_id" "$skill_name"
    ' | while read -r line; do
        PROCESSED=$((PROCESSED + 1))
        IFS='|' read -r status repo skill verdict <<< "$line"

        if [ "$status" == "DONE" ]; then
            case "$verdict" in
                "SAFE") COUNT_SAFE=$((COUNT_SAFE + 1)); log "[$PROCESSED/$TOTAL_TODO] ${BLUE}${repo}_${skill}${NC} -> ${GREEN}[SAFE]${NC}" ;;
                "SUSPICIOUS") COUNT_SUSP=$((COUNT_SUSP + 1)); log "[$PROCESSED/$TOTAL_TODO] ${BLUE}${repo}_${skill}${NC} -> ${YELLOW}[SUSPICIOUS]${NC}" ;;
                "MALICIOUS") COUNT_MAL=$((COUNT_MAL + 1)); log "[$PROCESSED/$TOTAL_TODO] ${BLUE}${repo}_${skill}${NC} -> ${RED}[MALICIOUS]${NC}" ;;
                *) COUNT_ERR=$((COUNT_ERR + 1)); log "[$PROCESSED/$TOTAL_TODO] ${repo}_${skill} -> ${CYAN}[${verdict}]${NC}" ;;
            esac
        else
            COUNT_ERR=$((COUNT_ERR + 1))
            log "[$PROCESSED/$TOTAL_TODO] ${RED}Failed: ${repo}_${skill}${NC}"
        fi

        if (( PROCESSED % 20 == 0 )); then
            log "${CYAN}Progress: SAFE=$COUNT_SAFE | SUSP=$COUNT_SUSP | MAL=$COUNT_MAL | ERR=$COUNT_ERR${NC}"
        fi
    done

    log "======================================"
    log "Analysis Complete!"
    log "SAFE: $COUNT_SAFE | SUSPICIOUS: $COUNT_SUSP | MALICIOUS: $COUNT_MAL | ERR: $COUNT_ERR"
    log "======================================"
}

main "$@"
