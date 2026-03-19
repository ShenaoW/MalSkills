#!/bin/bash
#
# Script 3: Download repositories
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

init_config

log_info "=========================================="
log_info "Step 3: Download Repositories"
log_info "=========================================="

cd "$PROJECT_ROOT"

# Check mapping files
if [ ! -f "$DATA_DIR/repo_skill_mapping.json" ]; then
    log_error "Mapping file not found: $DATA_DIR/repo_skill_mapping.json"
    log_error "Please run step 2 (generate mapping) first"
    exit 1
fi

# Run downloader
python3 -c "
import sys
sys.path.insert(0, '.')
from scanner.scanner import RepoDownloader, Config

config = Config()
downloader = RepoDownloader(config)

# Load mapping
import json
with open('$DATA_DIR/repo_skill_mapping.json', 'r') as f:
    mapping = json.load(f)

# Prepare repo info with id_prefix
for item in mapping:
    item['id_prefix'] = item.get('id_prefix', 'rest_')

# Download
result = downloader.download_all(mapping, limit=$DOWNLOAD_LIMIT)

print(f\"Total: {result['total']}\")
print(f\"Success: {result['success']}\")
print(f\"Failed: {result['failed']}\")
print(f\"Skipped: {result['skipped']}\")
"

log_success "Download complete!"
log_info "ZIP files: $WORKSPACE_DIR/zip/"
