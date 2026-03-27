#!/bin/bash
#
# Script 4: Static security scan
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

init_config

log_info "=========================================="
log_info "Step 4: Static Security Scan"
log_info "=========================================="

cd "$PROJECT_ROOT"

# Check inputs
zip_count=$(find "$WORKSPACE_DIR/zip" -name "*.zip" 2>/dev/null | wc -l)
repo_count=$(find "$WORKSPACE_DIR/repo" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
if [ "$zip_count" -eq 0 ] && [ "$repo_count" -eq 0 ]; then
    log_error "No ZIP files found in $WORKSPACE_DIR/zip and no unpacked repos found in $WORKSPACE_DIR/repo"
    log_error "Please run step 3 (download) first or place unpacked samples in $WORKSPACE_DIR/repo"
    exit 1
fi

if [ "$zip_count" -gt 0 ]; then
    log_info "Found $zip_count ZIP files"
else
    log_info "Found $repo_count unpacked repositories"
fi

# Run scanner
SCAN_LIMIT_VALUE="${SCAN_LIMIT:-None}"

python3 -c "
import sys
sys.path.insert(0, '.')
from scanner.scanner import RepoSecurityScanner, Config
from pathlib import Path

config = Config()
scanner = RepoSecurityScanner(config)

zip_files = list(Path('$WORKSPACE_DIR/zip').glob('*.zip'))
repo_dirs = [p for p in Path('$WORKSPACE_DIR/repo').iterdir() if p.is_dir()] if Path('$WORKSPACE_DIR/repo').exists() else []
print(f'ZIP inputs: {len(zip_files)}')
print(f'Repo inputs: {len(repo_dirs)}')

# Scan
limit = $SCAN_LIMIT_VALUE
result = scanner.scan_all(limit=limit)

print(f\"\\nScan Results:\")
print(f\"Total: {result['total']}\")
print(f\"Scanned: {result['scanned']}\")
print(f\"Skipped: {result['skipped']}\")
print(f\"Failed: {result['failed']}\")
print(f\"\\nRisk Distribution:\")
for risk, count in result['by_risk'].items():
    if count > 0:
        print(f\"  {risk}: {count}\")
"

log_success "Static scan complete!"
log_info "Reports in: $WORKSPACE_DIR/{critical,high,medium,low,safe}/"
