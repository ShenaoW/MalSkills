#!/bin/bash
#
# Script 1: Crawl skill data
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

init_config

log_info "=========================================="
log_info "Step 1: Crawl Skill Data"
log_info "=========================================="

# Check if skip is requested
if [ "$SKIP_CRAWL" = "true" ]; then
    log_warn "Skipping crawl (SKIP_CRAWL=true)"
    exit 0
fi

cd "$PROJECT_ROOT"

# Crawl skills.rest
if python3 -c "
import sys
sys.path.insert(0, '.')
from crawler.crawler import SkillsRestCrawler, Config

config = Config()
crawler = SkillsRestCrawler(config)
count = crawler.run()
print(f'SkillsRest: {count} new items')
"; then
    log_success "SkillsRest crawl complete"
else
    log_error "SkillsRest crawl failed"
fi

# Crawl skillsmp (if API key available)
if [ -n "$SKILLSMP_API_KEY" ]; then
    if python3 -c "
import sys
import os
sys.path.insert(0, '.')
os.environ['SKILLSMP_API_KEY'] = '$SKILLSMP_API_KEY'

from crawler.crawler import SkillsmpCrawler, Config

config = Config()
crawler = SkillsmpCrawler(config)
count = crawler.run()
print(f'SkillsMP: {count} new items')
"; then
        log_success "SkillsMP crawl complete"
    else
        log_warn "SkillsMP crawl failed"
    fi
else
    log_warn "SKILLSMP_API_KEY not set, skipping SkillsMP crawl"
fi

# Merge data
if python3 -c "
import sys
sys.path.insert(0, '.')
from crawler.crawler import DataMerger, Config

config = Config()
merger = DataMerger(config)
result = merger.merge()
print(f'Merge: {result}')
"; then
    log_success "Data merge complete"
else
    log_error "Data merge failed"
fi

log_success "Step 1 complete!"
