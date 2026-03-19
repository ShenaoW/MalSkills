# Claude Skill Security Scanner

**This is the code component of [MaliciousAgentSkillsBench](../) - a security benchmark for Claude Code Agent Skills.**

A comprehensive security analysis pipeline for Claude Code Skills. Performs static code analysis, detailed AI-powered security auditing, and dynamic execution monitoring.

## Overview

This project provides an end-to-end security scanning pipeline for Claude Code Skills:

1. **Crawl** - Fetch skill metadata from skills.rest and skillsmp platforms
2. **Download** - Download skill repositories from GitHub
3. **Static Scan** - Rule-based security scanning
4. **CC Analysis** - AI-powered deep security analysis using Claude Code
5. **Dynamic Execute** - Execute skills in monitored Docker sandbox

## Features

- Multi-platform crawler (skills.rest, skillsmp.com)
- Concurrent repository downloading with branch fallback
- Static security scanning with configurable rules
- AI-powered code analysis using Claude Code API
- Dynamic execution in isolated Docker sandbox
- Comprehensive monitoring (strace, tcpdump, NOVA hooks)
- API key pool for concurrent operations
- Configurable pipeline with step-by-step execution

## Project Structure

```
code/                                 # This directory
├── analyzer/           # CC (Claude Code) analyzer module
│   ├── cc_analyzer.sh
│   └── prompts/         # Audit prompts
├── crawler/            # Web crawler module
│   └── crawler.py
├── data/               # Crawled data (gitignored)
├── executor/           # Dynamic execution module
│   ├── batch_runner.py
│   ├── nova-hooks/      # NOVA hook scripts
│   ├── nova_setup.sh
│   ├── run_skill.sh
│   └── smart_monitor.py
├── scanner/            # Static scanner module
│   ├── scanner.py
│   └── skill-security-scan/
├── scripts/            # Pipeline control scripts
│   ├── run_pipeline.sh  # Main pipeline entry point
│   ├── lib.sh           # Shared functions
│   ├── 01_crawl.sh
│   ├── 02_generate_mapping.sh
│   ├── 03_download.sh
│   ├── 04_scan.sh
│   ├── 05_gen_cc_queue.sh
│   ├── 06_cc_analyze.sh
│   ├── 07_gen_run_queue.sh
│   └── 08_execute.sh
├── tasks/              # Task queues (gitignored)
├── utils/              # Utility modules
│   ├── api_key_pool.py
│   ├── config_loader.py
│   └── path_helper.py
├── workspace/          # Working directory (gitignored)
├── scan_results/       # Analysis results (gitignored)
├── execution_logs/     # Execution logs (gitignored)
├── config.yaml         # Configuration file
├── .env.example        # Environment template
├── nova-requirements.txt  # NOVA ML dependencies
├── Dockerfile          # Docker sandbox image
├── DOCKER_BUILD.md     # Docker build guide
└── requirements.txt    # Python dependencies
```

## Installation

### Prerequisites

**For local analysis (outside Docker):**
- Python 3.10+
- GitHub Token (for downloading repositories)
- Anthropic API Key (for CC analysis)

**For Docker-based execution:**
- Docker (required for sandboxed skill execution)

**Both:**
- GitHub Token
- Anthropic API Key

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd MaliciousAgentSkillsBench/code
```

2. Install Python dependencies (for local analysis):
```bash
pip install -r requirements.txt
```

3. Build Docker sandbox image (for dynamic execution):

**Basic (without NOVA):**
```bash
docker build -t claude-skill-sandbox .
```

**With NOVA Lite** (pattern matching hooks only):
```bash
docker build --build-arg NOVA_MODE=lite -t claude-skill-sandbox .
```

**With NOVA Full** (includes ML dependencies for semantic analysis, ~2GB larger):
```bash
docker build --build-arg NOVA_MODE=full -t claude-skill-sandbox .
```

| Mode | ML Dependencies | Size | Features |
|------|-----------------|------|----------|
| `none` (default) | None | ~500MB | Basic strace/tcpdump monitoring |
| `lite` | None | ~520MB | Pattern-based hooks (keyword matching) |
| `full` | torch, transformers, sentence-transformers | ~2.5GB | Semantic analysis with NOVA framework |

4. Configure environment:
```bash
cp .env.example .env
# Edit .env with your API keys
```

5. Create API key pool (optional):
```bash
echo "sk-ant-key1" > api_keys.conf
echo "sk-ant-key2" >> api_keys.conf
```

## Usage

### Run Complete Pipeline

```bash
# Run all steps
./scripts/run_pipeline.sh

# Run from specific step
./scripts/run_pipeline.sh "Static Scan"
```

### Run Individual Steps

```bash
# Step 1: Crawl skill data
./scripts/01_crawl.sh

# Step 2: Generate repository mapping
./scripts/02_generate_mapping.sh

# Step 3: Download repositories
./scripts/03_download.sh

# Step 4: Static security scan
./scripts/04_scan.sh

# Step 5: Generate CC analysis queue
./scripts/05_gen_cc_queue.sh

# Step 6: Run CC analysis
./scripts/06_cc_analyze.sh

# Step 7: Generate execution queue
./scripts/07_gen_run_queue.sh

# Step 8: Dynamic execution
./scripts/08_execute.sh
```

### Python API

```python
from utils.config_loader import Config
from crawler.crawler import SkillsRestCrawler
from scanner.scanner import RepoSecurityScanner

# Load configuration
config = Config()

# Run crawler
crawler = SkillsRestCrawler(config)
crawler.run()

# Run scanner
scanner = RepoSecurityScanner(config)
scanner.scan_all()
```

## Configuration

Edit `config.yaml` to customize:

- API endpoints and limits
- Download concurrency and timeout
- Scanner thresholds and workers
- Analyzer settings
- Executor parameters

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | GitHub token for repository access |
| `ANTHROPIC_API_KEY` | Anthropic API key for Claude Code |
| `ANTHROPIC_BASE_URL` | API base URL (optional) |
| `SKILLSMP_API_KEY` | SkillsMP API key (optional) |
| `SKIP_CRAWL` | Skip crawl phase (true/false) |
| `MAX_WORKERS` | Override concurrent worker count |

## Output

### Static Scan Results
- `workspace/critical/` - Critical risk repositories
- `workspace/high/` - High risk repositories
- `workspace/medium/` - Medium risk repositories
- `workspace/low/` - Low risk repositories
- `workspace/safe/` - Safe repositories

### CC Analysis Results
- `scan_results/SAFE/` - Skills verified safe
- `scan_results/SUSPICIOUS/` - Skills with suspicious patterns
- `scan_results/MALICIOUS/` - Skills with confirmed vulnerabilities

### Execution Logs
- `execution_logs/{risk_level}/{repo_id}/{skill_name}/`
  - `strace.log` - System call trace
  - `network.pcap` - Network traffic capture
  - `nova/` - NOVA hook reports
  - `claude_output.txt` - Claude execution output
  - `filesystem_changes.json` - File system changes

## License

MIT License - See [../LICENSE](../LICENSE) for details.

## Contributing

Contributions are welcome! Please submit pull requests or open issues for bugs and feature requests.

For more details about the MaliciousAgentSkillsBench project, see the [main README](../).
