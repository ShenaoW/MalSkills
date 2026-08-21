# Docker Build Guide

This guide explains how to build the Claude Skill Sandbox Docker image with different NOVA configurations.

## Build Modes

| Mode | Description | Size | ML Dependencies |
|------|-------------|------|-----------------|
| `none` (default) | Basic monitoring only (strace, tcpdump) | ~500MB | None |
| `lite` | Pattern-based hooks without ML | ~520MB | None |
| `full` | Full semantic analysis with NOVA | ~2.5GB | torch, transformers, sentence-transformers |

## Quick Start

```bash
# Default build (no NOVA)
docker build -t claude-skill-sandbox .

# With NOVA Lite
docker build --build-arg NOVA_MODE=lite -t claude-skill-sandbox .

# With NOVA Full
docker build --build-arg NOVA_MODE=full -t claude-skill-sandbox .
```

## Using Local Python Packages (Optional)

If you have pre-built Python packages (e.g., from `python-packages/` directory), you can use them instead of downloading from PyPI:

```bash
# Copy your nova package to the build context
cp -r /path/to/python-packages/nova ./executor/nova-package/

# Then build with NOVA Full (it will use local package if available)
docker build --build-arg NOVA_MODE=full -t claude-skill-sandbox .
```

To use local packages, uncomment and modify this line in Dockerfile:
```dockerfile
COPY executor/nova-package/ /opt/nova-protector/nova/
```

## NOVA Modes Explained

### NOVA_MODE=none
- No NOVA hooks installed
- Monitoring via strace/tcpdump only
- Fastest build, smallest image
- Suitable for basic dynamic analysis

### NOVA_MODE=lite
- Installs NOVA hook scripts
- Pattern-based detection (keyword matching)
- No ML dependencies required
- Good for detecting obvious malicious patterns

### NOVA_MODE=full
- Installs complete NOVA framework
- Includes ML models for semantic analysis
- Can detect obfuscated/hidden malicious prompts
- Requires ~2GB additional space
- Longer build time (ML dependencies)

## Troubleshooting

### Build fails with "executor/nova-hooks not found"
Make sure you're building from the `code/` directory:
```bash
cd MaliciousAgentSkillsBench/code
docker build -t claude-skill-sandbox .
```

### NOVA Full build takes too long
The ML dependencies (torch, transformers) are large. Consider using:
- A pre-built image: `docker pull ghcr.io/your-org/claude-skill-sandbox:full`
- NOVA Lite mode for faster iteration
- Build cache: Docker will cache layers, subsequent builds are faster

### Running out of space during NOVA Full build
Increase Docker daemon storage limit or use NOVA Lite mode instead.

## Verification

Check installed NOVA mode:

```bash
docker run --rm claude-skill-sandbox cat /opt/nova-protector/nova_mode 2>/dev/null || echo "NOVA not installed"
```

Expected output:
- `none` - NOVA not installed
- `lite` - Pattern-based hooks only
- `full` - Full NOVA with ML dependencies
