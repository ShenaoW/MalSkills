FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        git \
        nodejs \
        npm \
        ripgrep \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN python -m venv .venv \
    && .venv/bin/python -m pip install --upgrade pip \
    && .venv/bin/python -m pip install -e . pytest semgrep

RUN if [ ! -f vendor/yasa/package.json ]; then \
        rm -rf vendor/yasa \
        && mkdir -p vendor \
        && git clone --branch v0.3.1 --depth 1 https://github.com/antgroup/YASA-Engine.git vendor/yasa; \
    fi \
    && npm --prefix vendor/yasa ci \
    && cd vendor/yasa \
    && npx tsc

ENV PATH="/app/.venv/bin:${PATH}"

CMD ["bash", "scripts/demo_reproduce.sh", "--no-pause", "--skip-tests"]
