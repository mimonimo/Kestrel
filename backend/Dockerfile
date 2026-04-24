FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# docker compose CLI plugin — sandbox manager spawns vulhub stacks via the
# host docker daemon (DooD). Bundled as a sibling executable to /usr/bin/docker
# so ``docker compose ...`` works without pulling in the whole Docker Engine.
RUN ARCH="$(dpkg --print-architecture)" \
    && case "$ARCH" in \
         amd64)  COMPOSE_ARCH=x86_64 ;; \
         arm64)  COMPOSE_ARCH=aarch64 ;; \
         *) echo "unsupported arch $ARCH" && exit 1 ;; \
       esac \
    && mkdir -p /usr/local/lib/docker/cli-plugins \
    && curl -fsSL "https://github.com/docker/compose/releases/download/v2.32.4/docker-compose-linux-${COMPOSE_ARCH}" \
         -o /usr/local/lib/docker/cli-plugins/docker-compose \
    && chmod +x /usr/local/lib/docker/cli-plugins/docker-compose \
    && curl -fsSL "https://download.docker.com/linux/static/stable/${COMPOSE_ARCH}/docker-27.4.0.tgz" \
         | tar xz -C /tmp \
    && mv /tmp/docker/docker /usr/local/bin/docker \
    && rm -rf /tmp/docker

# --- Optional: Claude Code CLI for the "claude_cli" AI analysis provider ---
# Enable with: docker compose build --build-arg INSTALL_CLAUDE_CLI=1
# See README "AI 심층 분석 — Claude Code CLI".
ARG INSTALL_CLAUDE_CLI=0
RUN if [ "$INSTALL_CLAUDE_CLI" = "1" ]; then \
      apt-get update \
      && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
      && apt-get install -y --no-install-recommends nodejs \
      && npm install -g @anthropic-ai/claude-code \
      && rm -rf /var/lib/apt/lists/*; \
    fi

# Install dependencies
COPY pyproject.toml ./
RUN pip install --upgrade pip && pip install -e .

# Copy application
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./

# Non-root user
RUN groupadd --gid 1001 app && useradd --uid 1001 --gid app --shell /bin/bash --create-home app \
    && chown -R app:app /app
USER app

EXPOSE 8000
ENV PORT=8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://localhost:8000/api/v1/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
