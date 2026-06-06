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

# --- Claude Code CLI for the in-dashboard "Claude 로그인" flow (PR 10-AD) ---
# Default: installed. The settings page runs `claude setup-token` inside
# this container to drive OAuth without ever exposing the CLI to the user.
# Set INSTALL_CLAUDE_CLI=0 to skip (~200 MB image savings, disables AI
# analysis entirely until you wire a different provider).
ARG INSTALL_CLAUDE_CLI=1
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
# 운영 스크립트(예: scripts.reindex_meili — to_document/필터 속성 변경 후 Meili 전수
# 재색인). 이미지에 포함해 `python -m scripts.reindex_meili` 로 바로 실행 가능.
COPY scripts ./scripts

# Non-root user
RUN groupadd --gid 1001 app && useradd --uid 1001 --gid app --shell /bin/bash --create-home app \
    && chown -R app:app /app

# Pre-create named-volume mount points with app ownership *in the image*
# so docker copies these permissions to the empty volume on first mount.
# Without this, named volumes are root-owned by default and the non-root
# app user can't `git init` / write credentials. (PR 10-AF / 10-AD.)
RUN mkdir -p /data/mitre_cvelist /home/app/.claude \
    && chown -R app:app /data /home/app/.claude

USER app

EXPOSE 8000
ENV PORT=8000

# Build provenance — exposed via /api/v1/version so an operator can
# confirm `update.sh` actually rolled new code into the container.
# Pass --build-arg KESTREL_GIT_COMMIT=$(git rev-parse HEAD) at build time
# to populate; defaults to "unknown" for ad-hoc local builds.
ARG KESTREL_GIT_COMMIT=unknown
ARG KESTREL_BUILD_TIME=unknown
ENV KESTREL_GIT_COMMIT=$KESTREL_GIT_COMMIT
ENV KESTREL_BUILD_TIME=$KESTREL_BUILD_TIME

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://localhost:8000/api/v1/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
