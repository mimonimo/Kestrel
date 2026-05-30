#!/bin/bash
# Kestrel 단일 호스트 자동 셋업 (PR 10-CU).
# Amazon Linux 2023 ARM 가정. 한 번만 실행됨 (cloud-init).
#
# 흐름:
#   1) 패키지 설치 (docker / git / openssl)
#   2) 데이터 EBS 마운트 → /data
#   3) Docker root 를 /data/docker 로 이동 (모든 docker volume 이 EBS 에)
#   4) git clone Kestrel → /opt/kestrel
#   5) .env / Caddyfile / docker-compose 오버라이드 생성
#   6) systemd unit 등록 → docker compose up + caddy 자동 시작
#
# 변경 변수는 Terraform templatefile 이 주입.
set -euxo pipefail
exec > >(tee /var/log/kestrel-bootstrap.log | logger -t kestrel-bootstrap) 2>&1

DOMAIN="${DOMAIN}"
TLS_EMAIL="${TLS_EMAIL}"
INITIAL_ADMIN_EMAILS="${INITIAL_ADMIN_EMAILS}"
GIT_REPO_URL="${GIT_REPO_URL}"
GIT_BRANCH="${GIT_BRANCH}"
DATA_DEVICE_HINT="${DATA_VOLUME_DEVICE}"

# ── 1) 패키지 ────────────────────────────────────────────────
dnf -y update
dnf -y install docker git openssl jq

systemctl enable docker

# ── 2) 데이터 EBS 마운트 ─────────────────────────────────────
# AL2023 ARM 에서 EBS 가 /dev/nvme1n1 으로 노출됨 (sdb 힌트는 무시됨).
# nvme1n1 이 없으면 sdb 그대로 시도.
DATA_DEV=""
for cand in /dev/nvme1n1 /dev/nvme2n1 "$DATA_DEVICE_HINT"; do
  if [ -b "$cand" ]; then DATA_DEV="$cand"; break; fi
done
if [ -z "$DATA_DEV" ]; then
  echo "ERROR: 데이터 EBS 장치를 찾지 못했습니다." >&2
  exit 1
fi

# 이미 ext4 포맷된 EBS 면 그대로 마운트 (재attach 케이스). 비어 있으면 새로 포맷.
if ! blkid "$DATA_DEV" >/dev/null 2>&1; then
  mkfs.ext4 -L kestrel-data "$DATA_DEV"
fi
mkdir -p /data
if ! grep -q "/data " /etc/fstab; then
  echo "LABEL=kestrel-data /data ext4 defaults,nofail 0 2" >> /etc/fstab
fi
mount -a

# ── 3) Docker root → /data/docker ────────────────────────────
mkdir -p /data/docker
mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<EOF
{
  "data-root": "/data/docker",
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "5" }
}
EOF
systemctl restart docker

# docker compose v2 plugin (AL2023 dnf 에 없으므로 직접 설치).
mkdir -p /usr/local/lib/docker/cli-plugins
curl -sSL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-aarch64" \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

# ── 4) Repo clone ────────────────────────────────────────────
mkdir -p /opt
if [ ! -d /opt/kestrel/.git ]; then
  git clone --branch "$GIT_BRANCH" --depth 1 "$GIT_REPO_URL" /opt/kestrel
fi

# ── 5) .env / Caddyfile ──────────────────────────────────────
cd /opt/kestrel
if [ ! -f .env ]; then
  JWT_SECRET="$(openssl rand -hex 32)"
  POSTGRES_PASSWORD="$(openssl rand -hex 16)"
  MEILI_MASTER_KEY="$(openssl rand -hex 24)"
  PUBLIC_HOST="$${DOMAIN:-$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4).nip.io}"
  cat > .env <<EOF
# 자동 생성 — 운영자 외 접근 금지. chmod 600 .env
POSTGRES_USER=kestrel
POSTGRES_PASSWORD=$$POSTGRES_PASSWORD
POSTGRES_DB=kestrel
DATABASE_URL=postgresql+asyncpg://kestrel:$$POSTGRES_PASSWORD@postgres:5432/kestrel

REDIS_URL=redis://redis:6379/0

MEILI_HOST=http://meilisearch:7700
MEILI_MASTER_KEY=$$MEILI_MASTER_KEY

JWT_SECRET=$$JWT_SECRET
JWT_EXP_HOURS=12
INITIAL_ADMIN_EMAILS=$INITIAL_ADMIN_EMAILS

# CORS — Caddy 가 같은 origin 으로 프록시하므로 사실상 same-origin 이지만
# 도메인 명시는 안전 마진.
CORS_ORIGINS=["https://$$PUBLIC_HOST"]

# Frontend → backend 호출 — Caddy 가 /api/* 를 backend 로 라우팅하니
# 클라이언트에서는 상대경로 사용. NEXT_PUBLIC_API_BASE_URL 은 빌드 타임 값이라
# Docker compose 빌드 인자로 별도 주입.
NEXT_PUBLIC_API_BASE_URL=/api/v1
INTERNAL_API_BASE_URL=http://backend:8000/api/v1

# Vulhub / sandbox — single-host 에서는 비활성화. 필요시 활성화 후 storage 늘릴 것.
VULHUB_REPO_PATH=/data/vulhub
VULHUB_HOST_PATH=/data/vulhub

# Docker socket group 권한 — 호스트 docker group GID 매칭 (sandbox 비활성 시 무의미).
DOCKER_GID=0
EOF
  chmod 600 .env
fi

# Caddyfile — same-origin 으로 frontend + /api/* 라우팅 + 자동 TLS.
PUBLIC_HOST="$${DOMAIN:-$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4).nip.io}"
mkdir -p /opt/kestrel/caddy
cat > /opt/kestrel/caddy/Caddyfile <<EOF
{
  email $TLS_EMAIL
}

$$PUBLIC_HOST {
  encode gzip zstd

  @api {
    path /api/* /docs /openapi.json
  }
  handle @api {
    reverse_proxy backend:8000
  }

  handle {
    reverse_proxy frontend:3000
  }
}
EOF

# docker-compose override — caddy 서비스 추가 + frontend 빌드 인자 + ports 노출 조정.
cat > /opt/kestrel/docker-compose.override.yml <<EOF
services:
  caddy:
    image: caddy:2-alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./caddy/Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config
    depends_on:
      - frontend
      - backend

  # 호스트의 80/443 만 외부에 노출하고 backend/frontend 의 host port 매핑은 제거.
  backend:
    ports: !reset []
  frontend:
    ports: !reset []
    build:
      args:
        NEXT_PUBLIC_API_BASE_URL: /api/v1

volumes:
  caddy_data:
  caddy_config:
EOF

# ── 6) systemd unit ──────────────────────────────────────────
cat > /etc/systemd/system/kestrel.service <<'EOF'
[Unit]
Description=Kestrel docker compose stack
Requires=docker.service
After=docker.service network-online.target
StartLimitIntervalSec=0

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/kestrel
ExecStart=/usr/bin/docker compose up -d --build
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=1800

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable kestrel.service
systemctl start kestrel.service

echo "Bootstrap finished. Caddy will fetch TLS cert from Let's Encrypt within 1-2 minutes."
