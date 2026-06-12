#!/usr/bin/env bash
# Kestrel 운영 배포 — pull 기반(권장).
#
# 약한 단일 호스트(t4g.small, 2GB)에서 on-box 빌드(`--build`)는 메모리 압박(OOM
# 위험) + 매번 수 분이 걸린다. 그래서 빌드는 CI(GitHub Actions, 네이티브 arm64)가
# 맡아 GHCR 에 이미지를 올리고, 운영 박스는 그 이미지를 *pull* 만 한다.
#
# 배포 흐름:
#   1) backend/frontend 변경은 커밋 메시지에 [skip ci] 없이 push
#      → CI(build-images.yml)가 ghcr.io/<owner>/kestrel-{backend,frontend}:latest 빌드.
#      (또는 GitHub Actions 에서 "Build & Push Images" 워크플로 수동 실행.)
#   2) CI 성공 후 박스에서 이 스크립트 실행(SSM 또는 SSH):
#        cd /opt/kestrel && ./scripts/deploy.sh
#
# 인프라/문서만 바꾼 커밋(backend/frontend 무관)은 [skip ci] 로 CI 를 건너뛴다.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "▶ git pull"
git pull --ff-only origin main

echo "▶ docker compose pull (CI 빌드 이미지 수신)"
docker compose pull

echo "▶ docker compose up -d (재기동)"
docker compose up -d

echo "▶ 상태"
docker compose ps --format '{{.Service}}\t{{.Status}}'
