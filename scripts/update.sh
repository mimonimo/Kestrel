#!/usr/bin/env bash
#
# Kestrel 업데이트 스크립트
# ===========================
#
# 기존 설치본에 최신 변경사항을 안전하게 적용합니다.
#
# 동작 순서:
#   1. git pull --ff-only (작업 트리가 깨끗해야 함)
#   2. .env 와 .env.example 차이 확인 — 새 키가 있으면 경고
#   3. backend / frontend 이미지 재빌드 (변경된 파일만)
#   4. docker compose up -d (백엔드 시작 시 alembic upgrade head 자동 실행)
#   5. Meilisearch 인덱스 스키마 갱신 + 필요 시 reindex
#   6. 헬스체크 — backend /healthz 가 200 응답할 때까지 대기 (최대 60초)
#
# 사용법:
#   bash scripts/update.sh                    # 일반 업데이트
#   bash scripts/update.sh --reindex-meili    # Meili 문서까지 강제 재색인
#   bash scripts/update.sh --skip-build       # 코드 변경만 있고 의존성은 그대로
#   bash scripts/update.sh --no-pull          # 이미 git pull 한 경우
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

REINDEX=0
SKIP_BUILD=0
NO_PULL=0
for arg in "$@"; do
  case "$arg" in
    --reindex-meili) REINDEX=1 ;;
    --skip-build)    SKIP_BUILD=1 ;;
    --no-pull)       NO_PULL=1 ;;
    -h|--help)
      sed -n '2,/^set -e/p' "$0" | sed 's/^# \?//' | head -n -1
      exit 0
      ;;
    *) echo "알 수 없는 옵션: $arg (--help 참고)"; exit 2 ;;
  esac
done

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
info() { printf '\033[36m▸ %s\033[0m\n' "$*"; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$*"; }
ok()   { printf '\033[32m✔ %s\033[0m\n' "$*"; }
err()  { printf '\033[31m✘ %s\033[0m\n' "$*"; }

# ---------------------------------------------------------------------------
# 1. git pull (선택)
# ---------------------------------------------------------------------------
if [ "$NO_PULL" -eq 0 ]; then
  info "Step 1/6 — 최신 코드 받기 (git pull --ff-only)"
  if ! git diff-index --quiet HEAD --; then
    err "작업 트리에 커밋되지 않은 변경사항이 있습니다. 먼저 commit/stash 하세요."
    git status --short
    exit 1
  fi
  PRE_HEAD="$(git rev-parse HEAD)"
  git pull --ff-only origin "$(git rev-parse --abbrev-ref HEAD)"
  POST_HEAD="$(git rev-parse HEAD)"
  if [ "$PRE_HEAD" = "$POST_HEAD" ]; then
    ok "이미 최신 상태 ($POST_HEAD)"
  else
    ok "$PRE_HEAD → $POST_HEAD"
    bold "변경된 파일:"
    git --no-pager diff --stat "$PRE_HEAD".."$POST_HEAD" | tail -n +1
  fi
else
  info "Step 1/6 — git pull 건너뜀 (--no-pull)"
fi

# ---------------------------------------------------------------------------
# 2. .env 검사
# ---------------------------------------------------------------------------
info "Step 2/6 — .env 와 .env.example 비교"
if [ ! -f .env ]; then
  warn ".env 가 없습니다. .env.example 을 복사해 주세요: cp .env.example .env"
elif [ -f .env.example ]; then
  MISSING=$(
    comm -23 \
      <(grep -E '^[A-Z_]+=' .env.example | cut -d= -f1 | sort -u) \
      <(grep -E '^[A-Z_]+=' .env          | cut -d= -f1 | sort -u)
  )
  if [ -n "$MISSING" ]; then
    warn "다음 환경변수가 .env 에 없습니다 (.env.example 에는 있음):"
    echo "$MISSING" | sed 's/^/    /'
    warn "필요한 값을 .env 에 추가한 뒤 이 스크립트를 다시 실행하세요."
  else
    ok ".env 에 누락된 키 없음"
  fi
fi

# ---------------------------------------------------------------------------
# 3. 이미지 재빌드
# ---------------------------------------------------------------------------
COMPOSE_FILES=(-f docker-compose.yml)
if [ -n "${INSTALL_CLAUDE_CLI:-}" ] && [ "${INSTALL_CLAUDE_CLI:-0}" = "1" ]; then
  COMPOSE_FILES+=(-f docker-compose.claude-cli.yml)
  info ".env INSTALL_CLAUDE_CLI=1 — claude-cli 오버레이 포함"
fi

if [ "$SKIP_BUILD" -eq 0 ]; then
  info "Step 3/6 — backend / frontend 이미지 재빌드"
  GIT_COMMIT="$(git rev-parse HEAD 2>/dev/null || echo 'unknown')"
  BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  docker compose "${COMPOSE_FILES[@]}" build \
    --build-arg "KESTREL_GIT_COMMIT=$GIT_COMMIT" \
    --build-arg "KESTREL_BUILD_TIME=$BUILD_TIME" \
    backend frontend
  ok "재빌드 완료 (commit ${GIT_COMMIT:0:7} @ $BUILD_TIME)"
else
  info "Step 3/6 — 빌드 건너뜀 (--skip-build)"
fi

# ---------------------------------------------------------------------------
# 4. 컨테이너 재기동 (백엔드 시작 시 alembic upgrade head 자동 실행)
# ---------------------------------------------------------------------------
info "Step 4/6 — docker compose up -d"
docker compose "${COMPOSE_FILES[@]}" up -d
ok "컨테이너 시작 — 백엔드는 alembic upgrade head 후 uvicorn 기동"

# ---------------------------------------------------------------------------
# 5. Meilisearch 스키마 갱신 + 선택적 reindex
# ---------------------------------------------------------------------------
info "Step 5/6 — 백엔드 헬스체크 대기 (최대 60초)"
HEALTHY=0
for i in $(seq 1 30); do
  if curl -fsS "http://localhost:8000/api/v1/health" >/dev/null 2>&1; then
    HEALTHY=1
    break
  fi
  sleep 2
done
if [ "$HEALTHY" -eq 1 ]; then
  ok "backend /api/v1/health 200"
else
  err "backend 가 60초 안에 healthy 상태가 되지 못했습니다"
  echo "  로그 확인: docker compose logs backend | tail -50"
  exit 1
fi

if [ "$REINDEX" -eq 1 ]; then
  info "Step 6/6 — Meilisearch 문서 재색인 (--reindex-meili)"
  docker compose "${COMPOSE_FILES[@]}" exec -T backend python -m scripts.reindex_meili
  ok "Meili 재색인 완료"
else
  info "Step 6/6 — Meili 문서 재색인 건너뜀 (스키마 변경 시 --reindex-meili 옵션 사용)"
fi

bold ""
ok "업데이트 완료"
echo "  대시보드: http://localhost:3000"
echo "  API docs: http://localhost:8000/docs"
