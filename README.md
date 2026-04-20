# Kestrel

> 실시간 CVE · 제로데이 취약점 모니터링 대시보드. NVD · Exploit-DB · GitHub Advisory 세 곳을 한 화면에서.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Next.js 15](https://img.shields.io/badge/Next.js-15-000?logo=next.js)](https://nextjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-async-009688?logo=fastapi)](https://fastapi.tiangolo.com/)
[![PostgreSQL 16](https://img.shields.io/badge/PostgreSQL-16-336791?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Meilisearch](https://img.shields.io/badge/Search-Meilisearch-FF5CAA)](https://www.meilisearch.com/)
[![Docker](https://img.shields.io/badge/Docker-compose-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)

Kestrel은 공개 취약점 정보를 한 곳으로 모아 보안 엔지니어 · 개발자 · SOC 담당자가 빠르게 위협을 인지·추적할 수 있게 해주는 오픈소스 대시보드입니다. 여러 소스의 CVE를 실시간 파싱하여 PostgreSQL에 정규화해 저장하고, Meilisearch로 인스턴트 검색을 제공합니다.

---

## 목차

- [Why Kestrel](#why-kestrel)
- [핵심 기능](#핵심-기능)
- [아키텍처](#아키텍처)
- [스크린샷](#스크린샷)
- [Tech Stack](#tech-stack)
- [Quick Start (Docker)](#quick-start-docker)
- [Ubuntu 22.04 원클릭 셋업](#ubuntu-2204-원클릭-셋업)
- [설정 (환경변수)](#설정-환경변수)
- [로컬 개발 (Docker 없이)](#로컬-개발-docker-없이)
- [실행 & 사용법](#실행--사용법)
- [API 요약](#api-요약)
- [데이터 흐름](#데이터-흐름)
- [프로젝트 구조](#프로젝트-구조)
- [테스트](#테스트)
- [로드맵](#로드맵)
- [기여](#기여)
- [License](#license)

---

## Why Kestrel

- **단일 창구**: 세 개 소스(NVD · Exploit-DB · GitHub Advisory)의 포맷 차이를 정규화된 스키마로 통일합니다.
- **검색 중심 UX**: 히어로 검색창 + 팩싯 필터(심각도·OS·취약점 유형·기간)로 원하는 CVE에 2초 안에 도달하도록 설계했습니다.
- **나만의 취약점 뷰**: 등록한 자산(벤더·제품·버전)을 CPE와 매칭해 "내 시스템 취약점"만 따로 보여줍니다.
- **운영 지향 설계**: 레이트 리미터(Redis sliding window), 지수 백오프 재시도, 파서별 격리된 장애 추적, Meilisearch 장애 시 PostgreSQL tsvector 자동 폴백.
- **도커 한 줄 실행**: `docker compose up --build` 으로 프런트/백엔드/DB/검색엔진/캐시 전부 기동.

---

## 핵심 기능

### 수집 (Ingestion)
- **NVD 2.0 API** — 증분 수집(`lastModStartDate`). 키 없음 5req/30s, 키 있음 50req/30s 자동 전환.
- **Exploit-DB** — GitLab 미러 CSV 파싱, 최신순 정렬 후 색인.
- **GitHub Advisory** — GHSA GraphQL. 토큰 없을 시 스킵.
- APScheduler가 소스별 staggered 스케줄로 백그라운드 실행.
- 수동 "지금 다시 수집" 버튼 + 사용자 키를 헤더로 전달.

### 검색 & 필터
- Meilisearch(오타 허용, 팩싯, 랭킹) + PG tsvector 폴백.
- URL 동기화 필터: `?q=log4j&severity=critical&os=linux&type=RCE&from=2026-01-01`.
- 디바운스 검색(300ms), `keepPreviousData`로 깜빡임 없는 전환.

### 사용자 경험
- 다크/라이트/시스템 테마 (pre-hydration boot script로 FOUC 제거).
- CVE 즐겨찾기 (별 토글) + "즐겨찾기만" 뷰.
- 자산 등록 → 실시간 CPE 매칭 → "내 시스템 취약점" 카드.
- 우측 하단 플로팅 시스템 상태 팝오버(DB/Redis/Meili 핑, 마지막 수집 성공/실패).

### 운영성
- `/health` (단순 liveness) · `/status` (의존성 전체 상태 + 파서별 최근 수집 로그).
- 구조화 로깅 (structlog, dev 콘솔 / prod JSON).
- Sentry · OpenTelemetry 선택 활성화 (`pip install -e ".[sentry,otel]"`).
- Playwright 스모크 테스트.

---

## 아키텍처

```
┌──────────┐   HTTPS    ┌──────────────┐   async    ┌────────────┐
│ Browser  │ ─────────▶ │  Next.js 15  │ ─────────▶ │  FastAPI   │
│ (Client) │ ◀───────── │  App Router  │ ◀───────── │  async     │
└──────────┘            └──────────────┘            └─────┬──────┘
                                                          │
                  ┌───────────────────────────────────────┼──────────────┐
                  │                                       │              │
            ┌─────▼─────┐     ┌────────────┐     ┌────────▼────┐   ┌─────▼─────┐
            │ Postgres  │     │ Meilisearch│     │    Redis    │   │APScheduler│
            │ (truth DB)│     │  (search)  │     │ (rate-limit)│   │ (ingest)  │
            └───────────┘     └────────────┘     └─────────────┘   └─────┬─────┘
                                                                         │
                               ┌─────────────────────────────────────────┼────────┐
                               │                                         │        │
                         ┌─────▼─────┐                          ┌────────▼───┐  ┌─▼──────┐
                         │ NVD 2.0   │                          │ Exploit-DB │  │ GHSA   │
                         │ REST API  │                          │ CSV mirror │  │GraphQL │
                         └───────────┘                          └────────────┘  └────────┘
```

- PostgreSQL이 단일 진실 소스. Meilisearch는 색인 레이어(장애 시 자동 폴백).
- Alembic 마이그레이션이 컨테이너 기동 시 자동 실행.
- `raw_data JSONB` 컬럼으로 소스 원본 보존 → 스키마 변경 시 재파싱 가능.

---

## 스크린샷

> 실제 환경에서 스크린샷/gif를 추가해 주세요 (`docs/screenshots/` 디렉터리 권장).

| Dashboard | CVE Detail | Settings |
| :-------: | :--------: | :------: |
| <img width="1655" height="902" alt="스크린샷 2026-04-20 09 05 07" src="https://github.com/user-attachments/assets/a2b1a92f-862f-4784-ba44-fc7d6933a390" />| <img width="1655" height="902" alt="스크린샷 2026-04-20 09 07 18" src="https://github.com/user-attachments/assets/2874f850-527d-4313-86d5-b04fffb1ef4e" />| <img width="1655" height="902" alt="스크린샷 2026-04-20 09 08 05" src="https://github.com/user-attachments/assets/c04e0cce-e5a5-4293-a04d-687a6e97cd92" />|

---

## Tech Stack

| Layer       | Tech                                                                 |
| ----------- | -------------------------------------------------------------------- |
| Frontend    | Next.js 15 (App Router) · React 19 · TypeScript · TailwindCSS · TanStack Query v5 · lucide-react |
| Backend     | FastAPI · SQLAlchemy 2.0 async · asyncpg · Pydantic v2 · APScheduler · tenacity · structlog |
| Database    | PostgreSQL 16 (JSONB + tsvector + GIN 인덱스)                        |
| Search      | Meilisearch v1.10 (rankingRules 튜닝, stopWords, typoTolerance)      |
| Cache       | Redis 7 (sliding window rate limiter)                                |
| Infra       | Docker Compose · (linux/amd64 타겟 빌드)                              |
| Observability (optional) | Sentry · OpenTelemetry                                   |
| Testing     | Playwright (frontend e2e)                                            |

---

## Quick Start (Docker)

```bash
git clone https://github.com/mimonimo/Kestrel.git
cd Kestrel
cp .env.example .env
# (선택) NVD_API_KEY, GITHUB_TOKEN 을 .env에 채우면 레이트 리밋이 완화됩니다
docker compose up --build
```

- Frontend: http://localhost:3000
- Backend API · Swagger UI: http://localhost:8000/docs
- Meilisearch: http://localhost:7700

첫 실행 시 NVD에서 최근 30일 치 CVE를 자동 수집합니다(몇 분 소요). 이후 스케줄러가 증분 수집을 유지합니다.

### 플랫폼별 실행 방법

기본 `docker-compose.yml`에는 **플랫폼 핀이 없습니다**. 호스트 아키텍처를 그대로 따라가므로 Apple Silicon(arm64) Mac, Intel/AMD Linux(amd64), x86_64 Windows(WSL2) 모두 별도 설정 없이 동작합니다.

#### 로컬 개발 (Apple Silicon Mac · arm64)

```bash
docker compose up -d --build       # 또는 docker-compose
docker compose ps                  # 5개 컨테이너 모두 healthy 확인
docker compose logs -f backend     # 마이그레이션·스케줄러 로그
```

> 일부 macOS 환경에는 `docker compose`(공백) 대신 `docker-compose`(하이픈)만 깔려 있습니다. 둘 중 동작하는 쪽을 사용하세요. 동작 차이는 없습니다.

#### Ubuntu x86_64 서버 배포

amd64 Ubuntu 서버에서는 위 명령을 그대로 실행하면 호스트가 amd64이므로 자연스럽게 amd64 이미지가 빌드됩니다.

#### Apple Silicon에서 amd64 이미지를 강제로 빌드해야 할 때

(다른 amd64 서버로 이미지를 통째로 복사·푸시할 때만 필요합니다.)

옵션 A — 일회성 환경변수 + buildx:

```bash
DOCKER_DEFAULT_PLATFORM=linux/amd64 docker buildx build \
  --platform linux/amd64 -t cve-watch-backend:latest ./backend --load
DOCKER_DEFAULT_PLATFORM=linux/amd64 docker buildx build \
  --platform linux/amd64 -t cve-watch-frontend:latest ./frontend --load
```

옵션 B — `docker-compose.prod.yml` override 파일 작성:

```yaml
services:
  backend:
    platform: linux/amd64
  frontend:
    platform: linux/amd64
```

배포 시:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

> compose 파일 본체에 `platform: linux/amd64`를 직접 박아두면 Apple Silicon 로컬 실행이 막힙니다(클래식 빌더가 platform 메타데이터를 박지 않으면 “image was found but does not provide the specified platform” 에러 발생). 배포 전용 override로 분리해두는 편이 안전합니다.

---

## Ubuntu 22.04 원클릭 셋업

새로 설치한 Ubuntu 22.04 LTS 서버에서 아래 순서대로 실행하면 Kestrel이 `http://<서버IP>:3000`에서 바로 뜹니다.

### 1. Docker · Docker Compose 플러그인 설치

```bash
# 기본 툴
sudo apt update && sudo apt install -y ca-certificates curl gnupg git ufw

# Docker 공식 APT 저장소 등록
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# 현재 유저에 docker 그룹 부여 (로그아웃 후 재로그인 필요)
sudo usermod -aG docker $USER
newgrp docker

# 설치 확인
docker --version
docker compose version
```

### 2. 방화벽 설정 (UFW)

공개 서버면 3000(프런트)과 8000(API)만 열고 나머지는 컨테이너 내부에서만 쓰도록 닫아 두세요.

```bash
sudo ufw allow OpenSSH
sudo ufw allow 3000/tcp   # 프런트엔드
sudo ufw allow 8000/tcp   # 백엔드 API (리버스 프록시 쓸 땐 생략)
sudo ufw enable
sudo ufw status
```

> 운영 환경이라면 8000을 직접 열지 말고 Nginx/Caddy로 3000과 함께 443(TLS)에서 리버스 프록시하시는 것을 권장합니다.

### 3. 저장소 클론 · 환경변수

```bash
cd /opt
sudo git clone https://github.com/mimonimo/Kestrel.git
sudo chown -R $USER:$USER Kestrel
cd Kestrel
cp .env.example .env

# (선택) NVD API 키 / GitHub 토큰 채우기
# - NVD_API_KEY: https://nvd.nist.gov/developers/request-an-api-key
# - GITHUB_TOKEN: https://github.com/settings/tokens (repo scope 불필요)
nano .env
```

### 4. 기동

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f backend       # 첫 수집 로그 확인
```

- Frontend: `http://<서버IP>:3000`
- Swagger: `http://<서버IP>:8000/docs`
- 첫 기동 시 Alembic 마이그레이션과 NVD 최근 30일 분 수집이 자동 수행됩니다(2~5분).

### 5. systemd로 부팅 시 자동 기동 (선택)

`docker-compose.yml`에 `restart: unless-stopped`가 걸려 있어 Docker 데몬이 뜨면 컨테이너도 복구됩니다. Docker 데몬 자체는 Ubuntu 22.04 기본 설정에서 이미 `enable` 상태이므로 별도 systemd 유닛 없이도 재부팅 후 자동 복귀합니다. 명시적으로 확인하려면:

```bash
sudo systemctl enable docker
sudo systemctl status docker
```

### 6. 업데이트 · 롤백

```bash
cd /opt/Kestrel
git pull
docker compose up -d --build
docker compose logs -f
```

문제가 생기면:

```bash
git log --oneline -5
git checkout <이전_커밋_SHA>
docker compose up -d --build
```

데이터는 Docker named volume(`postgres_data`, `redis_data`, `meili_data`)에 유지되므로 컨테이너 재생성 후에도 살아 있습니다. 완전 초기화가 필요하면:

```bash
docker compose down -v   # ⚠️ DB · 수집 이력 전부 삭제
```

---

## 설정 (환경변수)

`.env.example`을 참고하세요. 최소 설정으로도 동작하며, 모든 키는 선택입니다.

| Key | 목적 | 기본값 |
| --- | ---- | ------ |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | Postgres 접속 | `kestrel` 계열 |
| `DATABASE_URL` | 비동기 드라이버 포함 DSN | `postgresql+asyncpg://…` |
| `REDIS_URL` | Redis 연결 | `redis://redis:6379/0` |
| `MEILI_HOST` / `MEILI_MASTER_KEY` | Meilisearch | `http://meilisearch:7700` |
| `NVD_API_KEY` | 5→50 req/30s 한도 상향 | — |
| `GITHUB_TOKEN` | GHSA GraphQL 호출용 | — |
| `CORS_ORIGINS` | 허용 오리진 JSON 배열 | `["http://localhost:3000"]` |
| `SENTRY_DSN` | Sentry(선택) | — |
| `OTEL_ENABLED` / `OTEL_EXPORTER_OTLP_ENDPOINT` | OpenTelemetry(선택) | `false` |

설정 페이지(`/settings`)에서는 NVD 키·GitHub 토큰·자산·테마를 브라우저 localStorage에 저장합니다. 이 값들은 서버로 전송되지 않으며, 재수집 버튼을 누를 때만 헤더로 1회성 전달됩니다.

---

## 로컬 개발 (Docker 없이)

> 사전 요구: Python 3.12+, Node.js 20+, PostgreSQL 16, Redis 7, Meilisearch v1.10 로컬 실행.
> Postgres/Redis/Meili 세 개만 도커로 띄우고 앱 코드는 호스트에서 돌리는 하이브리드가 가장 편합니다.

```bash
# 1) 외부 인프라만 도커로
docker compose up -d postgres redis meilisearch

# 2) Backend
cd backend
uv sync                             # 또는 python -m venv .venv && pip install -e .
cp ../.env.example ../.env
# .env의 DATABASE_URL 호스트를 'postgres' → 'localhost'로 바꿔주세요
#   DATABASE_URL=postgresql+asyncpg://kestrel:kestrel@localhost:5432/kestrel
#   REDIS_URL=redis://localhost:6379/0
#   MEILI_HOST=http://localhost:7700
alembic upgrade head
uv run uvicorn app.main:app --reload --port 8000

# 3) Frontend (새 터미널)
cd frontend
cp .env.example .env.local          # NEXT_PUBLIC_API_BASE_URL=http://localhost:8000/api/v1
npm install
npm run dev                          # http://localhost:3000
```

### 자주 쓰는 개발 명령

```bash
# 새 Alembic 마이그레이션
cd backend
uv run alembic revision --autogenerate -m "add_foo_column"
uv run alembic upgrade head

# 백엔드 로그 레벨 조정
LOG_LEVEL=DEBUG uv run uvicorn app.main:app --reload

# 프런트 타입 체크 · 린트
cd frontend
npm run lint
npx tsc --noEmit

# 프런트 E2E
npx playwright install chromium     # 최초 1회
npm run test:e2e                    # 또는 npm run test:e2e:ui
```

---

## 실행 & 사용법

설치가 끝나면 `http://localhost:3000`(또는 서버 IP)에서 Kestrel이 뜹니다. 주요 흐름은 아래 순서입니다.

### 1. 첫 화면 — 대시보드

- 상단 검색창에 키워드 입력 → 300ms 뒤 자동 검색 (`log4j`, `windows kernel`, `CVE-2024-` 등).
- 왼쪽 패널에서 **심각도 · OS · 취약점 유형 · 기간** 필터를 조합. URL에 그대로 반영돼 새로고침/공유에도 상태가 유지됩니다.
- 상단의 **마지막 동기화** 뱃지로 소스별 최신 수집 시각 확인.
- 오른쪽 위 **수동 새로고침** 버튼으로 즉시 재수집 트리거(localStorage에 저장된 사용자 키를 헤더로 전달).

### 2. CVE 상세 보기

- 카드 클릭 → `/cve/{id}` (SSR). CVSS 점수/벡터, 영향 제품·버전, 참고 링크(Advisory/Exploit/Patch), 원본 소스 URL 표시.
- 우측 상단 **X** 버튼 또는 뒤로가기로 목록 복귀.

### 3. 즐겨찾기

- 리스트·상세 어디서나 별 아이콘을 눌러 북마크 (브라우저 localStorage 저장).
- 대시보드 헤더의 **⭐ 즐겨찾기만 (N)** 토글을 켜면 북마크한 CVE만 표시. 백엔드가 `/cves/batch`로 일괄 조회합니다.

### 4. 내 자산 등록 → CPE 매칭

1. 우측 상단 **⚙ 설정** → **내 자산** 섹션.
2. `vendor` · `product` · `version(선택)` 입력 후 **추가**. 예: `apache` / `log4j` / `2.14.0`, `microsoft` / `windows_11`.
3. 대시보드로 돌아오면 상단에 **내 시스템 취약점** 카드가 뜨고, 등록 자산과 매칭된 CVE가 최신순 상위 8건 표시됩니다.
4. 매칭은 `/assets/match` 엔드포인트에서 `AffectedProduct.vendor/product`에 ILIKE로 수행됩니다(버전 범위 일치는 후속 과제).

### 5. API 키 등록 (선택, 권장)

- 설정 페이지의 **NVD API Key** · **GitHub Token** 필드에 값을 입력하고 **저장 + 새로고침** 클릭.
- 키는 localStorage에만 저장되며, `/admin/refresh` 호출 시에만 `X-NVD-API-Key` · `X-GitHub-Token` 헤더로 1회성 전달됩니다.
- NVD 키가 있으면 레이트 리밋이 5 → 50req/30s로 완화돼 수집이 훨씬 빨라집니다.

### 6. 테마

- 설정 페이지 상단 **라이트 / 다크 / 시스템** 3지선다.
- 선택 즉시 반영, localStorage에 저장. 새로고침 시 FOUC 없이 pre-hydration script가 클래스를 먼저 붙입니다.

### 7. 시스템 상태 확인

- 우측 하단 **"경고 보기 / 상태 보기"** 플로팅 버튼(색상: 초록=정상, 하늘=알림, 주황=경고).
- 클릭하면 팝오버로 DB·Redis·Meili 연결, 마지막 수집 성공/실패 사유, 키 미등록 안내를 보여줍니다.
- **이 알림 숨기기**로 같은 시그니처 경고는 세션 동안 재표시되지 않습니다.

### 8. CLI / curl 사용 예시

```bash
# 헬스체크
curl -s http://localhost:8000/api/v1/health

# 심각도 critical + Linux + RCE 검색
curl -s 'http://localhost:8000/api/v1/search?severity=critical&os=linux&type=RCE&pageSize=5' | jq '.items[].cveId'

# 단건 조회
curl -s http://localhost:8000/api/v1/cves/CVE-2021-44228 | jq '.title'

# 수동 재수집 (NVD 키 포함)
curl -s -X POST http://localhost:8000/api/v1/admin/refresh \
  -H "X-NVD-API-Key: <your_key>" \
  -H "X-GitHub-Token: <your_token>"

# 자산 매칭
curl -s -X POST http://localhost:8000/api/v1/assets/match \
  -H "Content-Type: application/json" \
  -d '{"assets":[{"vendor":"apache","product":"log4j"}]}' | jq '.total'
```

---

---

## API 요약

Swagger UI: http://localhost:8000/docs

| Method · Path                     | 설명 |
| --------------------------------- | ---- |
| `GET  /api/v1/health`             | Liveness (의존성 무관) |
| `GET  /api/v1/status`             | DB/Redis/Meili 핑 + 키 유무 + 파서별 최근 수집 |
| `GET  /api/v1/search`             | 풀텍스트 + 필터 검색 (Meili → PG 폴백) |
| `GET  /api/v1/cves/{id}`          | 단건 상세 (제품·참고·타입 포함) |
| `GET  /api/v1/cves/batch?ids=...` | 복수 ID 일괄 조회 (즐겨찾기 뷰용) |
| `POST /api/v1/assets/match`       | 자산 리스트 → 매칭된 CVE |
| `POST /api/v1/admin/refresh`      | 수동 재수집 트리거 (`X-NVD-API-Key`, `X-GitHub-Token`) |

응답 키는 모두 camelCase로 통일되어 있어 프런트 TypeScript 타입과 1:1 매칭됩니다.

---

## 데이터 흐름

```
NVD / Exploit-DB / GHSA
        │
        ▼  BaseParser (ABC) → ParsedVulnerability dataclass
ingestion.py (orchestrator)
  ├─ upsert into PostgreSQL (vulnerabilities · types · products · references)
  ├─ IngestionLog 행 append (성공/실패 분리 추적)
  └─ Meilisearch index_many (camelCase 문서)
        │
        ▼
  /search → Meili 1차 / PG tsvector 2차 (자동 폴백)
  /cves/{id} → Postgres 직조회 (selectinload로 관계 즉시 로드)
```

---

## 프로젝트 구조

```
Kestrel/
├── README.md
├── PROGRESS.md                    # 단계별 작업 로그
├── docker-compose.yml
├── .env.example
├── backend/
│   ├── Dockerfile
│   ├── alembic/                   # 마이그레이션
│   └── app/
│       ├── main.py                # FastAPI · lifespan(스케줄러)
│       ├── core/                  # config · database · redis · logging
│       ├── models/                # SQLAlchemy 2.0 모델
│       ├── schemas/               # Pydantic v2 (CamelModel 베이스)
│       ├── api/v1/                # 라우터 (health/status/cves/search/assets/admin)
│       ├── services/
│       │   ├── parsers/           # nvd · exploit_db · github_advisory
│       │   ├── ingestion.py       # 오케스트레이터
│       │   ├── search_service.py  # Meilisearch 래퍼
│       │   └── rate_limiter.py    # Redis sliding window
│       ├── scheduler/             # APScheduler 잡
│       └── utils/                 # tenacity 재시도 등
└── frontend/
    ├── Dockerfile
    ├── app/                       # Next.js App Router
    │   ├── page.tsx               # 대시보드
    │   ├── cve/[id]/              # 상세 (SSR)
    │   ├── settings/              # API 키 · 자산 · 테마
    │   └── layout.tsx             # pre-hydration theme boot
    ├── components/
    │   ├── cve/                   # 리스트 아이템 · 상세 · 즐겨찾기 버튼
    │   ├── dashboard/             # RefreshBar · MyAssetsPanel
    │   ├── search/                # FilterPanel · Pagination · SearchBar
    │   ├── settings/              # ApiKeyField · ThemeSwitcher · AssetsManager
    │   └── system/                # StatusBanner (플로팅 상태)
    ├── hooks/                     # useCveSearch · useStatus · useDebounce
    └── lib/                       # api · bookmarks · assets · theme · url-state
```

---

## 테스트

```bash
# Playwright (frontend e2e)
cd frontend
npx playwright install chromium   # 최초 1회
npm run test:e2e
```

---

## 로드맵

- [ ] 티켓 시스템 (미확인 / 조치완료 상태 + 주의/경고/심각 뱃지)
- [ ] CVSS 게이지 시각화 + "최근 수정순" 정렬
- [ ] Slack · Discord · Webhook 알림
- [ ] GitHub Advisory · OSV 스키마 확장
- [ ] 커뮤니티 (`users`, `posts`, `comments`) 활성화
- [ ] LLM 요약 교체 (현재는 휴리스틱)

---

## 기여

이슈 · PR 환영합니다. 브랜치 컨벤션:

- `feat/...` · `fix/...` · `chore/...` · `docs/...`
- Conventional Commits 권장 (예: `feat: add bookmark filter`)

버그 리포트 시 `/api/v1/status` 응답을 함께 첨부해 주세요.

---

## License

[MIT](./LICENSE) © mimonimo

원본 취약점 데이터의 저작권은 각 제공처(NVD · Exploit-DB · GitHub Advisory)에 있습니다. Kestrel은 정규화·검색 레이어만 제공합니다.
