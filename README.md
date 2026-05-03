# Kestrel

> 실시간 CVE 모니터링 + AI 페이로드 분석 + 격리 샌드박스 재현 — NVD · Exploit-DB · GitHub Advisory 세 소스의 취약점을 한 화면에서 검색하고, 클릭 한 번으로 vulhub 기반 reproducer 또는 AI가 합성한 lab 컨테이너에서 직접 페이로드를 검증합니다.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Next.js 15](https://img.shields.io/badge/Next.js-15-000?logo=next.js)](https://nextjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-async-009688?logo=fastapi)](https://fastapi.tiangolo.com/)
[![PostgreSQL 16](https://img.shields.io/badge/PostgreSQL-16-336791?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Meilisearch](https://img.shields.io/badge/Search-Meilisearch-FF5CAA)](https://www.meilisearch.com/)
[![Docker](https://img.shields.io/badge/Docker-compose-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)

Kestrel은 공개 취약점 정보를 한 곳으로 모아 보안 엔지니어, 개발자, SOC 담당자가 빠르게 위협을 인지·추적·검증할 수 있도록 돕는 오픈소스 대시보드입니다. 여러 소스의 CVE를 실시간으로 파싱·정규화하여 PostgreSQL에 저장하고 Meilisearch로 인스턴트 검색을 제공하며, 사용자 자산 기반 CPE 매칭과 익명 커뮤니티 기능에 더해 **격리된 샌드박스 컨테이너에서 실제 페이로드를 재현/검증**할 수 있는 AI 기반 lab synthesizer 까지 한 호스트에서 단일 명령으로 띄울 수 있습니다.

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
- [AI 심층 분석](#ai-심층-분석)
- [샌드박스 (CVE → 격리 컨테이너 → 자동 검증)](#샌드박스-cve--격리-컨테이너--자동-검증)
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
- **검색 중심 UX**: 히어로 검색창과 팩싯 필터(심각도 · OS · 취약점 유형 · 기간)를 통해 원하는 CVE에 빠르게 도달할 수 있도록 설계되었습니다.
- **자산 기반 매칭**: 사용자가 등록한 자산(벤더 · 제품 · 버전)을 CPE와 매칭해 사용자 시스템과 관련된 취약점만 별도로 노출합니다.
- **익명 커뮤니티**: 로그인 없이 디바이스 단위로 게시글과 댓글을 작성할 수 있으며, CVE 상세 페이지에도 댓글 스레드가 통합됩니다.
- **AI 페이로드 + 검증**: CVE 별 구체적 공격 페이로드와 패치 매핑을 LLM 으로 생성하고, vulhub reproducer 또는 AI 가 합성한 lab 컨테이너에서 페이로드를 자동 발사 후 응답 본문에 success indicator 가 떴는지로 성공/실패를 판정합니다.
- **운영 지향 설계**: Redis sliding-window 레이트 리미터, 지수 백오프 재시도, 파서별 격리된 장애 추적, Meilisearch 장애 시 PostgreSQL tsvector 자동 폴백, 합성 이미지 LRU GC, internal-only bridge 네트워크 + cgroup/PID 한도 등 운영 표면을 기본 제공합니다.
- **단일 명령 기동**: `docker compose up --build` 한 줄로 프런트엔드, 백엔드, DB, 검색 엔진, 캐시, 그리고 샌드박스 네트워크까지 전부 실행됩니다.

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
- URL 동기화 필터: `?q=log4j&severity=critical&os=linux&type=RCE&from=2026-01-01&sort=cvss`.
- **부분 CVE-id 검색** — `"44228"`, `"2021-44"`, `"cve-2024-3"` 처럼 숫자/대시 단편만 쳐도 ILIKE 매칭으로 prepend (페이지 1 한정으로 pagination drift 회피).
- **전역 sort** — `newest / oldest / severity / cvss` 4 키 모두 Meili sortable attribute(`severityRank`, `cvssScore`, `publishedAt`) 로 처리해 페이지 단위가 아닌 전체 결과 기준 정렬. severity/cvss 는 `publishedAt:desc` tiebreak.
- **카테고리 세분화** — vuln-type 16 종(RCE/XSS/SQLi/CSRF/XXE/SSRF/LFI/Path-Traversal/Deserialization/Open-Redirect/Privilege-Escalation/Info-Disclosure/Memory-Corruption/DoS/Auth/Other), 기간 프리셋 6 종(`오늘 / 7일 / 30일 / 90일 / 1년 / 직접 입력`, KST 로컬 타임존 기준).
- **도메인 분류 (PR 10-B)** — vuln-type(메커니즘)과 별도 축으로 *기술 표면* 18 종(`커널 / OS / 브라우저 / 웹서버 / 웹프레임워크 / DB / 미디어 / 네트워크 / 메일 / 인증 / 암호 / 런타임 / 모바일 / 가상화 / 오피스 / 엔터프라이즈 / IoT / 메신저`)을 chip 으로 다중 선택. 한 CVE 가 여러 도메인을 가질 수 있어 (예: 오디오 코덱 버그가 SSH 클라이언트까지 위협 → `media + auth`), `vulnerabilities.domains TEXT[]` + GIN index `&&` 으로 overlap 매칭. 인제스션 시 `domain_classifier.infer_domains(parsed)` 가 vendor/product CPE 룰 + 본문 키워드 룰 두 층으로 도출.
- 디바운스 검색(300ms), `keepPreviousData`로 깜빡임 없는 전환.

### 사용자 경험
- 다크/라이트/시스템 테마 (pre-hydration boot script로 FOUC 제거).
- CVE 즐겨찾기 (별 토글) + "즐겨찾기만" 뷰.
- 자산 등록 → 실시간 CPE 매칭 → "내 시스템 취약점" 카드.
- 우측 하단 플로팅 시스템 상태 팝오버(DB/Redis/Meili 핑, 마지막 수집 성공/실패).

### 샌드박스 (재현 + 검증)
- **vulhub reproducer 우선** — `vulhub_harvester` 가 vulhub 저장소를 git clone/pull 해서 CVE → compose 디렉터리 매핑을 빌드. 호스트 docker 데몬이 sibling 으로 lab 컨테이너를 띄움.
- **6 종 generic lab 폴백** — vulhub 매핑도 없고 합성도 안 된 CVE 는 CWE/키워드 기반 분류로 6 클래스 (`xss / rce / sqli / ssti / path-traversal / ssrf`) 중 가장 가까운 generic Flask lab 으로 폴백. 빌드는 `bash sandbox-labs/build_all.sh` 한 줄, 모두 `python:3.12-slim + flask + gunicorn` 공유 베이스라 cold ~3-5 분 / warm <30s.
- **AI lab synthesizer** — vulhub 도 generic 도 안 맞는 CVE 는 LLM 이 단일 파일 Dockerfile + 앱 + 주입 지점 + 페이로드 + success indicator 를 한 번에 만들고, 격리 네트워크에서 실제 빌드/검증한 다음에만 `cve_lab_mappings(verified=true)` 로 캐시. prompt 가 9 클래스 (RCE/SQLi/SSTI/path-traversal/XSS/XXE/open-redirect/deserialization/SSRF) 모두를 동등하게 가이드하므로 모든 CVE 가 XSS 로 환원되지 않음.
- **백엔드 ground-truth 검증 (PR 9-L/9-M/9-N)** — 합성 lab 의 신뢰 게이트가 LLM 폐쇄 루프에서 백엔드 probe 로 이동. RCE / path-traversal / SSTI / XSS / time-based SQLi / XXE / open-redirect / deserialization / SSRF 9 클래스에 대해 백엔드가 직접 만든 페이로드 + `docker exec` 로 stamp 한 카나리 (또는 redirect nonce / file-side-effect / inbound HTTP 캐너리 컨테이너) + benign nonce 음성 대조로 echo machine 형태 lab 을 빌드 직후에 거부. echo trap 셰이프(`success_indicator` 가 너무 짧음 / payload 와 동일 / `files[*].content` 에 그대로 박힘 / `response_kind` 누락) 는 빌드 전에 차단.
- **격리 토폴로지** — `kestrel_sandbox_net` 은 internal-only bridge (인터넷 X), 모든 lab 컨테이너는 256MB / 0.5 CPU / 128 PIDs 한도. `SANDBOX_HARDEN=true` 시 read-only rootfs, `no-new-privileges`, custom seccomp.
- **자동 페이로드 + 판정** — `payload_adapter` 가 LLM 또는 cached known-good payload 를 골라 lab 의 주입 지점으로 발사 → 응답 본문에 success indicator 가 보이면 success, 아니면 retry/실패 판정.
- **사용자 평가 루프 (PR 9-J/K)** — 합성 lab 카드에서 👍/👎 + 노트. `down ≥ 2 AND down ≥ up + 2` 면 자동 격하되어 다음 호출에서 skip. "새로 합성으로 시도" 클릭 시 이전 시도(베이스/주입 지점/페이로드/👎 노트 + 직전 probe 거부 사유)를 다음 LLM 프롬프트에 자연어 블록으로 주입하는 self-refinement 루프. 사용자 신호는 보조이고 truth oracle 은 backend probe 가 유지.
- **LRU GC + 운영자 대시보드** — 합성 이미지가 disk 를 다 먹지 않도록 총량/개수/age 3중 ceiling 으로 LRU 회수, 사용 중인 이미지는 skip. `GET /sandbox/synthesize/cache` 로 현재 상태와 다음에 evict 될 후보를 노출.

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
        ┌─────────────────────────────────────────────────┼───────────────────────────┐
        │                                                 │                           │
  ┌─────▼─────┐     ┌────────────┐     ┌────────▼────┐    ┌─────▼─────┐    ┌──────────▼──────────┐
  │ Postgres  │     │ Meilisearch│     │    Redis    │    │APScheduler│    │ Sandbox / Synthesizer│
  │ (truth DB)│     │  (search)  │     │ (rate-limit)│    │ (ingest)  │    │ (host docker daemon) │
  └───────────┘     └────────────┘     └─────────────┘    └─────┬─────┘    └──────────┬──────────┘
                                                                │                     │ DooD via /var/run/docker.sock
                          ┌─────────────────────────────────────┼─────────┐           │
                          │                                     │         │           ▼
                    ┌─────▼─────┐                       ┌───────▼─────┐ ┌─▼──────┐  ┌──────────────────────┐
                    │ NVD 2.0   │                       │ Exploit-DB  │ │ GHSA   │  │ kestrel_sandbox_net  │
                    │ REST API  │                       │ CSV mirror  │ │GraphQL │  │ (internal bridge)    │
                    └───────────┘                       └─────────────┘ └────────┘  │  ├─ vulhub lab(s)    │
                                                                                    │  └─ kestrel-syn-*    │
                                                                                    └──────────────────────┘
```

- PostgreSQL이 단일 진실 소스. Meilisearch는 색인 레이어(장애 시 자동 폴백).
- Alembic 마이그레이션이 컨테이너 기동 시 자동 실행.
- `raw_data JSONB` 컬럼으로 소스 원본 보존 → 스키마 변경 시 재파싱 가능.
- 샌드박스는 호스트 도커 데몬을 마운트해 sibling 컨테이너로 lab 을 띄우는 DooD 모델 — backend 컨테이너 자체가 격리 네트워크에 들어가지 않으므로 lab 의 인터넷 차단/리소스 한도가 backend 의 외부 통신에 영향을 주지 않습니다.

---

## 스크린샷

| Dashboard | CVE Detail | Settings |
| :-------: | :--------: | :------: |
| <img width="1655" height="902" alt="스크린샷 2026-04-20 09 05 07" src="https://github.com/user-attachments/assets/a2b1a92f-862f-4784-ba44-fc7d6933a390" />| <img width="1655" height="902" alt="스크린샷 2026-04-20 09 07 18" src="https://github.com/user-attachments/assets/2874f850-527d-4313-86d5-b04fffb1ef4e" />| <img width="1655" height="902" alt="스크린샷 2026-04-20 09 08 05" src="https://github.com/user-attachments/assets/c04e0cce-e5a5-4293-a04d-687a6e97cd92" />|

---

## Tech Stack

| Layer       | Tech                                                                 |
| ----------- | -------------------------------------------------------------------- |
| Frontend    | Next.js 15 (App Router) · React 19 · TypeScript · TailwindCSS · TanStack Query v5 · lucide-react |
| Backend     | FastAPI · SQLAlchemy 2.0 async · asyncpg · Pydantic v2 · APScheduler · tenacity · structlog · httpx |
| Database    | PostgreSQL 16 (JSONB + tsvector + GIN 인덱스)                        |
| Search      | Meilisearch v1.10 (rankingRules 튜닝, stopWords, typoTolerance)      |
| Cache       | Redis 7 (sliding window rate limiter)                                |
| AI          | OpenAI · Anthropic · Gemini · Groq · OpenRouter · Cerebras · Claude Code CLI (다중 제공자, 활성 키 스위치) |
| Sandbox     | Docker SDK for Python · vulhub git harvester · custom AI lab synthesizer · internal bridge network · cgroup/PID 한도 + 옵트인 seccomp |
| Infra       | Docker Compose (멀티 아키텍처 자동 빌드, DooD via host socket)         |
| Observability (optional) | Sentry · OpenTelemetry                                   |
| Testing     | Playwright (frontend e2e)                                            |

---

## Quick Start (Docker)

```bash
git clone https://github.com/mimonimo/Kestrel.git
cd Kestrel
cp .env.example .env
# 선택: .env 의 NVD_API_KEY, GITHUB_TOKEN 을 채우면 외부 API 레이트 리밋이 크게 완화됩니다.
docker compose up --build
```

| 서비스 | URL |
| --- | --- |
| Frontend | http://localhost:3000 |
| Backend (Swagger) | http://localhost:8000/docs |
| Meilisearch | http://localhost:7700 |

첫 기동 시 Alembic 마이그레이션이 자동 적용되고, NVD에서 최근 30일 분 CVE가 백그라운드로 수집됩니다(약 2~5분). 이후에는 스케줄러가 소스별 증분 수집을 자동으로 이어갑니다.

### 지원 플랫폼

기본 `docker-compose.yml` 은 호스트 아키텍처를 그대로 사용하도록 구성되어 있어, 별도 설정 없이 다음 환경에서 동일한 명령으로 실행됩니다.

| 환경 | 비고 |
| --- | --- |
| Apple Silicon macOS (arm64) | 네이티브 빌드, 가장 빠름 |
| Intel/AMD Linux (amd64) | 운영 서버 권장 |
| Windows (WSL2) | 호스트 아키텍처와 동일 |

`docker compose` (Compose v2, 공백) 와 `docker-compose` (Compose v1, 하이픈) 중 시스템에 설치된 쪽 어느 것을 사용해도 동작합니다.

### arm64 호스트에서 amd64 이미지를 빌드해야 할 때

Apple Silicon에서 빌드한 이미지를 amd64 운영 서버로 푸시·배포해야 하는 경우에만 필요합니다. `buildx` 또는 별도 override 파일을 통해 플랫폼을 명시할 수 있습니다.

**buildx 직접 호출**

```bash
docker buildx build --platform linux/amd64 \
  -t kestrel-backend:latest ./backend --load
docker buildx build --platform linux/amd64 \
  -t kestrel-frontend:latest ./frontend --load
```

**Compose override 사용** — `docker-compose.prod.yml`

```yaml
services:
  backend:
    platform: linux/amd64
  frontend:
    platform: linux/amd64
```

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

> 메인 `docker-compose.yml` 에 `platform: linux/amd64` 를 직접 추가하면 Apple Silicon 로컬 환경에서 빌드와 실행 아키텍처가 어긋나 컨테이너 기동이 실패할 수 있으므로, 운영 환경 전용 override 파일로 분리하는 것을 권장합니다.

---

## Ubuntu 22.04 원클릭 셋업

아래 절차는 깨끗한 Ubuntu 22.04 LTS 서버를 기준으로 합니다. 모두 수행하면 Kestrel이 `http://<서버IP>:3000` 에서 즉시 동작합니다.

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

# 현재 사용자에 docker 그룹 부여 (로그아웃 후 재로그인 시 적용)
sudo usermod -aG docker $USER
newgrp docker

# 설치 확인
docker --version
docker compose version
```

### 2. 방화벽 설정 (UFW)

공개 서버라면 3000(프런트엔드)과 8000(API) 포트만 열고, 나머지 의존 서비스는 Docker 내부 네트워크에서만 통신하도록 닫아 두는 것을 권장합니다.

```bash
sudo ufw allow OpenSSH
sudo ufw allow 3000/tcp   # 프런트엔드
sudo ufw allow 8000/tcp   # 백엔드 API (리버스 프록시 쓸 땐 생략)
sudo ufw enable
sudo ufw status
```

> 운영 환경에서는 8000을 직접 노출하지 말고, Nginx 또는 Caddy를 사용해 3000과 함께 443(TLS) 경로에서 리버스 프록시하는 구성을 권장합니다.

### 3. 저장소 클론 · 환경변수

```bash
cd /opt
sudo git clone https://github.com/mimonimo/Kestrel.git
sudo chown -R $USER:$USER Kestrel
cd Kestrel
cp .env.example .env

# 선택: 외부 API 호출 한도를 늘리려면 다음 키들을 .env 에 채워 주세요.
# - NVD_API_KEY: https://nvd.nist.gov/developers/request-an-api-key
# - GITHUB_TOKEN: https://github.com/settings/tokens (별도 scope 불필요)
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

첫 기동 시 Alembic 마이그레이션과 NVD 최근 30일 분 수집이 자동으로 수행되며, 보통 2~5분 정도 소요됩니다.

### 5. systemd로 부팅 시 자동 기동 (선택)

`docker-compose.yml` 의 모든 서비스는 `restart: unless-stopped` 정책을 사용하므로, Docker 데몬이 시작되면 컨테이너도 자동으로 복구됩니다. Ubuntu 22.04에서는 Docker 데몬이 기본적으로 활성화되어 있어 별도 systemd 유닛을 만들지 않아도 재부팅 후 자동 기동됩니다. 상태를 직접 확인하려면 다음 명령을 사용합니다.

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
| `SANDBOX_NETWORK` | lab 컨테이너가 붙는 internal-only bridge 이름 | `kestrel_sandbox_net` |
| `SANDBOX_TTL_SECONDS` | lab 자동 reaping 주기 | `1800` |
| `SANDBOX_HARDEN` | `true` 시 read-only rootfs · no-new-privileges · seccomp 강화 (옵트인) | `false` |
| `SANDBOX_RUNTIME` / `SANDBOX_SECCOMP_PATH` | 런타임/seccomp 프로파일 (예: `runsc`, gVisor 환경) | — |
| `VULHUB_REPO_PATH` / `VULHUB_HOST_PATH` | vulhub 저장소 경로 (컨테이너/호스트 동일하게 두는 것을 권장) | `/data/vulhub` |
| `VULHUB_REPO_REMOTE` | git clone 원격 | `https://github.com/vulhub/vulhub.git` |
| `DOCKER_GID` | Linux 호스트에서 docker.sock 그룹 GID (macOS+OrbStack 은 0) | `0` |
| `INSTALL_CLAUDE_CLI` | `1` 시 backend 이미지에 `claude` CLI 설치 (Claude Code CLI 제공자용) | `0` |
| `SENTRY_DSN` | Sentry(선택) | — |
| `OTEL_ENABLED` / `OTEL_EXPORTER_OTLP_ENDPOINT` | OpenTelemetry(선택) | `false` |

설정 페이지(`/settings`)에서는 NVD 키, GitHub 토큰, 사용자 자산, 테마 등을 모두 브라우저 localStorage 에 저장합니다. 이 값들은 서버로 영구 전송되지 않으며, 수동 재수집을 트리거할 때만 요청 헤더로 1회성 전달됩니다.

---

## AI 심층 분석

CVE 상세 페이지에서 **"AI 심층 분석 요청"** 버튼을 누르면 LLM이 해당 CVE만의 구체적 공격 기법·PoC 페이로드·패치 방안을 한국어로 생성합니다. 페이로드는 취약점 유형(XSS·SQLi·RCE·SSRF·경로 순회 등)에 맞춰 실제 테스트 환경에서 재현할 수 있는 형태로 작성되며, 대응 방안은 그 페이로드가 어떤 검사·패치로 무력화되는지 1:1로 매핑해 제시합니다.

제공자·모델·키는 설정 페이지(`/settings`)에서 여러 개 등록하고 활성 키를 스위치할 수 있습니다. 저장된 키에서 모델만 즉석 변경도 가능합니다.

### 지원 제공자

| 제공자 | 등록 방식 | 비고 |
| --- | --- | --- |
| **OpenAI** | API 키 | `gpt-5`, `gpt-5-mini`, `gpt-4.1` 계열. `json_schema` strict 응답 형식 사용. |
| **Anthropic** | API 키 | `claude-opus-4-7`, `claude-sonnet-4-6`, `claude-haiku-4-5-20251001`. Anthropic Messages API 직접 호출. |
| **Google Gemini (무료 티어)** | API 키 | [aistudio.google.com](https://aistudio.google.com/apikey)에서 발급. Flash 일 1,500 요청 무료. OpenAI 호환 엔드포인트 사용. |
| **Groq (무료 티어)** | API 키 | [console.groq.com](https://console.groq.com/keys) 발급. Llama 3.3 70B / 3.1 8B / Mixtral / Gemma2, 분당 30·일 14,400 요청 무료. |
| **OpenRouter (:free 모델)** | API 키 | [openrouter.ai/keys](https://openrouter.ai/keys) 발급. `:free` 접미사 모델만 무료 (DeepSeek, Llama 3.3, Qwen 등). |
| **Cerebras (무료 티어)** | API 키 | [cloud.cerebras.ai](https://cloud.cerebras.ai)에서 발급. Llama 3.3 70B 일 100만 토큰 무료, 추론 속도 최고 수준. |
| **Claude Code CLI** | 키 불필요 | 호스트에 설치된 `claude` CLI(본인 구독)로 분석 수행. 아래 섹션 참고. |

### Claude Code CLI 연동

별도 Anthropic API 결제 없이 본인이 이미 쓰고 있는 Claude Code 구독으로 분석을 돌리고 싶을 때 사용합니다. 백엔드 컨테이너에 `claude` CLI를 설치하고, 호스트의 `~/.claude` 로그인 정보를 읽기 전용으로 마운트합니다.

**1. 호스트에서 claude CLI에 먼저 로그인** (아직 안 돼 있다면)

```bash
npm install -g @anthropic-ai/claude-code
claude login
```

**2. (macOS만) 키체인의 OAuth 토큰을 파일로 내보내기**

macOS의 Claude Code CLI는 OAuth 토큰을 **Keychain**(`Claude Code-credentials`)에 저장하므로, `~/.claude` 를 그냥 마운트해도 Linux 컨테이너 안의 CLI는 만료된 legacy `~/.claude/.credentials.json` 으로 폴백해 401 또는 빈 응답이 됩니다. 동기화 헬퍼를 한 번 실행하세요. (Linux 호스트는 호스트 CLI 가 직접 파일을 갱신하므로 건너뛰세요.)

```bash
backend/scripts/sync_claude_creds_from_keychain.sh
# → synced: /Users/<you>/.claude/.credentials.json (expiresAt=2026-05-03T21:56:41)
```

> 스크립트가 Keychain 페이로드의 JSON 모양을 검증한 뒤 원자적으로 `~/.claude/.credentials.json` 에 기록하고, 만료 시각을 출력합니다. 토큰이 만료되거나 401 이 다시 보이면 같은 스크립트를 한 번 더 돌리면 됩니다 (백엔드 재빌드 불필요 — read-only mount 가 호스트 파일의 새 내용을 바로 봅니다). 토큰 만료 패턴이 짧다면 `cron` 또는 macOS LaunchAgent 로 주기적 호출을 권장합니다.

오류 메시지에 `claude CLI 인증 실패. macOS 호스트라면 ...` hint 가 같이 뜨므로 어떤 단계에서 막혔는지 바로 알 수 있고, 컨테이너 안 CLI 가 호스트보다 구버전이라 silent empty 가 발생하면 `_call_claude_cli_text()` 가 `npm install -g @anthropic-ai/claude-code@latest` 로 1회 자동 self-upgrade 후 재시도합니다 (역시 rebuild 불필요).

**3. `.env` 에 플래그 설정**

```env
INSTALL_CLAUDE_CLI=1
# 기본은 ~/.claude 를 사용합니다. 다른 경로에 저장한다면:
# CLAUDE_HOME=/custom/path/.claude
# CLAUDE_CONFIG=/custom/path/.claude.json
```

**4. Claude CLI 오버레이와 함께 기동**

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.claude-cli.yml \
  up -d --build
```

**5. 설정 페이지에서 키 추가**

- 제공자: `Claude Code CLI (로컬 구독)` 선택
- 모델: `claude-opus-4-7` 등
- API 키 입력란 없음 — 바로 저장

이후 CVE 상세 페이지의 **AI 심층 분석 요청** 이 호스트의 Claude 구독을 통해 동작합니다.

> ⚠️ `~/.claude/.credentials.json` 에는 세션 토큰이 있으므로 마운트는 읽기 전용입니다. 컨테이너 외부에 노출되지 않도록 주의하세요. 공용/공유 서버에서 이 방식을 쓰는 것은 권장하지 않습니다.

### AI 의 두 가지 역할

Kestrel 에서 LLM 은 두 곳에서 쓰입니다 — 같은 활성 키가 두 작업 모두에 사용됩니다.

1. **CVE 심층 분석** (CVE 상세 → "AI 심층 분석 요청") — 공격 기법, 페이로드, 대응 방안을 한국어 마크다운으로 생성.
2. **Lab 합성** (샌드박스 → vulhub 매핑이 없을 때) — Dockerfile + 앱 코드 + 주입 지점 + 페이로드 + success indicator 를 JSON 으로 생성, backend 가 빌드/검증 후 캐시. 자세한 동작은 다음 섹션 참고.

### 무료·저비용 시작 팁

- **아무 키도 없을 때**: Groq → Cerebras → Gemini 순서로 시도해보세요. 등록이 가장 간단하고 속도도 빠른 건 Groq, 출력 품질은 Gemini가 가장 좋은 경향입니다.
- **Anthropic API 크레딧 부족 오류가 뜰 때**: `console.anthropic.com` 에서 결제 수단을 등록하거나, Claude Code CLI 방식으로 전환하세요.
- **Gemini 403 `PERMISSION_DENIED`**: 지역 제한 또는 프로젝트 플래그로 차단된 경우입니다. AI Studio에서 **새 프로젝트**로 키를 다시 발급하면 대부분 해결됩니다.

---

## 샌드박스 (CVE → 격리 컨테이너 → 자동 검증)

CVE 상세 페이지의 **샌드박스** 카드에서 **세션 시작** 을 누르면, 해당 CVE 가 실제로 트리거되는 격리 컨테이너가 즉석에서 떠오르고, AI 가 만든 페이로드를 자동으로 발사한 다음, 응답 본문에 success indicator 가 보였는지로 성공/실패를 보여줍니다. 외부 인터넷 접근이 차단된 internal-only 브리지 위에서, 메모리/CPU/PID 한도가 강제된 상태로 돌아갑니다.

### 어떻게 lab 이 결정되는가 (resolver chain)

```
1. cve_lab_mappings(kind=vulhub, verified=true)        ← vulhub_harvester 가 git 에서 채워둔 정식 reproducer
2. cve_lab_mappings(kind=synthesized, verified=true)   ← AI 가 합성 + 검증 통과 후 캐시한 lab
                                                       (is_degraded(mapping) 면 skip → 다음 단계로)
3. classifier 가 추정한 generic lab (CWE → 일반 카탈로그)
4. 사용자가 명시 동의 시 → AI 합성 실시간 호출 (별도 24h 쿨다운)
```

- **격하 (degradation)**: 합성 lab 카드의 👎 가 `down ≥ 2 AND down ≥ up + 2` 를 넘기면 매핑이 자동 skip 됩니다. 한 명의 사용자가 lab 을 죽일 수 없도록 최소 2명의 별개 클라이언트를 요구합니다.
- **Self-refinement**: 격하 후 "새로 합성으로 시도" 를 누르면 이전 시도(베이스 이미지 / 주입 지점 / 페이로드 / 👎 노트 / 직전 backend probe 거부 사유) 가 다음 LLM 프롬프트에 자연어 블록으로 주입돼, 같은 실패를 반복하지 않도록 다른 접근을 강제합니다.
- **백엔드 ground-truth 검증 (PR 9-L/9-M)**: 빌드 직후 spawn 한 lab 에 대해 `response_kind` 별로 매칭되는 backend probe (RCE 카나리 read / path-traversal 카나리 read / SSTI 산술식 평가 / XSS 두-nonce reflect / time-based blind SQLi / XXE `file://` 엔티티 카나리 / open-redirect Location nonce / deserialization 파일 side-effect 카나리) 를 실행. 각 probe 는 페이로드/카나리/예상 substring/음성 대조를 모두 백엔드가 만들어내며, lab 안의 카나리는 `docker exec` 로 stamp 합니다 (HTTP 표면을 거치지 않으므로 LLM 이 위조 불가). 양성 probe 가 하나라도 통과 + 음성 대조 깨끗하면 `verified=backend_probe`, 모두 실패하면 `rejected` (legacy LLM-indicator 결과는 통과해도 구제하지 않음). probe 가 적용 안 되는 vuln class 는 `llm_indicator_only` 약식 검증으로 통과시키되 매핑 카드에 ⚠️ 표시.
- **빌드 전 echo trap 차단**: `success_indicator` 가 8자 미만 / payload 와 동일 / `files[*].content` 에 그대로 박힘 / `response_kind` 누락 시 `_validate_parsed` 가 빌드 진입 전에 거부합니다 — LLM 이 자기-일관된 echo 루프를 만들지 못하도록 하는 정적 게이트.

### 격리 + 안전장치

- **네트워크**: `kestrel_sandbox_net` 은 `internal: true` 브리지 — lab 컨테이너는 외부 인터넷에 접근할 수 없고, exfil 패턴이 동작하지 않습니다.
- **리소스**: 컨테이너당 메모리 256MB · CPU 0.5 코어 · PID 128 한도 (기본값, `.env` 로 조정 가능). 동시 lab 수도 `SANDBOX_MAX_CONCURRENT` 로 제한.
- **TTL 자동 회수**: `sweeper` 가 30분 (`SANDBOX_TTL_SECONDS`) 마다 idle lab 을 자동 stop. 합성 이미지는 별도 LRU GC 로 디스크 캡 (총량/개수/age 3중 ceiling) 안에서 회수.
- **하드닝 (옵트인)**: `.env` 에 `SANDBOX_HARDEN=true` + (선택) `SANDBOX_RUNTIME=runsc` / `SANDBOX_SECCOMP_PATH=...` 를 두면 read-only rootfs · `no-new-privileges` · 사용자 지정 seccomp 가 적용됩니다.
- **DooD 모델**: backend 컨테이너가 `/var/run/docker.sock` 을 마운트해 호스트 도커 데몬에 lab 을 sibling 으로 띄웁니다. 즉 docker-in-docker 가 아니므로 lab 의 격리 정책이 backend 자체에 영향을 주지 않습니다. 반대로 docker.sock 마운트는 사실상 root 권한이므로, 운영 환경에서는 backend 가 받는 이미지/리소스/네트워크 파라미터를 화이트리스트로 제한합니다 (`app/services/sandbox/manager.py`).

### vulhub 저장소 준비

vulhub reproducer 를 자동 활용하려면 호스트의 어딘가에 vulhub 저장소가 있어야 합니다. 첫 기동 시 Kestrel 이 자동으로 clone 합니다 (`VULHUB_REPO_REMOTE` 기본값). 이미 다른 곳에 받아둔 저장소가 있다면:

```bash
# .env 에 호스트 경로와 컨테이너 경로를 같게 두는 것을 권장 (compose 사이블링이 호스트 경로로 읽음)
VULHUB_HOST_PATH=/data/vulhub
VULHUB_REPO_PATH=/data/vulhub

# 수동 동기화
curl -X POST http://localhost:8000/api/v1/sandbox/vulhub/sync
```

### 사용 예 (curl)

```bash
# 1. CVE 가 어떤 lab 으로 매핑되는지 + 합성 가능한지 확인
curl -s http://localhost:8000/api/v1/cves/CVE-2021-44228 | jq '.title'

# 2. 세션 시작 — vulhub 매핑이 없고 합성도 거부했다면 422 lab_degraded / no_lab 가 떨어짐
curl -s -X POST http://localhost:8000/api/v1/sandbox/sessions \
  -H "Content-Type: application/json" \
  -H "X-Client-Id: $(uuidgen)" \
  -d '{"cveId":"CVE-2021-44228","attemptSynthesis":false}'

# 3. 명시 동의로 AI 합성 호출 (실시간 진행상황은 SSE 로 노출)
curl -N http://localhost:8000/api/v1/sandbox/synthesize/stream \
  -H "Content-Type: application/json" \
  -d '{"cveId":"CVE-2099-EXAMPLE"}'

# 4. 합성 캐시 상태 보기 / 즉석 GC
curl -s http://localhost:8000/api/v1/sandbox/synthesize/cache | jq '.'
curl -s -X POST http://localhost:8000/api/v1/sandbox/synthesize/gc | jq '.evicted | length'
```

### 무엇을 검증하지 않는가 (한계)

- **Lab 의 "CVE 정확성" 은 backend probe 가 커버하는 vuln class 안에서만 보장됩니다**. PR 9-M 시점에 RCE / path-traversal / SSTI / XSS / time-based SQLi / XXE / open-redirect / deserialization 8 종은 backend probe 가 ground-truth 로 거부/통과를 판정합니다. 그 외 클래스(SSRF, auth bypass, IDOR, JNDI 등) 는 약식 `llm_indicator_only` 검증으로만 통과되며 매핑 카드에 ⚠️ 표시 — 사용자 👍/👎 평가가 보조 신호로 사용됩니다.
- **외부 의존이 큰 CVE 는 합성에 부적합**합니다. systemd / mysql / 외부 OAuth 같이 무거운 스택이 필요한 CVE 는 vulhub 매핑이 있어야 의미 있습니다.
- 운영 환경에 띄울 때는 반드시 `SANDBOX_HARDEN=true` + 가능한 경우 gVisor (`SANDBOX_RUNTIME=runsc`) 조합을 권장합니다.

---

## 로컬 개발 (Docker 없이)

> **사전 요구사항** — Python 3.12+, Node.js 20+, 그리고 호스트에서 접근 가능한 PostgreSQL 16, Redis 7, Meilisearch v1.10 인스턴스가 필요합니다.
> 가장 권장되는 구성은 인프라(PostgreSQL · Redis · Meilisearch)만 Docker 로 실행하고 애플리케이션 코드는 호스트에서 직접 구동하는 하이브리드 모드입니다.

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
| `POST /api/v1/sandbox/vulhub/sync` | vulhub 저장소 git pull + CVE 매핑 재빌드 |
| `POST /api/v1/sandbox/sessions`   | CVE 에 대한 격리 lab 세션 시작 (`X-Client-Id`) |
| `GET  /api/v1/sandbox/sessions/{id}` | 세션 상태 + lab 정보 + 사용자 평가 |
| `DELETE /api/v1/sandbox/sessions/{id}` | 세션 즉시 종료 + 컨테이너 stop |
| `POST /api/v1/sandbox/sessions/{id}/exec` | lab 으로 페이로드 발사 + 응답/판정 |
| `POST /api/v1/sandbox/sessions/{id}/feedback` | 합성 lab 평가 (`{vote: "up"\|"down", note?}`) |
| `POST /api/v1/sandbox/synthesize` | AI lab 합성 호출 (블로킹) |
| `POST /api/v1/sandbox/synthesize/stream` | 합성 진행상황 SSE 스트림 |
| `GET  /api/v1/sandbox/synthesize/cache` | 합성 이미지 캐시 리포트 (운영자 대시보드) |
| `POST /api/v1/sandbox/synthesize/gc` | 합성 이미지 LRU GC 즉시 실행 |

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
│       ├── api/v1/                # 라우터 (health/status/cves/search/assets/admin/sandbox/...)
│       ├── services/
│       │   ├── parsers/           # nvd · exploit_db · github_advisory
│       │   ├── ingestion.py       # 오케스트레이터
│       │   ├── search_service.py  # Meilisearch 래퍼
│       │   ├── rate_limiter.py    # Redis sliding window
│       │   ├── ai_analyzer.py     # 다중 제공자 LLM 클라이언트 (CVE 분석 + lab 합성 공용)
│       │   └── sandbox/
│       │       ├── manager.py            # docker SDK 래퍼 (lab spawn/stop/proxy/exec)
│       │       ├── lab_resolver.py       # vulhub → 합성 → generic resolver chain
│       │       ├── vulhub_harvester.py   # git clone/pull + compose 매핑 빌더
│       │       ├── synthesizer.py        # AI lab 합성기 (self-refinement 포함)
│       │       ├── synthesizer_probes.py # backend ground-truth probes (PR 9-L)
│       │       ├── synthesizer_gc.py     # 합성 이미지 LRU GC
│       │       ├── catalog.py            # generic lab 카탈로그
│       │       ├── classifier.py         # CWE → generic lab 분류기
│       │       ├── payload_adapter.py    # cached / LLM 페이로드 선택
│       │       ├── result_analyzer.py    # 응답 본문 → 성공/실패 판정
│       │       └── sweeper.py            # TTL 기반 idle lab 회수
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
    │   ├── cve/                   # 리스트 아이템 · 상세 · 즐겨찾기 · AI 분석 패널 · SandboxPanel
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

- [x] 익명 커뮤니티 (게시글 · 댓글 · CVE 단위 토론 스레드)
- [x] 사용자 자산 등록 + CPE 매칭
- [x] 즐겨찾기 (백엔드 영속화)
- [x] AI 심층 분석 — 다중 제공자(OpenAI · Anthropic · Gemini · Groq · OpenRouter · Cerebras · Claude Code CLI) + 활성 키 스위치
- [x] 티켓 시스템 (미확인 / 조치완료 상태 + 주의 / 경고 / 심각 뱃지)
- [x] 격리 샌드박스 (vulhub reproducer + DooD + internal-only bridge + cgroup/PID 한도 + 옵트인 seccomp)
- [x] AI lab 합성기 (Dockerfile + 앱 + 페이로드 + indicator 자동 생성 + 검증 후 캐시)
- [x] 합성 lab LRU GC + 운영자 대시보드
- [x] 합성 진행 SSE 스트리밍
- [x] 사용자 평가(👍/👎) → 자동 격하 + self-refinement 루프 (이전 시도를 다음 LLM 프롬프트에 주입)
- [x] 백엔드 ground-truth 검증 (RCE / path-traversal / SSTI / XSS / time-based SQLi backend probe + canary + echo-trap 거부)
- [x] backend probe 클래스 확장 (XXE / open-redirect / deserialization — PR 9-M)
- [ ] backend probe 추가 클래스 (SSRF OOB 사이드카 / auth-bypass / JNDI)
- [ ] 합성 lab 다중 후보 보존 + best-of-N 선택 (PR 9-N 예정)
- [ ] CVSS 게이지 시각화 및 다양한 정렬 옵션
- [ ] Slack · Discord · Webhook 알림
- [ ] OSV 스키마 확장
- [ ] LLM 요약 교체 (현재는 휴리스틱 기반)

---

## 기여

이슈와 Pull Request 모두 환영합니다.

- 브랜치 접두사: `feat/...`, `fix/...`, `chore/...`, `docs/...`
- 커밋 메시지는 Conventional Commits 형식을 권장합니다 (예: `feat: add bookmark filter`).
- 버그 리포트를 작성할 때는 `/api/v1/status` 응답을 함께 첨부해 주시면 원인 파악이 빠릅니다.

---

## License

[MIT](./LICENSE) © mimonimo

원본 취약점 데이터의 저작권은 각 제공처(NVD, Exploit-DB, GitHub Advisory)에 있으며, Kestrel은 이를 정규화하고 검색·시각화하는 레이어만 제공합니다.
