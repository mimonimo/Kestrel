# Kestrel — Work Progress Log

---

## Step 1 — Architecture & Schema Design ✅

**완료일:** 2026-04-18

### Tech Stack 결정
- Frontend: Next.js 15 (App Router) + TypeScript + TailwindCSS + shadcn 스타일 UI + TanStack Query + Zustand
- Backend: FastAPI (Python 3.12) + SQLAlchemy 2.0 async + Alembic + APScheduler
- DB: PostgreSQL 16 (JSONB + tsvector GIN 인덱스)
- Search: Meilisearch (인스턴트 검색, 오타 허용, 팩싯 필터)
- Cache: Redis (rate limit + 세션)
- Infra: Docker Compose, Vercel(FE) + Fly.io/Railway(BE), GitHub Actions

### 핵심 DB 스키마
- `vulnerabilities` (메인, tsvector 포함)
- `vulnerability_types` ↔ `vulnerability_type_map` (M:N)
- `affected_products` (os_family 인덱스로 OS 필터 고속화)
- `references` (advisory/exploit/patch/writeup)
- `ingestion_logs` (파싱 이력 추적)
- 커뮤니티용: `users`, `posts`, `comments`, `votes`, `tags` (NULLABLE FK로 CVE/독립 게시 양립)

---

> 진행 상황: Step 1 ✅ · Step 2 ✅ · Step 3 ✅ · Step 4 ✅ · Step 5 ✅ · Step 6 ✅ · Step 7 ✅ · Step 8 ✅ · Step 9 🚧

---

## Step 2 — Frontend UI/UX ✅

**완료일:** 2026-04-19

- Next.js 15 + TypeScript 스캐폴딩 (Dockerfile 멀티스테이지 + standalone 모드)
- 다크 모드 기본 적용 (`surface-0~3` 팔레트, 심각도별 반투명 컬러)
- 컴포넌트: SearchBar (히어로), FilterPanel, CveListItem, CveDetail (출처 URL 최하단), SeverityBadge, Header, Footer
- 페이지: 대시보드, 상세, 404
- Mock 데이터 15건 (현실적 CVE — OpenSSL TLS RCE, Chrome V8 0-day, iOS WebKit, Spring SpEL 등)

---

## Step 3 — Backend API & Ingestion ✅

**완료일:** 2026-04-19

### 추가된 백엔드 구조

```
backend/
├── pyproject.toml                  # FastAPI, SQLAlchemy 2.0 async, asyncpg, APScheduler, tenacity, meilisearch, structlog
├── Dockerfile                      # python:3.12-slim, non-root user, healthcheck
├── alembic.ini
├── alembic/
│   ├── env.py                      # async engine
│   └── versions/0001_initial.py    # 전체 스키마 + tsvector 트리거
└── app/
    ├── main.py                     # FastAPI + lifespan(스케줄러 start/stop)
    ├── core/
    │   ├── config.py               # pydantic-settings (.env 자동 로드)
    │   ├── database.py             # async engine + SessionLocal
    │   ├── redis_client.py
    │   └── logging.py              # structlog (dev=콘솔, prod=JSON)
    ├── models/                     # SQLAlchemy 모델
    │   ├── vulnerability.py        # Vuln, Type, Product, Reference, IngestionLog + Enum
    │   └── community.py            # User/Post/Comment/Vote/Tag (M:N + 다형 vote)
    ├── schemas/                    # Pydantic v2 응답 스키마
    ├── api/v1/
    │   ├── router.py
    │   ├── health.py
    │   ├── cves.py                 # GET /cves, /cves/{id}
    │   ├── search.py               # GET /search (Meili → PG fallback)
    │   └── community.py            # 501 placeholder
    ├── services/
    │   ├── parsers/
    │   │   ├── base.py             # BaseParser ABC + ParsedVulnerability dataclass
    │   │   ├── nvd.py              # NVD 2.0 API + sliding-window rate limit (5/30s 또는 50/30s)
    │   │   ├── exploit_db.py       # GitLab CSV 미러 파싱
    │   │   └── github_advisory.py  # GHSA GraphQL
    │   ├── ingestion.py            # 오케스트레이터: upsert + IngestionLog + Meili 색인
    │   ├── search_service.py       # Meilisearch 색인/쿼리 래퍼
    │   ├── summarizer.py           # 휴리스틱 요약 (LLM으로 교체 가능 인터페이스)
    │   └── rate_limiter.py         # Redis sorted-set sliding window
    ├── scheduler/jobs.py           # APScheduler — 소스별 staggered 실행, coalesce
    └── utils/retry.py              # tenacity exponential backoff + jitter
```

### 안정성·확장성 설계

1. **Rate Limit**: 소스별 Redis sliding-window. NVD 키 유무에 따라 5/30s ↔ 50/30s 자동 전환. 다중 워커가 동일 키 공유.
2. **재시도**: `tenacity`로 5xx/429/네트워크 오류 시 exponential backoff + jitter. 4xx(429 제외)는 즉시 실패.
3. **장애 격리**: 파서별 IngestionLog 행으로 실패 추적. 한 소스 실패가 다른 소스에 영향 없음 (`asyncio.gather(... return_exceptions=True)`).
4. **검색 이중화**: 1순위 Meilisearch (인스턴트 + 오타 허용 + 팩싯), 2순위 PostgreSQL `tsvector` (DB 트리거로 자동 동기화). Meili 다운 시 자동 폴백.
5. **증분 수집**: `IngestionLog.finished_at`을 마지막 성공 시각으로 사용 → NVD `lastModStartDate` 등에 전달.
6. **플러그인 구조**: 새 소스는 `BaseParser` 상속해서 `services/parsers/` 아래 파일 하나만 추가. `ALL_PARSERS`에 등록.
7. **민감 정보**: 모든 API 키/시크릿은 `.env`로만 관리. `.env`는 `.gitignore` 등재.

### Docker Compose 통합

- `backend` 서비스 활성화 — `alembic upgrade head && uvicorn` 자동 실행
- `postgres`, `redis`에 `healthcheck` 추가 → backend가 `service_healthy` 조건으로 대기
- 모든 서비스 `restart: unless-stopped`

### 다른 기기 배포 워크플로

```bash
git clone <repo> && cd kestrel
cp .env.example .env
# (선택) NVD_API_KEY, GITHUB_TOKEN을 .env에 채우면 수집 속도/범위 향상
docker compose up --build
```

- Frontend: http://localhost:3000
- Backend: http://localhost:8000/docs (Swagger UI)
- Meilisearch: http://localhost:7700

---

## Step 4 — Frontend ↔ Backend 연동 ✅

**완료일:** 2026-04-19

### 구조 변경

- **Backend 응답 camelCase 통일**: `pydantic.alias_generators.to_camel` + `CamelModel` 공용 베이스 + 라우트에 `response_model_by_alias=True`. 프론트 타입과 키가 1:1 매칭.
- **`Vulnerability.os_families` 프로퍼티** 추가: `affected_products`에서 OS 유니크 집합을 자동 산출 → 리스트 API가 경량 응답으로 OS 배지 렌더 가능.
- **`VulnerabilityListItem.types` 평탄화**: `field_validator(mode="before")`로 ORM 객체 → 문자열 배열로 변환.

### 프론트엔드 새 구성

```
frontend/
├── components/
│   ├── providers.tsx              # TanStack QueryClientProvider
│   ├── cve/CveListSkeleton.tsx    # 로딩 스켈레톤
│   ├── cve/CveListStates.tsx      # EmptyState, ErrorState
│   └── search/Pagination.tsx      # 페이지네이션 컨트롤
├── hooks/
│   ├── useDebounce.ts             # 300ms 디바운스
│   ├── useCveSearch.ts            # useQuery + keepPreviousData
│   └── useCveDetail.ts
└── lib/
    ├── api.ts                     # 브라우저용 클라이언트 (ApiError 포함)
    ├── server-api.ts              # 서버 컴포넌트용 (Docker 내부 URL)
    └── url-state.ts               # useSearchParams ↔ 필터 상태 양방향 동기화
```

### 주요 동작

1. **검색어 디바운스**: 타이핑 중에는 로컬 상태만 갱신, 300ms 후 URL+쿼리 실행. `keepPreviousData`로 타이핑 중에도 이전 결과를 흐리게 유지 → 깜빡임 없음.
2. **URL 동기화 필터**: `?q=...&severity=critical&os=linux&type=RCE&from=2026-01-01&page=2`. 뒤로가기/공유/새로고침에서 상태 보존. `router.replace({ scroll: false })`로 스크롤 점프 방지.
3. **페이지네이션**: 페이지 변경 시 URL의 `page` 파라미터만 갱신 → TanStack Query 자동 재조회.
4. **상세 페이지 SSR**: `app/cve/[id]/page.tsx`는 서버 컴포넌트로 백엔드 직접 호출 → SEO 대응 + CVE 메타 제목/설명 자동 삽입. 404는 `notFound()`, 기타 에러는 본문에 안내.
5. **이원 URL 환경변수**: `NEXT_PUBLIC_API_BASE_URL`(브라우저) / `INTERNAL_API_BASE_URL`(서버 컴포넌트, Docker 내부 DNS `backend:8000`) 분리. `docker-compose.yml`에서 자동 세팅.
6. **에러 핸들링**: `ApiError.status + detail`을 화면에 노출. 빈 결과는 "조건에 맞는 취약점이 없습니다" 안내.

### UX 디테일

- 스켈레톤 카드 6개로 레이아웃 시프트 없이 로딩 표현
- `isPlaceholderData` 때 opacity-60 → 필터 변경 시 부드러운 전환
- 타입·OS 배지 둘 다 표시, "other" OS는 숨김
- `publishedAt` 없으면 시간 태그 자체 생략

---

## Step 5 — DB 최적화 & 엣지 케이스 ✅

**완료일:** 2026-04-20

### 1. DB 인덱스 (alembic `0002_perf_indexes.py`)

- `vulnerabilities (severity, published_at DESC NULLS LAST)` — 대시보드 최신순+심각도 조합의 핵심 경로
- `vulnerabilities (source, published_at DESC NULLS LAST)` — 소스별 최근 수집 현황
- `vulnerabilities (published_at DESC NULLS LAST)` — 단일 정렬 인덱스 명시 (이전 순방향 단일 인덱스 교체)
- `affected_products (os_family, vulnerability_id)` — OS 필터 → vuln join (이전 단독 `os_family` 인덱스 대체)
- `vulnerability_type_map (type_id, vulnerability_id)` — 타입 필터 EXISTS 서브쿼리 가속
- `ingestion_logs (source, started_at DESC)` — `/status` 핸들러의 "소스별 마지막 수집" 조회 최적화

### 2. Meilisearch 튜닝 (`services/search_service.py`)

- 문서 키를 **camelCase**로 통일 (`cveId`, `osFamilies`, `cvssScore`, `publishedAt`) — 프론트 타입과 1:1
- `rankingRules`: words → typo → attribute → proximity → exactness → `publishedAt:desc`
- `stopWords`: 영문 관사 + 보안 도메인 흔한 단어("vulnerability", "attacker", "could" 등)
- `typoTolerance`: 5자 이상부터 1오타, 9자 이상부터 2오타 / **`cveId`는 typo 비활성** (CVE-2026-1234 같은 정확매칭 보호)
- `meili_healthy()` 추가 — `/status` 라이트 핑

### 3. `/health` 분리 + `/status` 신설

- `/health`: 200 OK 단순 liveness (Docker/k8s healthcheck용 — 의존성 장애로 플래핑하지 않음)
- `/status`: DB·Redis·Meili 핑 + `nvdKeyPresent`/`githubTokenPresent` + 소스별 마지막 `IngestionSnapshot`
- 응답은 `CamelOut` 베이스로 camelCase 통일

### 4. 프론트엔드 상태 배너

- `hooks/useStatus.ts` — 60초 폴링, 30초 stale, retry 0
- `components/system/StatusBanner.tsx` — DB/Redis 다운(warn), Meili fallback(info), NVD 키/토큰 누락(info), 마지막 수집 실패(warn) 표시
- `app/layout.tsx`에 `<Header /><StatusBanner />` 순서로 삽입 — 닫기 버튼으로 세션 dismiss 가능

### 5. 관측성 훅 (옵셔널)

- `core/observability.py` — `init_sentry()`, `init_otel(app)` 모두 dependency/env 미설정 시 silent no-op
- `pyproject.toml` extras: `[sentry]`, `[otel]` (기본 이미지에는 미포함 → 이미지 크기 유지)
- 환경변수: `SENTRY_DSN`, `SENTRY_TRACES_SAMPLE_RATE`, `OTEL_ENABLED`, `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`
- `.env.example`에 안내 주석 추가
- 활성화: `pip install -e ".[sentry]"` 또는 `".[otel]"` + 해당 env 세팅

### 6. Playwright 스모크 테스트

- `frontend/playwright.config.ts` — `webServer: npm run dev` 자동 기동, `E2E_BASE_URL` 지정 시 외부 서버 사용
- `frontend/e2e/dashboard.spec.ts` — 히어로 렌더 + 검색 입력 디바운스 후 URL `?q=` 동기화 + 결과/Empty 중 하나 표시 확인
- `package.json`에 `test:e2e`, `test:e2e:ui` 스크립트 + `@playwright/test` devDep
- `.gitignore`에 `playwright-report/`, `test-results/`, `.playwright/` 등재

### 7. 검색·페이지네이션 엣지 케이스

- **PG fallback에 OS/Type 필터 추가**: 이전엔 Meili 다운 시 OS/Type가 무시됐음 → `EXISTS` 서브쿼리로 처리 (DISTINCT 없이도 중복 없음)
- **날짜 필터 Meili에도 전달**: `from_ts`/`to_ts`로 `publishedAt` 비교 필터 추가
- **페이지 클램프**: URL 직접 입력으로 `page=99`처럼 totalPages를 넘으면 `useEffect`로 마지막 페이지로 자동 이동
- **Meili fallback 로깅**: `search.meili_fallback` 구조화 로그로 사후 추적 가능

### 운영 체크리스트

- [ ] 배포 시 `alembic upgrade head` 자동 실행 (compose `command`에 이미 포함)
- [ ] `.env`에 `NVD_API_KEY`, `GITHUB_TOKEN` 설정 시 배너에서 자동 사라짐
- [ ] Sentry/OTel 사용 시 Dockerfile에 `pip install -e ".[sentry,otel]"` 한 줄 추가
- [ ] Playwright 첫 실행: `cd frontend && npx playwright install chromium`

---

## Step 6 — 자산 매칭 · 즐겨찾기 · 커뮤니티 ✅

**완료일:** 2026-04-20

### 1. 즐겨찾기 (Bookmarks)

- **DB 스키마**: `bookmarks (id, client_id varchar(64), cve_id varchar(32), created_at)` + `UNIQUE(client_id, cve_id)` + `INDEX(client_id)` (alembic `0003_bookmarks.py`)
- **익명 소유권**: 브라우저가 localStorage(`kestrel:client-id`)에 UUID를 발급/보관 → 모든 요청에 `X-Client-Id` 헤더로 전달. 로그인 없이 디바이스 단위 즐겨찾기 가능.
- **API**: `GET /bookmarks`, `POST /bookmarks` (idempotent), `DELETE /bookmarks/{cveId}`. POST는 UNIQUE 위반을 무시해 중복 토글 안전.
- **Frontend**: `lib/clientId.ts`(UUID 발급) + `lib/api.ts`(헤더 자동 첨부) + `lib/bookmarks.ts` 훅이 localStorage 캐시 + 백엔드 동기화 (옵티미스틱 업데이트, 실패 시 자동 롤백).
- **UI**: 리스트/상세의 `BookmarkButton`(Star 아이콘) + 대시보드의 `[즐겨찾기만 (n)]` 토글. 토글 시 `/cves/batch?ids=...`로 한 번에 조회.

### 2. 자산 매칭 (CPE)

- **저장 위치**: 자산 목록은 localStorage(`kestrel:assets`)에 vendor/product/version으로 보관. 서버에 영구 저장하지 않음.
- **API**: `POST /assets/match` — 등록한 vendor/product 페어를 ILIKE로 OR-clause 조합하여 `affected_products` 매칭, 관련 CVE를 최신순으로 반환. version_range는 자유 텍스트라 서버 측 strict 검증은 하지 않음.
- **Frontend**:
  - `components/settings/AssetsManager.tsx` — 설정 페이지에서 vendor/product/version 등록·삭제
  - `components/dashboard/MyAssetsPanel.tsx` — 대시보드 상단에 자산 매칭 결과 8건 노출, 비어 있으면 설정으로 안내 CTA

### 3. 커뮤니티 (익명 게시판 + 댓글)

- **DB 마이그레이션** (alembic `0004_community_anon.py`): `posts.user_id` / `comments.user_id` → nullable + FK ondelete=SET NULL. 양쪽에 `client_id varchar(64)` + `author_name varchar(64) DEFAULT '익명'` 컬럼 추가 + `client_id` 인덱스.
- **API** (`/community`):
  - `GET /community/posts?page=&pageSize=&vulnerabilityId=` — 페이지네이션 + CVE별 필터, `commentCount` 집계 동봉
  - `POST /community/posts`, `GET/PATCH/DELETE /community/posts/{id}` — 작성자 본인(`X-Client-Id` 일치)만 수정/삭제. 상세 조회 시 `viewCount` 자동 증가.
  - `GET /community/comments?postId=|vulnerabilityId=` · `POST /community/comments` · `DELETE /community/comments/{id}`
  - 응답에 `isOwner` 플래그 포함 → UI가 본인 글에만 삭제 버튼 노출
- **Frontend 페이지**:
  - `/community` — 게시글 리스트 + `NewPostModal`(제목·이름(선택)·본문) + 페이지네이션
  - `/community/[id]` — 게시글 상세 + 본인 글 삭제 + 하단 `CommentThread`
  - `/cve/[id]` 상세에도 동일한 `CommentThread`를 mount → CVE 단위 토론 가능 (게시글 없이도 댓글만 달 수 있음)
- **컴포넌트**:
  - `components/community/NewPostModal.tsx` — 모달 폼, TanStack Mutation로 작성 후 `community-posts` 쿼리 무효화
  - `components/community/CommentThread.tsx` — `postId` 또는 `vulnerabilityId` 둘 다 지원. 옵티미스틱 작성·삭제, 본인 글에는 휴지통 아이콘.

### 4. 보안·UX 메모

- 로그인 없이 동작하므로 `X-Client-Id`는 “디바이스 단위 의사 소유권”에 불과. 실제 인증이 필요해지는 시점에 `users` 연결을 복구하면 됨 (`user_id` 컬럼은 그대로 보존).
- `client_id`가 손상/초기화되면 본인 글에 대한 삭제 권한이 사라지지만, 데이터는 그대로 남음 (다른 사람이 임의 삭제 불가).
- Header에 `대시보드` ↔ `커뮤니티` 링크 노출, 기존 “커뮤니티 준비 중” 안내 제거.

---

## Step 7 — 리브랜드 & AI 심층 분석 고도화 ✅

**완료일:** 2026-04-21

### 1. 리브랜드 (cvewatch → kestrel)

- DB 사용자/비밀번호/DB 이름, localStorage 키(`kestrel:*`), `COMPOSE_PROJECT_NAME`, OTEL 서비스명, Sentry release 등 식별자 전역 교체.
- 공개 저장소 URL: `github.com/mimonimo/Kestrel` (신규 레포로 재구성).
- 데이터베이스 리셋 후 재빌드 → 정상 기동 확인.

### 2. 다중 AI 자격 증명 & 활성 키 스위처

- **DB 마이그레이션** (alembic `0008_ai_credentials.py`):
  - `ai_credentials` 테이블 신설 (id, label, provider, model, api_key, base_url, created_at, updated_at)
  - `app_settings` 의 기존 `ai_provider/ai_model/ai_api_key/ai_base_url` 컬럼 제거
  - `app_settings.active_credential_id` FK(`ai_credentials.id`, ON DELETE SET NULL) 추가
- **API**: `GET/POST /settings/credentials`, `PATCH /settings/credentials/{id}`(필드별 수정), `DELETE /settings/credentials/{id}`, `POST /settings/credentials/{id}/activate`.
- **CORS**: `PATCH` preflight 400 이슈 수정 — `allow_methods` 에 `PATCH` 명시 추가.
- **Frontend**: `components/settings/AiSettingsForm.tsx`
  - 저장된 키 목록 + 라디오로 활성 전환 + 삭제 버튼
  - 저장된 키에서 모델만 즉석 변경 (PATCH 기반 `ModelSelect` inline select)
  - 활성 상태 UI를 sky 계열로 통일 (`accent-sky-500`, `border-sky-500/50 bg-sky-500/10`, "사용 중" 뱃지 `text-sky-300`)
  - `Input` / `Button` 버튼 `whitespace-nowrap shrink-0` 으로 줄바꿈 방지

### 3. 무료 티어 제공자 확장 + Claude Code CLI 연동

- **OpenAI 호환군 확장**: `_OPENAI_COMPATIBLE = {openai, gemini, groq, openrouter, cerebras}`, 공통 wire 포맷으로 dispatch. `base_url` 만 자격 증명별로 다름.
- **JSON 응답 포맷 분기**: `_SUPPORTS_JSON_SCHEMA = {openai, gemini}` 은 `response_format: json_schema strict`, 그 외는 widely-supported 한 `json_object`.
- **프론트 PROVIDERS 메타 확장**: `defaultBaseUrl`, `note`, `requiresApiKey` 필드 추가. 제공자 선택 시 base URL 자동 채움 + 무료 티어 안내 배너.
- **Claude Code CLI 제공자** (`claude_cli`):
  - `_call_claude_cli` — `asyncio.create_subprocess_exec("claude", "-p", prompt, "--model", model, "--output-format", "text")`. 타임아웃 180초, stderr 400자까지 사용자에게 노출.
  - `_load_active_credential` 에서 `claude_cli` 만 api_key 빈 값 허용.
  - Dockerfile ARG `INSTALL_CLAUDE_CLI=0` (기본 오프) — 1일 때 Node.js 20 + `@anthropic-ai/claude-code` 글로벌 설치.
  - `docker-compose.claude-cli.yml` 오버레이에서 `${HOME}/.claude` 와 `${HOME}/.claude.json` 을 읽기 전용으로 마운트.
  - Frontend: `requiresApiKey: false` 인 프로바이더는 API 키·Base URL 입력을 숨기고 백엔드엔 `apiKey: "local"` 센티넬을 전송.

### 4. AI 심층 분석 프롬프트 실무 지향 개편

- **공격 기법**: (1) 취약 컴포넌트/버전 범위 (2) 전제조건(인증·네트워크·설정) (3) 트리거 경로(엔드포인트·파라미터·함수) (4) 영향(RCE/SSRF 등) 4단 강제. "악성 페이로드 전송" 같은 추상적 표현 금지.
- **페이로드**: 취약점 유형별 최소 형식 강제. XSS/SQLi/명령인젝션/경로순회/SSRF/템플릿 인젝션 → 주입 문자열 본체. HTTP 로 직접 트리거되는 RCE/인증우회만 curl/HTTP 원문 여러 줄. `# 용도 / # 핵심 / # 확인 포인트` 주석으로 내부 구조 설명.
- **영향 회수 메커니즘 필수화**: XSS → 쿠키/토큰 exfil fetch, SQLi → UNION/blind 로 실제 값 추출, 명령 인젝션 → `curl .../?d=$(명령 | base64)`, SSRF → 클라우드 메타데이터, RCE → 결과 회수까지 한 세트.
- **대응 방안 1:1 매핑**: mitigation 배열의 각 항목이 "위에서 작성한 payload 자체"를 어떻게 막는지 구체적 코드/설정/필터로 지목하도록 강제. `코드패치 / 설정변경 / 입력검증 / WAF·네트워크 / 버전업그레이드` 분류 태그 + payload 인용.

### 5. Notion 스타일 코드 블록 UI

- `components/cve/AiAnalysisPanel.tsx` 의 `<pre>` 한 덩어리를 `CodeBlock` 컴포넌트로 교체.
- `detectLanguage` 휴리스틱이 payload 본문을 보고 `http / bash / python / nuclei / msf / text` 중 하나를 추정 → 상단 언어 라벨 표기.
- `CopyButton` — 클립보드 복사 + 1.5초 후 초록색 체크 피드백.
- 좌측 gutter 에 줄번호 표시, 본문은 `whitespace-pre` + 수평 스크롤 유지.
- 대응 방안 체크리스트는 기존 옵티미스틱 토글 유지.

### 6. Docker 재빌드 패턴 주의

- `docker-compose.yml` 에 소스 볼륨 마운트가 없어, 코드 수정 후 `docker compose restart` 만으로는 반영되지 않음. 프롬프트/백엔드/프론트 변경 시엔 반드시 `docker compose build <service>` 후 `up -d --build`.
- 볼륨 마운트를 dev 전용으로 분리하려면 별도 `docker-compose.dev.yml` 오버레이 방식 추천(현재는 미도입).

---

## Step 8 — 취약점 샌드박스 (CVE → 격리 컨테이너 → AI 적응 페이로드 → 자동 판정) ✅

**완료일:** 2026-04-24

CVE 상세 페이지에서 한 번 클릭으로 (1) 해당 취약점 분류에 맞는 가벼운 실습 컨테이너를 호스트 docker 데몬에 형제 컨테이너로 띄우고 (2) AI 가 CVE 정보를 읽어 그 컨테이너의 실제 엔드포인트/파라미터에 맞춰 페이로드를 재작성한 뒤 (3) 백엔드가 직접 HTTP 요청을 던지고 (4) 응답을 다시 AI 가 보고 성공/실패 판정을 내리는 end-to-end 파이프라인을 추가했습니다.

### 1. 격리 토폴로지 (DooD + internal bridge)

- `docker-compose.yml` 의 backend 에 `/var/run/docker.sock` 마운트 + `group_add: ["${DOCKER_GID:-0}"]`. macOS+OrbStack 은 컨테이너 내부에서 socket 이 root:root 로 보이므로 GID 0 추가로 동작, Linux 호스트는 `.env` 의 `DOCKER_GID` 를 호스트 docker 그룹 GID 로 지정.
- 새로운 도커 네트워크 `kestrel_sandbox_net` (`internal: true`, bridge) — 인터넷·호스트로의 egress 자체를 차단. 백엔드와 모든 lab 컨테이너가 여기에 부착되어 컨테이너 이름으로 서로를 호출.
- backend 컨테이너는 `default` + `sandbox` 두 네트워크에 동시 부착 → 외부 API 호출(LLM 등)은 default 로, lab 호출은 sandbox 로.

### 2. 라이프사이클 관리

- **모델**: `sandbox_sessions(id UUID PK, vulnerability_id FK ON DELETE SET NULL, lab_kind, container_id, container_name, target_url, status enum, error, last_run JSONB, created_at, expires_at)` (alembic `0009_sandbox_sessions.py`, `_pg_enum` + 수동 `CREATE TYPE`).
- **`services/sandbox/manager.py`**:
  - `start_lab` — docker SDK 로 `image, mem_limit, nano_cpus, pids_limit, cap_drop=["ALL"], security_opt=["no-new-privileges:true"]`, `network=kestrel_sandbox_net` 형제 컨테이너 기동. 라벨에 `kestrel.sandbox=1`, `kestrel.session_id`, `kestrel.expires_at` 부착.
  - `stop_lab` — 컨테이너 강제 제거.
  - `proxy_request` — httpx 로 `http://<container_name>:<port><path>` 호출 (응답 본문 64KB 로 잘라서 반환).
  - `reap_expired` — 라벨 기반으로 TTL 초과 컨테이너 정리. `GET /sandbox/sessions/{id}` 호출 시 만료된 세션은 자동으로 `EXPIRED` 로 동기화.
- **동기 docker SDK 호출은 모두 `asyncio.to_thread` 로 감싸 이벤트 루프 블로킹 방지.**
- TTL 기본 1800초(30분), `SANDBOX_TTL_SECONDS` 로 조정.

### 3. Lab 카탈로그 + CWE 분류기

- `services/sandbox/catalog.py` — `LabDefinition(kind, image, container_port, target_path, injection_points: list[InjectionPoint])`. 각 `InjectionPoint` 는 `name, method, path, parameter, location(query|body|header|path), response_kind, notes`.
- 1차 lab: `xss` → `kestrel-lab-xss:latest` (Flask, 5000 포트, 3 개의 reflection 지점 — `/echo?msg=`, `/search?q=`, `POST /comment` body).
- `services/sandbox/classifier.py` — CWE → kind 우선 매핑(`CWE-79/80/83/87 → xss`), 매핑 실패 시 제목/설명 키워드 폴백("xss", "cross-site scripting", "stored xss" 등). 미매칭이면 사용자에게 "지원하는 lab 유형이 아직 없습니다" 안내 후 시작 거부.

### 4. AI 페이로드 적응 + 응답 판정

- `services/ai_analyzer.py` 에서 `call_llm(db, system, user, *, force_json=True)` 을 공개 함수로 추출 → CVE 분석과 샌드박스 모듈이 동일 자격 증명/모델을 공유.
- **`services/sandbox/payload_adapter.py`**: CVE 본문 + 일반 PoC + lab 의 모든 injection point 를 LLM 에 넘겨 실제 엔드포인트/파라미터/메서드 + 적응된 페이로드 본문 + `success_indicator` + `rationale` 을 JSON 으로 회수. 모델이 lab 에 존재하지 않는 path/parameter 를 환각하면 즉시 reject 하고 첫 injection point 로 재시도.
- **`services/sandbox/result_analyzer.py`**: 휴리스틱(`payload literal in response body`) 으로 1차 신호를 만든 뒤, LLM 에 요청·응답·휴리스틱 신호를 함께 보여주고 `{success, confidence(low/medium/high), summary, evidence, next_step}` JSON 으로 최종 판정. LLM 호출 실패 시 휴리스틱-단독 폴백으로 graceful degrade.

### 5. API & UI

- `POST /sandbox/sessions` — CVE 분류 → lab 컨테이너 기동 → SandboxSession 반환.
- `GET /sandbox/sessions/{id}` — 상태 조회 (TTL 만료 시 자동 EXPIRED 동기화 포함).
- `DELETE /sandbox/sessions/{id}` — 컨테이너 제거 + 세션 STOPPED.
- `POST /sandbox/sessions/{id}/exec` — 풀 파이프라인 (CVE 본문 ↔ AI 적응 → 컨테이너로 HTTP 전송 → AI 판정) 한 번에. 응답으로 `adapted, exchange, verdict` 모두 반환 → UI 에서 단계별로 노출.
- **Frontend**: `components/cve/SandboxPanel.tsx` 가 CVE 상세에 새 카드로 들어감. `[샌드박스 시작]` → 상태 칩 + 컨테이너명 + injection point 목록 → `[AI 페이로드 적응 + 실행]` 버튼 → 적응 페이로드/요청 메서드·경로/응답 본문(잘림 표시 포함)/AI 판정 배지(성공·실패 + 신뢰도 + 근거 + 다음 시도) + 휴리스틱 신호.
- 30분 후 자동 회수, 사용자가 직접 `정지` 버튼으로 즉시 종료 가능.

### 6. Lab 이미지 (`sandbox-labs/`)

- `xss-flask/` — 의도적으로 `request.args.get("msg")` 를 escape 없이 그대로 `<div id='echo'>` 에 보간. `/comment` 는 POST body 의 `body` 를 그대로 페이지 하단에 출력. 이미지 크기 ~80MB 수준 (`python:3.12-slim` + Flask 만).
- `sandbox-labs/README.md` — `docker build -t kestrel-lab-xss:latest sandbox-labs/xss-flask` 빌드 가이드. 카탈로그에 새 kind 추가하는 절차도 함께 기재.

### 7. AI 분석 신뢰성 보강 (Claude CLI)

- `_call_claude_cli` 가 종전엔 stderr 만 사용자에게 보였는데 claude CLI 는 401 같은 인증 오류를 **stdout** 으로 출력함 → stdout 도 함께 회수해 메시지에 포함하도록 수정. 더 이상 "오류: (stderr 없음)" 로 끝나지 않고 실제 원인을 보여줌.
- macOS 호스트에서는 `~/.claude` 에 OAuth 토큰이 들어 있지 않고 **Keychain** 에 저장되므로 디렉터리만 마운트해도 컨테이너에서는 `Not logged in` 으로 떨어짐. `README.md` 의 Claude CLI 설치 가이드에 `security find-generic-password -s "Claude Code-credentials" -w > ~/.claude/.credentials.json` 한 줄을 추가해 토큰을 파일로 export 하도록 안내. Linux 호스트는 이 단계 생략.

### 8. 운영 메모

- 샌드박스 컨테이너는 항상 `kestrel-sandbox-<sessionhash>` 이름 + `kestrel.sandbox=1` 라벨 → 외부에서 일괄 정리 시 `docker ps --filter "label=kestrel.sandbox=1"` 로 식별.
- backend 컨테이너의 docker.sock 권한 문제는 거의 항상 **GID 불일치** 가 원인. macOS+OrbStack 은 `DOCKER_GID` 미설정(=0) 으로 동작, Ubuntu 서버는 `getent group docker | cut -d: -f3` 결과를 `.env` 에 박아야 함.
- backend 컨테이너에 새 lab 이미지를 추가할 때는 (a) `services/sandbox/catalog.py` 에 `LabDefinition` 한 개 등록 (b) `services/sandbox/classifier.py` 에 CWE/키워드 매핑 추가 (c) `sandbox-labs/<kind>/Dockerfile` 만 작성하면 됨. 백엔드 코드 수정 없이 신규 vuln class 가 늘어남.

---

## Step 9 — 실무용 샌드박스 (CVE-별 reproducer + AI lab synthesis) 🚧

**시작일:** 2026-04-24

### 목표

Step 8 의 generic class lab (XSS only) 을 확장해, **임의 CVE 에 대해 가장 정확한 reproducer 를 자동 결정** 하고 부족할 때만 AI 가 lab 코드까지 생성하는 구조로 끌어올린다. 실무 사용자가 최신 CVE 를 그 자리에서 검증할 수 있어야 한다.

### Resolver chain (전체 그림)

```
CVE → resolve_lab(cve, db):
  1. cve_lab_mappings (정확한 매핑 hit)         → kind=vulhub|synthesized, verified
  2. generic class lab (CWE → kind)              → kind=generic
  3. AI lab synthesis (PR4)                       → 즉석 빌드 → 검증 통과 시 mapping 에 캐시
  4. reject ("재현 환경을 만들 수 없음")
```

핵심 원칙:
- **모든 lab 은 동일한 격리 토폴로지** 를 통과한다 (`internal: true` 네트워크, cap_drop, no-new-privileges, TTL).
- **AI 호출은 캐시 우선** — 같은 (cve, lab) 조합으로 페이로드를 한 번 적응시키면 mapping 에 저장하고 재사용한다. 사용자가 명시적으로 `force_regenerate` 한 경우만 LLM 재호출.
- **검증된 reproducer 만 "verified"** 라벨 — UI 가 사용자에게 신뢰도 정보로 노출.

### PR 분할 (인프라 → 시드 → 안전 → 합성 → 자동화)

| PR | 범위 | 상태 |
|----|------|------|
| **9-A** | cve_lab_mappings 테이블 + lab_resolver chain + manager LabSpec 리팩터 + UI 배지 (인프라만) | ✅ |
| **9-B** | vulhub git harvester (AI 0회) + manager `run_kind="compose"` 분기 + sweeper(DB 기반) + `/sandbox/vulhub/sync` API | ✅ |
| **9-C** | 샌드박스 격리 강화: 옵트인 `SANDBOX_HARDEN`(read_only) + `SANDBOX_RUNTIME`(gVisor 등) + `SANDBOX_SECCOMP_PATH`. compose-mode 는 자동 생성 override 파일로 동일 정책 주입 | ✅ |
| 9-D | AI lab synthesizer (Dockerfile + app 코드 생성) + 빌드 격리 + 검증 루프 | 대기 |
| 9-E | resolver 가 mapping miss 시 자동으로 D 트리거 + UI 동의 플로우 | 대기 |

### 9-A 완료 메모 (인프라 PR)

#### 1. DB 스키마 — `cve_lab_mappings` (alembic 0010) + sandbox_sessions 확장 (0011)

```
cve_lab_mappings(
  id, cve_id, kind enum(vulhub|generic|synthesized), lab_kind,
  spec JSONB, known_good_payload JSONB, verified bool,
  last_verified_at, notes, created_at, updated_at,
  UNIQUE(cve_id, kind), INDEX(cve_id), INDEX(kind), INDEX(kind, verified)
)

sandbox_sessions += lab_source enum, verified bool, lab_kind 64→128
```

세 종류 row 가 같은 모양 공유: vulhub(사전 등록), generic(첫 성공 시 자동 생성, 페이로드 캐시 전용), synthesized(추후 PR9-D AI 합성).

#### 2. Resolver chain — `services/sandbox/lab_resolver.py`

```
resolve_lab(db, vuln, forced_kind=None) -> ResolvedLab | None
  1. cve_lab_mappings WHERE cve_id=X AND kind=vulhub      → 우선
  2. cve_lab_mappings WHERE cve_id=X AND kind=synthesized → 차선
  3. classify_vulnerability → in-code LAB_CATALOG (+ generic 캐시 row 조회)
  4. None
```

`ResolvedLab` 은 `LabSpec` (manager 가 spawn 할 정보) + `source` (배지용) + `verified` + `cached_payload` 를 담는다.

#### 3. `LabSpec` 추상화 — `services/sandbox/manager.py`

`run_kind: "image" | "compose"` 두 종을 타입에 미리 표현. 이번 PR 은 image 만 spawn 가능 (compose 는 9-B). 기존 `LabDefinition` 직접 의존을 manager/payload_adapter 에서 제거.

#### 4. AI 호출 캐시 단락 — `payload_adapter.py`

```
adapt_payload(..., cached_payload, force_regenerate):
  if cached_payload and not force_regenerate:
    return from_cache_dict(cached_payload)   # LLM 호출 0회
  ...
```

성공한 exec 후 `lab_resolver.record_success_payload` 가 mapping row 에 페이로드 저장. 같은 (CVE, lab) 다음 exec 부터는 LLM 안 부르고 즉시 재생. UI 에 `재생성` 버튼으로 강제 무효화 가능.

#### 5. API/UI 배지

- `SandboxSessionOut` 에 `labSource: "vulhub"|"generic"|"synthesized"` + `verified: bool`.
- `AdaptedPayloadOut` 에 `fromCache: bool`.
- `SandboxPanel.tsx` 의 `<SourceBadge>` — vulhub(초록 ShieldCheck), generic(회색 FlaskConical), synthesized(앰버 Sparkles). verified 시 "검증됨" suffix.
- `<RunResult>` 가 `fromCache` 시 sky 배지 "캐시 사용".
- 실행 버튼: `verified` 일 때 "캐시된 페이로드 재생" + 옆에 "재생성" 버튼 노출.

#### 6. 회귀 검증

```
$ POST /api/v1/sandbox/sessions {cveId: CVE-2026-40472}
→ status: running, labSource: "generic", verified: false, lab.injectionPoints[3]
$ DELETE /api/v1/sandbox/sessions/{id}  → 204, 컨테이너 정상 회수
```

기존 XSS 흐름이 새 resolver 를 통과해 동일 동작. PR9-A 완료.

#### AI 호출 효율 요약 (Step 9 전체에서 일관 적용)

| 시점 | LLM 호출 |
|------|----------|
| `POST /sandbox/sessions` | 0회 (resolver 는 DB lookup + 코드 카탈로그만) |
| 첫 `exec` (캐시 miss) | 2회 (`analyze_vulnerability` + `adapt_payload` + `analyze_run`. analyze 는 ai_credentials 모델 응답 캐시가 있어 실질 1회) |
| 같은 (CVE, lab) 두 번째 `exec` | 1회 (`analyze_run` 만 — adapt 는 캐시 hit) |
| `force_regenerate=true` | 첫 exec 와 동일 |

---

### 9-B 완료 메모 (vulhub git harvester + compose 분기)

#### 1. 설정 + 인프라

- `core/config.py`: `vulhub_repo_path`, `vulhub_host_path`, `vulhub_repo_remote`, `sandbox_compose_project_prefix` 추가.
- `Dockerfile`: backend 이미지에 `git`, `docker` static binary, `docker-compose` CLI 플러그인 설치 (DooD 용).
- `docker-compose.yml`: vulhub 리포 bind mount (`${VULHUB_HOST_PATH}:${VULHUB_REPO_PATH}`).
- `.env`: macOS+OrbStack 의 경우 양측 경로를 `/Users/.../data/vulhub` 으로 동일화 (compose CLI가 컨테이너 측에서 파일을 읽고, daemon도 같은 경로를 봐야 함).

#### 2. Harvester — `services/sandbox/vulhub_harvester.py`

```
sync_repo()                  # git init + fetch --depth 1 + reset --hard
                             # (bind mount 위에서 동작하도록 init 후 fetch 사용)
_walk_repo(repo_root)        # docker-compose.yml 가진 폴더 + CVE-NNNN-NNNN 토큰 매칭
_pick_target_service(yaml)   # 첫 service 의 ports → (service_name, container_port)
_read_readme_description()   # README.md 의 첫 의미있는 paragraph
sync_all(db) -> HarvestStats # cve_lab_mappings(kind=vulhub) upsert 일괄 처리
```

LLM 호출 0회. 변경 없는 row 는 건드리지 않음(`updated_at` 보존).

#### 3. Manager — `run_kind="compose"` 분기

```
_start_compose_lab(spec, session_id):
  project = "kestrel-sandbox-<short>"
  docker compose -p <project> -f <compose_path> up -d
  docker compose -p <project> ps -q <target_service>  → 타깃 컨테이너 ID 획득
  네트워크 attach: project 의 모든 컨테이너 → kestrel_sandbox_net (internal)
  반환: LaunchedLab(container_id=project, container_name=target_container, target_url=http://<target>:<port>)

stop_lab(handle):
  prefix("kestrel-sandbox-") 면 docker compose -p <handle> down -v --remove-orphans
  아니면 단일 컨테이너 reap
```

Compose 컨테이너에는 `docker container update --label` 이 미지원이라 라벨 후처리 실패 시도까지만 (best-effort). 대신 새로 만든 `services/sandbox/sweeper.py` 가 DB 의 `sandbox_sessions.expires_at` 을 직접 보고 `stop_lab(container_id)` 호출.

#### 4. API

- `POST /api/v1/sandbox/vulhub/sync` → `VulhubSyncResponse{foldersScanned, candidates, upserted, skipped, errors[]}`. 운영자/관리자 트리거(인증은 추후).
- 기존 `POST /sandbox/sessions` 가 시작 시 `reap_expired_sessions(db)` 도 함께 호출 → compose-mode 만료 세션 자동 정리.
- `DELETE /sandbox/sessions/{id}`: `container_id`(compose 의 경우 project name) 우선 사용으로 변경.

#### 5. 검증

```
$ POST /api/v1/sandbox/vulhub/sync
→ {"foldersScanned":326,"candidates":246,"upserted":246,"skipped":0,"errors":[]}

$ POST /api/v1/sandbox/sessions {cveId: CVE-2017-12615}
→ status:running, labSource:"vulhub", labKind:"tomcat/CVE-2017-12615",
  containerName:"kestrel-sandbox-fea0040cbb30-tomcat-1",
  targetUrl:"http://kestrel-sandbox-fea0040cbb30-tomcat-1:8080"

$ docker ps --filter "label=com.docker.compose.project=kestrel-sandbox-fea0040cbb30"
→ tomcat-1 Up, networks: project_default + kestrel_sandbox_net

$ DELETE /sandbox/sessions/{id}  → 204
$ docker ps -a --filter "label=kestrel.sandbox=true"  → 비어있음
```

XSS 회귀(image-mode CVE-2026-40472) 도 정상 동작.

---

### 9-C 완료 메모 (격리 강화 — 옵트인)

#### 1. 설정 (3개, 모두 default off)

```
sandbox_harden        bool   기본 False  → True 시 read_only=True (image+compose)
sandbox_runtime       str?   기본 None   → "runsc" 등 daemon-side 런타임명
sandbox_seccomp_path  str?   기본 None   → JSON profile 절대경로
sandbox_override_dir  str    기본 ""     → 빈값이면 <vulhub_repo_path>/.kestrel-overrides 사용
```

기본값으로는 9-A/9-B 동작을 그대로 유지. 운영자는 `.env` 에 환경변수로 켜기만 하면 됨.

#### 2. Image-mode (`manager.start_lab`)

- `read_only` 를 `settings.sandbox_harden` 로.
- `runtime=` kwarg 를 `sandbox_runtime` 이 있을 때만 추가 (없으면 daemon 기본 runtime).
- `security_opt` 에 `seccomp=...` 를 `sandbox_seccomp_path` 가 있을 때만 추가.

#### 3. Compose-mode (`manager._build_override`)

base compose 파일을 읽어 모든 service 에 동일 정책을 주입한 override YAML 을 자동 생성, `docker compose -f base -f override` 로 가동:

```yaml
services:
  <svc>:
    security_opt: ["no-new-privileges:true", "seccomp=<path>"]
    cap_drop: ["ALL"]
    runtime: runsc          # if set
    read_only: true         # if HARDEN
    tmpfs: ["/tmp:rw,size=64m"]
```

override 파일은 vulhub bind mount 안에 두어 backend 컨테이너와 host docker daemon 이 같은 절대경로로 본다. 세션 stop 시 자동 삭제 (`_cleanup_override`).

#### 4. `stop_lab` 라우팅 버그 수정 (9-B 잔존 버그 동반 수정)

이전에는 핸들 prefix 만 보고 compose vs image 를 구분했는데, image-mode 컨테이너 이름도 같은 prefix(`kestrel-sandbox-`)를 쓰기 때문에 compose down 이 빈 프로젝트에 대해 성공 종료하고 image 컨테이너는 살아남는 케이스 발생.

수정: docker daemon 에 컨테이너 존재 여부를 먼저 물어, 단일 컨테이너면 image-reap, 없으면 compose-down. 이후 양쪽 모드 모두 깨끗히 회수됨.

#### 5. 검증

```
$ XSS image-mode 세션 생성 → DELETE → docker ps 비어있음 ✓
$ Tomcat compose-mode 세션 생성 → tomcat-1 + sandbox_net 부착 → DELETE → 프로젝트 전체 정리 ✓
```

런타임 강화(`SANDBOX_RUNTIME=runsc` 등)는 macOS+OrbStack 에서는 검증 불가 — Linux 호스트(Kali)에서 gVisor 설치 후 `SANDBOX_HARDEN=1 SANDBOX_RUNTIME=runsc` 로 실측 필요.

---

### Step 9-D — AI lab 합성기 (Synthesizer) ✅ 완료

vulhub 에 없는 CVE 에 대해 LLM 이 직접 reproducer Dockerfile + 앱 코드 + 페이로드 + 성공 지표를 생성, 빌드 → 격리 네트워크에서 한 번 트리거 → 성공 지표가 응답에 보이면 `cve_lab_mappings(kind=synthesized, verified=true)` 로 캐시. 검증 실패는 캐시하지 않음.

#### 1. 새 파일 / 변경 파일

- `backend/app/services/sandbox/synthesizer.py` (신규)
  - `synthesize(db, vuln)` — LLM 호출 → JSON 파싱 → 빌드 컨텍스트 stage → `manager.build_image` → `start_lab` + `proxy_request` 로 검증 → 성공 시 `cve_lab_mappings` 업서트 + `known_good_payload` 미리 채움 → 실패 시 image 제거.
  - `_spec_hash` 로 sha16 산출 → image tag `kestrel-syn-<sha>:latest`. 동일 합성은 멱등.
  - 빌드 컨텍스트는 `/tmp/kestrel-syn-builds/<sha>/`. 빌드 후 항상 정리.
  - 보안: `files[].path` 절대경로/`..` 거부, internal-only network, mem 256MB·CPU 0.5 한도 그대로.
- `backend/app/services/sandbox/manager.py`
  - `build_image(context_dir, tag, timeout)` — 저수준 `cli.api.build` 사용해 스트리밍 로그 수집, 실패 시 마지막 30줄을 SandboxError 에 담음.
  - `remove_image(tag)` — best-effort 정리.
- `backend/app/api/v1/sandbox.py`
  - `POST /api/v1/sandbox/synthesize` — body: `{cveId, forceRegenerate?}`. 검증 실패도 200 으로 진단 정보(`buildLogTail`, `responseBodyPreview`, `error`) 와 함께 반환 — UI 가 그대로 렌더할 수 있도록.
- `backend/app/schemas/sandbox.py` — `SynthesizeRequest` / `SynthesizeResponse` (camelCase 응답).
- `backend/app/services/sandbox/__init__.py` — `synthesize`, `SynthesisResult` export.
- `backend/app/core/config.py` — synthesizer 전용 setting 5종 추가:
  ```python
  sandbox_syn_image_prefix: str = "kestrel-syn"
  sandbox_syn_build_dir: str = ""  # → /tmp/kestrel-syn-builds
  sandbox_syn_build_timeout_seconds: int = 240
  sandbox_syn_verify_timeout_seconds: int = 60
  sandbox_syn_max_attempts: int = 1
  ```

#### 2. LLM 프롬프트 디자인

시스템: "취약 동작 그대로 재현하는 최소 Dockerfile + 앱 코드 + 트리거 페이로드 + 응답에 반드시 등장하는 성공 지표". 사이즈 제약 명시 (`python:3.11-slim` + flask 단일파일 / `node:20-alpine` + express 단일파일 수준). systemd/nginx/mysql 등 무거운 의존성 금지.

JSON 스키마: `{description, dockerfile, files[], container_port, target_path, injection_point, payload_example, success_indicator}`.

핵심 규칙: payload 를 그대로 보냈을 때 success_indicator 가 응답 본문에 **그대로** 등장해야 함 — exfil 채널 같은 것은 internal-only network 에서 동작하지 않으므로 echo back 형태로만 검증.

#### 3. 자동 검증 루프

```
synthesize() →
  call_llm → parse → validate schema →
  stage build context (/tmp/kestrel-syn-builds/<sha>/) →
  build_image(timeout=240s) →
  start_lab(image-mode, internal sandbox net) →
  wait_ready →
  proxy_request(method/path/parameter/location/payload) →
  indicator in body? →
    yes: insert mapping(verified=True, known_good_payload=...) → 다음 sandbox session 부터 vulhub 다음 우선순위로 자동 사용.
    no:  remove_image, no DB write, error 반환.
  finally: stop_lab, cleanup build context.
```

#### 4. 검증 (스모크)

```
$ docker compose up -d --build backend
$ curl http://localhost:8000/openapi.json | jq '.paths | keys[] | select(contains("sandbox"))'
"/api/v1/sandbox/sessions"
"/api/v1/sandbox/sessions/{session_id}"
"/api/v1/sandbox/sessions/{session_id}/exec"
"/api/v1/sandbox/synthesize"   ← 신규
"/api/v1/sandbox/vulhub/sync"
```

스키마 형태 정상 (`cveId`, `forceRegenerate`, response: `imageTag`, `verified`, `mappingId`, `attempts`, `error`, `spec`, `payload`, `buildLogTail`, `responseStatus`, `responseBodyPreview`).

End-to-end live 호출(LLM 토큰 소모) 은 Kali 배포본에서 active credential 로 실측 예정.

---

### Step 9-E — Resolver 자동 fallback + UI consent ✅ 완료

vulhub/generic 모두 miss 인 경우 사용자 동의 하에 resolver 가 합성을 자동으로 실행하고, 24시간 cooldown 으로 같은 CVE 의 반복 실패에 토큰을 태우지 않도록 가드.

#### 1. DB 변경 (마이그레이션 0012)

```sql
ALTER TABLE cve_lab_mappings
ADD COLUMN last_synthesis_attempt_at timestamptz;
```

매 합성 시도 시(성공/실패 무관) `now()` 로 갱신. 실패 시 row 는 `verified=false` 로 남고, 24h 안에 재호출하면 cooldown 메시지 반환.

#### 2. 백엔드

- `synthesizer.synthesize` 재구조화
  - 시작 시점에 `(cve_id, SYNTHESIZED)` row 를 get-or-create. `last_synthesis_attempt_at=now`, `verified=false`, `lab_kind="synthesized/<cve>/pending"` 으로 placeholder 삽입.
  - 24h 이내 미검증 시도가 있으면 `forceRegenerate` 없는 한 즉시 rate-limit 메시지 반환.
  - 성공 시: 동일 row 를 update (lab_kind/spec/known_good_payload/verified=true/last_verified_at).
  - 실패 시: row 의 `notes` 만 업데이트 (cooldown 은 이미 stamp 됨).
- `lab_resolver.resolve_lab(..., attempt_synthesis=False)` 신호 추가
  - 1단계 (vulhub/synthesized) — `verified=false` synthesized placeholder 는 skip (합성 실패 row 가 resolver 결과로 새지 않게).
  - 2단계 (generic) — 동일.
  - 3단계 신규: `attempt_synthesis=True` 일 때만 lazy import 후 `synthesize(db, vuln)` 호출 → 성공 시 mapping 재조회로 `ResolvedLab(SYNTHESIZED, verified=True)` 반환.
- `POST /sandbox/sessions` body 에 `attemptSynthesis: bool = false` 추가
  - resolver miss + consent 없음 → `422 {code:"no_lab", canSynthesize:true, message}`
  - resolver miss + consent 있음(합성도 실패) → `422 {code:"synthesis_failed", message}`
  - 두 경우 모두 detail 이 dict 로, 프론트가 구조 인식 가능.

#### 3. 프론트엔드

- `lib/api.ts`
  - `ApiError.detail` 필드 추가 — FastAPI 422 detail 객체 보존.
  - `request()` — `detail` 이 객체면 `message` 만 뽑아 `Error.message` 로, 객체 자체는 `error.detail` 로 노출.
  - `startSandbox({attemptSynthesis})` 추가, `synthesizeSandbox()` helper 추가.
  - `NoLabDetail` 타입 + `isNoLabDetail()` 가드.
  - 중복 export 정리 (파일 끝의 `export { ApiError }` 제거).
- `components/cve/SandboxPanel.tsx`
  - start mutation 에 `{attemptSynthesis?}` 옵션 받도록.
  - `noLabDetail` 추출 → 빨간 에러 박스 대신 amber consent 박스로 렌더 ("AI 합성으로 시도" + "취소").
  - 합성 진행 중에는 "AI 합성 진행 중 — Dockerfile/앱 코드 생성 + 빌드 + 검증 (수십초~수분 소요)…" 표시.

#### 4. 검증

```
$ curl -X POST http://localhost:8000/api/v1/sandbox/sessions \
  -H 'Content-Type: application/json' -d '{"cveId":"CVE-2026-0081"}'
HTTP/1.1 422
{"detail":{"code":"no_lab","canSynthesize":true,
  "message":"이 CVE 에 대응하는 등록된 lab 이 없습니다. ..."}}

$ docker compose exec -T postgres psql -U kestrel -d kestrel -c "\d cve_lab_mappings"
... last_synthesis_attempt_at | timestamp with time zone ✓
```

프론트 빌드 통과 후 `/cve/CVE-2026-0081` 에서 amber consent 박스가 정상 렌더되는 것을 시각 확인 (수동 단계). End-to-end 합성 토큰 소모 실측은 Kali 배포본에서 active credential 로.

---

### Step 9-F — 합성 이미지 LRU 캐시 회수 정책 ✅ 완료

AI 합성 lab 은 1개당 ~150-400MB 이미지를 docker daemon 에 남긴다. 장기 배포에서 캐시가 무한히 커지는 것을 막기 위해 LRU 기반 회수 정책을 추가. opportunistic 트리거(`synthesize()` 진입 시 자동 sweep) + 운영자용 수동 엔드포인트(`POST /sandbox/synthesize/gc`) 두 가지 경로로 동작.

#### 1. DB 변경 (마이그레이션 0013)

```sql
ALTER TABLE cve_lab_mappings
ADD COLUMN last_used_at timestamptz;
```

`POST /sandbox/sessions` 가 mapping 으로 lab 을 띄우는 데 성공하면 `last_used_at = now()` stamp. resolver 가 mapping_id 를 반환하지 않는 경우(첫 generic-class lab — exec 성공 시 `record_success_payload` 로 row 생성됨) 는 자연히 skip.

#### 2. 설정 (`Settings`)

- `sandbox_syn_image_max_total_mb: 4096` — 합성 이미지 합계 크기 ceiling (~4GB).
- `sandbox_syn_image_max_count: 50` — 보관 가능한 합성 이미지 개수 상한.
- `sandbox_syn_image_max_age_days: 30` — 마지막 사용 시점이 N일을 초과하면 evict.

세 값은 endpoint body 에서 per-call override 가능 (`targetTotalMb`, `targetMaxCount`, `targetMaxAgeDays`).

#### 3. GC 모듈 (`services/sandbox/synthesizer_gc.py`)

```
gc_synthesized_images(db, *, target_total_mb=None, target_max_count=None, target_max_age_days=None) → GcStats
  ├─ verified=true SYNTHESIZED row 모두 조회 → LRU 키((last_used_at NULLS FIRST, created_at)) 정렬
  ├─ 한 번에 docker SDK 로 (image size, ancestor 컨테이너 존재 여부) inspect, tuple 에 캐시
  ├─ Pass 1: image 가 사라진 row → 매핑만 drop (image_missing)
  ├─ Pass 2: age cutoff 초과 + 사용 중 아님 → evict (age)
  ├─ Pass 3: count 초과분만큼 가장 오래된 것부터 evict (count)
  ├─ Pass 4: 합계 size > ceiling 이면 오래된 것부터 evict 하면서 합계 줄이기 (total_size)
  └─ 사용 중(컨테이너 ancestor 존재) 이면 모든 pass 에서 skip → stats.skipped_in_use 에 기록

GcStats(scanned, evicted: list[EvictedImage], freed_mb, retained_count, retained_total_mb, skipped_in_use)
EvictedImage(cve_id, image_tag, size_mb, reason)
```

세이프티: `cli.images.remove(force=False)` — docker daemon 이 컨테이너 ancestor 가 있으면 제거 거부 (sweep 도중 라이브 세션 보호용 이중장벽).

#### 4. API + 호출 wiring

- `POST /api/v1/sandbox/synthesize/gc` 신규 엔드포인트 — body 의 override 값(없으면 기본값) 으로 sweep 후 `GcStats` 를 camelCase 로 반환.
- `synthesize()` 함수 진입부에서 `gc_synthesized_images(db)` opportunistic 호출 — 실패해도 best-effort (warning log, 진행 계속).
- `start_session()` 마지막에서 `resolved.mapping_id` 가 있으면 `last_used_at = now()` stamp.

#### 5. 검증 (스모크)

```
$ docker compose exec -T postgres psql -U kestrel -d kestrel -c "SELECT version_num FROM alembic_version;"
 0013

$ docker compose exec -T postgres psql -U kestrel -d kestrel -c "\d cve_lab_mappings" | grep last_used
 last_used_at | timestamp with time zone

$ curl -s http://localhost:8000/openapi.json | jq '.paths | keys[] | select(contains("sandbox"))'
"/api/v1/sandbox/sessions"
"/api/v1/sandbox/sessions/{session_id}"
"/api/v1/sandbox/sessions/{session_id}/exec"
"/api/v1/sandbox/synthesize"
"/api/v1/sandbox/synthesize/gc"   ← 신규
"/api/v1/sandbox/vulhub/sync"

$ curl -sX POST http://localhost:8000/api/v1/sandbox/synthesize/gc \
  -H 'Content-Type: application/json' -d '{}'
{"scanned":0,"evicted":[],"freedMb":0,"retainedCount":0,
 "retainedTotalMb":0,"skippedInUse":[]}

$ curl -sX POST http://localhost:8000/api/v1/sandbox/synthesize/gc \
  -H 'Content-Type: application/json' -d '{"targetMaxCount":0}'
{"scanned":0,"evicted":[], ...}   # override 도 200 OK
```

실제 evict path (Dockerfile build → image 생성 → quota 초과 → reason="count" 로 제거 + 매핑 row 삭제) 는 LLM credential 이 살아있는 Kali 배포본에서 라이브 검증 예정.

---

### Step 9-G — 합성 캐시 운영자 대시보드 ✅ 완료

PR 9-F 가 회수 정책을 깔았으니, 운영자가 *무엇이* 회수될지 미리 보고 즉시 sweep 도 누를 수 있는 UI 가 필요. 수치만 노출하는 read-only 엔드포인트 + 기존 GC 엔드포인트를 묶은 작은 패널을 settings 페이지에 추가.

#### 1. 백엔드 — read-only 캐시 리포트

`synthesizer_gc.report_synthesized_cache(db) → CacheReport(count, total_mb, in_use_count, missing_image_count, oldest_last_used_at, entries: list[CacheEntry])`

기존 GC sweep 과 동일한 docker SDK 호출(`_image_size_and_in_use`)을 재사용하되 evict 는 안 함. `entries` 는 LRU 키((last_used_at NULLS FIRST, created_at)) 기준 오래된 순으로 정렬되어 — UI 가 다음 회수 후보를 위에서부터 보여줄 수 있게.

`CacheEntry`: cve_id, image_tag, lab_kind, size_mb, in_use, image_present, last_used_at, last_verified_at, created_at, age_days.

#### 2. 신규 엔드포인트

- `GET /api/v1/sandbox/synthesize/cache` → `SynthesizeCacheReport` (camelCase). 응답에 설정값 ceiling(`maxTotalMb`, `maxCount`, `maxAgeDays`) 함께 동봉 — UI 가 별도 settings round-trip 없이 utilization 게이지 렌더 가능.

#### 3. 프론트엔드 — 운영자 패널

- `lib/api.ts`: `getSynthesizerCache()`, `triggerSynthesizerGc(body?)`, `SynthesizeCacheReport`, `SynthesizeCacheEntry`, `EvictedImage`, `SynthesizeGcResponse` 타입 추가.
- `components/settings/SynthesizerCachePanel.tsx`:
  - React Query 로 `/cache` 폴링(staleTime 10s) → 두 개의 진행률 바(디스크 / 개수, 70%/90% 임계에 amber/rose).
  - 메타라인: 최대 보관 기간, 사용 중 개수, 사라진 이미지 row 수(있으면 amber 경고), 가장 오래된 last_used_at relative.
  - 액션 두 개: "새로고침"(refetch), "지금 GC 실행"(POST /synthesize/gc) — GC 결과는 emerald 배너로 회수 항목/MB/reason 까지 inline 표시.
  - LRU 정렬 테이블: CVE / image / size / 마지막 사용(relative + age days) / 상태 뱃지(이미지 없음 / 사용 중 / 대기).
  - 빈 상태 dashed placeholder.
- `app/settings/page.tsx` — "내 자산" 섹션 다음에 "합성된 lab 캐시" 섹션으로 마운트.

#### 4. 검증 (스모크)

```
$ docker compose up -d --build backend frontend
$ curl -s http://localhost:8000/api/v1/sandbox/synthesize/cache | jq
{
  "count": 0, "totalMb": 0, "inUseCount": 0, "missingImageCount": 0,
  "oldestLastUsedAt": null,
  "maxTotalMb": 4096, "maxCount": 50, "maxAgeDays": 30,
  "entries": []
}
$ curl -s http://localhost:8000/openapi.json | jq '.paths | keys[] | select(contains("synthesize"))'
"/api/v1/sandbox/synthesize"
"/api/v1/sandbox/synthesize/cache"   ← 신규
"/api/v1/sandbox/synthesize/gc"
$ curl -s http://localhost:3000/settings | grep -c "합성된 lab 캐시"
1
```

frontend `next build` 통과(타입체크 포함). 실제 row 가 생긴 상태의 GC 동작 시각 확인은 LLM credential 이 살아있는 Kali 배포본에서 라이브 검증 예정.

---

### Step 9-H — SSE streaming 으로 합성 진행 실시간 노출 ✅ 완료

PR 9-G 까지는 합성이 30~120초간 "AI 합성 진행 중…" 라는 정적 spinner 만 보여줬다. 사용자는 LLM 이 멈춘 건지, 빌드가 막힌 건지, 검증이 실패한 건지 알 수 없었다. 합성 함수에 progress 콜백 훅을 박고, 같은 함수를 호출하는 SSE 엔드포인트를 추가해 단계별 이벤트를 그대로 흘려보낸다. 프론트는 단계 체크리스트로 렌더 — done/spinner/대기 의 3-state.

#### 1. 백엔드 — 합성 함수에 progress hook

```python
ProgressCallback = Callable[[str, str, dict | None], Awaitable[None]]

async def synthesize(db, vuln, *, force_regenerate=False, progress: ProgressCallback | None = None):
    emit = progress or _noop_progress
    await emit("start", ..., {"cveId": cve_id})
    # short-circuits
    if cached_verified: await emit("cached_hit", ...); return ...
    if cooldown:        await emit("cooldown",   ...); return ...
    # main loop
    await emit("call_llm", ...);      raw = await call_llm(...)
    await emit("parsed", ...);        sha, image_tag = ...
    await emit("build_started", ...); logs = await build_image(...)
    await emit("build_done", ...)
    await emit("lab_started", ...);   ok, exchange = await _verify(...)
    if not ok: await emit("verify_failed", ..., {status, bodyPreview}); continue
    await emit("verify_ok", ...)
    # cache + commit
    await emit("cached", ..., {mappingId, imageTag})
    return result
# on exhaustion
await emit("failed", ..., {attempts})
```

기존 `POST /synthesize` 호출 사이트는 모두 `progress=None` 이므로 non-breaking.

#### 2. 신규 엔드포인트 — `POST /sandbox/synthesize/stream`

`StreamingResponse(media_type="text/event-stream")` + 백그라운드 task + asyncio.Queue 패턴. 각 progress 콜백은 `event: step\ndata: {phase, message, payload}\n\n` SSE 프레임으로 큐에 push. 종료 시 `event: done` 프레임에 `SynthesisResult` 풀 페이로드(camelCase) 첨부. 예외 시 `event: error\ndata: {message}`. Sentinel(None) 으로 generator 닫음.

연결이 중간에 끊겨도 백그라운드 task 는 계속 돈다 — LLM 토큰은 이미 썼고, DB 캐시 / 이미지 빌드는 끝까지 완료해야 다음 호출이 그대로 사용 가능. 클라이언트는 Cache-Control: no-cache, no-transform + X-Accel-Buffering: no 헤더로 nginx/CF 의 응답 버퍼링도 차단.

#### 3. 프론트엔드 — 진행 체크리스트 UI

- `lib/api.ts`
  - `streamSse(path, body, onEvent, signal?)` — fetch + ReadableStream 기반 SSE 파서. EventSource 는 POST 미지원이라 직접 구현. `\n\n` 단위로 frame 분리, `event:` / `data:` 라인 파싱, JSON.parse 실패 시 raw string 반환.
  - `streamSynthesizeSandbox(body, onEvent, signal?)` 헬퍼.
  - 타입: `SynthesizePhase`, `SynthesizeStepEvent`, `SynthesizeDoneEvent`, `SynthesizeErrorEvent`, `SynthesizeStreamEvent` union.
- `components/cve/SandboxPanel.tsx`
  - 합성 상태(`synthLog`, `synthRunning`, `synthError`) 컴포넌트 state 로 관리, AbortController 로 중단 가능.
  - amber consent 박스: "AI 합성으로 시도" 클릭 시 `startSynthesis()` 가 SSE 스트림 열고 step 이벤트마다 `synthLog` 누적.
  - `done.verified=true` → resolver 가 새로 생긴 매핑을 잡도록 `start.mutate(undefined)` 호출 (consent 플래그 없이) → 세션 시작.
  - `done.verified=false` 또는 `error` → `synthError` 표시 + "재시도" 버튼.
  - `SynthesisTimeline` 컴포넌트:
    - 기본 timeline(`start → call_llm → parsed → build_started → build_done → lab_started → verify_ok → cached`) 을 미리 렌더 → 받은 phase 마다 체크 마크.
    - cached_hit / cooldown 짧은 분기는 timeline 자체를 그 두 이벤트만으로 교체.
    - 각 row: 완료(✓ emerald), 실패(✗ rose), 진행 중(loader amber), 대기(빈 원 neutral). message 본문도 함께 노출.
    - "연결 끊기" 버튼은 클라이언트만 끊음 — 백엔드 합성은 끝까지 완료된다는 안내문 동봉.

#### 4. 검증 (스모크)

```
$ docker compose up -d --build backend frontend
$ curl -s http://localhost:8000/openapi.json | jq '.paths | keys[] | select(contains("synthesize"))'
"/api/v1/sandbox/synthesize"
"/api/v1/sandbox/synthesize/cache"
"/api/v1/sandbox/synthesize/gc"
"/api/v1/sandbox/synthesize/stream"   ← 신규

$ curl -sN -X POST http://localhost:8000/api/v1/sandbox/synthesize/stream \
  -H 'Content-Type: application/json' -d '{"cveId":"CVE-2026-0081"}' --max-time 8
event: step
data: {"phase": "start", "message": "...", "payload": {"cveId": "CVE-2026-0081"}}

event: step
data: {"phase": "call_llm", "message": "LLM 호출 (시도 1/1)", ...}

event: step
data: {"phase": "failed", "message": "LLM 호출 실패: ...", "payload": {"attempts": 1}}

event: done
data: {"cveId": "CVE-2026-0081", "verified": false, "mappingId": 245, ...}

# 두 번째 호출 — 24h cooldown 단축 경로
$ curl -sN -X POST .../synthesize/stream -d '{"cveId":"CVE-2026-0081"}'
event: step  data: {"phase":"start", ...}
event: step  data: {"phase":"cooldown", "payload":{"hoursRemaining":24}}
event: done  data: {"verified": false, "error": "...최근 24시간 내에..."}
```

응답 헤더 검증: `Content-Type: text/event-stream; charset=utf-8`, `Transfer-Encoding: chunked`, `Cache-Control: no-cache, no-transform`, `X-Accel-Buffering: no` 모두 정상. frontend `next build` 통과 (타입체크 포함).

happy path live (이미지 build_started → build_done → verify_ok → cached) 시각 검증은 LLM credential 살아있는 Kali 배포본에서.

---

### Step 9-I — 합성 다이제스트 (한 줄 요약) ✅ 완료

backend:
- `synthesizer._build_digest(parsed, attempts, sha)` — Dockerfile 의 `FROM` 줄에서 베이스 이미지를 뽑고 injection_point (method/path/location:parameter/response_kind) 와 합쳐 한국어 한 줄로 포맷:
  - 예: `AI 합성 — python:3.11-slim 베이스, GET /reflect 의 query:msg 에 html-reflect 페이로드 주입 (attempts=2, sha=deadbeef)`
- `_spec_dict_for_mapping(..., digest=...)` — JSONB spec 에 `digest` 필드 추가 (resolver 가 spec 만으로도 다이제스트를 복원 가능).
- 성공 경로의 `mapping.notes` 값을 더 이상 `attempts/sha` 만 적던 짧은 문자열이 아니라 위 다이제스트로 덮어쓰기. (실패 경로 notes 는 그대로 — 디버그 단서).
- emit("cached") payload 에 `digest` 동봉 → SSE 스트림 시청자가 done 이벤트 전에도 결과 요약을 읽을 수 있음.
- `LabSpec.digest` 신설, `lab_resolver._spec_from_mapping` 이 `spec.digest → mapping.notes` 순서로 fallback (PR9-I 이전에 만들어진 row 도 자동 호환).

API 스키마:
- `LabInfoOut.digest: str = ""` — `/sandbox/sessions/{id}` 응답의 `lab.digest` 로 노출. vulhub/generic lab 은 빈 문자열.

frontend:
- `LabInfo.digest: string` 타입 추가.
- `SandboxPanel` 의 세션 카드에 `lab.digest` 가 비어있지 않으면 `<Sparkles>` 아이콘 + amber 라인으로 한 줄 표시 (target URL 위쪽). 일반 lab 에는 표시되지 않으므로 합성된 lab 인지 즉시 식별 가능.

smoke 검증:
```text
$ docker compose exec backend python -c "from app.services.sandbox.synthesizer import _build_digest; print(_build_digest({...parsed...}, attempts=2, sha='deadbeefcafef00d'))"
AI 합성 — python:3.11-slim 베이스, GET /reflect 의 query:msg 에 html-reflect 페이로드 주입 (attempts=2, sha=deadbeefcafef00d)

# cached_hit 경로 — POST /synthesize 가 spec.digest 를 그대로 노출
$ curl -s -X POST .../sandbox/synthesize -d '{"cveId":"CVE-2026-0081"}' | jq '.spec.digest'
"AI 합성 — python:3.11-slim 베이스, GET /reflect 의 query:msg 에 html-reflect 페이로드 주입 (attempts=2, sha=deadbeef)"

# 세션 응답에도 lab.digest 가 그대로 옴
$ curl -s .../sandbox/sessions/<id> | jq '.lab.digest'
"AI 합성 — python:3.11-slim 베이스, GET /reflect 의 query:msg 에 html-reflect 페이로드 주입 (attempts=2, sha=deadbeef)"
```

OpenAPI: `LabInfoOut.properties` 에 `digest` 필드 등록 확인. `next build` 통과 (타입 호환성 OK).

---

## Step 9 — 다음 PR 예고

PR 9-N (예정): 다중 후보 spec 보존 + best-of-N 선택. PR 9-L/9-M 이 lab-자체 검증을 강화한 위에서, 같은 CVE 에 대해 검증 통과한 후보를 N 개까지 병렬 보관하고 probe 점수가 가장 높은 것을 우선 매핑. 사용자 평가는 보조 신호로만 활용 (truth oracle 은 backend probe 가 유지).

---

## Step 10 — 대시보드 검색 UX 개선 (전역 sort · 부분 CVE-id · 카테고리/기간 세분화) 🚧

> 사용자 보고: (1) 검색창에 "44228" 처럼 CVE 숫자만 쳐도 안 잡힌다, (2) sort 가 현재 페이지 20 건만 정렬한다 (pagination 전체에 적용 안 됨), (3) 심각도/OS/유형 카테고리가 너무 거칠다, (4) 기간 필터가 raw 날짜 입력 뿐이라 분류가 어렵다. 4가지 모두를 PR-A 한 묶음으로 출하 — 모두 search/list UX 의 "안정적 동작" 한 축이고 분리하면 churn.

### PR 10-A — 검색 UX 4종 세트 (partial CVE-id · 전역 sort · 16 vuln-types · 날짜 프리셋) ✅

**완료일:** 2026-04-26

**Backend (`app/services/search_service.py`, `app/api/v1/search.py`)**
- `SEVERITY_RANK = {critical:4, high:3, medium:2, low:1}` 추가 + `to_document()` 가 `severityRank` 필드를 항상 emit. Meili 문서 49,799 건 reindex 완료 (sortable attrs 에 `severityRank` 등록).
- `SORT_SPECS` dict — 4 키 (`newest`/`oldest`/`severity`/`cvss`) 모두 명시적 spec, severity/cvss 는 `publishedAt:desc` tiebreak. 기본 fallback 은 newest. `search()` 가 `sort: str` 파라미터를 받아 page-aware Meili 쿼리에 그대로 전달 — 클라이언트의 페이지 단위 재정렬을 제거.
- `_CVE_PARTIAL_RE = re.compile(r"^[0-9-]{3,}$")` + `_cve_id_ilike_pattern(q)` — `CVE-`/`CVE` 접두사 제거 후 숫자/대시 토큰만 남으면 `%CVE-%<safe>%` 패턴 반환, 그 외 generic 쿼리는 None (쓸데없는 ILIKE 부담 회피). `"44228"` → `%CVE-%44228%`, `"2021-44"` → `%CVE-%2021-44%`, `"log4j"` → None.
- 페이지 1 에서만 `cve_id ILIKE pattern` LIMIT pageSize 를 별도 쿼리해 Meili hit 앞에 prepend — pagination drift 회피 (페이지 2+ 는 Meili 결과만). PG fallback 은 `or_(text_cond, Vulnerability.cve_id.ilike(cve_pattern))` 로 한 쿼리에 묶음.
- `_severity_rank_case()` SQLAlchemy CASE 식 + `_pg_order_by(sort)` — Meili 미가용 시 fallback 도 동일 sort 키 4 종을 ORDER BY 절로 변환 (severity 는 enum→정수 ordinal CASE).

**Frontend**
- `lib/types.ts` — `VulnType` 16 종으로 확장: RCE, XSS, SQLi, CSRF, XXE, SSRF, LFI, Path-Traversal, Deserialization, Open-Redirect, Privilege-Escalation, Info-Disclosure, Memory-Corruption, DoS, Auth, Other. backend 는 `vulnerability_types.name` 자유 문자열이라 마이그레이션 불필요.
- `components/search/FilterPanel.tsx` — vuln-type 칩 16 종 노출 (긴 이름은 한국어 라벨을 `title` 툴팁으로). 기간 프리셋 6 종(`오늘 / 7일 / 30일 / 90일 / 1년 / 직접 입력`) — 클릭 시 `fromDate=todayIso() - N`, `toDate=""` 로 open-ended 적용, `오늘` 만 from=to=today 로 단일 날짜 좁힘. `customMode` 가 sticky — 한번 "직접 입력" 누르면 raw 입력이 우연히 프리셋과 일치해도 highlight 가 안 빠진다. `todayIso()`/`isoDaysAgo()` 모두 로컬 타임존 — KST 1AM 사용자가 "오늘" 눌러서 UTC 어제로 잡히는 사고 방지.
- `lib/url-state.ts` — `sort: SortKey` 를 URL 1급 상태로 승격 (newest 가 아닐 때만 `?sort=...` 직렬화). `TYPE` 화이트리스트 16 종으로 확장.
- `hooks/useCveSearch.ts` — `sort` 를 4번째 인자 + queryKey 에 포함 → sort 변경 시 React Query 가 새 페치를 트리거.
- `app/page.tsx` — 로컬 `useState<SortKey>` 제거, `url.sort` 가 단일 source-of-truth. `SortSelect onChange` → `url.set({sort, page:1})`. 검색 결과는 server-sorted 라 client `sortVulnerabilities` 호출을 제거 — 북마크 모드(arbitrary 순서로 batch-fetch) 만 client-sort 유지.

**검증 (`backend/scripts/smoke_search.py` — 신규, 13 + 4 + 4 케이스)**
- A. `_cve_id_ilike_pattern` 13 케이스: `"44228"`/`"2021-44228"`/`"CVE-2021"`/`"cve-2024-3"`/`"CVE2024"`/`"2021-44"`/`"  44228  "` 양성, `"log4j"`/`"apache struts"`/`"12"`/`""`/`"CVE-"`/`"100% off"` None 반환 — 모두 PASS.
- B. `_pg_order_by` 4 키: 첫 ORDER BY 절이 각각 `published_at desc`/`asc`/`case when ... severity`/`cvss_score desc` 를 포함 — SQLAlchemy 렌더 문자열은 버전 따라 흔들리므로 정확 일치 대신 substring 검증.
- C. `SORT_SPECS` 4 키 × 각 spec 모두 `:asc|:desc` 방향 suffix 보유 + severity spec 이 `severityRank` 참조 — PASS.
- 결과: `OK — PR-A smoke green`. PR 9-L/9-M smoke 회귀도 동시 green.

**라이브 동작 확인 (49,799 건 인덱스)**
- `?q=44228` → `total:1`, `CVE-2021-44228` 단일 매치.
- `?q=2021-44` → 16 건 (CVE-2021-44XXX 시리즈 prepend).
- `?sort=severity&pageSize=5` → critical 5 건 (cvss 9.8/9.8/9.9/9.1/9.1) — severityRank desc 후 publishedAt desc tiebreak.
- `?sort=cvss&pageSize=5` → cvss 10.0 critical 5 건 — cvssScore desc 후 publishedAt desc tiebreak.

**왜 페이지 1 에서만 cve-id prepend 인가**
- 페이지 2 이후에 prepend 를 깔면 같은 결과가 두 번 보이거나(Meili 가 같은 doc 을 페이지 2 에 다시 반환) total/offset 회계가 어그러진다. 페이지 1 에서만 prepend + 중복 제거 (`seen` set 으로 cveId 단위) 로 "전형적 사용자 흐름(첫 페이지에서 찾는다)" 만 보장하고 깊은 페이지는 Meili 단일 소스로 유지.

**왜 Meili sort 를 클라이언트 재정렬 대신 쓰는가**
- 기존 `sortVulnerabilities(items, sort)` 는 `useQuery` 가 반환한 페이지 1 건들 만 정렬했다 — 페이지 2 로 넘기면 sort 가 다시 깨졌다. Meili 가 sortable attribute 를 가지면 페이지/오프셋 무관하게 글로벌 sort 를 보장한다. 단 북마크 모드는 cveId 기반 batch-fetch 라서 sort 가 임의 순서 — 거기는 client sort 유지.

**다음 PR 예고**
- PR 10-B (예정): 도메인 카테고리 (audio / kernel / SSH / web / network / driver 등) — CVE 가 여러 도메인에 걸칠 수 있도록 (예: CVE-2026-22564 는 audio 취약점이지만 SSH 까지 위협). 현재 schema 에는 단일 vuln-type tag 만 있고 affected_products 도 vendor/product 수준 — domain 분류는 별도 정규화 테이블이 필요. spec 부터.

---

### PR 10-B — cross-domain 분류 (`vulnerabilities.domains TEXT[]` + 18 도메인 chip 그룹) ✅

**완료일:** 2026-05-03

> 사용자 보고 mid-PR-A: "예를들면 CVE-2026-22564 이거 같은경우에는 오디오 분야 취약점인데 SSH 까지 위협 받는거잖아 이런식으로 다양한 분야를 분석 할 수 있도록 세분화". 즉 한 CVE 가 여러 *기술 표면(technology surface)* 에 걸칠 수 있어야 한다 — vuln-type(RCE/XSS/...) 은 *메커니즘(weakness class)* 만 표현하고 surface 정보가 손실. 도메인을 별도 축으로 모델링.

**스키마 (alembic 0015_vuln_domains)**
- `vulnerabilities.domains TEXT[] NOT NULL DEFAULT '{}'` + GIN index `ix_vuln_domains_gin` — 18 controlled-vocab 으로 작아서 별도 normalize 테이블 보다 array overlap (`&&`) / contains (`@>`) 가 join 없이 빠르다.
- 정규화 테이블을 안 쓴 이유: 도메인 set 이 small(~20)/거의 mutate 안 함/한 CVE 당 1-3 개. M:N 테이블은 매번 join 강제 + 빈 결과(uncategorized) 표현이 어색.

**Classifier (`backend/app/services/domain_classifier.py`)**
- `DOMAINS = (kernel, os, browser, web-server, web-framework, database, media, network, mail, auth, crypto, runtime, mobile, virtualization, office, enterprise, iot, messaging)` — 18 종 closed set.
- 두 층 신호 union (신뢰도 내림차순):
  1. `_PRODUCT_RULES` — `f"{vendor} {product}"` 매칭 18 정규식 (CPE-derived, strong)
  2. `_TEXT_RULES` — `title + description` 매칭 17 정규식 (CPE 없는 케이스 + crossover)
- `infer_domains(parsed)` (인제스션) + `infer_domains_from_row(title, desc, products)` (백필) — 동일 로직, 호출 모양만 다름.
- **CWE 의도적 미사용**: CWE 는 weakness class 를 기술. CWE-787(out-of-bounds write) 은 audio 코덱과 kernel driver 에 모두 등장 — 도메인 추론에 쓰면 양쪽 모두 흐려짐.
- 빈 list = "uncategorized" — chip 필터는 `&&` overlap 이라 빈 array 는 어떤 chip 에도 매치 안 됨. all-OR-nothing 잘못된 동작 회피.

**모델/인제스션 배선**
- `Vulnerability.domains: Mapped[list[str]]` (postgresql ARRAY of Text), `__table_args__` 에 `ix_vuln_domains_gin` GIN.
- `ParsedVulnerability.domains: list[str]` field — 파서는 비워두고 `_upsert` 에서 `infer_domains(parsed)` 로 채워 insert/update 양쪽 경로에서 persist.
- `VulnerabilityListItem.domains: list[str] = []` — Pydantic schema 에 추가해 GET 응답에 노출.

**Meili 인덱스 + 검색 서비스**
- `to_document()` 가 `"domains": list(v.domains or [])` emit.
- `ensure_index().update_filterable_attributes(...)` 에 `"domains"` 추가.
- `search_service.search()` 가 `domains: list[str] | None` 인자 받아 `domains IN [...]` 필터 절 추가.
- 모든 75,005 docs 재인덱스 (큐 task 599 까지 enqueue, 즉시 drained).

**API + PG fallback (`app/api/v1/search.py`)**
- `domain: list[str] = Query(default=[], alias="domain")` 라우트 인자.
- Meili 경로 → `search_service.search(..., domains=domain or None, ...)`.
- PG fallback → `Vulnerability.domains.op("&&")(domain)` (TEXT[] overlap 연산자, GIN index hit).

**Frontend**
- `lib/types.ts` — `Domain` union type 18 종 + `DOMAINS` readonly array. `SearchFilters.domains?: Domain[]`, `VulnerabilityListItem.domains: string[]`.
- `lib/url-state.ts` — `?domain=auth&domain=media` 다중값 직렬화/역직렬화 (whitelist intersect).
- `components/search/FilterPanel.tsx` — 새 "도메인" chip 그룹 (한국어 라벨 매핑 `DOMAIN_LABELS`, value 는 canonical 영어 키). `EMPTY_FILTERS` / `hasFilters` / `toggle` 모두 domains 인지.
- `components/cve/CveListItem.tsx` — 결과 카드에 cyan-tinted outline domain badge 추가 (vuln-type 칩 옆).
- `app/page.tsx` + `lib/api.ts` — filter forwarding 한 줄씩.

**백필 (`backend/scripts/backfill_domains.py`)**
- 75,004 rows 처리 → 33,787 update / 41,214 uncategorized (55%) / 7,269 multi-domain (10%). PK 기반 cursor pagination 으로 OFFSET cost 회피.
- 분포 (top 5): database 8665 / os 4664 / web-framework 4582 / browser 4089 / kernel 3132. 18 도메인 모두 정상 분포.

**검증 (`backend/scripts/smoke_domains.py`)**
- Fixture 9 케이스 PASS — kernel use-after-free / openssh / **audio→ssh crossover** / firefox / wordpress SQLi / openssl / vmware / qualcomm baseband / "no signal" 빈 결과.
- 500-row 실 DB 샘플 분포 health-check (43% 분류, 8% multi-domain, 18 도메인 모두 발견).
- PR-A regression (`smoke_search.py`) 동시 green.
- 라이브 API: `GET /search?domain=auth` total 2110 / `?domain=auth&domain=kernel` total 5174 / `?domain=auth&domain=media` total 4472, 모든 hit 이 chip 매치 ✓.

**왜 Edge / WordPress text rule 을 PR 9-K-style fix 로 추가했는가**
- 첫 500-row 분포에서 "Microsoft Edge (Chromium-based) ..." 와 "plugin for WordPress" 같은 제목이 vendor 비어있고 text rule 도 키워드 부족으로 누락 → uncategorized 가 57% 까지 올라옴. browser 룰에 `microsoft edge|chromium-based`, web-framework 룰에 `wordpress|drupal|joomla|magento|typo3|phpmyadmin|plugin for wp|wp[- ]plugin|wp[- ]admin` 추가해 web-framework 가 15→19 / browser 가 21→25 (작은 표본의 분산 내) — 의도는 룰 누락의 *대표 케이스* 수정, 미세 튜닝은 후속.

**알려진 한계 / 다음 PR 으로 넘김**
- 55% uncategorized 는 niche/old CVE (NCSA httpd, Tenda router, Hassan Shopping Cart 등) 가 vendor 도 키워드도 안 잡혀 발생. 룰 추가는 churn 대비 가치 낮아 v1 출하. 향후 `domain` chip 클릭 시 "이 도메인은 X% 커버" 같은 transparency surface 가 더 가치.
- 도메인 라벨 i18n 은 frontend `DOMAIN_LABELS` 한 군데에서 하드코딩 — 다국어 추가 시 별도 i18n 레이어가 필요하나 현 단계에선 over-engineering.

---

### PR 10-BA — 라이트 모드 흰글씨/안 보이는 버튼 일괄 fix ✅

> 사용자 보고: "버튼중에 라이트모드에서 자꾸 흰색 글씨라 안보이는 부분이 생기네. 개선해 전체적으로"

**찾아 고친 곳들**
- `dashboard/MyAssetsPanel.tsx` — 자산 등록하기 버튼: `bg-sky-500 text-white` (sky-500 은 light cyan, 흰 텍스트와 대비 부족) → `bg-sky-600` (라이트) / `dark:bg-sky-500` (다크). 카드 자체도 sky 그라데이션 hero 톤 → 모노크롬 카드.
- `cve/SeverityBadge.tsx` — medium/low 가 dark-only 색상 (`text-yellow-400`, `text-green-400`) 이라 라이트 모드 알파 배경 위에서 색-on-색 → `text-{yellow,green}-700 dark:text-{...}-400` 페어링. unknown 칩도 라이트 모드 톤 추가.
- `cve/BookmarkButton.tsx` — 비활성 hover 가 다크 전용 (`hover:text-neutral-200`) → `hover:text-neutral-700 dark:hover:text-neutral-200`.
- `app/page.tsx` — 즐겨찾기만 토글: 비활성 `border-neutral-700 text-neutral-400` (다크 전용) → 라이트 페어링 추가. 빈-상태 카드 `bg-surface-1/50 border-neutral-800` → 라이트/다크 페어링.
- `dashboard/SortSelect.tsx` — 다크 전용 (`border-neutral-700 bg-surface-2 text-neutral-300`) → 라이트 `bg-white text-neutral-700`. `<option>` 까지 라이트/다크 모두.
- `settings/ApiKeyField.tsx` & `settings/AiSettingsForm.tsx` — 회귀 잔재 (`dark:hover:text-neutral-800 dark:hover:text-neutral-200` 중복) 정리. ApiKeyField "발급" 링크 `rounded-full` 로 통일.

**Python 감사 스크립트** 추가 — `dark:hover:text-* dark:hover:text-*` 중복 + `bg-{light} text-white` 위험 패턴 자동 검출. 이번 PR 부터 회귀 방지.

**검증**: tsc exit 0. frontend rebuild + `/` `/settings` `/cve/<id>` 모두 200.

---

### PR 10-AZ — 전역 rounded 강화 + 헤더 알림/설정 pill + StatusBanner 페어링 + 36 클래스 rounded-md→lg ✅

> 사용자 보고: "이런 버튼들도 아직 너무 네모임 개선해주고 현재 대시보드처럼 커뮤니티, 설정탭, 알림 등 모든 부분에 적용 및 업데이트 부탁"

**기본 primitive radius 한 단계 bump**
- `components/ui/button.tsx` default `rounded-md` → `rounded-lg`. 모든 호출자가 자동 혜택. rounded-full 필요한 곳은 className override 로.
- `components/ui/input.tsx` `rounded-md` → `rounded-lg`. 입력 필드도 통일.

**Header — 네비/알림/설정 모두 pill 톤**
- nav link active state: `bg-neutral-100 text-neutral-900` (subtle) → `bg-neutral-900 text-neutral-50` (high-contrast pill). 다크는 반전. rounded-md → rounded-full + px-3 py-1.5 로 pill 느낌 강조.
- NVD 외부 링크도 같은 rounded-full pill.
- 설정 버튼 → rounded-full pill, 활성 시 high-contrast 반전.

**NotificationBell — 둥근 아이콘 버튼 + popover**
- 종 버튼: `rounded-md border` 사각형 → `rounded-full` 32×32 icon-only. unread 배지 `ring-2 ring-white dark:ring-surface-0` 로 surface 와 분리.
- popover 카드: `rounded-lg border-neutral-800 bg-surface-1` → `rounded-xl` + 라이트/다크 페어링 (header/divider/footer/링크/타임스탬프 모두).

**RefreshBar — 패널 + 새로고침 버튼 페어링 + pill 버튼**
- 카드 자체 `bg-surface-1` → `bg-white dark:bg-surface-1` + `rounded-xl`.
- "수동 새로고침" 버튼 `rounded-md` → `rounded-full`, 라이트/다크 페어링.

**VulnDistributionPanel — 토글 그룹·접기 버튼 둥글게**
- 막대/원형 토글 그룹 `rounded-md` 박스 → `rounded-full` pill. 활성 항목 high-contrast (`bg-neutral-900 text-neutral-50`).
- 펼치기/숨기기 버튼: `rounded-md` 텍스트 박스 → `rounded-full` 28×28 icon-only.
- 로딩 상태 sky 그라데이션 → 신중한 white/surface-1 카드.

**StatusBanner (우측 하단 floating)** — 라이트/다크 페어링
- 팝오버 카드 `rounded-lg bg-surface-1` → `rounded-xl` + 라이트 `bg-white border-neutral-200` 페어링.
- 헤더·푸터·구분선·닫기 버튼·"이 알림 숨기기" 텍스트 모두 양쪽 모드 톤. 닫기 버튼·dismiss 버튼은 `rounded-full`.

**전역 bulk** — `rounded-md` → `rounded-lg`
- Python 스크립트로 className 안의 `rounded-md` 36개를 `rounded-lg` 로 일괄 변경. 모든 카드·박스가 한 단계 더 부드러워짐.

**검증**: tsc exit 0. frontend rebuild + `/` `/settings` `/community` `/cve/<id>` 모두 200.

---

### PR 10-AY — 설정/CVE 상세 패널 surface 통일 + MITRE 백필 버튼 톤 정렬 + rounded 강조 ✅

> 사용자 보고:
> - "난 우리 페이지에서 이부분(분포 패널)이 제일 맘에 들어" → 분포 패널 톤을 전체에.
> - "동글동글한 느낌 좋아" → rounded-lg/full 일관 유지.
> - "설정 페이지에 톤 안맞는 버튼 있음 찾아서 수정해"

**Bulk 정규화 — `bg-surface-1` `bg-surface-2` `border-neutral-800` `text-neutral-100/200/300`**
- 8 파일 (ApiKeyField, SandboxSessionsPanel, SynthesizerCachePanel, AssetsManager, ResourcesPanel, AiSettingsForm, SandboxPanel, AiAnalysisPanel) 라이트/다크 페어링 일괄. 65 surface 토큰 + 59 텍스트 톤 + 12 prefix-variant 보정.
- 결과: 모든 패널·하위 카드가 `bg-white border-neutral-200` (라이트) ↔ `dark:bg-surface-1 dark:border-neutral-800` (다크) 로 단일 surface 시스템.

**`components/cve/AiAnalysisPanel.tsx`**
- CodeBlock 라이트/다크 페어링. 코드 블록 라이트 모드 `bg-neutral-50 border-neutral-200`, 헤더 `bg-white`. 가상 line gutter 까지 분리.
- mitigation `<li>` 카드도 라이트 `bg-neutral-50`, 다크 `bg-surface-2`. 둥근 `rounded-lg`.
- AI 심층 분석 요청 primary button → `rounded-full bg-violet-600` (panel 의 violet 액센트 톤 사용, rounded-full 로 둥근 느낌 강조).
- 본문 안내 문장 한 줄로 축소 (TMI 제거).

**`components/settings/MitreBackfillPanel.tsx` — 톤 안 맞는 버튼 fix**
- "전체 백필 시작" 버튼이 `border-violet-500/40 text-violet-800` outline 으로 다른 설정 페이지 primary 버튼과 톤 불일치 → `variant="default"` (neutral high-contrast) 로 변경. 확인 단계 (`confirmFull`) 만 amber outline 으로 위험 표시.
- 취소 버튼의 redundant text-neutral 클래스 제거 (Button ghost variant 이 이미 페어링 보유).

**검증**: tsc exit 0. frontend rebuild + `/` 200 + `/settings` 200 + `/cve/<id>` 200.

---

### PR 10-AX — 가시성 회귀 수정 (active chip, search button, badge contrast) + 다크 surface 톤 완화 ✅

> 사용자 보고 연속:
> 1. "메인 대시보드 각종 태그들 라이트모드 가독성 안좋음"
> 2. "왼쪽 필터는 누르면 흰색이라 안보이고 오른쪽 메인은 검정으로 나와서 안보임"
> 3. "검색 부분도 버튼 안보임"
> 4. "다크모드를 너무 다크 말고 조금 덜 다크로 / 보기 편안한 다크 톤으로"
> 5. "Statista 느낌으로 / 통계에 신뢰를 줄 수 있도록"

**`tailwind.config.ts` — surface 토큰 완화**
- `surface-0` `#0a0a0b` → `#15171c` (페이지 bg)
- `surface-1` `#111114` → `#1c1e24` (카드/패널)
- `surface-2` `#17171c` → `#23262d` (raised input/chip bg)
- `surface-3` `#1f2028` → `#2b2f37` (hover/active raise)
- 약간 cool tint (HSL ~220°), 단계마다 ~3% lightness 차이 → Linear/Vercel 느낌. 터미널-블랙에서 dashboard-네이비-그레이로.

**`components/search/FilterPanel.tsx` — Chip active 액센트**
- 기존: `bg-neutral-900 text-neutral-50` (light) / `bg-neutral-100 text-neutral-900` (dark) — high-contrast 반전이지만 white-on-white / black-on-black 처럼 보이는 케이스가 발생.
- 변경: sky 액센트 — `border-sky-500 bg-sky-50 text-sky-800` (light) / `dark:bg-sky-500/15 dark:text-sky-200` (dark). 카드 surface 와 명확히 구분.
- count suffix 도 active 시 sky 톤, 비활성 시 neutral.

**`components/ui/badge.tsx` — default 톤 완화**
- 기존: `bg-neutral-900 text-neutral-50` / `dark:bg-neutral-100 dark:text-neutral-900` — 너무 punchy (다크 모드에서 흰 pill 이 "구멍" 처럼 보임).
- 변경: `bg-neutral-800 text-neutral-50` / `dark:bg-neutral-200 dark:text-neutral-900` — 한 톤씩 부드럽게. secondary 도 다크쪽 `dark:bg-neutral-700` 로 raised.

**`components/search/SearchBar.tsx` — primary CTA 액센트**
- 검색 버튼이 neutral 반전이라 input 와 같은 톤대역으로 묻힘 → `bg-sky-600 hover:bg-sky-700` 으로 강조. dashboard 단일 primary action 이 명확히 보임.

**검증**: tsc exit 0. frontend rebuild + `/` `/settings` `/community` 200.

---

### PR 10-AW — 전역 컴포넌트 라이트/다크 페어링 + Header active-state + 카드/배지/버튼/입력 토큰 정비 ✅

> 사용자 지시: "전체적으로 진행해 / claude design 사용해서 최적화된 UI/UX 구성. 상용 서비스 급으로"

모든 페이지에서 공통으로 보이는 lowest-level UI primitive + 네비게이션을 한 번에 다듬어 dashboard 전체 톤을 정렬했습니다.

**`components/layout/Header.tsx`**
- 활성 라우트 highlight 추가 (`usePathname`). Linear/Vercel 식 hover/active 상태.
- 라이트/다크 페어링: `bg-white/85` (라이트) ↔ `bg-surface-0/80` (다크), 텍스트 모두 페어링.
- nav-item hover/active 배경 (`bg-neutral-100 dark:bg-surface-2`), 외부 NVD 링크는 ↗ 표기.
- `Route` 타입 import 로 typedRoutes 모드와 호환.

**`components/layout/Footer.tsx`**
- 라이트/다크 페어링. 출처 라벨에 MITRE 추가, 안내 문장 한 줄로 축소.

**`components/ui/card.tsx`**
- 기본 카드 → `bg-white border-neutral-200 hover:border-neutral-300` (라이트) ↔ `dark:bg-surface-1 dark:border-neutral-800 dark:hover:border-neutral-700` (다크).
- CardFooter border-top 도 양쪽 페어링.

**`components/ui/badge.tsx`**
- default: `bg-neutral-900 text-neutral-50` ↔ `dark:bg-neutral-100 dark:text-neutral-900` (high-contrast 반전).
- outline / secondary 모두 라이트/다크 두 톤. 호출자에서 dark: override 안 줘도 자연스러움.

**`components/ui/button.tsx`**
- default: 라이트 `bg-neutral-900 text-neutral-50`, 다크 `bg-neutral-100 text-neutral-900` — 페이지 surface 와 반대 톤으로 primary action 강조 (Linear/Vercel 패턴).
- outline/ghost 도 페어링. 호출자가 일관된 톤 받음.

**`components/ui/input.tsx`**
- 라이트 `bg-white border-neutral-300`, 다크 `bg-surface-1 border-neutral-800`. focus ring 도 두 톤.

**`components/search/SearchBar.tsx`**
- hero 모드 (대시보드 상단 검색바) 형태 정리: 거대한 `h-14 rounded-full bg-surface-2` 에서 `h-11 rounded-lg bg-white dark:bg-surface-1` 로. 검색 버튼도 안쪽 작게.

**`components/search/FilterPanel.tsx`**
- 카드 배경 페어링. 그룹 제목 `text-[10px] tracking-wider` 로 더 작고 단정.
- Chip 활성 상태: 라이트 `bg-neutral-900 text-neutral-50`, 다크 `bg-neutral-100 text-neutral-900` — Badge 와 동일 한 hi-contrast.
- 비활성 Chip 도 라이트 `border-neutral-300 bg-white text-neutral-700`.

**`components/cve/CveListItem.tsx`**
- 모든 텍스트 노드 페어링. 도메인 outline 칩 색까지.

**검증**: tsc --noEmit exit 0. frontend rebuild + `/` `/settings` `/community` `/cve/<id>` 모두 200.

---

### PR 10-AV — 공유 PieGroup 컴포넌트 + 대시보드 hero 슬림화 + LabKind 원형 차트 ✅

> 사용자 요청 3건:
> 1. "취약점 수집 분포 부분 개선"
> 2. "실습 환경 분포 부분도 원형 차트로 변경"
> 3. "전체적인 UI/UX 고도화 작업이 필요함 — claude design 사용해서 최적화된
>    UI/UX 구성 바람. 상용 서비스 급으로"

**Shared — `components/ui/pie-chart.tsx` (신규)**
- `<PieGroup>` + `<SvgPie>` 재사용 컴포넌트. donut 트랙 색을 `dark:stroke-*`
  로 페어링, 텍스트도 라이트/다크 양쪽 톤. `PIE_PALETTE` 도 export.
- 추후 다른 패널에서 분포 차트가 필요할 때 import 하면 끝 — VulnDistribution,
  LabKindStats 둘 다 이미 활용.

**Settings — `components/settings/LabKindStatsPanel.tsx`**
- 가로 stacked-bar + 색칩 리스트 → SvgPie + 컬러 도트 범례 형태로 전면 교체.
- 출처별/유형별 두 차트 grid. 출처 팔레트는 SOURCE_COLOR (vulhub emerald,
  generic neutral, synthesized amber) — SandboxPanel 의 LabKindBadge 와 동일
  축으로 인식되게 함.
- header 의 description 한 문장 (`전체 N개 · 검증 V`) 으로 축소. 검증 0
  이면 검증 라벨 자체 숨김 — TMI 제거.
- 카드 배경 라이트 `bg-white` / 다크 `bg-surface-1`, 보더도 페어링.

**Dashboard — `components/dashboard/VulnDistributionPanel.tsx`**
- 로컬 `PieGroup` + `SvgPie` 정의 삭제 → 공유 컴포넌트 import.
- 카드 톤 `bg-gradient-to-br from-sky-500/5` → `bg-white dark:bg-surface-1`
  로 변경. 모노크롬 base + 헤더 정보만 노출. sky 액센트 칩/아이콘은 제거 —
  카드 자체가 색조를 띠지 않아 옆에 놓일 다른 패널과 시각적 균형.
- header 가벼워짐: 큰 sky 박스 아이콘 제거, "수집된 취약점 분포" 텍스트 +
  tabular-nums 개수 + (sm 이상에서만) 기간 한 줄. 차트 토글 (막대/원형) 도
  중립 톤 (`bg-neutral-100 dark:bg-surface-3` 활성)으로 통일.
- 펼치기/숨기기 버튼 라벨 텍스트 제거 → 아이콘 + aria-label 만 (영역 좁아짐).

**Dashboard — `app/page.tsx`**
- 16rem 패딩의 거대한 "Kestrel" gradient 헤로 + 안내 문구 + 큰 검색바 →
  "검색바 한 줄" 만 남기는 슬림 헤더로. dashboard 라우트는 사용자가 이미
  들어와 있는 화면 — landing 톤 불필요. 첫 viewport 에 분포 + 필터 + 리스트
  바로 보임.

**검증**: tsc --noEmit exit 0. frontend rebuild + `/` 200 + `/settings` 200.

---

### PR 10-AU — 라이트/다크 페어링 전체 일괄 (28 파일, 169 클래스) ✅

> 사용자 지시: "너가 진행해" — 남은 라이트/다크 미페어링 컴포넌트 일괄 처리.

**Frontend — 28개 파일 / 169개 색상 클래스 자동 변환**

스크립트로 처리한 단일톤 → 페어링 변환 (`text-<color>-{200,300,400}` → `text-<color>-{800,700,600} dark:text-<color>-{200,300,400}`). 처리 대상은 설정/CVE 상세/대시보드/커뮤니티/시스템 컴포넌트 전반:

- 설정 페이지: SandboxSessionsPanel, LabKindStatsPanel, SynthesizerCachePanel, VersionPanel, ResourcesPanel, AiSettingsForm, AssetsManager.
- CVE 상세: SandboxPanel (44 클래스), SourceBadgeCluster, AiAnalysisPanel, TicketControl, SeverityBadge, BookmarkButton, CveListItem.
- 대시보드: VulnDistributionPanel, MyAssetsPanel, RefreshBar, DateRangeControl.
- 시스템: StatusBanner, NotificationBell.
- 커뮤니티: CommentThread, NewPostModal.
- 페이지 라우트: app/page.tsx, app/community/page.tsx, app/community/[id]/page.tsx.

**보정**: 1차 자동 스크립트가 `hover:text-X-300` 같은 prefix-variant 클래스도 잘못 처리해 (`hover:text-X-700 dark:text-X-300` 형태 — dark 모드에서 hover 상관없이 항상 적용됨) 9곳 회귀 발생. 2차 보정 스크립트가 이를 `hover:text-X-700 dark:hover:text-X-300` 으로 fix.

**검증**: tsc --noEmit exit 0. frontend rebuild + /settings 200 OK.

---

### PR 10-AT — 라이트/다크 색 페어링 + .credentials.json 포맷 일치 + 설정 UI 다듬기 ✅

> 사용자 보고 3건:
> 1. "글자 색깔 부분도 너는 다크/라이트 둘다 고려하지 않는 경향이 있음.
>    그렇게 하지마" — 단일 톤 텍스트 (`text-amber-200` 등) 가 라이트 모드에서
>    배경 alpha 와 합쳐져 거의 안 보이는 패턴 반복.
> 2. "claude design 기능 활용할 수 있으면 적극 활용해서 높은 품질의 UI/UX 를
>    구현하기 바람" — Linear/Vercel/Sentry 류 monochrome + 절제된 액센트
>    레퍼런스 적용.
> 3. "claude 연동 후 AI 취약점 분석 기능, 샌드박스 기능이 정상 동작하지 않음"
>    — OAuth 직접 교환은 성공했지만 그 뒤 ai_analyzer / sandbox 가 동작 안 함.

**Backend — `app/api/v1/claude_auth.py`**
- `.credentials.json` 의 `expiresAt` 단위 SECONDS → MILLISECONDS. Claude CLI
  내부에서 ``expiresAt - Date.now()`` 로 만료 계산하는데 SECONDS 로 저장하면
  ``Date.now()`` (ms) 와 1000× 차이라 year-1970 으로 인식 → 매번 refresh
  시도 → AI 분석/샌드박스 호출 직전에 토큰 갱신 실패 / 비정상 동작.
  CLI binary strings 안에 ``60000`` 같은 ms 상수 + ``Date.now()`` 사용
  확인 후 fix.
- `clientId` 필드 추가 (CLI 가 ``.credentials.json`` 에 보관하는 표준 필드,
  값은 우리가 이미 쓰던 public OAuth client id 와 동일).
- ``StatusOut.expires_at`` 주석도 "epoch milliseconds (matches CLI)" 로 명시.

**Frontend — `components/settings/ClaudeAuthPanel.tsx`**
- ``formatExpires(epochMs)`` 시그니처 정정. 이전엔 인자명 ``epochSeconds`` +
  ``* 1000`` 처리였는데 backend 가 이제 ms 를 그대로 보내므로 곱셈 제거.

**Frontend — 다크/라이트 페어링 (`feedback-box.tsx`, `ClaudeAuthPanel.tsx`,
`ApiKeyField.tsx`, `MitreBackfillPanel.tsx`)**
- 패턴 정착: `text-<color>-{700~900}` (라이트) + `dark:text-<color>-{200~300}`
  (다크). 배경 alpha 도 라이트 ``/10~/15`` / 다크 ``/5~/10`` 로 페어링.
- `feedback-box.tsx` ErrorBox/NoticeBox TONE 매트릭스 → 모든 호출자 자동
  혜택. body/hint 도 `text-neutral-900 dark:text-neutral-100`.
- 진행-중 OAuth 세션 카드 sky 톤, 로그인 완료/미완료 카드 emerald/amber 톤,
  MITRE 진행 상태 카드 running/failed/success 모두 두 모드 명확 대비.
- 수동 자격증명 붙여넣기 expander 의 textarea 도 white/dark surface 페어링.

**Memory**: `feedback_light_dark_parity.md` 작성 → 차후 세션에서도 단일 톤
색 사용을 자동으로 거르도록 함.

**검증**: tsc 통과, backend rebuild + /health 200, frontend rebuild + /settings 200.

---

### PR 10-AS — Claude 로그인 OAuth 직접 교환 (CLI 우회) + UI 정리 ✅

> 최우선 사용자 보고:
> 1. "로그인 완료에 실패했습니다 / Claude CLI 가 60초 안에 응답하지 않았습니다.
>    수신 바이트: 108 byte. 표시 출력: ******* (92 asterisks)" — 진단 강화 덕에
>    원인 좁힘: CLI 가 코드는 받았지만 토큰 교환 단계에서 silent hang.
> 2. "로그인 하면 이정보만 오는데 내가 어떻게 적용하니" — `.credentials.json`
>    수동 붙여넣기 우회 경로는 사용자에게 실용성 낮음 (대부분 `.credentials.json`
>    이 다른 환경에 있지도 않음).
> 3. "외부 데이터 소스 API 키도 이미 등록 되어있을때는 저 알림을 보내면 안되지
>    … 발급 버튼 바로 왼쪽에 전체 다시받기버튼 만들어서 적용해"

**Backend — `app/api/v1/claude_auth.py` (대대적 재작성)**
- PTY 기반 `claude setup-token` 자동화 경로 폐기 → 백엔드가 직접 OAuth 2.0 +
  PKCE 흐름 수행. CLI 의 Bun-compiled native binary 가 black box 인 채로
  토큰 교환에서 멈추던 문제 원천 제거.
- `/start`: ``code_verifier`` (32 random bytes → b64url, ~43 chars) +
  ``code_challenge`` (SHA-256(verifier) → b64url) + ``state`` 자체 생성. CLI
  binary 안 임베드된 public ``client_id`` (``9d1c250a-e61b-44d9-88ed-5944d1962f5e``)
  + 알려진 redirect_uri (``platform.claude.com/oauth/code/callback``) 로
  authorize URL 직접 구성. session registry 에는 verifier+state 만 보관.
- `/{sid}/submit`: 사용자 페이스트에서 ``<code>#<state>`` 분리, state 일치 검증
  후 ``https://platform.claude.com/v1/oauth/token`` 에 PKCE 토큰 교환 POST.
  성공 시 ``access_token`` / ``refresh_token`` / ``expires_in`` / ``scope`` 를
  기존 CLI 가 쓰던 ``{"claudeAiOauth":{...}}`` 형태로 ``.credentials.json``
  기록 → 다운스트림 (status / ai_analyzer / sandbox synthesizer) 모두 무변경.
- 실패 시 Anthropic 의 실제 에러 메시지 그대로 surface — 60s 동안 stdout 비운
  채 멈추던 것 대신 즉시 명확한 사유.
- `_call_anthropic_text` 같은 데드 코드 / PTY 보조 (TIOCSWINSZ, ANSI strip,
  Bracketed paste, retry loops) 모두 제거 → 585줄 → 281줄 (50% 감소).

**Frontend — `components/settings/ApiKeyField.tsx`**
- "전체 다시 받기" 버튼을 발급 버튼 바로 왼쪽으로 이동 (사용자 요청: "발급
  버튼 바로 왼쪽"). 11px 보더 버튼 (amber-500/40 테두리 + amber-700/300 텍스트
  — 라이트/다크 모두 충분한 대비) + Loader/History 아이콘 + tooltip 한 줄
  ("과거 수집 실패로 누락된 항목이 있을 때만 사용") 만 남김.
- 카드 본문 하단의 amber 안내 박스 통째 제거. 키가 등록되어 있을 때만 버튼이
  보이므로 별도 안내 텍스트 불필요.

**검증 (라이브)**
```
# Start
$ curl -X POST /api/v1/settings/claude-auth/start
{"sessionId":"ZKg1jQFMNPcJYOvJmxU9KQ", "url":"https://claude.com/cai/oauth/authorize?..."}
URL 길이: 346자 (CLI 가 생성하던 것과 동일 형태, PKCE 도 우리가 직접 만든 값)

# Submit fake code
$ curl -X POST /api/v1/settings/claude-auth/<sid>/submit -d '{"code":"fake_code_xxxxx"}'
ELAPSED: 0s   ← 이전 60s timeout → 즉시 응답
{"detail":"Anthropic 토큰 교환 실패 (400): Invalid 'code' in request.. 코드가
  이미 사용됐거나 만료되었을 수 있습니다 — 다시 로그인 시작."}
```

---

### PR 10-BQ — KEV/EPSS 통합 + 패치 우선순위 매트릭스 + AI 분석 강화 + 샌드박스 제거 ✅

세션 누적 대규모 정리 + 신기능. 사용자 참조 이미지의 *"AI 시대의 취약점,
무엇부터 고칠 것인가 — 심각도가 아니라 실제 위협을 기준으로"* 컨셉을
구현했습니다.

**우선순위 신호 — KEV + EPSS**
- 새 alembic 마이그레이션 `0019_kev_epss` — `Vulnerability` 에 `kev_listed`,
  `kev_date_added`, `kev_due_date`, `epss_score`, `epss_percentile`,
  `epss_updated_at` 컬럼 + 부분 인덱스 (kev_listed=true, epss_score NOT NULL).
- `services/priority_signals.py` — CISA KEV catalog (JSON ~1MB) 시간 단위
  pull, FIRST EPSS daily CSV (~5MB gzip) 일 단위 pull. EPSS 는 임시
  staging table + 단일 `UPDATE ... FROM` 으로 set-based 갱신 (300k 행
  ~2분). KEV 검증: 1602 건 전체 매칭. EPSS 검증: 334,567 건 매칭.
- 새 admin endpoint `POST /admin/refresh-priority-signals` (수동 트리거).
- scheduler 부팅 후 60s 에 KEV / 180s 에 EPSS 첫 실행.

**패치 우선순위 4-tier 매트릭스**
- `GET /dashboard/priorities` — KEV / EPSS상위 / CVSS중간+EPSS높음 /
  CVSS높음+EPSS낮음 각 tier 별 top N CVE + 전체 카운트 반환. tier 간
  중복 방지 (KEV 등재는 다른 tier 에서 제외).
- `GET /search?priority=<key>` — Meili 우회 PG 직행으로 tier 전체 조회.
- frontend `PriorityOverviewPanel` 위젯 — 3 pillar chip (CVSS / EPSS / KEV)
  + 4-tier 랭킹 리스트. 행 클릭 시 `/cves?priority=<key>` 로 드릴다운.
  숫자 1-4 배지는 tier 색 단색 배경 + 흰 숫자로 시인성 확보 (사용자 피드백).
- `/cves` 페이지 헤더에 active tier chip + × 해제 버튼.

**AI 분석 강화**
- 새 라우터 `analysis.py` — `POST /analysis/ask` (follow-up Q&A, 이전 분석
  컨텍스트 + history 함께 전달), `POST /analysis/compare` (2-5 CVE 공통
  패턴 / 차이점 / 통합 완화 전략 비교).
- `ai_analyzer.py` — `answer_followup_question()` + `compare_vulnerabilities()`
  헬퍼 추가. 기존 `_USER_TEMPLATE` 을 strict 명세 다수 → 핵심 항목만 압축
  (1/5 크기). CLI subprocess 에 `stdin=DEVNULL` 추가 — "Warning: no stdin
  data received in 3s" 로 인한 3초 지연 제거. Sonnet 4.6 full prompt 응답
  시간 측정: 압축 전 5분+ → 압축 후 약 2분 14초.
- `AiAnalysisPanel` — useEffect 로 settled 감지 후 `clearRunning` 호출
  (이전 queryFn finally 가 useQuery abort 에서도 발화돼 새로고침 시
  마커가 즉시 지워지던 버그 수정). 진행 시간 카운터 + 모델별 안내 힌트
  (Haiku 10-15s / Sonnet 1-2m / Opus 2-4m). 분석 카드 하단에 `FollowUpThread`
  서브컴포넌트 — Q&A 누적, Markdown "리포트 다운로드" 액션.
- 새 lib `analysis-qa.ts` (Q&A localStorage 영속), `analysis-report.ts`
  (Markdown 빌더 + Blob download), `analysis-running.ts` (in-flight 영속).
- `/analysis` 페이지에 "패턴 비교" 탭 신설 — 분석 기록에서 2-5 CVE 체크 →
  비교 분석 호출 → 요약 / 공통 패턴 / 차이점 / 통합 완화 / per-CVE 메모 렌더.

**페이지 분리 — `/` 와 `/cves`**
- 메인 `/` 는 *시각화 전용* — 검색바·필터·리스트 전부 제거, 헤더 + 동기화
  바 + 분포 패널 + 위젯 grid + 우선순위 매트릭스.
- 새 `/cves` 페이지 — FilterPanel + SearchBar + 검색 결과 + 정렬 / 페이지
  네이션 / 즐겨찾기 토글. `useUrlState` 라우터 하드코딩 (`/?...`) →
  현재 pathname 유지로 수정 (분리 후 `/cves` 에서 필터 토글 시 메인으로
  튕기던 버그 해결).
- Header nav 4탭 → 5탭 ("취약점 조회" 추가).

**대시보드 위젯 5종 + 통합**
- 새 `widgets/` 디렉토리 — `WidgetCard` 공통 chrome + 5 위젯.
- `TimelinePanel` — 7/30/90일 stacked-area, severity 색, hover tooltip.
- `TopVendorsPanel` — 가로 막대 Top 10. 사용자 보고 ("Microsoft vs
  microsoft, Oracle vs Oracle Corporation 같은 게 갈라짐") → 백엔드에서
  벤더 정규화: `lower()` + 회사 접미사 (Corporation / Corp / Inc / Ltd /
  Foundation / Systems …) 제거 + Title Case + 약어 보존 룩업 (IBM / HP /
  VMware / GitHub). 결과: Microsoft 15,929 (8,343 + 7,398 합산), Linux
  14,944, Oracle 9,028 (4,875 + 4,153 합산).
- `CvssBucketsPanel` — 사용자 요청으로 4구간 → 10-bin 히스토그램 +
  평균·중앙값·p90 마커. bin 클릭 시 severity 매핑 드릴다운. 백엔드
  `func.width_bucket` 단일 GROUP BY + `percentile_cont` aggregates.
- `RecentCriticalPanel` — 가장 최근 critical 5건 카드.
- `PriorityOverviewPanel` — 위 우선순위 통합 위젯 (이전 PrioritySignals +
  WhatToFixFirst 두 위젯을 한 카드로 사용자 피드백 반영).
- 메인 페이지 grid 에 배치. 사용자 요청으로 우선순위 위젯은 페이지 맨
  아래에 배치 (보조 정보 성격).

**FloatingDock 통합 — `system/StatusBanner.tsx` + `system/AnalysisHistoryButton.tsx` → 단일 컴포넌트**
- 두 floating pill 이 우측 하단에서 겹치던 문제 (PR 10-BP 에서 좌우 분리
  시도 → 사용자 "어색하다") → 단일 통합 카드로 합침. 한 pill, 한 popover,
  안에 시스템 상태 + AI 분석 두 섹션. 우선순위는 가장 심각한 신호 (경고 >
  분석중 > 알림 > 정상) 색/아이콘.

**카피 + UI 톤 일관성**
- 도메인 / OS / vuln-type 필터 칩 영문 통일 (사용자 요청, "Kernel /
  Browser / Web Server / Database / ..."). 한글 매핑 제거.
- `CommentThread` + `TicketControl` — 다크 일변 → Card 컴포넌트 래핑 +
  light/dark paired 색상. textarea 흰 배경, rounded pill 버튼.
- SearchBar `rounded-full` + 내부 버튼도 pill.
- 위젯 description / EmptyState / 에러 메시지 친근 톤 ("…했습니다" →
  "…했어요") 일관성. ai_analyzer 에러 메시지도 동일.
- VulnDistributionPanel — `placeholderData: keepPreviousData` 적용 +
  isStale opacity-70 dimming. cross-filter 시 패널 사라지는 깜박임 해소
  (사용자 보고).
- `useUrlState` typedRoutes 호환을 위한 `as Route` cast 추가.

**샌드박스 기능 제거**
- 사용자 요청 "삭제 처리". UI 모두 제거: `CveDetail.SandboxPanel`,
  설정 페이지 샌드박스 카테고리 3 카드, settings 컴포넌트 4 파일 삭제.
- 백엔드 라우터 `sandbox.router` include 제거 (코드는 다른 마이그레이션과의
  의존성 위해 disk 에 잔존, 라우터만 비활성). `/api/v1/sandbox/sessions`
  → 404 확인.

**README 재작성 — 709 → 118 줄**
- 샌드박스 섹션 제거, KEV/EPSS/우선순위 핵심 가치로 끌어올림. 상용 서비스
  landing 톤 (사용자 요청: "주절주절 보기 어렵다"). Hero + TL;DR + 4-tier
  표 + 데이터 소스 표 + 화면 표 + AI 모델 표 + API 표 + 개발 명령 + Tech.
  설치 6단계 / 환경변수 reference / 아키텍처 다이어그램 등 긴 섹션은 제거.

**검증**
- 백엔드 `pytest` 영향 없음 (기존 테스트는 샌드박스/통합 외 영역 유지).
- frontend `tsc --noEmit` exit 0.
- 단일 docker build (backend + frontend) 한 번에 완료.
- 핵심 API 검증:
  - `/dashboard/priorities` → KEV 1602 건 + EPSS/CVSS tier 카운트 정상.
  - `/dashboard/insights` → CVSS 히스토그램 10 bin + mean 6.62 / median 6.7 / p90 9.1.
  - `/search?priority=kev` → 1602 건 반환.
  - `/cves/{id}/analyze` (Sonnet 4.6 full prompt) → 141 초 만에 정상 JSON.

---

### PR 10-CN — 회원가입/로그인 + 분석기록 DB + 즐겨찾기 user-scoped + admin 가드 + AWS IaC 일괄 push ✅

사용자 요청 (3개 turn 누적):
> "회원가입 기능 추가하고 / 각자의 Claude 연동 / 분석 기록은 DB 저장 후 모든 이용자
> 가 볼 수 있도록 / 댓글 작성·분석·즐겨찾기는 로그인 해야 / NVD·GitHub 토큰은
> 관리자 계정만 입력 가능 / 일반 유저 설정은 개인설정·AI 분석 탭만 / 대시보드
> 동기화는 관리자만 / 분석 기록에 사용자 태그 + 같은 CVE 여러 명 분석 시 히스토리
> 별도로 볼 수 있도록 / 다른 사람 분석은 커뮤니티 탭"

> 보안 명시: "**중요 토큰은 유출되지 않도록 주의하고**"

**Phase 1 (이번 PR) — 백엔드 + IaC.** Frontend (Login/Signup UI, Settings
탭 분기, 분석 히스토리 모달, admin 게이트) 는 PR 10-CO 로 이어 진행.

신규/변경 백엔드:
- `app/core/security.py` — bcrypt(cost 12) + JWT (HS256, ``JWT_SECRET`` 환경변수).
  토큰 디코드 실패는 호출 측에 노출 X (None 반환). ``is_admin_email()`` 로
  ``INITIAL_ADMIN_EMAILS`` 매칭 시 자동 admin.
- `app/api/v1/deps.py` — ``get_optional_user`` / ``get_current_user`` /
  ``require_admin``. 쿠키 ``access_token`` 만 source-of-truth.
- `app/api/v1/auth.py` — POST signup/login/logout, GET me. 쿠키는
  HttpOnly + (운영) Secure + SameSite=Lax + Path=/. 로그인 실패는 이메일
  존재 여부 노출 안 하도록 동일 메시지.
- `app/api/v1/profile.py` — GET/PATCH ``/me/profile`` (nickname/bio).
- `app/api/v1/analysis_records.py` — `/me/analyses` (내것), `/community/analyses`
  (남이 한 공개 분석, 본인 자동 제외), `/cves/{id}/analyses` (해당 CVE 의
  분석 히스토리), `/analyses/{id}` GET/PATCH(visibility·title)/DELETE.
  응답에는 author = {username, nickname} 만 — 이메일/role 절대 노출 X.
- `app/api/v1/cves.py` — `/cves/{id}/analyze` 에 로그인 필수 +
  결과 자동 ``AnalysisResult`` 저장 (markdown 본문 + category/visibility).
- `app/api/v1/analysis.py` — router-level ``Depends(get_current_user)`` 로
  ``/analysis/ask`` ``/analysis/compare`` 비로그인 차단.
- `app/api/v1/bookmarks.py` — 익명 ``X-Client-Id`` 헤더 → ``get_current_user``
  로 전환. 신규 즐겨찾기는 ``user_id`` 만 사용. HEAD ``/bookmarks/{cve_id}``
  로 단건 확인.
- `app/api/v1/admin.py` / `resources.py` / `settings.py` — router-level
  ``Depends(require_admin)`` — refresh / refresh-priority-signals /
  mitre-backfill / 자원 점검 / NVD·GitHub·credential 입력 전부 관리자만.
- `app/models/community.py::User` — ``nickname``, ``bio`` 컬럼 추가.
- `app/models/bookmark.py` — ``user_id`` FK + ``uq_bookmark_user_cve``.
  ``client_id`` 는 nullable 로 backward compat.
- `app/models/analysis_result.py` — 신규. ``visibility`` (public/private),
  ``cve_id`` / ``user_id`` 인덱스 3종으로 me/커뮤니티/CVE 별 정렬 빠르게.
- `alembic/versions/0020_auth_profile_analysis.py` — users.nickname/bio +
  bookmarks.user_id FK + analysis_results 테이블 + 인덱스.
- `pyproject.toml` — passlib[bcrypt], python-jose[cryptography],
  email-validator 추가.
- `app/core/config.py` — ``jwt_secret`` / ``jwt_exp_hours`` /
  ``initial_admin_emails``.

신규/변경 인프라:
- `infra/modules/secrets/main.tf` — ``random_password "jwt_secret"`` (64자).
  Secrets Manager 의 ``app/runtime`` 에 ``JWT_SECRET`` /
  ``INITIAL_ADMIN_EMAILS`` 키 추가. ``lifecycle ignore_changes`` 로
  콘솔에서 admin 이메일을 채워도 terraform 이 되돌리지 않음.
- `infra/modules/ecs_service_api/main.tf` — task definition 의 secrets 배열에
  JWT_SECRET / INITIAL_ADMIN_EMAILS 두 줄 추가 (``valueFrom = "${arn}:KEY::"``).
- `docker-compose.yml` — JWT_SECRET / JWT_EXP_HOURS / INITIAL_ADMIN_EMAILS
  env. dev 기본값은 ``dev-only-...`` prefix 로 운영 사용 금지 명시.

토큰 유출 방지 점검:
- DB 의 ``password_hash`` 는 응답 모델 어디에도 포함되지 않음 (스키마는
  명시 직렬화만 사용).
- ``/auth/me`` / 프로필 / 분석 응답에 ``role`` 은 들어가지만 ``email`` 은
  본인 응답에만 (``/community/analyses`` 등 타인 노출 응답은 ``author`` =
  {username, nickname} 으로 제한).
- JWT 는 HttpOnly 쿠키만 — JS 에서 토큰 자체 접근 불가.
- ``JWT_SECRET`` 은 운영 시 Secrets Manager → ECS task secrets 로 주입,
  태스크 환경변수에만 일시 존재. 코드/리포에는 dev 기본값만 남음.
- Claude OAuth credentials (`/home/app/.claude`) 는 네임드 볼륨 그대로 유지
  — Phase 2 (per-user credential) 에서 ``ai_credentials.user_id`` FK 도입.

후속 (PR 10-CO 예정):
- frontend AuthContext + login/signup 페이지
- Settings 탭 일반 사용자/관리자 분기 (일반 = 개인설정/AI분석, 관리자
  = 전체)
- 메인 대시보드 동기화 버튼 admin 게이트
- 즐겨찾기/AI 분석 버튼 로그인 가드 (401 → 로그인 페이지 리다이렉트)
- 분석 카드에 작성자 닉네임 + 같은 CVE 분석 히스토리 모달
- 프로필 편집 (닉네임/소개글)

---

### PR 10-AR — API 키 카드 help 문구 제거 + 발급 링크 작은 버튼화 ✅

사용자 요청: "NVD 에서 발급받은 API 키를 입력하면… / GitHub Advisory 데이터를
안정적으로 가져오는데… repo 권한 없이 발급해도 됩니다 — 이거 안내문 없애고,
발급받기 부분도 작은 버튼으로 구현"

변경:
- `lib/user-settings.ts`: SETTING_META 타입에서 `help` 필드 제거.
- `components/settings/ApiKeyField.tsx`: help 단락 삭제 + "발급받기 ↗" 텍스트
  링크 → ExternalLink 아이콘 + "발급" 라벨이 있는 11px 보더 버튼 (다른 카드
  속 "URL 복사" 등과 통일된 톤).

---

### PR 10-AQ — Claude 자격증명 수동 붙여넣기 + "전체 다시 받기" 안내 대비 개선 ✅

> 사용자 보고: "로그인 완료에 실패했습니다 / Claude CLI 가 60초 안에
> 응답하지 않았습니다. 수신 바이트: 108 byte. 표시 출력: ********...
> (92개 아스타리스크)" — PR 10-AM 진단 강화 덕분에 결정적인 단서 확보.
>
> 92 자 코드 (48자 + `#` + 43자, 사용자가 공유한 실제 OAuth 코드 형태) 가
> CLI 에 정상 입력 → mask-echo 까지 도달 → 그 다음 토큰 교환 단계에서
> CLI 가 stdout 을 비운 채 멈춤. 우리 PTY 입출력 코드가 아니라 컨테이너
> 안 ``claude.exe`` (Bun-compiled native binary) 의 내부 동작이 원인.
> Anthropic OAuth 엔드포인트 자체는 컨테이너에서 0.27s 응답 — 네트워크 이슈
> 아님.
>
> 그리고 "데이터 수집 / 전체 다시 받기" 카드 안내 문구가 안 보임 보고 — 색
> 대비 부족 (amber-200/80 on amber-500/5) + 사용자에게 의미 없는 jargon
> ("since-window", "last_success") 두 문제.

**Backend — `app/api/v1/claude_auth.py`**
- `POST /settings/claude-auth/credentials` 신규: 잘 동작하는 호스트에서 받은
  ``~/.claude/.credentials.json`` 내용을 그대로 받아 백엔드 named volume 의
  ``.credentials.json`` 으로 write + AI credential 자동 활성화. PTY 우회 경로.
- shape 검증: 객체이거나 JSON 문자열이어야 하고, ``claudeAiOauth.accessToken``
  필드가 있어야 함. 의도 다른 페이스트는 422 가 아니라 400 으로 메시지와 함께
  거절.

**Frontend — `components/settings/ClaudeAuthPanel.tsx` + `lib/api.ts`**
- 로그인 안 된 상태에서만 노출되는 expander 추가: "위 흐름이 60초 후 멈춘다면
  — 자격증명 직접 붙여넣기". 클릭 시 3-step 안내 + textarea + 저장 버튼.
- API 클라이언트에 ``saveClaudeCredentials(credentials)`` 메소드.

**Frontend — `components/settings/ApiKeyField.tsx`**
- "전체 다시 받기" 카드: 텍스트 색 ``amber-200/80`` → ``amber-900 dark:amber-100``
  로 변경 (실모드 / 다크모드 모두 충분한 대비). 배경/테두리 alpha 도
  ``amber-500/5,/20`` → ``amber-500/10,/40`` 로 한 단계 올려 카드 가시성 확보.
- 안내 문구: "과거 토큰 미설정/실패로 since-window 가 앞당겨져 누락분이 있을
  때 사용하세요. last_success 무시하고 처음부터 다시 가져옵니다." → "과거 수집
  실패로 누락된 항목이 있을 때만 사용하세요. 처음부터 다시 받아옵니다." — 30자
  대 60자.

**검증**
- tsc --noEmit exit 0.
- 로컬 docker build 안 함 (OrbStack NFS 보호 — 사용자 환경에서 `bash
  scripts/update.sh` 로 적용).

---

### PR 10-AO — 설정 페이지 안내 문구 간결화 + ClaudeAuthPanel 방어 추가 ✅

> 사용자 보고: "MITRE cvelistV5 백필 / MITRE 가 canonical 로 보유한 ~340k 전체
> CVE 를 받아옵니다… 이런 멘트들도 너무 TMI 임 핵심만 남겨" 그리고 "로그인
> 버튼 클릭하면 화면 비율 이상해지는건 왜 개선안함?"

**Frontend — `components/settings/SettingsLayout.tsx`**
- 페이지 상단 부제 + 모든 섹션 description 을 한 줄 핵심 문장으로 압축.
  - "내 자산", "외부 데이터 소스 API 키", "MITRE 전체 백필", "Claude 인증 +
    모델 라벨", "실행 중인 샌드박스 세션", "합성된 실습 환경 저장 공간",
    "실습 환경 출처별 분포", "내부 자원 관리", "버전 정보 / 업데이트" 9개.
- 헤더의 "테마와 외부 API 키, 자산 정보 등을 관리합니다. 화면 설정과 외부 API
  키는 이 기기 안에만 저장되며…" 한 문단 제거 — 같은 내용이 페이지 하단 "설정
  저장 위치 안내" 섹션에 이미 더 정확히 있음.

**Frontend — `components/settings/ClaudeAuthPanel.tsx`**
- 패널 root 에 `min-w-0` 추가. PR 10-AM 에서 `SettingsLayout` 우측 그리드 컬럼에
  `min-w-0` 을 넣어 OAuth URL chip 가 컬럼을 stretch 시키지 못하게 했지만 —
  패널이 다른 곳에 임포트돼 들어갈 경우 (또는 사용자 배포가 옛 이미지로 돌
  때) 방어가 한 겹 더 있는 편이 안전. defense in depth.
- 로그인 안내 두 문장 ("AI 심층 분석과… 본인의 Claude 구독으로…") + 세션
  만료 안내 ("자격증명은 백엔드의 영구 저장 공간(named volume)에 저장되어…")
  을 핵심만 한 줄로 줄임.

**Frontend — `components/settings/MitreBackfillPanel.tsx`**
- 백필 안내 3줄을 "전체 ~340k CVE 를 한 번에 채웁니다." 한 줄로.

**검증**
- compare.png 스크린샷: `min-w-0` 무 / 유 두 케이스 나란히 렌더해 URL chip 가
  컬럼을 가로로 stretch 시키는 회귀 사례가 fix 적용 시 truncate + "URL 복사"
  버튼 가시화로 정상 동작함을 시각적으로 확인.
- `npx tsc --noEmit` exit 0.
- 풀 빌드 + 페이지 200.

**알려진 잔여**
- Claude 로그인 자체 60s timeout 문제는 PR 10-AM 의 진단 메시지 강화 이후
  사용자 측 재시도 결과 대기. CLI 가 코드를 받고도 토큰 교환 단계에서
  silent 한 hang 을 보이는 동작은 그대로 — claude.exe 가 Bun-compiled native
  binary 라 우리 쪽에서 더 파보기 어려움.

---

### PR 10-AN — GHSA since-window 갭 복구 ("전체 다시 받기") + GraphQL 오류 surface ✅

> 사용자 보고: "GHSA 이거는 정상 수집 안되는듯 지금 3개밖에 없음." 대시보드 수집
> 분포 패널에서 GHSA 막대가 거의 안 보임. DB 점검 결과 다른 출처는 수만 건인데
> source='github_advisory' 만 250개대. 첫 ingestion 만 241건 채우고 그 뒤로는
> publishedSince=last_success 가 새 advisory 가 없는 짧은 구간을 가리켜 0건 반환만
> 반복 — 한 번 since 가 앞당겨지면 그 사이에 publish 된 advisory 는 다시 못 잡는
> 구조였음.

**Backend — `app/services/parsers/github_advisory.py`**
- GraphQL `errors` payload 가 오면 조용히 return 하던 부분을 `RuntimeError` 로
  raise — `run_parser` 의 try/except 가 `error_message` 컬럼에 사유를 적어 사용자
  설정 패널 status 행에서 "토큰 만료" / "rate limit" 등 실제 원인이 보임.
  이전엔 같은 상황이 status='success', items_processed=0 으로 기록돼 사용자가
  뭐가 잘못됐는지 알 수 없었음.

**Backend — `app/services/ingestion.py` + `app/api/v1/admin.py`**
- `run_parser(..., full_resync: bool = False)` 추가. True 일 때 `_last_success`
  을 무시하고 `since=None` 으로 fetch 호출 → publishedSince 필터 해제, 처음부터
  다시 walk. since-window 갭으로 누락된 advisory 를 회수.
- `POST /admin/refresh` 가 `X-Full-Resync: ghsa | nvd | exploit_db | all`
  헤더 (쉼표 분리) 수용. 응답 payload 에 `fullResync` 객체 추가.
- 같은 엔드포인트가 헤더 미제공 시 `app_settings` 의 저장 토큰을 fallback 으로
  사용하도록 통일 — 스케줄러는 PR 10-AJ 이래 이미 그렇게 동작했지만 manual
  refresh 만 env+header 만 보고 있었음. 다른 기기/브라우저에서 "전체 다시 받기"
  눌러도 token-less 로 떨어지지 않음.

**Frontend — `components/settings/ApiKeyField.tsx` + `lib/api.ts`**
- `refreshIngestion(keys, fullResync?)` 가 `X-Full-Resync` 헤더 부착.
- 키가 저장된 상태일 때 카드 안에 "전체 다시 받기" 버튼 + 안내 한 줄 노출 —
  "과거 토큰 미설정/실패로 since-window 가 앞당겨져 누락분이 있을 때
  사용하세요" 문구로 의도 명확화. 한 번 누르면 background 로 풀-리싱크 트리거.

**검증 (라이브)**
```
# Before
GHSA: 250

# Trigger full resync
$ curl -X POST -H 'X-Full-Resync: ghsa' /api/v1/admin/refresh
{"queued":true,"usedKeys":{"nvd":true,"github":true},
 "fullResync":{"nvd":false,"ghsa":true,"exploit_db":false}}

# Watch ingestion_logs (took ~10 min)
items_processed=26973 items_new=219 items_updated=26521 status=success

# After
GHSA primary-source count: 469 (+219)
sources[] containing 'github_advisory' total: ~27,000
(많은 advisory 가 NVD/MITRE 에 먼저 등록되어 primary=다른 출처 + sources 에 ghsa 가 append 됨)
```

**알려진 잔여**
- 풀-리싱크 도중 스케줄러가 같은 source 의 정기 tick 을 별도 ingestion_logs
  행으로 동시에 실행할 수 있음 (manual 트리거는 scheduler 의 max_instances=1
  락을 우회). GitHub GraphQL 의 rate-limit (5000 pts/h) 안에서 충돌은 무해하나
  같은 시간대 두 행이 비슷한 카운트를 기록해 혼란 가능성. 후속.
- 다중-출처 표시: VulnDistributionPanel 의 "출처" 막대는 여전히 primary
  source 만 카운트 — "이 CVE 는 GHSA 에도 있다" 를 시각화하려면 sources[]
  unnest 도 별도 그룹으로 추가하는 추가 작업 필요.

---

### PR 10-AM — Claude 로그인 진단·라이트 분석 + 설정 페이지 wrap 방지 + status 토큰 영속 인식 ✅

> 사용자 보고 3건 한 번에:
> 1) "로그인 완료 버튼 클릭 시 로딩만 되고 타임아웃 걸림" — 60초 후 504, snippet 은 항상 "(없음)".
> 2) "클로드 로그인 시 UI 깨지는거도 체크해서 마저 수정 해" — PR 10-AL 의 panel 내부 `min-w-0` chain 만으로는 부족했음.
> 3) GHSA / NVD 토큰을 대시보드에서 저장해도 status 배너가 계속 "키 미설정" 으로 표시.

**Backend — `app/api/v1/claude_auth.py`**
- PTY 윈도우 1×400 → 40×200: Ink 가 코드 입력 후 그리는 mask-echo (`****`) + verifying spinner 가 1-row 뷰포트 밖으로 떨어져 매번 0~14 byte 만 캡처됐음. 정상적 터미널 크기로 키우니 코드 수신 직후 80 byte 캡처되어 timeout snippet 이 실제로 의미를 가짐 — "(없음)" 대신 "수신 바이트: 80 byte. 표시 출력: ****..." 가 나옴.
- URL 캡처 regex 가 wrap 1회 허용: 40×200 윈도우에선 ~350자 OAuth URL 이 한 번 줄바꿈됨. `_URL_CHARS + (?:\r*\n + _URL_CHARS)?` + `_join_url` 로 wrap 지점 CR/LF 제거. wrap 을 무제한 허용하면 뒤따라오는 "Paste code here if prompted" 까지 끌어들이는 부작용이 있어 정확히 1회만 허용.
- code 전송 `b"\n"` → `b"\r"`: PTY cooked mode 에선 두 코드가 동일 처리되지만 Ink raw-mode stdin 에선 `\r` 만 Enter 키 — 차후 cooked mode 가 비활성화되거나 다른 raw-mode TUI 호출 시에도 안전.
- 504 timeout 메시지 강화: 수신 바이트 수 + 표시 출력 발췌 + "CLI 가 코드는 받았지만 토큰 교환에서 멈췄음, 취소 후 새 세션으로 재시도" 안내. log 라인에도 raw_tail 추가해 운영자가 docker compose logs 로 진단 가능.

**Backend — `app/api/v1/health.py`**
- `/status` 의 `nvdKeyPresent` / `githubTokenPresent` 가 환경변수(`get_settings()`) 만 확인했었음 — 대시보드에서 사용자가 저장한 키는 `app_settings` 테이블에 들어가지만 status 에서는 보이지 않아 "키 미설정" 배너가 계속 떴음. PR 10-AJ 의 스케줄러는 이미 DB fallback 으로 키를 사용하고 있었으므로 status 만 false negative 였음. env 우선 / DB fallback 패턴으로 통일.

**Frontend — `components/settings/SettingsLayout.tsx`**
- 우측 본문 컬럼 `<div>` 에 `min-w-0` 추가. CSS Grid item 의 implicit min-width 가 content intrinsic size 라, `min-w-0` 가 없으면 패널 내부 어느 곳에서든 unbounded text (예: OAuth URL chip) 가 칼럼을 grid template 밖으로 밀어내 페이지 비율을 깨뜨림. ClaudeAuthPanel 내부의 min-w-0 chain (PR 10-AL) 은 그 자체로는 정확하지만 상위 grid item 이 함께 shrink-allowed 여야 의도대로 동작.

**검증 (라이브)**
```
# /status 토큰 인식
$ curl /api/v1/status | jq '{nvd: .nvdKeyPresent, gh: .githubTokenPresent}'
{"nvd":true,"gh":true}   ← 이전에는 false,false 였음 (env 비어 있고 DB 만 채워져 있을 때)

# OAuth URL 캡처
$ curl -X POST /api/v1/settings/claude-auth/start | jq '.url | length'
346    ← wrap 처리 후 정상 (이전 wrap-aware regex 미적용 시 200 에서 잘리거나 "Pastecode..." 가 붙음)

# Submit fake code (가짜 코드는 CLI 가 토큰 교환 실패로 멈춤 — timeout 진단만 검증)
$ curl -X POST /api/v1/settings/claude-auth/<sid>/submit -d '{"code":"fake#aaa"}'
{"detail":"Claude CLI 가 60초 안에 응답하지 않았습니다. 수신 바이트: 80 byte.
  표시 출력: ****************************************************************
  — CLI 가 코드 입력은 받았으나 토큰 교환 단계에서 멈췄습니다. 1) '취소' 후
  '다시 로그인' 으로 새 세션을 시작하고, 2) Anthropic 페이지에서 갓 받은 코드를
  그대로 한 번에 붙여넣어 보세요 (이전에 받은 코드는 만료됩니다)."}
```

**알려진 잔여 이슈**
- 토큰 교환 자체가 실패할 때 CLI 가 어떤 메시지도 stdout 으로 남기지 않는 동작은 그대로 — `claude.exe` 가 Bun-compiled native binary 라 내부 진단 출력 추가가 어려움. 사용자 안내 문구로 "코드 만료/세션 mismatch 가 가장 흔한 원인" 을 알리는 것이 현재 최선.
- GHSA "지금 3개밖에 없음" 보고 건은 사용자가 어느 화면을 봤는지 명확하지 않아 별건. DB 에는 250 row 가 있고 facets 도 250 으로 응답. 추후 사용자 화면 확인 후 후속.

---

### PR 10-AD — 대시보드 내 Claude 로그인 (호스트 ~/.claude 마운트 제거) ✅

**완료일:** 2026-05-09

> 사용자 보고: "자꾸 CLI Claude code 오류 나네. 차라리 방법을 개선해서 내 서비스 안에 키 넣는거 처럼 로그인 API 이런식으로는 개선 못하나? 근본 개선하고 나는 API 키 가져다 쓸 일 없음 CLI 말고 대시보드 내 설정에서 로그인 가능하면 저런식으로 구현 바람." 그동안 claude_cli 인증이 macOS 호스트 ~/.claude 바인드 + Keychain 동기화 + launchd 크론에 묶여 있어 컨테이너 재생성 / Linux 배포 / 인덱스 swap 등에서 끊임없이 깨졌음. 사용자가 한 번도 터미널에 들어가지 않고 설정 화면에서 로그인 한 번이면 끝나는 구조로 전면 전환.

**Backend — `app/api/v1/claude_auth.py` (신규)**
- 핵심 통찰: `claude setup-token` 이 device-code OAuth 플로우 — localhost callback 필요 없이 사용자가 코드 받아서 붙여넣기. 우리 UI 에 딱 맞음.
- `pty.openpty()` + `TIOCSWINSZ(rows=1, cols=400)` 로 와이드 가상 TTY 만들어 `claude setup-token` 실행 — CLI 가 isTTY 검사 통과하고, OAuth URL 이 줄바꿈 없이 한 줄로 출력되어 regex 한 방에 캡처. ANSI escape sequence 는 `_strip_ansi()` 로 제거.
- 4 endpoints: `GET /status` (자격증명 파일 파싱) / `POST /start` (서브프로세스 + URL 캡처, 25s 타임아웃) / `POST /{sid}/submit` (master fd 에 코드 + \n 쓰고 30s 종료 대기) / `POST /{sid}/cancel` (SIGTERM + 2s grace + SIGKILL) / `POST /logout` (자격증명 파일 unlink).
- 세션 레지스트리는 in-memory `dict[sid → _LoginSession(proc, master_fd, url, started_at)]` + 10분 TTL GC. 단일 백엔드 인스턴스 가정 (self-hosted).
- Non-blocking master fd read 로 startup banner / ASCII art 동안 polling 가능.

**Backend — 인프라 변경**
- `docker-compose.yml`: `claude_credentials` named volume → `/home/app/.claude` 마운트. `INSTALL_CLAUDE_CLI` 기본값 0 → 1. 이제 호스트 바인드 없이 컨테이너 자체가 인증 상태를 영구 보유.
- `backend/Dockerfile`: `ARG INSTALL_CLAUDE_CLI=1` 기본값으로 — node + claude CLI 베이스 이미지에 baked.
- `backend/app/services/ai_analyzer.py`: `_ensure_kestrel_claude_home()` 이 mirror 파일 존재 여부로 분기. 없으면 (named volume 모드) 그냥 HOME=/home/app, 있으면 (legacy macOS 호스트 마운트) 기존 scratch HOME workaround. 두 토폴로지가 한 코드 패스.

**Frontend — `components/settings/ClaudeAuthPanel.tsx` (신규)**
- 상태 카드 — 로그인됨 = emerald (CheckCircle2 + 만료 시각 + 권한 list + 로그아웃 버튼), 미로그인 = amber (ShieldAlert + 안내).
- `start mutate` 성공 시 자동으로 새 탭에서 OAuth URL 열고, 코드 입력 필드에 포커스 — 사용자 motion 1번 (창 열기 + 코드 받기 + 한 번 paste).
- 2 단계 안내 (`<ol>`) — 1: URL 열기/복사 + 직접 클릭 가능한 truncated chip, 2: 코드 입력 폼 + 로그인 완료 / 취소 버튼.
- 컴포넌트 unmount 시 `cancelClaudeAuth(sid)` best-effort — 사용자가 페이지 떠나면 PTY 자동 정리.
- `cliPresent: false` 일 때는 시작 버튼 대신 NoticeBox 로 `INSTALL_CLAUDE_CLI=1 + bash scripts/update.sh --no-pull` 안내.
- `lib/api.ts`: 5 helper (status/start/submit/cancel/logout) + 4 타입.

**설정 페이지 재배치**
- 새 섹션 "Claude 로그인" — 'AI 분석 키' 자리. 인증 상태가 *AI 기능의 prerequisite* 이라 가장 위에 둔다.
- 기존 `AiSettingsForm` 섹션은 "AI 분석 모델 선택" 으로 리네임 — 더 이상 키 입력이 아니라 *어떤 모델로 호출할지* 의 의미만 남음.

**왜 device-code 흐름인가 (vs localhost callback)**
- `claude login` 의 일반 플로우는 CLI 가 자동 포트에 listen → Anthropic 이 그 포트로 redirect. 우리 컨테이너 안에서는 (a) 포트 forwarding 필요 (b) 호스트 / 컨테이너 localhost 가 다르다 (c) 자동 포트 캡처 fragile.
- `claude setup-token` 은 redirect 없이 *Anthropic 가 코드를 화면에 표시 → 사용자가 복사 → CLI stdin 에 paste* 흐름. 포트도 callback 도 필요 없고, 우리는 stdin 에 1줄 쓰면 된다. 컨테이너에 가장 자연스러운 선택.

**왜 PTY 인가 (vs 그냥 Pipe)**
- `claude setup-token` 이 stdin/stdout/stderr 의 isTTY 검사를 함 — 일반 Pipe 면 OAuth flow 자체를 시작하지 않고 헤드리스 모드로 떨어진다. `pty.openpty()` 로 진짜 TTY 슬레이브를 자식에게 주고 마스터 fd 는 우리가 read/write.
- 추가 보너스: `TIOCSWINSZ` 로 cols=400 박아서 OAuth URL 이 줄바꿈으로 분리되지 않게 → regex 매치 단순화. 80-col 기본이면 URL 이 5줄에 걸쳐 잘려 reassembly 가 골치아픔.

**왜 named volume 인가 (vs DB 저장)**
- `claude` CLI 가 OAuth 토큰 자동 갱신을 직접 수행 — 우리가 만지면 갱신 로직을 다시 짜야 한다. 파일 1개 (`~/.claude/.credentials.json`) 로 두면 CLI 가 알아서 refresh, 우리 코드는 거기 없음. named volume 으로 컨테이너 재생성에도 살아남음.
- 보안: named volume 은 docker daemon 권한 필요 — 호스트 사용자가 평범한 ls 로 못 봄. DB 저장 vs encrypted column 등 추가 인프라 불필요.

**검증 (라이브)**
- 풀 빌드 (`bash scripts/update.sh --no-pull`) → claude_credentials volume 생성 → 백엔드 재기동 → /api/v1/health 200.
- `GET /api/v1/settings/claude-auth/status` → `{loggedIn:false, cliPresent:true, cliVersion:"2.1.126"}`.
- `POST /api/v1/settings/claude-auth/start` → `{sessionId, url:"https://claude.com/cai/oauth/authorize?code=true&client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e&response_type=code&redirect_uri=...&scope=user%3Ainference&code_challenge=...&state=..."}` — 한 줄 캡처 OK, `code=true` 로 device-code 모드 확인.
- `POST /{sid}/cancel` → 200, 서브프로세스 SIGTERM 후 정상 종료.
- 풀 OAuth round-trip (사용자가 코드 paste 까지) 은 본 PR 시점에서는 자동 검증 불가 — 사용자가 다음 로그인 시도에서 검증.
- `tsc --noEmit` 통과.

**알려진 한계 / 다음 PR 으로 넘김**
- `claude` CLI 가 토큰 만료 시 *자동 갱신* 을 시도하지만 갱신 실패 시 사용자에게 surface 가 부족 — Status 패널이 expiresAt 만 보여주지 "갱신 실패" 같은 errorKind 는 ai_analyzer 호출 실패 후에야 알 수 있음. errorKind 가 `auth_expired` 면 ClaudeAuthPanel 의 status 를 자동 invalidate 하는 cross-component 훅이 향후 개선 여지.
- `docker-compose.claude-cli.yml` overlay 는 macOS 호스트 마운트 모드를 위해 *deprecation 으로* 그대로 유지. README 업데이트는 별도 PR.
- 단일 백엔드 인스턴스 가정 — 멀티 워커 환경에서는 in-memory 세션 레지스트리가 sticky session 필요. self-hosted 단일 노드에서만 동작 보장.

---

### PR 10-Z — 설정 → 내부 자원 관리 서브 페이지 (DB / Redis / Meili) ✅

**완료일:** 2026-05-09

> 사용자 보고: "설정 창 내에 한페이지에서 내부 프론트엔트 백엔드 DB 자원 관리 가능하도록 페이지도 한개 생성." 그동안 운영자가 "Redis 가 멈춘 것 같다 / 검색 인덱스가 비었다 / 큰 수집 후 검색이 느리다" 같은 상황에서 컨테이너에 들어가 `psql` / `redis-cli` / `curl meilisearch:7700/indexes` 를 직접 쳐야 했음. UI 한 화면에서 사용량 + 점검 동작을 끝낼 수 있도록 별도 서브 페이지 신설.

**Backend — `app/api/v1/resources.py` (신규)**
- `GET /api/v1/resources` — DB / Redis / Meili 한 번에 조회.
  - DB: `SHOW server_version`, `pg_database_size(current_database())`, `pg_total_relation_size` + `reltuples` 로 18개 추적 테이블 별 row 추정 + 디스크 사용량. `pg_class` 조인 한 번으로 N+1 없음.
  - Redis: `client.info()` + `dbsize()`. 사용량 / 키 수 / 버전.
  - Meili: SDK `index.get_stats()` + `client.get_all_stats()` + `client.get_version()` — sync 호출이라 `asyncio.to_thread` 로 offload (event loop block 회피).
- `POST /resources/db/analyze` — 추적 테이블 18개에 `ANALYZE` (autocommit 필요해 `raw = await db.connection(); raw.execute("COMMIT"); for t: raw.execute(f'ANALYZE "{t}"')`). VACUUM FULL 은 의도적으로 노출 안 함 (ACCESS EXCLUSIVE 잠금).
- `POST /resources/redis/flush` — `FLUSHDB`. 전후 `dbsize` 캡처해 "삭제된 키 N개" 응답.
- `POST /resources/meili/drop` — `client.delete_index(meili_index)`. 응답에 *재색인 명령* (`python -m scripts.reindex_meili`) 명시 — 빈 인덱스만 다음 startup `ensure_index()` 가 다시 만들고 본문 채움은 운영자 책임.
- 모든 응답 `_CamelOut` 베이스 + `ActionResponse {ok, detail, payload}` 통일 — 프론트가 한 가지 모양으로 처리.

**Frontend — `app/settings/resources/page.tsx` 별도 라우트**
- 메인 설정 페이지의 마지막 직전에 진입 카드 추가 (Server 아이콘 + ChevronRight). 운영 점검은 일상 설정과 *맥락이 다른* 작업이라 한 화면에 섞지 않고 sub-route 로 분리.
- 상단에 `← 설정으로 돌아가기` 링크. `max-w-5xl` 로 메인 설정(`max-w-3xl`)보다 넓게 — 카드 3장이 유의미한 폭을 차지.

**`components/settings/ResourcesPanel.tsx`**
- 카드 3장 (`DbCard` / `RedisCard` / `MeiliCard`) — 각 카드 = 헤더(아이콘 + 이름 + 정상/오류 배지) + 통계 chip 그리드 + 점검 동작.
- DB 카드는 `<details>` 안에 테이블별 크기 표 (이름 / 추정 행수 / 크기) — 펼치지 않으면 카드가 짧아 위치 차지가 적음.
- `ActionRow` 컴포넌트 — destructive 액션은 *inline confirm* 패턴 (한 번 누르면 amber 경고 + "확인하고 실행" 두 번째 버튼 제시 + amber 알림 박스). 모달 안 띄움 — 점검 동작이 짧고 컨텍스트 잃지 않게.
- React Query — 30s staleTime + 60s refetchInterval. 액션 성공 시 자동 `invalidateQueries` 로 통계 새로고침.
- 결과 표시: 성공 = NoticeBox (amber), 실패 = ErrorBox (rose). 두 컴포넌트 모두 `className` prop 받도록 `feedback-box.tsx` 시그니처 확장 (외부 컴포넌트가 마진 주려고 매번 wrap div 만드는 건 조잡함).

**`lib/api.ts`**
- `getResources()` + `flushRedis()` + `analyzeDb()` + `dropMeiliIndex()` helper. `ResourceReport` / `DbResource` / `RedisResource` / `MeiliResource` / `TableSize` / `ResourceActionResponse` 타입 추가.

**왜 별도 페이지인가 (vs 메인 설정에 누적)**
- 메인 설정은 *개인 설정* (테마, 키, 자산) 중심 — 평소 자주 안 들춤. 자원 관리는 *문제 진단/해결* 흐름 — 들어올 때 의도가 명확하다 (`Redis 캐시를 비울 때` / `ANALYZE 돌릴 때`). 두 흐름을 섞으면 한쪽이 다른쪽의 노이즈가 됨. 메인에는 entry card 한 장만 두고 풀 surface 는 sub-route 로.

**왜 destructive 액션을 inline-confirm 으로 했는가 (vs 모달)**
- 모달은 컨텍스트 단절을 만들어서, *어느 카드의 어떤 액션을 누르려 했는지* 확인 단계에서 잠깐 헷갈린다. inline-confirm 은 그 액션 카드 안에서 amber 박스로 "이 동작이 무엇을 비우는지" 한 번 더 보여준 뒤 두 번째 클릭 — 카드 시각적 위치가 그대로 유지되어 실수가 줄어든다.

**검증 (라이브)**
- `GET /api/v1/resources` → 200. DB(`pg 16.13` / 794 MB / 18 테이블) / Redis(`7.4.8` / 0 keys / 1.x MB) / Meili(`1.10.3` / 95285 docs / 569 MB).
- `POST /resources/db/analyze` → 200, `"ANALYZE 완료 (18개 테이블)"`.
- `POST /resources/redis/flush` → 200, `"Redis 캐시를 비웠습니다 (삭제된 키 0개)"`.
- `POST /resources/meili/drop` 은 라이브 테스트 안 함 (95k 문서 다시 색인하는 비용이 큼) — 단위 동작은 SDK API 호출만 wrapping 이라 unit-test 만으로 안전 판단.
- `tsc --noEmit` 통과.

**알려진 한계 / 다음 PR 으로 넘김**
- "프론트엔드 자원" 항목은 본 PR 범위 밖 — 브라우저 측 React Query 캐시 size / localStorage usage 같은 metric 은 client-only 라 backend endpoint 가 아닌 frontend self-instrumentation 이 필요. 사용자 가치 대비 구현 부담이 커서 별도 PR.
- `ANALYZE` 는 autocommit 필요한 statement 라 SQLAlchemy AsyncSession 의 transaction 안에서 못 돈다 — 우회로 `raw connection + COMMIT` 사용. 깔끔하지 않으나 이 endpoint 한정이라 helper 까지 짜진 않음.
- table 별 row 추정 (`reltuples`) 은 ANALYZE 가 돈 시점 기준 stale 일 수 있음 — UI 가 "추정" 라벨 명시.

---

### PR 10-Y — 기존 설치본 안전 업데이트 흐름 (`scripts/update.sh` + `/api/v1/version`) ✅

**완료일:** 2026-05-09

> 사용자 보고: "기존 레포지토리에서 설치된 버전에서 신규로 내가 프로젝트 업데이트하면 적용 가능하도록 개선." 그동안 README 의 업데이트 안내가 `git pull && docker compose up -d --build` 한 줄뿐이었고, (a) `.env` 에 새로 추가된 환경변수가 있어도 모름 (b) 빌드된 이미지가 어느 commit 에서 나온 건지 확인 불가 (c) Meilisearch 인덱스 스키마가 바뀐 릴리스인지 모름 — 운영자가 *맞게 적용됐는지 확신* 할 surface 가 없었음. 한-줄 스크립트 + 백엔드 `/version` endpoint + 설정 페이지 패널로 업데이트 흐름을 안전하게 보강.

**`scripts/update.sh` (신규, +chmod +x)**
- 6 단계 정해진 시퀀스 — `git pull --ff-only` → `.env`/`.env.example` 키 diff → `docker compose build backend frontend` (build-arg 로 git SHA + ISO date 주입) → `docker compose up -d` → `/api/v1/health` 60s polling → optional `python -m scripts.reindex_meili`.
- 안전장치 — 작업 트리 dirty 면 `git status --short` 보여주고 exit 1, `.env` 누락 키 발견 시 stderr 경고 후 사용자 확인 유도, 헬스체크 실패 시 `docker compose logs backend | tail -50` 안내 후 exit 1.
- 옵션 — `--reindex-meili` (스키마 바뀐 릴리스 전용), `--skip-build` (코드만 받았을 때), `--no-pull` (이미 pull 한 경우). `INSTALL_CLAUDE_CLI=1` 이 `.env` 에 있으면 `docker-compose.claude-cli.yml` 오버레이 자동 추가.
- 색깔 prefix (`▸ ▸ ▸` cyan info / `⚠` amber warn / `✔` green ok / `✘` red err) — 운영자가 진행 상황을 한눈에 읽을 수 있게.

**`backend/Dockerfile`**
- `ARG KESTREL_GIT_COMMIT=unknown` + `ARG KESTREL_BUILD_TIME=unknown` 후 `ENV` 로 승격. update.sh 가 `git rev-parse HEAD` + `date -u +%Y-%m-%dT%H:%M:%SZ` 를 그대로 baked. 수동 `docker compose build` 시에는 default `unknown` 으로 떨어져 frontend 패널에서 amber "기록 없음 (수동 빌드)" 표시.

**`backend/app/api/v1/health.py`**
- `GET /api/v1/version` 신규 — `gitCommit`/`gitCommitShort`/`buildTime`/`alembicRevision`/`startedAt` 반환.
- `alembicRevision` 은 `SELECT version_num FROM alembic_version` 으로 *DB 상태* 직접 조회 — 이미지가 기대하는 revision 과 DB 가 실제로 적용한 revision 이 다른 mismatch (예: 새 이미지 받았지만 alembic upgrade 가 실패해서 DB 는 아직 0015) 를 별도 surface 없이 비교 가능.
- `_PROCESS_STARTED_AT = datetime.now(...)` 를 import 시점에 캡처 — uvicorn worker uptime 기록. 매 호출마다 갱신되지 않음.

**`frontend/components/settings/VersionPanel.tsx` (신규)**
- 두 칸 Stat 그리드 — 좌: 현재 빌드 (gitCommitShort + GitHub commit 링크 + 빌드 시각), 우: DB 마이그레이션 (alembicRevision + 프로세스 시작 시각 상대 표시).
- 업데이트 명령 코드블록 + `Copy` 버튼 (clipboard API + 1.5s 토글). `<details>` 안에 옵션 3종 (`--reindex-meili / --skip-build / --no-pull`) 한 줄씩 설명 — 평소엔 접혀 있어 패널이 짧음.
- 안내 문구 — *"저장소를 클론한 디렉터리에서 아래 한 줄을 실행하면 최신 코드를 받아 이미지를 재빌드하고 DB 마이그레이션까지 자동으로 적용합니다. 작업 트리에 커밋되지 않은 변경이 있으면 안전하게 중단됩니다."* (사용자 톤 — PR 10-AA 와 일관).

**`frontend/lib/api.ts`**
- `api.getVersion()` helper + `VersionReport` 타입 추가.

**`app/settings/page.tsx`**
- 새 섹션 "버전 정보 / 업데이트" 를 "저장 위치 안내" 바로 위 (페이지 마지막에서 두 번째) 에 배치 — 평소 자주 들춰보지 않는 위치이지만 *문제가 생긴 후 진단할 때* 정확히 그 자리에서 찾는다.

**`README.md` "6. 업데이트 · 롤백 · 초기화"**
- 권장 = `bash scripts/update.sh` 한 줄 + 6 단계 표 (단계/동작/안전장치). 옵션 3종 별도 표시. 수동 fallback (`git pull && docker compose up -d --build`) 도 유지.

**검증**
- `bash -n scripts/update.sh` 통과.
- 라이브 `GET /api/v1/version` 200 — `{alembicRevision:"0016", startedAt:"2026-05-08T14:03:14Z", 나머지 unknown}` (현재 image 가 새 build-arg 없이 빌드돼 unknown — 사용자가 첫 update.sh 실행 시 baked 됨).
- frontend `tsc --noEmit` 통과.

**알려진 한계**
- update.sh 는 git 기반 설치 가정 — Docker Hub pre-built image 배포는 별도 흐름 필요.
- Meilisearch 스키마 변경을 자동 감지하지 않음 — `to_document()` 의 field set hash 를 인덱스 메타에 저장하고 변경 시 자동 reindex 하는 건 PR 10-Y 범위 밖. 현재는 release notes 가 명시할 때 운영자가 `--reindex-meili` 추가.
- `git_commit` baked 가 unknown 인 환경 (수동 build, CI baked 아님) 에서는 GitHub commit 링크가 안 뜸 — VersionPanel 이 amber 경고로 표시.

---

### PR 10-X — 설정 페이지 샌드박스 세션 관리 + vulhub 동기화 패널 ✅

**완료일:** 2026-05-08

> 사용자 보고: "설정에서 샌드박스 관리가 가능하도록 개선부탁." 그동안 샌드박스 세션은 *각 CVE 상세 페이지* 안에서만 시작/정지가 가능했고, 동시에 여러 CVE 를 띄운 운영자는 어떤 세션이 살아 있는지 한눈에 확인할 길이 없었음. 컨테이너 슬롯이 30분 TTL 안에 회수되긴 하지만 즉시 정리·정지 surface 가 없으니 "방금 띄운 lab 정지" 같은 일상 작업이 답답. 설정 페이지에 통합 관리 패널 신설.

**Backend — `GET /sandbox/sessions` 신규**
- 새 응답 모델 `SandboxSessionSummary` — 풀 `SandboxSessionOut` 에서 `LabInfoOut`/`injection_points`/`candidate_rank` 같은 무거운 필드 제거하고 *목록에서 의미 있는* 6+3 필드만 노출 (id, cve_id, lab_kind, lab_source, status, container_name, target_url, created_at, expires_at, error). `vulnerability_id` 대신 `cve_id` 를 backend 에서 미리 resolve — `Vulnerability.id IN (...)` 한 번에 배치 lookup 으로 N+1 회피.
- 기본 필터 = `status IN (pending, running)` 로 *지금 자원을 점유하고 있는* 세션만. 쿼리스트링 `include_stopped=true` 면 정지·만료·실패도 포함. `limit` 1-200 clamp.
- Surface-on-read: 응답 시점에 `expires_at <= now()` 인 RUNNING 행은 한꺼번에 `EXPIRED` 로 transition + commit. sweeper 가 안 돌아도 패널 정확도가 유지되고, 다음 호출에서 자연스럽게 사라진다.
- `POST /sandbox/sessions/reap` 신규 — 기존 `reap_expired_sessions(db)` 서비스 호출하고 `{reaped: int}` 반환. operator 가 컨테이너 슬롯을 즉시 비우고 싶을 때 강제 sweep 트리거.
- `app/schemas/sandbox.py` 에 `SandboxSessionListResponse {items, runningCount, total}` 추가, sandbox API import 도 동기화.

**Frontend — `components/settings/SandboxSessionsPanel.tsx` 신규**
- React Query — 10s staleTime + 30s refetchInterval 로 setting 페이지 열린 동안 패널이 자동으로 최신화. `includeStopped` 토글이 queryKey 의 한 자리이므로 키 바뀌면 캐시 분기.
- 헤더 통계 — `현재 실행 중 N개 / 목록 표시 M개 / 정지·만료된 세션도 보기` 체크박스 + `새로고침` + `만료 세션 정리` 버튼. Reap 결과는 `NoticeBox` 로 한 줄 요약 ("N개 세션이 정리되었습니다" / "정리할 세션이 없습니다").
- 세션 카드 — 상태 배지(`pending/running/stopped/expired/failed` 5종 — 각자 색조+아이콘), CVE id 클릭 시 `/cve/<id>` deep-link, 출처 칩(`vulhub/표준/AI 합성`), `lab_kind` font-mono, 시작/만료 상대시간 (`5분 전 / 12분 후`), `containerName`, 에러 본문, 우측에 `정지` 버튼 (running/pending 일 때만 활성).
- vulhub 동기화 sub-section — `POST /sandbox/vulhub/sync` 호출 + 결과 요약 배너 (폴더 N개 검사 / 환경 M개 갱신 / 후보 K개 / 건너뜀 L개). errors 배열은 `<details>` 로 접어 5건까지만 inline.
- `lib/api.ts` 에 helper 3종 (`listSandboxSessions`, `reapSandboxSessions`, `syncVulhub`) + 타입 3종 (`SandboxSessionSummary`, `SandboxSessionListResponse`, `VulhubSyncResponse`).

**설정 페이지 배치 (`app/settings/page.tsx`)**
- 새 섹션 "실행 중인 샌드박스 세션" 을 "합성된 실습 환경 저장 공간" 바로 위에 배치 — *세션 -> 저장공간 -> 환경 분포* 순으로 인프라 깊이가 깊어지는 흐름.

**왜 cve_id 를 backend 에서 resolve 했는가**
- `SandboxSession` 은 `vulnerability_id (UUID)` 만 보유. 프론트엔드가 직접 `vulnerability_id → cve_id` 매핑하려면 (a) 별도 API 호출 (N+1) 또는 (b) Vulnerability 전체 테이블 캐시. 둘 다 비효율. 백엔드에서 vuln_ids set 만들어 한 번에 `IN (...)` 쿼리 후 dict 로 채워 넣는 패턴이 가장 짧고 빠르다 (50 row 기준 단일 query).

**왜 GET /sandbox/sessions 가 응답 안에서 행을 commit 하는가 (read-side write)**
- API 호출이 *idempotent GET* 이지만 응답 결과의 의미는 "지금 이 시점의 상태" — 그러니 expired 인데 RUNNING 으로 보이면 거짓말. sweeper 의 30s schedule 사이에서도 사용자에게 일관된 view 를 주기 위해 read 시점에 transition. side-effect 가 있긴 하나 transition 은 monotonic (RUNNING→EXPIRED 한 방향) + idempotent (이미 EXPIRED 면 no-op) 이므로 GET semantics 는 유지된다.

**검증 (라이브 API)**
- `GET /sandbox/sessions` → 200, `total=3 / runningCount=3 / 모두 status="running"`. (이전 만료 세션 5건은 transition 후 다음 응답에서 제거됨.)
- `GET /sandbox/sessions?include_stopped=true&limit=5` → expired 5건 모두 노출 + cveId 미리 채워짐.
- `POST /sandbox/sessions/reap` → `{"reaped": 0}` (이미 모두 transition 됨).
- `tsc --noEmit` 통과.

**알려진 한계 / 다음 PR 으로 넘김**
- 패널이 패널 단위로 30s polling — 다중 사용자가 같은 세션을 동시에 정지시키는 race 는 백엔드의 idempotent stop_session 으로 흡수되지만 UI 가 잠시 stale 상태일 수 있음. WebSocket 푸시는 setting-page 가치 대비 over-engineering.
- 정지 동작은 단건만 — `Stop all` 일괄 버튼은 "운영자 실수로 모든 lab 끄기" 위험이 있어 의도적으로 안 깔았음. 필요 시 후속.
- 백엔드 source 가 image baked — 본 PR 은 `docker compose cp` 로 라이브 검증했고, full container 재생성 시점에는 `docker compose build backend && up -d backend` 한 번 필요 (그 외 dev container 는 mount 됨).

---

### PR 10-AA — In-app copy 보안 분석가 톤으로 전면 정리 ✅

**완료일:** 2026-05-08

> 사용자 보고: "내가 어디가서 설명하는게 아니라 서비스 이용자를 위한 설명이 핵심." 그동안 panel 안의 안내 문구 / 툴팁 / 배지 라벨 / 상태 메시지가 *개발자가 시스템 동작을 설명하는 톤* (lab, cooldown, GC, echo-trap, cve_lab_mappings, backend probe 같은 내부 어휘) 으로 굳어 있었음 — 보안 분석가/SOC 운영자가 화면을 처음 보고 *해야 할 일* 을 바로 이해하기 어려운 상태. 모든 사용자 노출 문자열을 *효익 + 다음 행동* 중심으로 재작성.

**`SandboxPanel.tsx` (가장 무거운 변경)**
- `PHASE_LABEL` 13종 — `call_llm` "LLM 호출 — Dockerfile + 앱 코드 + 주입 지점 + 페이로드 생성" → "AI가 격리된 실습 환경 명세와 공격 페이로드를 작성 중", `verifying` "페이로드 전송 + 응답 본문에서 success indicator 확인" → "공격 페이로드를 보내 실제로 취약점이 발현되는지 확인하는 중", `cached` "cve_lab_mappings 에 verified row 캐시" → "검증된 실습 환경을 저장 — 다음부터는 즉시 사용 가능합니다" 등.
- `SourceBadge` — `vulhub reproducer` / `일반 클래스 lab` / `AI 생성 lab` → `vulhub 공식 재현` / `표준 실습 환경` / `AI 합성 환경` + 각 출처별 신뢰도 한 줄 설명을 tooltip 으로 추가 (`tip` 필드 신설).
- `LabKindBadge` tooltip "generic lab class: ..." → "표준 실습 환경 분류: ...".
- 후보 선택 패널 — "합성 후보 목록 — 다른 후보로 시작" → "다른 합성 환경으로 시작하기", `placeholder/verified/degraded` → `준비중/검증됨/정확도 낮음`, "이 후보로 시작" → "이 환경으로 시작".
- 시작 안내문 — "CVE 분류에 맞는 격리된 실습 컨테이너를 띄우고…" → "이 CVE 를 안전하게 재현해 볼 수 있는 격리된 실습 환경을 띄웁니다. AI가 페이로드를 환경에 맞춰 자동 조정한 뒤 실행해 주므로 별도 세팅 없이 바로 결과를 확인할 수 있습니다."
- consent gate (`no_lab`) — "등록된 lab 이 없습니다" → "아직 준비된 실습 환경이 없습니다", "AI 합성으로 시도" → "AI에게 환경 합성 요청".
- consent gate (`lab_degraded`) — "사용자 평가로 격하된 lab 입니다" → "다른 사용자들이 부정확하다고 평가한 환경입니다", "새로 합성으로 시도" → "AI에게 새 환경 합성 요청".
- `SynthesisTimeline` — "AI 합성 진행 상황" → "AI 환경 합성 진행 상황", "연결 끊기" → "진행 화면 닫기", `cooldown` notice 제목 "합성 cooldown 중" → "잠시 합성이 보류되어 있습니다" + hint 도 사용자 톤. `verify_failed` hint "이미 빌드된 이미지가 캐시되어 있어 'verify 단계만 재개' 로 LLM 호출/빌드 없이…" → "환경 이미지는 이미 만들어져 있습니다. '검증만 다시 시도' 로 AI 호출/빌드 없이 몇 초 만에 재검증할 수 있습니다."
- `RunResult` — "캐시된 known-good 페이로드를 그대로 재생" → "이전에 검증된 페이로드를 그대로 재실행", 액션 버튼 "캐시된 페이로드 재생" / "AI 페이로드 적응 + 실행" / "재생성" → "검증된 페이로드 재실행" / "AI 페이로드 자동 조정 + 공격 실행" / "페이로드 새로 생성", 섹션 라벨 "AI 판정 / 전송된 페이로드 / 응답 본문" → "AI 판정 결과 / 실제로 보낸 페이로드 / 서버 응답 본문", `휴리스틱:` → `자동 분석 신호:`, `근거:` → `판단 근거:`, `다음 시도:` → `추천 다음 단계:`, `적응 근거:` → `AI 가 이 페이로드를 선택한 이유:`.
- `LabFeedbackButtons` — "이 lab 정확도" → "이 환경 정확도", tooltip "페이로드/주입 지점이 CVE 와 정확히 맞다" → "페이로드와 입력 지점이 이 CVE 와 정확히 일치합니다", "한 번 더 누르면 변경됩니다" → "다시 누르면 평가가 변경됩니다".
- `타깃 (내부 전용)` → "공격 대상 주소 (격리 네트워크 내부 전용)", `주입 지점 N개` → "공격 입력 지점 N개", `랩 컨테이너 시작 중…` → "실습 환경 준비 중…".

**`AiSettingsForm.tsx`**
- `claude_cli` provider note "별도 API 키 없이 본인 Claude Code 구독을 사용합니다. 백엔드 이미지에 claude CLI가 설치되어 있고 ~/.claude 가 마운트되어 있어야 합니다." → "별도의 API 키 없이 본인의 Claude Code 구독을 그대로 사용합니다. 설치 시 README 의 'Claude Code CLI' 섹션을 따라 한 번만 인증해 두면 자동으로 갱신됩니다."
- API key 안내 "서버 DB에 저장됩니다. 응답에는 다시 표시되지 않으므로 보관에 주의하세요." → "키는 안전하게 저장되며, 한번 등록 후에는 화면에 다시 표시되지 않으니 원본은 별도로 보관해 주세요."
- `remedyForKind()` 7종 errorKind 별 사용자 안내문 — `auth_expired/not_logged_in` 의 `launchd 가 매시간 자동 sync` 문구를 사용자 톤으로 다듬고 (정확한 명령은 유지), `config_missing` 의 `~/.claude.json 마운트가 stale inode 일 가능성` → "Claude 인증 파일이 백엔드와 연결되지 않았습니다. 백엔드 컨테이너를 한 번 재시작하면 해결됩니다.", `cli_missing` 의 `INSTALL_CLAUDE_CLI=1 로 backend 이미지를 rebuild` → "README 설치 가이드의 'AI 키 등록' 단계를 다시 진행해 주세요.", `empty_response` 의 `silent 실패` → "Claude 가 응답 없이 종료되었습니다. 자동 복구가 실패했다면 인증 토큰이 만료되었을 가능성이 큽니다." 등.

**`app/settings/page.tsx` 8 개 Section 제목·설명**
- "테마" → "화면 테마", "API 키" → "외부 데이터 소스 API 키" + 설명 "셀프 호스팅 시 외부 API의 레이트 리밋과 인증에 사용됩니다" → "NVD · GitHub Advisory 데이터를 더 빠르게 받아오기 위한 키입니다. 비워 두어도 동작하지만, 등록하면 수집 속도와 안정성이 좋아집니다."
- "AI 분석 설정" → "AI 분석 키", "내 자산" 설명 "등록한 벤더·제품은 파싱된 CVE의 CPE 정보와 매칭되어" → "운영 중인 벤더·제품을 등록하면 그에 영향을 주는 CVE 만 모아 대시보드 상단 '내 시스템 취약점' 카드에 표시됩니다."
- "합성된 lab 캐시" → "합성된 실습 환경 저장 공간", "CVE → lab 매핑 분포" → "실습 환경 출처별 분포". 설명도 동기화.
- "저장 위치" 섹션 — "서비스 정식 배포 단계에서는 백엔드 환경변수 NVD_API_KEY · GITHUB_TOKEN 으로 옮길 예정" 같은 개발 로드맵 멘션을 사용자에게는 의미 없으므로 "AI 분석 키와 등록한 자산은 서버에 안전하게 저장되어 모든 기기에서 공유됩니다." 로 대체.

**`SynthesizerCachePanel.tsx` / `LabKindStatsPanel.tsx`**
- 통계 라벨 "합계 디스크 사용량 / 이미지 개수" → "총 사용 용량 / 저장된 환경 수", "마지막으로 사용 안 된 시점" → "가장 오랫동안 사용되지 않은 시점".
- 액션 버튼 "지금 GC 실행" → "지금 즉시 정리", `GC 진행 중…` → `정리 중…`, `GC 완료 — N개 이미지 회수` → `정리 완료 — N개 환경 회수했습니다`, `reason=size/count/age/missing` raw 라벨 → `사유: 용량 한도 초과/개수 한도 초과/보관 기간 만료/이미지 누락` (`reasonLabel()` helper 신설).
- 빈 상태 "합성된 lab 이미지 없음. AI 합성을 한 번도 사용하지 않았거나 모두 회수됨." → "저장된 합성 환경이 없습니다…"
- 테이블 헤더 "이미지" → "환경 식별자", 상태 배지 `이미지 없음 / 사용 중 / 대기` → `이미지 누락 / 사용 중 / 대기 중`.
- LabKindStats footer "cve_lab_mappings 전체 N개 중 verified M개. 한 클래스로 쏠려있다면 합성 prompt 또는 classifier 룰 편향 신호" → "전체 N개 중 검증 완료 M개. 한쪽으로 크게 치우쳐 있다면 합성 품질을 점검할 신호일 수 있습니다.", 막대 그룹 제목 "provenance 별 (vulhub / generic / synthesized)" → "출처별 (vulhub 공식 / 표준 / AI 합성)".

**`MyAssetsPanel.tsx` / 대시보드 hero**
- "사용 중인 벤더 · 제품을 등록하면 CPE 매칭을 통해 관련 CVE만 별도로 모아볼 수 있습니다" → "운영 중인 벤더·제품을 등록해 두면 그 자산에 영향을 주는 CVE 만 따로 모아 보여드립니다. 매일 새로 들어오는 취약점도 자동 반영됩니다."
- 진행 메시지 "매칭 중…" → "자산과 일치하는 CVE 를 찾는 중…", 에러 "매칭 API 호출에 실패했습니다" → "자산 매칭에 실패했습니다. 잠시 후 다시 시도해 주세요."
- 대시보드 hero "NVD · Exploit-DB · GitHub Advisory를 한 화면에서. 실시간 CVE 및 제로데이 모니터링." → "NVD · Exploit-DB · GitHub Advisory 를 한 곳에서. 매일 들어오는 CVE 와 제로데이를 한 화면에서 모니터링하세요."

**`ApiKeyField.tsx` + `lib/user-settings.ts` SETTING_META**
- "아직 저장된 값이 없습니다" → "아직 등록된 키가 없습니다 — 비워 두어도 정상 동작합니다."
- 저장 버튼 "저장 + 새로고침" → "저장하고 즉시 재수집", saved/error 메시지도 다듬음.
- NVD/GitHub key help 문구 — 기능 설명 ("rate-limit 5→50 회") 만 적혀 있던 것을 "비워 두어도 동작합니다" 같은 사용자 가이드 추가.

**검증**
- `tsc --noEmit` 통과 (모든 9 파일).
- 라벨/툴팁만 변경 — 데이터 흐름·이벤트 핸들러·타입 어떤 것도 손대지 않아 회귀 위험 0.

**왜 한 번에 묶었는가**
- "사용자 톤" 은 *전체적인 일관성* 이 핵심이라 panel 단위로 쪼개 PR 을 내면 한 화면 안에서 톤이 섞이는 시기가 길어진다. 한 번에 commit 해 톤 분기를 없앰. 각 파일 변경은 라벨·문자열로 한정해 diff 가 커도 로직 review 부담은 작음.

**알려진 한계 / 다음 PR 으로 넘김**
- README, PROGRESS, 설치 가이드 등 *문서* 는 개발자/운영자 톤이 더 자연스러우므로 그대로 둠 — 사용자 톤은 in-app surface 한정.
- 백엔드 에러 message 본문은 일부 "JSON 파싱 실패" 같은 기술 메시지가 그대로 노출 — 백엔드 i18n/메시지 정리는 별도 PR.
- 일부 표 헤더 (`CVE`, `MB`) 는 의도적으로 영문 단위 유지 — 보안 분석가에게도 이 단위들은 1차 어휘.

---

### PR 10-AB — 기간 필터 인라인 이동 + AI 분석 안내 문구 사용자 톤 ✅

**완료일:** 2026-05-08

> 사용자 보고: "기간 수정도 총 xx건 옆에 현재 날짜 보여주는 곳에서 바로 적용 가능하도록 이동 조치. 입력은 사용자가 편리하게 할 수 있도록 할것." 사이드바 FilterPanel 의 "기간" FilterGroup 으로 가야만 기간을 바꿀 수 있던 두-단계 흐름을 → 결과 헤더의 코퍼스 범위 배지 자체가 클릭형 popover 가 되도록 한-단계로 줄였다. 같이 묶어 AiAnalysisPanel 의 안내 문구도 LLM 내부 동작 설명에서 "보안 운영팀 사용 가능" 사용자 톤으로 정리.

**`frontend/components/dashboard/DateRangeControl.tsx` — 신규**
- 비활성 상태에서는 기존 `CorpusRange` 와 동일한 `데이터 YYYY.MM.DD ~ YYYY.MM.DD` 배지 (corpus 전체 publishedAt 범위, `/search/facets` 60s TTL 캐시 활용) — 사용자 선호: 정보 손실 없이 클릭 가능 surface 만 추가.
- 활성 상태에서는 호박색 강조 + `기간 YYYY.MM.DD ~ YYYY.MM.DD` 라벨 + ✕ 1-click 해제 (popover 안 열고도 즉시 reset).
- 클릭 시 popover: 5 개 프리셋 (오늘 / 7일 / 30일 / 90일 / 1년) + `시작 / 종료` date input 두 개 + 코퍼스 범위 hint + 초기화/완료 푸터. **프리셋과 직접 입력이 동일 화면에서 동시 노출** — 기존엔 "직접 입력" 칩을 추가로 클릭해야 input 이 나타났다 (사용자 보고의 "편리한 입력" 핵심).
- date input 의 `min`/`max` 가 corpus 범위 + 반대편 endpoint 로 자동 클램프 — "시작 > 종료" / "코퍼스 밖 날짜" 같은 잘못된 범위를 input level 에서 봉쇄.
- 외부 클릭 + Esc 자동 닫힘 (`mousedown` + `keydown` window listener, `wrapperRef.contains` 가드).

**`frontend/app/page.tsx` 인라인 배치**
- 결과 헤더(`총 X건`)를 `flex flex-wrap items-center gap-x-2` 로 바꾸고 `<DateRangeControl />` 을 두 번째 자식으로 배치. 기존 `CorpusRange()` 로컬 컴포넌트 + `useQuery import` 일부 제거.
- onChange 가 `url.set({ filters: {...url.filters, fromDate, toDate}, page: 1 })` 로 라우팅 — URL state / useCveSearch / pagination 모두 무수정. 단일 source-of-truth 유지.

**`frontend/components/search/FilterPanel.tsx` 정리**
- "기간" FilterGroup, `DateInput` 헬퍼, `PresetKey`/`DATE_PRESETS`/`presetForDates`/`todayIso`/`isoDaysAgo`/`customMode` 상태 모두 삭제 (138 → 약 75 라인 감소). FilterState 의 `fromDate`/`toDate` 키는 URL 직렬화·backend 쿼리 hook 이 의존하므로 그대로 유지.
- `useState` import 도 남는 사용처가 없어 제거. `tsc --noEmit` 통과.

**AiAnalysisPanel 안내 문구 (사용자 톤)**
- 전: "LLM을 활용해 공격 기법·페이로드 예시·대응 방안을 생성합니다. 설정 페이지에서 등록한 제공자·모델·API 키가 사용됩니다."
- 후: "이 CVE 의 공격 시나리오, 재현 가능한 PoC 페이로드, 그리고 즉시 적용 가능한 차단 패치 항목을 한 번에 받아봅니다. 분석 결과는 보안 운영팀이 그대로 점검·티켓팅에 사용할 수 있는 형태로 정리됩니다."
- 사용자 메모리: "내가 어디가서 설명하는게 아니라 서비스 이용자를 위한 설명이 핵심" — 기능 *동작* 설명에서 *사용자 효익* 설명으로 전환.

**왜 사이드바에서 완전히 빼는가 (duplicate 가 아니라 move)**
- 기간은 결과 *볼륨* 과 가장 직접적으로 결합된 필터다 — "총 X건" 옆에 두면 "지금 보고 있는 X건이 어떤 기간 슬라이스인지" 한 줄에서 읽힌다. 사이드바 분리 시 사용자가 두 곳을 동기화해 봐야 했고, 사이드바를 *하나 더* 두면 어느 쪽이 truth 인지 헷갈린다. URL state 단일 source 원칙 유지.
- severity / OS / vuln-type / 도메인은 chip group 의 *공간 배치* 가 의미를 전달 (한눈에 토글) — 사이드바 잔존이 자연스럽다. 기간만 떼는 게 정합.

**알려진 한계**
- popover 가 절대 위치(`absolute left-0 top-[calc(100%+6px)]`) 라 좁은 뷰포트에서 우측 잘림 가능 — 결과 헤더 폭이 충분히 넓고 popover 자체가 300px 이라 현재 `max-w-7xl` 레이아웃에서는 안전. mobile 대응이 필요하면 추후 viewport-aware 반전 로직 추가.

---

### PR 9-P — generic lab × backend probe 라이브 통합 검증 + sqli probe 모던 CPU 보정 ✅

**완료일:** 2026-05-04

> PR 9-O 가 catalog/classifier 까지만 unit 검증 (smoke_lab_catalog.py 13/13). 실제로 컨테이너가 띄워지고 backend probe 가 라이브로 동작하는지는 미확인. End-to-end smoke 추가 + 발견된 sqli timing 한계 같이 수정.

**`backend/scripts/integration_generic_labs.py` — 신규 라이브 통합 smoke**
- 6 lab kinds 각각:
  1. `docker.from_env()` 로 lab 이미지를 `kestrel_sandbox_net` 위에 spawn (256MB / 0.5 CPU / cap_drop=ALL — 실제 sandbox 정책과 동일)
  2. `/healthz` polling 으로 listen 확인
  3. catalog 의 첫 번째 InjectionPoint 추출 → matching probe 인스턴스
  4. `probe.run(handle, ip)` — passed=True 기대
  5. cleanup (kill + remove)
- 기대 probe 매핑: xss → xss_reflect_nonce, rce → rce_canary_read, sqli → sqli_time_blind, ssti → ssti_arithmetic, path → path_traversal_canary, ssrf → ssrf_inbound_canary.

**SQLi probe 모던 CPU 보정 (`synthesizer_probes.py`)**
- 기존 마지막 fallback `randomblob(sleep_seconds * 1e8)` (200MB for 2s) 가 M-series CPU 에서 0.3s 만 걸려 threshold(`baseline + 1.4s`) 미달. 1GB(`* 5e8`) 로 키우면 lab 이 OOM disconnect.
- 해결: SQLite 전용 마지막 페이로드를 recursive CTE 로 교체 — `WITH RECURSIVE c(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM c LIMIT N) SELECT count(*) FROM c`. row 수 = `sleep_seconds * 10_000_000` (sleep=2 → 20M rows). 측정: 2M=0.30s, 5M=0.55s, 10M=1.07s, 20M=2.16s — 선형 + 메모리 압력 없음. 모든 architecture 에서 일관.
- 페이로드 8 → 7 종 (200MB random 유지 + 새 CTE 추가, 1GB 변형 제거).

**검증 결과**
- Live 통합: 6/6 PASS — sqli 가 4.49s delay 로 통과 (이전 0.3s).
- PR 9-L 회귀: 11/11 PASS (real-RCE / echo-machine / XXE / open-redirect / hardcoded-redirect-reject / deserialization / inert-deser-reject 등).
- PR 9-N 회귀: 4/4 PASS (SSRF 4 시나리오).

**알려진 한계 / 다음 PR 으로 넘김**
- integration smoke 는 manual (`python /app/integration_generic_labs.py`) — CI/cron 으로 묶을지는 출판 빈도 보고 결정. 6 lab 모두 spawn → probe → cleanup 까지 ~30s 라 매 PR 에 넣어도 무리 없음.
- sqli CTE row count 가 hard-coded `sleep_seconds * 10M` — 매우 느린 ARM/QEMU 환경에서 over-burn 가능. 향후 baseline 측정 후 dynamic sizing 으로 개선 여지.

---

### PR 9-O — generic lab 카탈로그 6 클래스 확장 (XSS-only → RCE / SQLi / SSTI / path-traversal / SSRF 추가) ✅

**완료일:** 2026-05-03

> 사용자 보고: "샌드박스 생성 누르면 lab 이 항상 xss 로 네이밍되고 step 도 저수준". 원인 — `LAB_CATALOG` / `classifier` / `sandbox-labs/` 모두 XSS 단일 항목. resolver 가 vulhub 매핑 없고 합성도 안 되면 폴백 generic lab 을 고르는데, classifier 매핑도 사실상 XSS 로만 가는 구조. PR 9-N 에서 합성 prompt 편향은 풀었지만 *합성 자체가 안 되는 / 시도하지 않는* 케이스는 여전히 XSS 로 수렴.

**`sandbox-labs/` 신규 5 개 generic lab (`python:3.12-slim + flask + gunicorn` 공유 베이스)**
- `rce-flask` — `/ping?host=` + `/lookup?domain=` (subprocess shell=True 합성, RceCanaryProbe 로 `; printf %s VALUE > PATH` 류 카나리 검증).
- `sqli-flask` — `/users?id=` + `/search?name=` (sqlite, raw concat — boolean-blind / UNION / `randomblob()` time-blind 모두 도달 가능, SqliTimeBlindProbe 의 6종 페이로드 중 sqlite 변형이 통과).
- `ssti-flask` — `/greet?name=` + `/render?tpl=` (`render_template_string` 직접 평가, `{{7*7}}` → 49 SstiArithmeticProbe 매칭).
- `path-flask` — `/file?name=` + `/view?p=` (`os.path.join` 정규화 X, `Dockerfile` 빌드 시 `/var/secret/flag.txt` 카나리 사전 배치).
- `ssrf-flask` — `/fetch?url=` + `/preview?target=` (`requests.get` 직접 호출, SsrfCanaryProbe 의 inbound 캐너리 매칭).

**`sandbox-labs/build_all.sh` — 6 이미지 일괄 빌드**
- 매니페스트 배열 (kind|context dir) 으로 6 이미지 (`xss/rce/sqli/ssti/path/ssrf`) 빌드. 공유 base layer 라 첫 빌드 ~3-5 분 / 재빌드 <30s. 결과 listing 자동 출력.

**`backend/app/services/sandbox/catalog.py` — 5 신규 LabDefinition**
- 각 kind 마다 2개씩 InjectionPoint 정의 (총 12 신규 + 기존 3 XSS = 15). `response_kind` 는 backend probe 매칭되는 alias (command-exec / sqli / ssti / path-traversal / ssrf), `notes` 에 어떤 syntax 가 트리거되는지 한 줄 설명.

**`backend/app/services/sandbox/classifier.py` — CWE + 키워드 매핑 확장**
- `_CWE_TO_KIND` — 기존 4 (CWE-79/80/83/87 → xss) 에 13 추가:
  - CWE-77/78/94 → rce, CWE-89/564 → sqli, CWE-1336/95 → ssti,
  - CWE-22/23/36/73 → path-traversal, CWE-918 → ssrf.
- `_KEYWORDS` — 6 클래스 모두 한국어/영어 정규화 키워드 5-7개씩. dict 순서가 우선순위 — `rce > sqli > ssti > path-traversal > ssrf > xss` 로 *더 specific 한* 클래스가 먼저 매칭 (XSS 가 더 이상 default 가 아님).

**검증 (`backend/scripts/smoke_lab_catalog.py` — 신규 3 블록)**
- A. catalog 가 6 kinds 모두 커버: PASS.
- B. classifier 12 케이스 (6 CWE + 6 키워드) — 모두 expected kind 반환. "OS command injection in foo" → rce, "directory traversal" → path-traversal, "blind SSRF" → ssrf 등.
- C. 13 InjectionPoint 모두 response_kind 가 backend probe 레지스트리에 있음 (fallback llm_indicator_only 모드로 빠지지 않음): PASS.
- 결과: `OK — lab catalog smoke green`.

**알려진 한계 / 다음 PR 으로 넘김**
- XXE / open-redirect / deserialization 클래스 generic lab 은 추가 안 함 — backend probe 는 있으나 generic lab 은 합성 vs vulhub 비율이 충분히 높아 미충족 수요가 작음. 필요 시 추후 같은 패턴으로 추가.
- classifier 가 *키워드 우선순위* 만 보고 정확히 한 kind 만 선택 — 한 CVE 가 RCE+SSTI 같이 두 클래스에 걸치면 첫 매치 (rce) 만 사용. multi-kind labelling 은 도메인 분류 (PR 10-B) 와 합쳐 향후 검토.

---

### PR 9-N — backend SSRF probe + 합성 클래스 편향 해소 (모든 lab 이 XSS 로 수렴하던 문제) ✅

**완료일:** 2026-05-03

> 두 가지 동시 출하: (1) PR 9-L/9-M 에서 빠져 있던 SSRF 클래스에 대해 backend probe 추가, (2) 사용자 보고 "모든 lab 이 XSS 만 나옴" — synthesizer prompt 가 XSS 로 강하게 anchor 돼 있었고 fallback 기본값까지 `html-reflect` 였음. NVD/Exploit-DB 에서 수집된 어떤 CVE 라도 그 *원본 클래스* 그대로 재현하도록 prompt 와 정규화 양쪽을 분리 수정.

**`synthesizer_probes.py` — SsrfCanaryProbe**
- aliases: `ssrf / server-side-request-forgery / url-fetch / remote-fetch / url-include / outbound-fetch`.
- 동작: `_ssrf_canary` async context manager 가 `python:3.12-alpine` + 인라인 stdlib HTTP server 를 `kestrel_sandbox_net` 위에 띄움 (호스트 포트 노출 X — 다른 lab 들과 동일한 격리 토폴로지). 모든 GET 을 `/tmp/hits.log` 에 append. lab 에 `http://<canary-name>/<positive_token>` 을 보낸 뒤 `exec_in_lab` 으로 로그를 읽어 토큰 일치 확인. 캐너리는 spec 직후 `--rm` 으로 정리.
- 음성 대조: 위와 동시에 `http://nonexistent-<negative_token>.invalid/<negative_token>` 도 송신 — 캐너리 로그에 *어느 토큰이든* 보이면 lab 이 입력 URL 무시하고 항상 캐너리를 호출하는 패턴이라 reject. 진짜 SSRF 는 양성 URL 만 hit 가 남는다.
- 캐너리 cap: 64 MB / 0.25 CPU / 64 PIDs / cap_drop=ALL / no-new-privileges / tmpfs(4 MB) — lab 들과 동일한 sandbox 정책.

**Synthesizer prompt 클래스 편향 해소 (`synthesizer.py`)**
- `_USER_TEMPLATE` 의 schema 예시에서 `"html-reflect" | "json-reflect" | "command-exec" | ..."` 같이 XSS 가 첫 두 자리에 박혀 있던 enumeration 을 빼고, **9 클래스 가이드 블록** 으로 교체 — command-exec / path-traversal / ssti / html-reflect / sqli / xxe / open-redirect / deserialization / ssrf 각각의 *어떤 동작* + *어떤 indicator 모양* 인지 한 줄씩. **"가장 흔한 실수: 모든 CVE 를 html-reflect (XSS) 로 만드는 것. 원본 CVE 가 RCE / SQLi / SSRF / path-traversal 이라면 그 클래스 그대로 재현하세요"** 명시.
- "매우 중요한 규칙 #1" 의 예시도 XSS 한 종류에서 4 종 (command-exec, path-traversal, ssti, html-reflect) 으로 확장. side-channel 또는 결정적 출력 (예: SSTI 의 `49`, path-traversal 의 `root:x:`) 도 valid indicator 로 인정.
- `_to_injection_point()` 에서 `response_kind` 의 `html-reflect` 폴백 제거 — `_validate_parsed` 가 이미 비어있으면 reject 하므로 폴백은 *실수로 모든 미선언 lab 이 XSS 가 되는* 두 번째 편향 원인이었음.

**검증 (`backend/scripts/smoke_pr9n.py` — 신규 4 블록)**
- A. `select_probes` dispatch — 6 SSRF aliases 가 모두 `ssrf_inbound_canary` 로 라우팅.
- B. real-SSRF fake lab (URL fetch 시뮬) → 양성 토큰이 캐너리 로그에 등장 → probe pass.
- C. echo-trap lab (payload 본문에 echo 만, fetch 안 함) → "토큰이 없음" rationale 로 reject.
- D. always-pings-canary 패혹로지 lab → 음성 토큰까지 캐너리 로그에 등장 → "음성 대조" rationale 로 reject.
- 결과: `OK — PR 9-N smoke green`. PR 9-L 회귀도 동시 green (echo-machine reject + open-redirect nonce + deserialization canary 모두 PASS 유지).

**알려진 한계 / 다음 PR 으로 넘김**
- auth-bypass 는 backend-stamped canary 가 어렵다 (보호된 응답 본문에 backend 토큰을 심을 방법 없음). status-differential 식 약식 probe 는 false-positive/negative 위험으로 PR 9-N 에서 제외, 별도 설계로 분리.
- best-of-N (PR 9-O 가 될 가능성) 은 probe 9 종으로 truth signal 이 충분히 두꺼워진 다음에 후보 점수화/선택을 깐다 — 사용자 메모리 정합 ("verification 강화 > feedback-loop 기능") 유지.
- prompt 변경의 효과는 라이브 합성 데이터로만 측정 가능 — 다음 합성 N 회 후 `cve_lab_mappings.lab_kind` 분포로 검증 예정.

---

### PR 9-M — backend probe 클래스 확장 (XXE / open-redirect / deserialization) ✅

> PR 9-L 이 RCE / path-traversal / SSTI / XSS / time-based SQLi 5 종에 대해 backend ground-truth 검증을 깔았지만, 그 외 클래스(XXE, SSRF, deserialization, auth bypass, IDOR, open-redirect 등) 는 여전히 `llm_indicator_only` 약식 fallback 으로만 통과했다. 사용자 메모리 지시 — "verification 강화(음성 대조, side-channel 카나리, behavior-class probe, indicator strength gate) 가 feedback-loop 기능(다중 후보, best-of-N 등) 보다 우선" — 에 따라 best-of-N(PR 9-N) 보다 probe 클래스 확장을 먼저 출하. 한 번에 3 클래스(XXE / open-redirect / deserialization) 를 추가해 약식 fallback 에 머물던 vuln class 를 줄였다.

**`synthesizer_probes.py` 신규 probe 3종**
- `XxeCanaryProbe` (xxe / xml-external-entity / xml_external_entity / xml-injection) — `exec_in_lab` 으로 `/tmp/kestrel_canary_<랜덤>` 에 카나리 stamp 후 3가지 XML 셰이프(인라인 SYSTEM entity, parameter entity 우회, DOCTYPE-only 헤더 누락) 로 `file://` 외부 엔티티 인용 시도. 음성 대조 = entity 가 없는 benign XML — 같은 카나리가 그래도 보이면 echo trap 으로 거부. requires_exec=True (lab 안에 카나리 stamp 필수).
- `OpenRedirectProbe` (open-redirect / open_redirect / redirect-to / url-redirect / openredirect) — backend 가 만든 nonce(`https://kestrel-redirect-<rand>.example/`) 를 redirect 파라미터로 보내고 응답이 `301/302/303/307/308` 이면서 `Location` 헤더에 그 nonce 가 그대로 들어가는지 확인. `httpx.AsyncClient(follow_redirects=False)` 직접 호출로 Location 을 보존. 음성 대조 = benign 상대 경로 — 그래도 nonce 가 Location 에 보이면 입력과 무관한 하드코딩 redirect 이므로 거부 (3xx 자체는 약하므로 nonce 일치를 truth signal 로).
- `DeserializationCanaryProbe` (deserialization / deser / insecure-deserialization / unsafe-deser / pickle / object-injection) — Python pickle `__reduce__` 가젯이 `os.system("printf %s <카나리값> > <카나리경로>")` 를 호출하도록 만든 `_PickleCanary` 를 base64 인코딩해 보냄. pre-flight 으로 `test ! -e <경로>` 확인, 음성 대조 = benign nonce 보낸 뒤 카나리 파일 부재 재확인, 양성 = base64 가젯 보내고 0.2 s 대기 후 `cat <경로>` 가 카나리 값을 반환하는지 확인. 가젯 실행이 lab 안의 파일 시스템 부수 효과로 표출되므로 HTTP 응답 셰이프와 무관하게 deserialization 의 코드 실행을 직접 검증. requires_exec=True.
- 셋 다 `_PROBE_CLASSES` 에 등록 → `select_probes(response_kind)` 가 자동 디스패치 + `known_kinds()` 가 LLM 프롬프트에 새 alias 들을 노출.

**검증 (`backend/scripts/smoke_pr9l.py` — PR 9-M 시나리오 추가)**
- 섹션 B (alias dispatch) 에 6 개 alias 추가 (xxe, xml-external-entity, open-redirect, url-redirect, deserialization, pickle) — 모두 통과.
- 섹션 C (fake-lab probe 실행 + verdict 종합) 에 5 개 시나리오 추가:
  - **real-XXE** — XML 페이로드의 `SYSTEM "file://<경로>"` 를 파싱해 stamp 된 카나리 값을 응답에 인라인하는 가짜 lab → `method=backend_probe` 통과.
  - **real-open-redirect** — `Location: <payload>` 그대로 302 응답하는 lab → `method=backend_probe` 통과.
  - **hardcoded-redirect (rejected)** — 항상 같은 URL 로 302, payload 무관 → `method=rejected` (Location 에 backend nonce 부재).
  - **real-deserialization** — base64 디코드 + pickle.loads 호출하는 가짜 lab. `os.system` 을 (그리고 pickle 이 실제로 resolve 하는 `posix.system` underlying module 도) 패치해 가젯의 `printf %s ... > ...` 명령을 캡처, 그 명령을 in-memory exec mock 의 stamp 채널로 적용 → `method=backend_probe` 통과.
  - **inert-deserialization (rejected)** — 페이로드는 받아 길이만 echo, 실제 pickle.loads 호출 없음 → 카나리 파일 부재 → `method=rejected`.
- 결과: 9/9 시나리오 통과 (`OK — PR 9-L smoke green`). PR 9-K smoke 회귀도 동시 green (`ALL SMOKE PASSED`).

**왜 deserialization 의 truth signal 이 stdout 이 아니라 file 카나리인가**
- pickle 가젯이 `os.system` 을 부르면 stdout 은 lab 컨테이너의 표준출력으로 빠지고 HTTP 응답 본문에는 나타나지 않는다. response 본문에 카나리를 박는 형태(`echo`, ``"$(...)`"` 등)도 만들 수 있지만 그건 사실상 RCE probe 와 같은 셰이프 — deserialization 고유의 신호가 아니다. 파일에 stamp 한 뒤 `docker exec` 로 read 하면 (1) HTTP 표면을 거치지 않으므로 LLM 이 lab 코드로 위조 불가, (2) pickle.loads 가 실제로 호출되었는지(=insecure deserialization 이 실제로 일어났는지) 의 ground-truth 가 file 의 존재로 환원된다.

**왜 XXE 도 file:// 만 쓰고 OOB 채널은 안 썼는가**
- 외부 인터넷 차단(`internal: true` bridge) 상태에서는 OOB DNS/HTTP 으로 카나리 exfil 이 동작하지 않는다. 거꾸로 그 격리가 lab 의 안전 보장이기도 하다 — XXE probe 는 이 격리를 깨지 않고 file:// 만으로 ground-truth 를 만들도록 설계.

**알려진 한계 / 다음 PR 으로 넘김**
- 여전히 fallback 경로(`llm_indicator_only`) 로만 통과되는 클래스: SSRF (외부 인터넷 차단으로 OOB callback 어려움 — 사이드카 callback 서버 구상 필요), auth-bypass (CVE 별로 인증 모델이 너무 다양해 일반 probe 가 어려움), IDOR (자원 모델 의존), JNDI/log4shell (별도 LDAP 사이드카 필요).
- best-of-N (PR 9-N) 으로 분리 — probe 7 종으로 truth signal 이 충분히 다각화된 다음에 후보 점수화/선택을 깐다.

---

### PR 9-L — 백엔드 ground-truth 검증 (echo machine 거부) ✅

> PR 9-K 가 자기개선 루프를 만들었지만 검증은 여전히 LLM 폐쇄 루프였다 — payload, success_indicator, 응답 처리 모두 LLM 이 만들고 LLM 이 짠 lab 이 그대로 echo 만 해도 통과. 사용자 👍/👎 는 lagging 신호이고, 그걸 검증의 주된 truth signal 로 삼을 수는 없다("진짜 CVE 구현이 핵심임 user feedback 좋아요 누르는걸로는 대체가 안됨"). PR 9-L 은 검증 자체를 backend 가 만들어낸 probe + canary 로 대체한다 — LLM 이 어떤 verification 보조 자료(예: negative control)를 제공해도 일절 신뢰하지 않는다("거짓으로 된걸로 치는건 의미가 없음").

**새 모듈 `backend/app/services/sandbox/synthesizer_probes.py`**
- `BackendProbe` 베이스 + 5 종 구현, 모든 페이로드/카나리/예상 substring/음성 대조를 백엔드가 직접 만든다 (LLM 입력 0). 각 probe 는 양성 시도 + benign nonce 음성 대조로 echo 트랩을 자체 거부.
- `RceCanaryProbe` (rce/command-exec/...) — `exec_in_lab` 으로 `/tmp/kestrel_canary_<랜덤>` 에 `KESTREL_RCE_OK_<랜덤>` 을 stamp 한 뒤 7가지 shell injection 셰이프(`; cat`, `|cat`, `&&`, ``` ` ``` , `$()`, newline, raw) 로 카나리 읽기 시도. 응답에 카나리 값이 보이면 양성, 같은 nonce 길이의 benign 입력에서도 보이면 echo 트랩으로 거부.
- `PathTraversalCanaryProbe` (path-traversal/lfi/file-read/...) — 동일 카나리, 6가지 traversal 셰이프(절대경로, `../*8`, `..%2f` 인코딩, `....//`, `file://`). 음성 대조 = 존재하지 않는 경로.
- `SstiArithmeticProbe` (ssti/template-injection) — 8개 엔진 별 산술식(jinja2/twig `{{7*191}}`→`1337`, freemarker `${...}`, erb `<%= ... %>`, smarty `{...}`, velocity `#set`, razor `@(...)`, 등). 실제 SSTI 는 평가 결과가 응답에 등장하면서 원식 자체는 등장하지 않음 — 둘 다 등장하면 단순 reflect 이므로 거부.
- `XssReflectProbe` (xss/html-reflect/json-reflect/stored-xss) — 두 개의 backend nonce(`KXSS_<rand>`) 를 각각 보내 자기 응답에만 reflect 되는지 확인. 두 번째 응답에 첫 nonce 가 보이면 입력과 무관한 하드코딩 영역이 있다고 판정해 거부.
- `SqliTimeBlindProbe` (sqli/sql-injection/blind-sqli) — 3 회 baseline 측정 후 6 종 sleep 페이로드(PG `pg_sleep`, MySQL `SLEEP`, MSSQL `WAITFOR`, SQLite `randomblob`) 시도. baseline + sleep×0.7 이상이면 양성. 양성 직후 다시 baseline 을 재서 일시적 전체 슬로우다운을 배제(post-baseline rule).
- `select_probes(response_kind)` / `known_kinds()` / `build_verdict(...)` 디스패치. verdict 정책: 적용된 probe 가 하나라도 통과 → `method=backend_probe`, 모두 실패 → `rejected` (legacy LLM 검증이 통과해도 구제하지 않음 — PR 9-L 의 핵심 의도). probe 가 0 개 적용 → 모르는 response_kind, legacy 결과로 fallback `method=llm_indicator_only` (warning 로그). 모르면 약식이라는 사실을 mapping 에 명시.

**`manager.exec_in_lab` (`backend/app/services/sandbox/manager.py`)**
- `docker exec` 헬퍼. probe 가 lab 컨테이너 안에 카나리를 stamp 하기 위한 채널. HTTP 표면(LLM 이 lab 코드를 통해 영향을 줄 수 있는 면)을 우회한다 — 카나리는 docker daemon 을 거쳐서만 들어가고, LLM 은 docker socket 에 접근할 수 없으므로 위조가 불가능.
- stdout+stderr 합쳐 `(exit_code, bytes)` 반환. `asyncio.wait_for` + `to_thread` 로 docker SDK 의 동기 호출을 안전하게 wrap.

**`synthesize()` 검증 경로 재작성 (`synthesizer.py`)**
- `_verify(spec, parsed)` 가 `(VerificationVerdict, exchange)` 를 반환하도록 시그니처 변경. lab 한 번 spawn → wait_ready → legacy LLM-payload 한 번 (UI 표시 + fallback 용으로만) → 적용 가능한 모든 probe 순차 실행 → `build_verdict` 로 종합 → 단일 `stop_lab` 으로 reap.
- probe 결과를 `spec_dict["verification"]` 에 `{method, passed, rejection_reason, probes:[{name, kind, passed, rationale, evidence}]}` 형태로 직렬화해 매핑 row 의 spec JSONB 에 영구 저장. PR 9-K 의 `_prior_attempts_block` 가 다음 시도 프롬프트에 그대로 surface — LLM 은 "지난 시도에서 어떤 probe 가 왜 reject 했는지" 를 정확히 보고 다른 접근을 잡는다.
- 약식 검증 통과(`llm_indicator_only`) 일 때는 digest 에 ⚠️ 마커를 붙여 매핑 카드에서 신뢰도 차이를 시각적으로 구분.
- progress 콜백 (`verify_failed`/`verify_ok`) payload 에 `method` + `probes[]` (name/passed/rationale) 추가. UI 가 어떤 probe 가 왜 reject 됐는지 한눈에 보일 수 있게.

**`_validate_parsed` 강화 — echo trap 을 빌드 전에 차단 (`synthesizer.py`)**
- `success_indicator` < 8 자 → 우연 일치 가능성으로 거부.
- `success_indicator == payload_example` → 닫힌 echo 루프이므로 거부.
- `success_indicator` 가 `files[*].content` 안에 그대로 박혀 있음 → lab 이 페이로드와 무관하게 indicator 를 노출하는 echo trap 으로 거부 (가장 흔한 실패 모드).
- `injection_point.response_kind` 가 비어 있음 → backend probe 디스패치 불가, 거부. 프롬프트에도 권장 enum 을 `known_kinds()` 로 동적으로 주입.

**프롬프트 변경 (`_USER_TEMPLATE`)**
- `{known_kinds}` 슬롯으로 backend probe 가 매칭되는 모든 alias 를 나열 — LLM 이 자유 문자열 대신 매칭되는 kind 를 고르도록 유도.
- "echo machine 형태(입력만 그대로 echo)는 backend probe 가 reject" 규칙을 명시. success_indicator 가 files 본문에 들어가면 echo trap 으로 거부된다는 규칙도 추가.

**검증 (`backend/scripts/smoke_pr9l.py`)**
- pure-python smoke. `proxy_request`/`exec_in_lab` 을 monkey-patch 해 docker 없이 probe 라이브러리 동작을 검증.
- (A) `_validate_parsed` 가 깨끗한 shape 는 통과시키고 4 가지 echo-trap 셰이프(짧은 indicator / indicator==payload / indicator-in-files / 누락 response_kind) 를 모두 거부.
- (B) `select_probes` 가 12 개 response_kind alias 를 정확한 probe 로 디스패치, 모르는 kind 는 0 개 매칭.
- (C) 가짜 lab 시나리오 3종:
  - 진짜 RCE 흉내(payload 가 카나리 경로를 포함하면 카나리 값을 응답) → `method=backend_probe`, 통과.
  - echo machine(항상 입력 그대로 응답) → `method=rejected`, 거부.
  - 모르는 response_kind + legacy 통과 → `method=llm_indicator_only` fallback.
- 결과: `OK — PR 9-L smoke green`. PR 9-K smoke 도 동시 회귀 — 세 시나리오 그대로 통과.

**왜 LLM 이 만든 verification 자료는 일절 신뢰하지 않는가**
- 사용자 명시 지적: "거짓으로 된걸로 치는건 의미가 없음". LLM 은 echo machine 에 대해서도 자기-일관된 (positive payload, negative control, behavior probe) 트리플을 통째로 만들 수 있다. 따라서 negative control 페이로드, behavior probe template, expected substring 모두 backend 가 직접 만들고, 카나리는 docker exec 채널로만 stamp 한다. 이렇게 해야 lab 의 HTTP 응답 단 하나에서 카나리 값이 등장하는 사건이 실제 익스플로잇이라는 보장이 생긴다.

**알려진 한계 / 다음 PR 으로 넘김**
- probe 가 커버하는 vuln class 는 5 개(rce/path-traversal/ssti/xss/sqli) — XXE, SSRF, deserialization, auth bypass, IDOR 등은 아직 fallback (`llm_indicator_only`) 경로로만 통과한다. 새 클래스 추가는 `BackendProbe` 서브클래스 한 개 + `_PROBE_CLASSES` 등록 한 줄.
- 다중 후보 보존(best-of-N)은 PR 9-M 으로 분리 — backend probe 통과한 후보 중 가장 신호가 강한 것을 우선 매핑하는 정책은 검증이 신뢰할 만해진 지금에서야 의미가 있다.

---

### PR 9-K — 합성 self-refinement 루프 + 격하된 lab 재합성 ✅

> PR 9-J 가 격하 신호를 만들었지만, "새로 합성으로 시도" 버튼이 사실상 동작하지 않았다 — 동의 후 재호출이 `cached_hit` 으로 같은 격하된 lab 을 그대로 돌려주거나, LLM 이 같은 베이스/주입 지점/페이로드를 또 만들어 똑같이 격하될 수밖에 없었다. PR 9-K 는 (1) 격하 시 cached_hit 우회, (2) 이전 시도(베이스·IP·페이로드·👎 노트)를 다음 LLM 프롬프트에 자연어 블록으로 주입, (3) 재합성 성공 시 평가 카운터/feedback 행 리셋, (4) GC `image_missing` 경로를 삭제 → demote 로 변경해 학습 컨텍스트 보존.

**`synthesize()` 변경 (`backend/app/services/sandbox/synthesizer.py`)**
- `existing.verified` 만으로 cached_hit 분기를 타지 않음 — `is_degraded(existing)` 면 cached_hit 우회. 즉 "동의 후 재시도" 가 항상 새 LLM 호출로 이어진다.
- 새 헬퍼 `_prior_attempts_block(db, existing)` — 이전 매핑이 있으면 `## 이전 시도 (피해야 할 접근)` 섹션을 만들어 `_USER_TEMPLATE` 의 새 `{prior_attempts}` 슬롯에 끼워넣음. 첫 시도(existing=None)면 빈 문자열 → 슬롯이 사라져 기존 프롬프트와 100% 동일.
- 블록 구성: 베이스 이미지(또는 image 태그), `injection_point.method/path/(location:parameter)/response_kind`, 페이로드 예 240자, success_indicator, 결과(verified+degraded vs 합성 실패), 사용자 👎 노트 최대 5개. 마지막에 "이 접근 반복 금지 — 다른 베이스/엔드포인트/location/취약 동작 클래스로 시도" 강조.
- 재합성 성공 후 attempt_row 를 덮어쓸 때 `DELETE FROM cve_lab_feedback WHERE mapping_id = ...` + `feedback_up=feedback_down=0`. 이전 평가가 새 spec 에 그대로 묻어가 zero-input 으로 다시 격하되는 사이클을 차단.
- `synthesizer.prior_context_injected` / `synthesizer.feedback_reset` 로그 — 운영자가 self-refinement 가 실제로 발화하는지 확인 가능.

**GC 동작 변경 (`backend/app/services/sandbox/synthesizer_gc.py`)**
- Pass 1 (image vanished from docker) — 기존: `db.delete(row)` 로 매핑 행 삭제 → FK CASCADE 가 `cve_lab_feedback` 까지 쓸어버림. 결과적으로 PR 9-K 의 학습 컨텍스트가 disk-pressure / `docker prune` 한 번에 증발.
- 변경: `row.verified = False` 로 demote 만 수행, 행 자체는 보존. resolver 는 unverified synthesized 매핑을 어차피 skip 하므로 세션 spawn 동작은 동일하지만, 다음 `synthesize()` 호출 시 `_prior_attempts_block` 이 노트/페이로드/평가를 그대로 읽어 LLM 에 다시 넘긴다.
- `EvictedImage(reason="image_missing", size_mb=0)` 형태로 stats 에는 그대로 남아 운영자 대시보드는 변화 없음.

**검증 (`backend/scripts/smoke_pr9k.py`)**
- `call_llm` 을 monkey-patch 해 실제 토큰/빌드 없이 `synthesize()` 가 LLM 에 넘긴 user_prompt 를 캡처. 일부러 잘못된 JSON 을 반환시켜 schema_invalid 경로로 빠져나오게 함.
- 세 시나리오 모두 통과:
  - **A. verified+degraded** (👍1/👎4) → cached_hit 우회 → call_llm 호출 → 프롬프트에 "이전 시도" 블록 + 👎 노트 포함.
  - **B. demoted (verified=False, image_missing 경로 모사)** → cooldown 우회(last_synthesis_attempt_at=None) → 동일하게 prior block 주입.
  - **C. 첫 시도 (existing=None)** → "이전 시도" 마커 없음, 기존 프롬프트 그대로.
- 시드 매핑은 `alpine:latest` (실제 로컬 이미지) 를 사용해 opportunistic GC 의 image_missing pass 가 fixture 를 demote 시키지 않도록 함.

**왜 cached_hit 우회만 추가했는가**
- PR 9-J 가 resolver 단계에서 격하 매핑을 skip 시켰지만, 그 다음 synthesize() 분기에서 같은 매핑을 cached_hit 으로 반환해 사용자 화면에 결국 같은 lab 이 다시 떴다 — 격하 신호가 사실상 무효화되는 구조였다. 격하면 cached_hit 도 함께 우회하고 self-refinement 컨텍스트를 LLM 에 던져야만 "새로 합성" 버튼이 의미 있게 동작.

**알려진 한계 / 다음 PR 으로 넘김**
- 같은 CVE 에 대한 다중 후보 spec 보존 (best-of-N) 은 아직 없다 — 재합성은 직전 매핑을 덮어쓰는 단일 후보 모델. 평가가 들쭉날쭉한 CVE 에 대해 N 개 후보를 병렬 보관하고 점수로 우선순위를 매기는 작업은 PR 9-L 로 분리.

---

### PR 9-J — 합성 lab 사용자 평가(👍/👎) 적재 + 신뢰도 낮은 lab 자동 격하 ✅

> 합성된 lab 이 매번 똑같이 잘 동작하지 않는 현실을 드러내기 위함. 사용자가 실패한 lab 을 👎 로 표시하면 매핑이 격하되어 다음 호출에서 자동 선택되지 않고, 사용자는 새로 합성으로 시도하라는 안내를 받음.

**스키마 (alembic 0014_lab_feedback)**
- `cve_lab_mappings.feedback_up`, `feedback_down` (INT NOT NULL DEFAULT 0) — 비정규화 카운터. resolver 가 join 없이 O(1) 격하 판정용.
- `cve_lab_feedback` (id, mapping_id FK CASCADE, client_id VARCHAR(64), vote VARCHAR(8), note TEXT, created_at, updated_at, UNIQUE(mapping_id, client_id)) — 익명 클라이언트별 1표.

**Resolver — `is_degraded(mapping)`**
- `down >= 2 AND down >= up + 2` — 최소 두 명의 별개 클라이언트가 👎 한 lab 만 격하. 한 명의 grumpy session 이 lab 을 죽일 수 없음.
- `resolve_lab` 의 synthesized 분기에서 격하된 mapping 은 skip → 다음 단계(generic / 합성 동의 게이트)로 자연스럽게 넘어감. 24h cooldown 은 그대로 유지 — 우회는 `forceRegenerate=true` 명시 동의 시에만.

**API**
- `POST /sandbox/sessions/{id}/feedback` — `{vote: "up"|"down", note?}`. `X-Client-Id` 헤더 필수 (북마크/티켓/커뮤니티와 동일 익명 컨벤션). 한 클라이언트가 여러 번 누르면 같은 row 를 upsert. 응답 후 `feedback_up/down` 을 SELECT GROUP BY 로 재계산해 비정규화 카운터에 반영 (drift 방지).
- 405가 아닌 명확한 에러: vulhub/generic lab 에 투표하면 409 (격하 대상 아님), bad vote → 422, 헤더 누락 → 400.
- `start_session` 에 새 422 `lab_degraded` 코드 추가 — 격하된 합성 lab 이 존재할 때만 표시. payload 는 `feedbackUp/feedbackDown/canSynthesize` 포함해 UI 가 별도 안내 배너를 그릴 수 있게 함.
- `LabInfoOut` 에 `feedbackUp/feedbackDown/myVote/degraded` 추가. `_session_to_out` 가 GET 시에도 client_id 헤더로 myVote 를 surface. resolver 가 격하 mapping 을 skip 하더라도 직접 lookup fallback 으로 lab 정보를 계속 표시 (이미 살아 있는 세션은 무엇이 돌아가는지 보여줘야 함).

**Frontend (`SandboxPanel.tsx`)**
- `LabFeedbackButtons` — 합성 lab 일 때만 lab 카드 안에 👍/👎 카운트 + 토글 상태로 표시. 한 번 더 누르면 다른 vote 로 전환된다는 힌트 표시.
- `lab_degraded` 코드 전용 빨강 배너 — 현재 평가 카운트와 함께 "새로 합성으로 시도" 버튼. 기존 `no_lab` 노란 배너와 색·문구로 구분.
- 진행 중인 세션이 격하되면 lab 카드에 `ShieldAlert` 줄로 안내 ("다음 시작 시 다른 매핑이 선택됩니다").
- API helper `submitLabFeedback` + `clientHeaders()` 일관 적용 (start/get/exec 도 X-Client-Id 헤더 추가 — myVote 표시 위함).

**검증**
```
# OpenAPI
GET /openapi.json → /api/v1/sandbox/sessions/{id}/feedback 등록 확인
LabInfoOut: digest, feedbackUp, feedbackDown, myVote, degraded
LabFeedbackResponse: mappingId, feedbackUp, feedbackDown, myVote, degraded

# 카운터/임계치/upsert 동작
voter A down → up=0/down=1 degraded=false
voter B down → up=0/down=2 degraded=true   ← 임계 통과
voter A 재투표 up → up=1/down=1 degraded=false   (row 업서트, 중복 row 없음)

# resolver 격하 mapping 회피
POST /sandbox/sessions {cveId: ...} → 422 lab_degraded
{"code":"lab_degraded","canSynthesize":true,"feedbackUp":0,"feedbackDown":2,...}

# GET fallback — resolver 가 격하시킨 mapping 도 직접 lookup 으로 lab 정보 유지
GET /sandbox/sessions/<id>  X-Client-Id: voter-aaa
→ lab.degraded=true, lab.myVote="down", lab.digest 그대로
다른 client / 헤더 없음 → myVote 만 다르게 (down / null)

# 거부 케이스
bad vote → 422, 헤더 누락 → 400
```

---

---

## Decisions & Notes

- **Meilisearch 결정 이유**: Elasticsearch는 설정/리소스 부담이 크고, 현 규모엔 Meilisearch의 인스턴트 검색/팩싯 필터로 충분. `search_service.py` 인터페이스로 분리되어 있어 향후 교체 가능.
- **PostgreSQL tsvector 동시 유지**: Meilisearch 장애 시 폴백. 트리거로 자동 동기화 → 별도 처리 불필요.
- **JSONB `raw_data` 보존**: 소스 API 스펙 변경에도 원본 보존. 재파싱 가능.
- **Next.js `output: "standalone"`**: Docker 이미지 크기 최소화.
- **다크 모드 팔레트**: `surface-0~3` 4계층으로 깊이감. 심각도는 반투명 배경 + 진한 텍스트로 다크 환경 가독성.
- **APScheduler `AsyncIOScheduler`**: FastAPI lifespan에서 직접 start. 분산 워커가 필요해지면 Celery beat로 교체.
- **NVD CWE → 라벨 매핑**: `CWE_TO_TYPE` 딕셔너리로 시작. 누락 CWE는 매핑되지 않으면 무시 (확장 가능).
- **`Vulnerability.summary`는 휴리스틱 생성**: 첫 문장 추출 + 300자 제한. 추후 LLM 요약으로 교체 시 `summarizer.generate_summary()`만 바꾸면 됨.

---

## File Map (전체 프로젝트)

```
kestrel/
├── README.md
├── PROGRESS.md                  ← 이 파일
├── .gitignore
├── .env.example
├── docker-compose.yml           ← frontend + backend + postgres + redis + meilisearch
├── frontend/                    # Next.js 15 (Step 2 완료)
└── backend/                     # FastAPI (Step 3 완료)
```
