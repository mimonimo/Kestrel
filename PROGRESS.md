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

PR 9-L (예정): 합성 lab 의 다중 후보 보존 + best-of-N 선택. 같은 CVE 의 여러 성공 spec 을 보관하고 평가가 가장 높은 것을 우선 매핑.

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
