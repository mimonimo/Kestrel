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

> 진행 상황: Step 1 ✅ · Step 2 ✅ · Step 3 ✅ · Step 4 ✅ · Step 5 ✅ · Step 6 ✅ · Step 7 ✅ · Step 8 ✅

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
