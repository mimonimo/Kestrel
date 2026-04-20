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

> 진행 상황: Step 1 ✅ · Step 2 ✅ · Step 3 ✅ · Step 4 ✅ · Step 5 ✅ · Step 6 ✅

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
