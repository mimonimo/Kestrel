<div align="center">

# Kestrel

### 무엇부터 패치할지 알려주는 CVE 인텔리전스 플랫폼

`CVSS` 이론 · `EPSS` 예측 · `KEV` 실측 — 세 신호로 본 패치 우선순위.

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Next.js](https://img.shields.io/badge/Next.js-15-000?logo=next.js)](https://nextjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi)](https://fastapi.tiangolo.com/)
[![Postgres](https://img.shields.io/badge/PostgreSQL-16-336791?logo=postgresql&logoColor=white)](https://www.postgresql.org/)

</div>

---

```bash
docker compose up -d --build
```

> Frontend → `:3000` · Backend → `:8000/api/v1/health`

---

## 핵심 가치

- **우선순위 매트릭스** — KEV·EPSS·CVSS 합성 4-tier로 *오늘 무엇을 먼저 패치할지* 즉답
- **AI 분석** — Claude 연동, PoC 페이로드 · 패치 매핑 · Follow-up Q&A · CVE 간 비교
- **단일 명령 배포** — Docker Compose 한 줄로 6개 소스 자동 수집 시작

---

## 패치 우선순위 (4-tier)

| | 기준 | 조치 |
|---|---|---|
| **①** | KEV 등재 | 실측 악용 — 최우선 |
| **②** | EPSS 상위 + 외부 접점 | 30일 내 예측 — 즉시 |
| **③** | CVSS 중간 + EPSS 높음 | 실제 터질 가능성 — 앞당겨 |
| **④** | CVSS 높음 + EPSS 낮음 | 이론 심각도만 — 계획된 주기 |

---

## 데이터 소스

| 소스 | 갱신 |
|---|---|
| NVD 2.0 · MITRE cvelistV5 | 분 / 30분 |
| Exploit-DB · GitHub Advisory | 시간 |
| CISA KEV · FIRST EPSS | 시간 / 일 |

---

## 화면

| 경로 | 용도 |
|---|---|
| `/` | 대시보드 (시각화 + 우선순위) |
| `/cves` | 취약점 조회 (검색·필터·리스트) |
| `/cve/{id}` | 상세 + AI 분석 + 대응 상태 + 댓글 |
| `/analysis` | AI 작업 공간 (분석 / 비교 / 즐겨찾기 / 검토 / 댓글) |
| `/settings` | 테마 · 자산 · 키 · Claude · 자원 |

---

## AI 분석

`/settings → Claude 연동` 에서 OAuth 로그인 후 모델 선택:

| 모델 | 응답 |
|---|---|
| Haiku 4.5 | 10–15초 |
| **Sonnet 4.6** (기본) | 1–2분 |
| Opus 4.7 | 2–4분 |

심층 분석 · Follow-up Q&A · CVE 간 패턴 비교 · Markdown 리포트 다운로드.

---

## API

전체 스펙: <http://localhost:8000/docs>

| Path | 설명 |
|---|---|
| `GET  /search?priority=kev` | tier 필터 검색 |
| `POST /cves/{id}/analyze` | AI 심층 분석 |
| `POST /analysis/ask` · `/compare` | Q&A · CVE 비교 |
| `GET  /dashboard/insights` · `/priorities` | 위젯 데이터 |
| `POST /admin/refresh-priority-signals` | KEV/EPSS 즉시 갱신 |

---

## 개발

```bash
docker compose up -d postgres redis meilisearch
cd backend && uv sync && uv run uvicorn app.main:app --reload
cd frontend && npm install && npm run dev
```

`npx tsc --noEmit` · `uv run pytest` · `uv run alembic upgrade head`

---

## Tech

`Next.js 15` · `FastAPI` · `PostgreSQL 16 (tsvector + GIN)` · `Meilisearch` ·
`Redis` · `APScheduler` · `Claude (CLI + API)` · `Sentry` · `OpenTelemetry`

---

<div align="center">

[MIT](./LICENSE) · <sub>Built with Next.js · FastAPI · PostgreSQL · Claude.</sub>

</div>
