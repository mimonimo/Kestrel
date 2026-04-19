# Kestrel

실시간 CVE 및 제로데이 취약점 모니터링 대시보드. 사이버 보안 전문가와 개발자를 위한 공개 취약점 정보 집약 플랫폼입니다.

## Features

- **실시간 데이터 수집**: NVD, Exploit-DB, GitHub Advisory에서 주기적으로 CVE를 파싱
- **검색 엔진 스타일 UI**: 직관적인 메인 검색창 + 복합 필터 (기간/OS/취약점 유형)
- **요약 미리보기**: 리스트에서 한눈에 핵심 파악
- **상세 보기**: CVSS, 영향 제품/버전, 출처 링크
- **확장 가능한 스키마**: 커뮤니티(게시판·댓글) 추가 준비 완료

## Tech Stack

| Layer    | Tech                                                    |
| -------- | ------------------------------------------------------- |
| Frontend | Next.js 15 (App Router), TypeScript, TailwindCSS        |
| Backend  | FastAPI (Python 3.12), SQLAlchemy 2.0 async, APScheduler |
| Database | PostgreSQL 16 + Meilisearch + Redis                     |
| Infra    | Docker Compose, GitHub Actions                          |

## Quick Start (Docker)

전체 스택을 한 번에 띄울 수 있습니다. 다른 기기에서 그대로 실행 가능합니다.

```bash
git clone <Kestrel>
cd cve-watch
cp .env.example .env
docker compose up --build
```

- Frontend: http://localhost:3000
- Backend API: http://localhost:8000/docs
- Meilisearch: http://localhost:7700

## Local Development (without Docker)

```bash
# Frontend
cd frontend
npm install
npm run dev

# Backend (추후 Step 3에서 구현)
cd backend
uv sync
uv run uvicorn app.main:app --reload
```

## Project Structure

```
kestrel/
├── frontend/   # Next.js 15 대시보드
├── backend/    # FastAPI API + 스케줄러
├── docs/       # 설계 문서
├── docker-compose.yml
└── PROGRESS.md # 작업 진행 로그
```

## Progress

진행 상황은 [PROGRESS.md](./PROGRESS.md)에서 확인하세요.

## License

MIT
