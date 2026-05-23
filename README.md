<div align="center">

<br/>

# **`Kestrel`**

<sub>**`CVSS`** 이론&nbsp;&nbsp;·&nbsp;&nbsp;**`EPSS`** 예측&nbsp;&nbsp;·&nbsp;&nbsp;**`KEV`** 실측 </sub>

<br/>

<img src="docs/screenshots/dashboard.png" alt="Kestrel 대시보드" width="100%"/>

<br/>
<br/>

[![docker compose up](https://img.shields.io/badge/DOCKER_COMPOSE_UP-2496ED?style=for-the-badge&logo=docker&logoColor=white)](#빠른-시작)
[![Claude AI](https://img.shields.io/badge/CLAUDE_AI-D97757?style=for-the-badge&logo=anthropic&logoColor=white)](#tech-stack)
[![KEV · EPSS](https://img.shields.io/badge/KEV_·_EPSS-F43F5E?style=for-the-badge&logo=cloudflare&logoColor=white)](#tech-stack)
[![MIT License](https://img.shields.io/badge/MIT_LICENSE-3B82F6?style=for-the-badge&logo=opensourceinitiative&logoColor=white)](./LICENSE)

</div>

---

<br/>

## 페이지

<table>
<tr>
<td width="50%" align="center">

#### 취약점 조회
<img src="docs/screenshots/cves.png" alt="취약점 조회" width="100%"/>

</td>
<td width="50%" align="center">

#### 상세 + AI 분석
<img src="docs/screenshots/cve-detail.png" alt="CVE 상세" width="100%"/>

</td>
</tr>
<tr>
<td width="50%" align="center">

#### AI 분석 작업
<img src="docs/screenshots/analysis.png" alt="AI 분석" width="100%"/>

</td>
<td width="50%" align="center">

#### 설정
<img src="docs/screenshots/settings.png" alt="설정" width="100%"/>

</td>
</tr>
</table>

<br/>

## Tech Stack

#### Frontend
![Next.js](https://img.shields.io/badge/Next.js-000000?style=for-the-badge&logo=nextdotjs&logoColor=white)
![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white)
![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white)
![TanStack Query](https://img.shields.io/badge/TanStack_Query-FF4154?style=for-the-badge&logo=reactquery&logoColor=white)

#### Backend
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![Python](https://img.shields.io/badge/Python_3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)
![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-D71F00?style=for-the-badge&logo=sqlalchemy&logoColor=white)
![Pydantic](https://img.shields.io/badge/Pydantic-E92063?style=for-the-badge&logo=pydantic&logoColor=white)

#### Data & Infra
![PostgreSQL](https://img.shields.io/badge/PostgreSQL_16-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-DC382D?style=for-the-badge&logo=redis&logoColor=white)
![Meilisearch](https://img.shields.io/badge/Meilisearch-FF5CAA?style=for-the-badge&logo=meilisearch&logoColor=white)
![Docker](https://img.shields.io/badge/Docker_Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white)

#### AI · Observability
![Claude](https://img.shields.io/badge/Anthropic_Claude-D97757?style=for-the-badge&logo=anthropic&logoColor=white)
![OpenTelemetry](https://img.shields.io/badge/OpenTelemetry-425CC7?style=for-the-badge&logo=opentelemetry&logoColor=white)
![Sentry](https://img.shields.io/badge/Sentry-362D59?style=for-the-badge&logo=sentry&logoColor=white)

<br/>

## 빠른 시작

```bash
git clone https://github.com/mimonimo/Kestrel.git
cd Kestrel
docker compose up -d --build
```

Frontend → <http://localhost:3000>  ·  Backend → <http://localhost:8000>

<br/>

<div align="center">

[MIT License](./LICENSE) &nbsp;·&nbsp; <sub>Built with `Next.js` · `FastAPI` · `PostgreSQL` · `Claude`</sub>

</div>
