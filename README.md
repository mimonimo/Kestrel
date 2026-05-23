<div align="center">

<br/>

```
   ╦╔═┌─┐┌─┐┌┬┐┬─┐┌─┐┬
   ╠╩╗├┤ └─┐ │ ├┬┘├┤ │
   ╩ ╩└─┘└─┘ ┴ ┴└─└─┘┴─┘
```

### **CVE 인텔리전스 플랫폼 — 무엇부터 패치할지 알려드립니다**

> 모든 것을 동시에 막을 수는 없습니다.
> 심각도가 아니라 *실제 위협*을 기준으로.

<br/>

[![docker compose up](https://img.shields.io/badge/docker_compose_up-한_줄_배포-2496ed?style=for-the-badge&logo=docker&logoColor=white)](#빠른-시작)
[![Claude](https://img.shields.io/badge/Claude_AI-심층_분석-d97757?style=for-the-badge&logo=anthropic&logoColor=white)](#ai-분석)
[![KEV · EPSS](https://img.shields.io/badge/KEV_·_EPSS-실시간-f43f5e?style=for-the-badge)](#패치-우선순위)
[![MIT](https://img.shields.io/badge/MIT-라이선스-3b82f6?style=for-the-badge)](./LICENSE)

</div>

<br/>

## 메인 대시보드

<p align="center">
  <img src="docs/screenshots/dashboard.png" alt="메인 대시보드" width="100%"/>
</p>

<br/>

## 데이터 흐름

```mermaid
flowchart LR
    classDef src fill:#1e293b,stroke:#475569,color:#e2e8f0,stroke-width:2px
    classDef sig fill:#7c3aed,stroke:#a78bfa,color:#fff,stroke-width:2px
    classDef matrix fill:#f43f5e,stroke:#fda4af,color:#fff,stroke-width:2px
    classDef out fill:#0ea5e9,stroke:#7dd3fc,color:#fff,stroke-width:2px

    NVD["NVD · MITRE<br/>Exploit-DB · GHSA"]:::src
    KEV["CISA KEV"]:::src
    EPSS["FIRST EPSS"]:::src

    NVD --> CVSS["CVSS · 이론"]:::sig
    KEV --> KEVSIG["KEV · 실측"]:::sig
    EPSS --> EPSSSIG["EPSS · 예측"]:::sig

    CVSS --> Matrix["4-tier<br/>패치 우선순위"]:::matrix
    KEVSIG --> Matrix
    EPSSSIG --> Matrix

    Matrix --> AI["AI 심층 분석<br/>PoC · 패치 매핑"]:::out
    Matrix --> List["/cves<br/>tier 드릴다운"]:::out
```

<br/>

## 패치 우선순위

```mermaid
flowchart TD
    classDef tier1 fill:#f43f5e,stroke:#fda4af,color:#fff,stroke-width:2px
    classDef tier2 fill:#fb923c,stroke:#fed7aa,color:#fff,stroke-width:2px
    classDef tier3 fill:#a78bfa,stroke:#c4b5fd,color:#fff,stroke-width:2px
    classDef tier4 fill:#0ea5e9,stroke:#7dd3fc,color:#fff,stroke-width:2px
    classDef ask fill:#1e293b,stroke:#475569,color:#e2e8f0,stroke-width:2px

    Ask([오늘 무엇부터<br/>패치해야 하나?]):::ask
    Ask --> T1["<b>① KEV 등재</b><br/>실측 악용 — 최우선"]:::tier1
    T1 --> T2["<b>② EPSS 상위 + 외부 접점</b><br/>30일 내 예측 — 즉시"]:::tier2
    T2 --> T3["<b>③ CVSS 중간 + EPSS 높음</b><br/>가능성 — 앞당겨"]:::tier3
    T3 --> T4["<b>④ CVSS 높음 + EPSS 낮음</b><br/>이론만 — 계획 주기"]:::tier4
```

<br/>

## AI 분석 흐름

```mermaid
flowchart LR
    classDef user fill:#1e293b,stroke:#475569,color:#e2e8f0,stroke-width:2px
    classDef api fill:#7c3aed,stroke:#a78bfa,color:#fff,stroke-width:2px
    classDef ai fill:#f43f5e,stroke:#fda4af,color:#fff,stroke-width:2px
    classDef out fill:#0ea5e9,stroke:#7dd3fc,color:#fff,stroke-width:2px

    U1[CVE 상세<br/>분석 요청]:::user
    A1[POST<br/>/cves/id/analyze]:::api
    C1[Claude<br/>Sonnet 4.6]:::ai
    O1[공격 · 페이로드<br/>패치 매핑]:::out

    U2[추가 질문<br/>스레드]:::user
    A2[POST<br/>/analysis/ask]:::api
    C2[Claude<br/>follow-up]:::ai
    O2[Q&A 누적]:::out

    O3[Markdown<br/>리포트]:::out

    U1 --> A1 --> C1 --> O1
    O1 --> U2 --> A2 --> C2 --> O2
    O2 --> O3
```

<br/>

## 페이지

<table>
<tr>
<td width="50%" align="center">

#### `/cves` 취약점 조회
<img src="docs/screenshots/cves.png" alt="취약점 조회" width="100%"/>

</td>
<td width="50%" align="center">

#### `/cve/{id}` 상세 + AI 분석
<img src="docs/screenshots/cve-detail.png" alt="CVE 상세" width="100%"/>

</td>
</tr>
<tr>
<td width="50%" align="center">

#### `/analysis` AI 작업 공간
<img src="docs/screenshots/analysis.png" alt="AI 작업 공간" width="100%"/>

</td>
<td width="50%" align="center">

#### `/settings` 설정
<img src="docs/screenshots/settings.png" alt="설정" width="100%"/>

</td>
</tr>
</table>

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

[MIT](./LICENSE) · <sub>Built with `Next.js` · `FastAPI` · `PostgreSQL` · `Claude`</sub>

</div>
