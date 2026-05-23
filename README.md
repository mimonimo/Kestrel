<div align="center">

<br/>

# **`Kestrel`**

<sub>**`CVSS`** 이론&nbsp;&nbsp;·&nbsp;&nbsp;**`EPSS`** 예측&nbsp;&nbsp;·&nbsp;&nbsp;**`KEV`** 실측 </sub>

<br/>

<img src="docs/screenshots/dashboard.png" alt="Kestrel 대시보드" width="100%"/>

<br/>
<br/>

<a href="#빠른-시작"><img src="docs/badges/deploy.svg" height="40" alt="docker compose up"/></a>
&nbsp;
<a href="#ai-분석-흐름"><img src="docs/badges/claude.svg" height="40" alt="Claude AI 심층 분석"/></a>
&nbsp;
<a href="#데이터-흐름"><img src="docs/badges/signals.svg" height="40" alt="KEV · EPSS 실시간 연동"/></a>
&nbsp;
<a href="./LICENSE"><img src="docs/badges/license.svg" height="40" alt="MIT 라이선스"/></a>

</div>

---

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

## AI 분석 흐름

```mermaid
sequenceDiagram
    autonumber
    participant U as 사용자
    participant F as Frontend
    participant B as Backend
    participant C as Claude

    U->>F: "AI 심층 분석 요청" 클릭
    F->>B: POST /cves/{id}/analyze
    B->>C: prompt (CVE 컨텍스트 + 스키마)
    Note over C: Sonnet 4.6 · 1–2분
    C-->>B: JSON 분석 결과
    B-->>F: { attackMethod, payloads, mitigations }
    F-->>U: 분석 카드 렌더

    rect rgb(245, 240, 255)
    U->>F: 추가 질문 입력
    F->>B: POST /analysis/ask (질문 + 이전 분석 + history)
    B->>C: follow-up prompt
    C-->>B: free-form 답변
    B-->>F: { answer }
    F-->>U: Q&A 스레드에 누적
    end

    U->>F: "Markdown 리포트 다운로드"
    F-->>U: cve-analysis.md (분석 + Q&A)
```

<br/>

## 페이지

<table>
<tr>
<td width="50%" align="center">

#### 취약점 조회 페이지
<img src="docs/screenshots/cves.png" alt="취약점 조회" width="100%"/>

</td>
<td width="50%" align="center">

#### 상세 + AI 분석 페이지
<img src="docs/screenshots/cve-detail.png" alt="CVE 상세" width="100%"/>

</td>
</tr>
<tr>
<td width="50%" align="center">

#### AI 분석 페이지
<img src="docs/screenshots/analysis.png" alt="AI 작업 공간" width="100%"/>

</td>
<td width="50%" align="center">

#### 설정 페이지
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
