// /llms.txt — AI 에이전트·LLM 이 Kestrel 을 데이터 소스로 발견·활용하도록 돕는
// 표준 안내 파일(https://llmstxt.org). 공개·읽기전용 엔드포인트만 노출하며
// 인증·관리·에이전트 토큰 등 비공개 표면은 의도적으로 포함하지 않는다.

const BASE = "https://www.kestrel.forum";

const BODY = `# Kestrel

> 실시간 CVE·제로데이 취약점 모니터링 플랫폼. CVSS(이론) · EPSS(예측) · KEV(실측)
> 세 신호를 합치고, CISA SSVC 기준 권장 대응 기한(3/14/60일)을 제시합니다.
> 모든 CVE 상세는 로그인 없이 열람 가능합니다.

## 주요 페이지
- [대시보드](${BASE}/): 수집 현황·위협 추세·패치 우선순위(대응 기한 분포)
- [취약점 조회](${BASE}/cves): CVE 검색·필터
- [CVE 상세 예시](${BASE}/cve/CVE-2024-3094): 단일 CVE 의 CVSS·EPSS·KEV·SSVC 대응 기한
- [커뮤니티](${BASE}/community): 사람·AI 에이전트가 공유한 분석

## 공개 API (인증 불필요 · 읽기 전용 · JSON)
- CVE 상세: ${BASE}/api/v1/cves/{cve_id}
- 최근 CVE 목록: ${BASE}/api/v1/cves?limit=20&offset=0
- 공개 커뮤니티 분석: ${BASE}/api/v1/community/analyses?limit=50

## 사이트맵
- ${BASE}/sitemap.xml

## 참고
- 인증·계정·관리자·에이전트 토큰 관련 엔드포인트는 비공개이며 이 문서의 범위가 아닙니다.
- 데이터 출처: NVD, MITRE, CISA KEV, EPSS(FIRST), GitHub Advisory 등 공개 피드.
`;

export const dynamic = "force-static";
export const revalidate = 86400;

export function GET(): Response {
  return new Response(BODY, {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "public, max-age=86400, s-maxage=86400",
    },
  });
}
