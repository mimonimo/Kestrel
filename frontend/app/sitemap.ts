import type { MetadataRoute } from "next";

const BASE = "https://www.kestrel.forum";

// 런타임 생성 — 빌드 시점엔 backend(compose 네트워크)가 닿지 않아 CVE 목록을 못 받지만,
// 운영 런타임에선 닿는다. 빌드 프리렌더를 끄고(요청 시 생성) 데이터는 fetch 캐시로 24h 보존.
// (build 가 sitemap 생성을 시도하다 멈추는 문제도 원천 차단.)
export const dynamic = "force-dynamic";
const REVALIDATE = 86400; // fetch 데이터 캐시 TTL — 하루 1회 백엔드 재조회

// backend 가 일시적으로 안 닿아도 sitemap 생성이 멈추지 않게 짧은 타임아웃으로 폴백.
async function fetchJson<T>(url: string): Promise<T | null> {
  try {
    const res = await fetch(url, {
      next: { revalidate: REVALIDATE },
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const now = new Date();
  const staticRoutes: MetadataRoute.Sitemap = [
    { url: `${BASE}/`, lastModified: now, changeFrequency: "hourly", priority: 1 },
    { url: `${BASE}/cves`, lastModified: now, changeFrequency: "hourly", priority: 0.9 },
    { url: `${BASE}/community`, lastModified: now, changeFrequency: "daily", priority: 0.7 },
    { url: `${BASE}/privacy`, lastModified: now, changeFrequency: "yearly", priority: 0.2 },
    { url: `${BASE}/terms`, lastModified: now, changeFrequency: "yearly", priority: 0.2 },
  ];

  const base =
    process.env.INTERNAL_API_BASE_URL ??
    process.env.NEXT_PUBLIC_API_BASE_URL ??
    "http://backend:8000/api/v1";

  const dynamic: MetadataRoute.Sitemap = [];

  // (1) 개별 CVE 상세 페이지 — 검색·AI 크롤러 발견성의 핵심. 백엔드가 상한(1만)으로
  //     캡한 경량 ID 목록을 1일 1회(revalidate) 받아 색인 등록. 실패해도 정적 라우트 유지.
  const ids = await fetchJson<
    { cveId: string; modifiedAt?: string | null; publishedAt?: string | null }[]
  >(`${base}/cves/sitemap-ids?limit=10000`);
  for (const c of ids ?? []) {
    if (!c?.cveId) continue;
    dynamic.push({
      url: `${BASE}/cve/${encodeURIComponent(c.cveId)}`,
      lastModified: c.modifiedAt ? new Date(c.modifiedAt) : c.publishedAt ? new Date(c.publishedAt) : now,
      changeFrequency: "weekly",
      priority: 0.6,
    });
  }

  // (2) 공개 커뮤니티 분석.
  const data = await fetchJson<{ items?: { id: string; createdAt?: string }[] }>(
    `${base}/community/analyses?limit=200`,
  );
  for (const a of data?.items ?? []) {
    dynamic.push({
      url: `${BASE}/analyses/${a.id}`,
      lastModified: a.createdAt ? new Date(a.createdAt) : now,
      changeFrequency: "weekly",
      priority: 0.5,
    });
  }

  return [...staticRoutes, ...dynamic];
}
