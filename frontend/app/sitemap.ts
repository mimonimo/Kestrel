import type { MetadataRoute } from "next";

const BASE = "https://www.kestrel.forum";

export const revalidate = 86400; // 하루 1회 재생성

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const now = new Date();
  const staticRoutes: MetadataRoute.Sitemap = [
    { url: `${BASE}/`, lastModified: now, changeFrequency: "hourly", priority: 1 },
    { url: `${BASE}/cves`, lastModified: now, changeFrequency: "hourly", priority: 0.9 },
    { url: `${BASE}/community`, lastModified: now, changeFrequency: "daily", priority: 0.7 },
    { url: `${BASE}/privacy`, lastModified: now, changeFrequency: "yearly", priority: 0.2 },
    { url: `${BASE}/terms`, lastModified: now, changeFrequency: "yearly", priority: 0.2 },
  ];

  // 공개된 커뮤니티 분석은 색인 가치가 있어 포함(실패해도 정적 라우트는 유지).
  const base =
    process.env.INTERNAL_API_BASE_URL ??
    process.env.NEXT_PUBLIC_API_BASE_URL ??
    "http://backend:8000/api/v1";

  const dynamic: MetadataRoute.Sitemap = [];

  // (1) 개별 CVE 상세 페이지 — 검색·AI 크롤러 발견성의 핵심. 백엔드가 상한(1만)으로
  //     캡한 경량 ID 목록을 1일 1회(revalidate) 받아 색인 등록. 실패해도 정적 라우트 유지.
  try {
    const res = await fetch(`${base}/cves/sitemap-ids?limit=10000`, { next: { revalidate } });
    if (res.ok) {
      const ids = (await res.json()) as {
        cveId: string;
        modifiedAt?: string | null;
        publishedAt?: string | null;
      }[];
      for (const c of ids) {
        if (!c?.cveId) continue;
        dynamic.push({
          url: `${BASE}/cve/${encodeURIComponent(c.cveId)}`,
          lastModified: c.modifiedAt ? new Date(c.modifiedAt) : c.publishedAt ? new Date(c.publishedAt) : now,
          changeFrequency: "weekly",
          priority: 0.6,
        });
      }
    }
  } catch {
    /* CVE 목록 실패 — 정적 + 분석만 */
  }

  // (2) 공개 커뮤니티 분석.
  try {
    const res = await fetch(`${base}/community/analyses?limit=200`, { next: { revalidate } });
    if (res.ok) {
      const data = (await res.json()) as { items?: { id: string; createdAt?: string }[] };
      for (const a of data.items ?? []) {
        dynamic.push({
          url: `${BASE}/analyses/${a.id}`,
          lastModified: a.createdAt ? new Date(a.createdAt) : now,
          changeFrequency: "weekly",
          priority: 0.5,
        });
      }
    }
  } catch {
    /* 분석 실패 — 무시 */
  }

  return [...staticRoutes, ...dynamic];
}
