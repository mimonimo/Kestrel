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
  try {
    const base =
      process.env.INTERNAL_API_BASE_URL ??
      process.env.NEXT_PUBLIC_API_BASE_URL ??
      "http://backend:8000/api/v1";
    const res = await fetch(`${base}/community/analyses?limit=200`, { next: { revalidate } });
    if (res.ok) {
      const data = (await res.json()) as { items?: { id: string; createdAt?: string }[] };
      const analyses: MetadataRoute.Sitemap = (data.items ?? []).map((a) => ({
        url: `${BASE}/analyses/${a.id}`,
        lastModified: a.createdAt ? new Date(a.createdAt) : now,
        changeFrequency: "weekly",
        priority: 0.5,
      }));
      return [...staticRoutes, ...analyses];
    }
  } catch {
    /* 정적 라우트만 반환 */
  }
  return staticRoutes;
}
