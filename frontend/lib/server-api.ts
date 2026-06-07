import type { Vulnerability } from "./types";
import type { AnalysisDetail } from "./api";

// Server-side: uses Docker service DNS (`backend:8000`). Client-side code never
// hits this module.
const BASE_URL =
  process.env.INTERNAL_API_BASE_URL ??
  process.env.NEXT_PUBLIC_API_BASE_URL ??
  "http://backend:8000/api/v1";

export class ServerApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = "ServerApiError";
  }
}

export async function fetchCveServer(cveId: string): Promise<Vulnerability | null> {
  const res = await fetch(`${BASE_URL}/cves/${encodeURIComponent(cveId)}`, {
    cache: "no-store",
    next: { revalidate: 0 },
  });
  if (res.status === 404) return null;
  if (!res.ok) {
    throw new ServerApiError(res.status, `Failed to fetch ${cveId}: ${res.status}`);
  }
  return (await res.json()) as Vulnerability;
}

/** 공개 분석 단건(SSR). 404/403(비공개) → null. 공개 분석은 비로그인도 조회 가능. */
export async function fetchAnalysisServer(id: string): Promise<AnalysisDetail | null> {
  const res = await fetch(`${BASE_URL}/analyses/${encodeURIComponent(id)}`, {
    cache: "no-store",
    next: { revalidate: 0 },
  });
  if (res.status === 404 || res.status === 403) return null;
  if (!res.ok) {
    throw new ServerApiError(res.status, `Failed to fetch analysis ${id}: ${res.status}`);
  }
  return (await res.json()) as AnalysisDetail;
}
