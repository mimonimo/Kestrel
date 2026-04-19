import type { Asset } from "./assets";
import { getClientId } from "./clientId";
import type { SearchFilters, SearchResponse, StatusReport, Vulnerability } from "./types";

const BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000/api/v1";

class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
    cache: "no-store",
  });
  if (!res.ok) {
    let message = `API ${path} failed: ${res.status}`;
    try {
      const body = await res.json();
      if (body?.detail) message = body.detail;
    } catch {
      /* ignore */
    }
    throw new ApiError(res.status, message);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

function clientHeaders(): Record<string, string> {
  const id = getClientId();
  return id ? { "X-Client-Id": id } : {};
}

export interface BookmarkListResponse {
  items: { cveId: string }[];
  total: number;
}

export const api = {
  searchVulnerabilities: (filters: SearchFilters, page = 1, pageSize = 20) => {
    const params = new URLSearchParams();
    if (filters.query) params.set("q", filters.query);
    filters.severity?.forEach((s) => params.append("severity", s));
    filters.osFamily?.forEach((o) => params.append("os", o));
    filters.types?.forEach((t) => params.append("type", t));
    if (filters.fromDate) params.set("from", filters.fromDate);
    if (filters.toDate) params.set("to", filters.toDate);
    params.set("page", String(page));
    params.set("pageSize", String(pageSize));
    return request<SearchResponse>(`/search?${params.toString()}`);
  },
  getVulnerability: (cveId: string) =>
    request<Vulnerability>(`/cves/${encodeURIComponent(cveId)}`),
  batchVulnerabilities: (ids: string[]) => {
    if (ids.length === 0) return Promise.resolve([] as SearchResponse["items"]);
    const params = new URLSearchParams({ ids: ids.join(",") });
    return request<SearchResponse["items"]>(`/cves/batch?${params.toString()}`);
  },
  getStatus: () => request<StatusReport>(`/status`),
  matchAssets: (assets: Asset[], limit = 100) =>
    request<SearchResponse>(`/assets/match`, {
      method: "POST",
      body: JSON.stringify({
        assets: assets.map(({ vendor, product, version }) => ({ vendor, product, version })),
        limit,
      }),
    }),
  refreshIngestion: (keys: { nvdApiKey?: string; githubToken?: string }) => {
    const headers: Record<string, string> = {};
    if (keys.nvdApiKey) headers["X-NVD-API-Key"] = keys.nvdApiKey;
    if (keys.githubToken) headers["X-GitHub-Token"] = keys.githubToken;
    return request<{ queued: boolean; usedKeys: { nvd: boolean; github: boolean } }>(
      `/admin/refresh`,
      { method: "POST", headers },
    );
  },
  getBookmarks: () =>
    request<BookmarkListResponse>(`/bookmarks`, { headers: clientHeaders() }),
  addBookmark: (cveId: string) =>
    request<{ cveId: string }>(`/bookmarks`, {
      method: "POST",
      headers: clientHeaders(),
      body: JSON.stringify({ cveId }),
    }),
  removeBookmark: (cveId: string) =>
    request<void>(`/bookmarks/${encodeURIComponent(cveId)}`, {
      method: "DELETE",
      headers: clientHeaders(),
    }),
};

export { ApiError };
