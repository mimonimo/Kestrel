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

  listPosts: (page = 1, pageSize = 20, vulnerabilityId?: string) => {
    const params = new URLSearchParams({ page: String(page), pageSize: String(pageSize) });
    if (vulnerabilityId) params.set("vulnerabilityId", vulnerabilityId);
    return request<PostListResponse>(`/community/posts?${params.toString()}`, {
      headers: clientHeaders(),
    });
  },
  getPost: (id: number) =>
    request<CommunityPost>(`/community/posts/${id}`, { headers: clientHeaders() }),
  createPost: (body: { title: string; content: string; authorName?: string; vulnerabilityId?: string }) =>
    request<CommunityPost>(`/community/posts`, {
      method: "POST",
      headers: clientHeaders(),
      body: JSON.stringify(body),
    }),
  updatePost: (id: number, body: { title?: string; content?: string }) =>
    request<CommunityPost>(`/community/posts/${id}`, {
      method: "PATCH",
      headers: clientHeaders(),
      body: JSON.stringify(body),
    }),
  deletePost: (id: number) =>
    request<void>(`/community/posts/${id}`, {
      method: "DELETE",
      headers: clientHeaders(),
    }),

  listComments: (params: { postId?: number; vulnerabilityId?: string }) => {
    const sp = new URLSearchParams();
    if (params.postId !== undefined) sp.set("postId", String(params.postId));
    if (params.vulnerabilityId) sp.set("vulnerabilityId", params.vulnerabilityId);
    return request<CommentListResponse>(`/community/comments?${sp.toString()}`, {
      headers: clientHeaders(),
    });
  },
  createComment: (body: {
    content: string;
    authorName?: string;
    postId?: number;
    vulnerabilityId?: string;
    parentId?: number;
  }) =>
    request<CommunityComment>(`/community/comments`, {
      method: "POST",
      headers: clientHeaders(),
      body: JSON.stringify(body),
    }),
  deleteComment: (id: number) =>
    request<void>(`/community/comments/${id}`, {
      method: "DELETE",
      headers: clientHeaders(),
    }),
};

export interface CommunityPost {
  id: number;
  title: string;
  content: string;
  authorName: string;
  vulnerabilityId: string | null;
  viewCount: number;
  commentCount: number;
  isOwner: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface PostListResponse {
  items: CommunityPost[];
  total: number;
  page: number;
  pageSize: number;
}

export interface CommunityComment {
  id: number;
  content: string;
  authorName: string;
  postId: number | null;
  vulnerabilityId: string | null;
  parentId: number | null;
  isOwner: boolean;
  createdAt: string;
}

export interface CommentListResponse {
  items: CommunityComment[];
  total: number;
}

export { ApiError };
