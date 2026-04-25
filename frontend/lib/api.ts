import type { Asset } from "./assets";
import { getClientId } from "./clientId";
import type { SearchFilters, SearchResponse, StatusReport, Vulnerability } from "./types";

const BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000/api/v1";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    // FastAPI 422 detail can be an object — sandbox uses
    // `{ code, canSynthesize, message }` to drive the consent flow.
    public detail?: unknown,
  ) {
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
    let detail: unknown;
    try {
      const body = await res.json();
      detail = body?.detail;
      if (typeof detail === "string") {
        message = detail;
      } else if (detail && typeof detail === "object" && "message" in detail) {
        message = String((detail as { message?: unknown }).message ?? message);
      }
    } catch {
      /* ignore */
    }
    throw new ApiError(res.status, message, detail);
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

export interface AssetCatalogEntry {
  vendor: string;
  product: string;
  osFamily: string;
  cveCount: number;
  sampleVersions: string[];
}

export interface AssetCatalogResponse {
  items: AssetCatalogEntry[];
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
  searchAssetCatalog: (q: string, limit = 20) => {
    const params = new URLSearchParams({ limit: String(limit) });
    if (q) params.set("q", q);
    return request<AssetCatalogResponse>(`/assets/catalog?${params.toString()}`);
  },

  listTickets: (status?: TicketStatus) => {
    const params = new URLSearchParams();
    if (status) params.set("status", status);
    const qs = params.toString();
    return request<TicketListResponse>(`/tickets${qs ? `?${qs}` : ""}`, {
      headers: clientHeaders(),
    });
  },
  upsertTicket: (body: { cveId: string; status: TicketStatus; note?: string | null }) =>
    request<Ticket>(`/tickets`, {
      method: "PUT",
      headers: clientHeaders(),
      body: JSON.stringify(body),
    }),
  patchTicket: (cveId: string, body: { status?: TicketStatus; note?: string | null }) =>
    request<Ticket>(`/tickets/${encodeURIComponent(cveId)}`, {
      method: "PATCH",
      headers: clientHeaders(),
      body: JSON.stringify(body),
    }),
  deleteTicket: (cveId: string) =>
    request<void>(`/tickets/${encodeURIComponent(cveId)}`, {
      method: "DELETE",
      headers: clientHeaders(),
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

  getAppSettings: () => request<AppSettingsResponse>(`/settings`),
  listAiCredentials: () => request<AiCredentialListResponse>(`/settings/credentials`),
  createAiCredential: (body: AiCredentialCreate) =>
    request<AiCredential>(`/settings/credentials`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateAiCredential: (id: number, body: AiCredentialUpdate) =>
    request<AiCredential>(`/settings/credentials/${id}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  deleteAiCredential: (id: number) =>
    request<void>(`/settings/credentials/${id}`, { method: "DELETE" }),
  activateAiCredential: (id: number) =>
    request<AppSettingsResponse>(`/settings/credentials/${id}/activate`, {
      method: "POST",
    }),

  analyzeCve: (cveId: string) =>
    request<AiAnalysisResponse>(`/cves/${encodeURIComponent(cveId)}/analyze`, {
      method: "POST",
    }),

  startSandbox: (body: {
    cveId: string;
    labKind?: string;
    attemptSynthesis?: boolean;
  }) =>
    request<SandboxSession>(`/sandbox/sessions`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  synthesizeSandbox: (body: { cveId: string; forceRegenerate?: boolean }) =>
    request<SynthesizeResponse>(`/sandbox/synthesize`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  getSandbox: (sessionId: string) =>
    request<SandboxSession>(`/sandbox/sessions/${encodeURIComponent(sessionId)}`),
  stopSandbox: (sessionId: string) =>
    request<void>(`/sandbox/sessions/${encodeURIComponent(sessionId)}`, {
      method: "DELETE",
    }),
  execSandbox: (
    sessionId: string,
    body: { genericPayload?: string; forceRegenerate?: boolean },
  ) =>
    request<SandboxExecResponse>(
      `/sandbox/sessions/${encodeURIComponent(sessionId)}/exec`,
      { method: "POST", body: JSON.stringify(body) },
    ),
};

export interface AiCredential {
  id: number;
  label: string;
  provider: string;
  model: string;
  baseUrl: string | null;
  hasApiKey: boolean;
  isActive: boolean;
}

export interface AiCredentialListResponse {
  items: AiCredential[];
  activeCredentialId: number | null;
}

export interface AppSettingsResponse {
  activeCredentialId: number | null;
  active: AiCredential | null;
}

export interface AiCredentialCreate {
  label: string;
  provider: string;
  model: string;
  apiKey: string;
  baseUrl?: string | null;
  activate?: boolean;
}

export interface AiCredentialUpdate {
  label?: string;
  provider?: string;
  model?: string;
  apiKey?: string;
  baseUrl?: string | null;
}

export interface AiAnalysisResponse {
  attackMethod: string;
  payloadExample: string;
  mitigation: string[];
}

export type SandboxStatus =
  | "pending"
  | "running"
  | "stopped"
  | "expired"
  | "failed";

export type LabSourceKind = "vulhub" | "generic" | "synthesized";

export interface InjectionPoint {
  name: string;
  method: string;
  path: string;
  parameter: string;
  location: string;
  responseKind: string;
  notes: string;
}

export interface LabInfo {
  kind: string;
  description: string;
  targetPath: string;
  injectionPoints: InjectionPoint[];
}

export interface SandboxLastRun {
  adapted: AdaptedPayload;
  exchange: SandboxExchange;
  verdict: SandboxVerdict;
  ranAt: string;
}

export interface SandboxSession {
  id: string;
  vulnerabilityId: string | null;
  labKind: string;
  labSource: LabSourceKind;
  verified: boolean;
  containerName: string | null;
  targetUrl: string | null;
  status: SandboxStatus;
  error: string | null;
  lastRun: SandboxLastRun | null;
  createdAt: string;
  expiresAt: string | null;
  lab: LabInfo | null;
}

export interface AdaptedPayload {
  method: string;
  path: string;
  parameter: string;
  location: string;
  payload: string;
  successIndicator: string;
  rationale: string;
  notes: string;
  fromCache: boolean;
}

export interface SandboxExchange {
  url: string;
  method: string;
  statusCode: number;
  responseHeaders: Record<string, string>;
  body: string;
  bodyTruncated: boolean;
}

export interface SandboxVerdict {
  success: boolean;
  confidence: string;
  summary: string;
  evidence: string;
  nextStep: string;
  heuristicSignal: string;
}

export interface SandboxExecResponse {
  session: SandboxSession;
  adapted: AdaptedPayload;
  exchange: SandboxExchange;
  verdict: SandboxVerdict;
}

export interface SynthesizeResponse {
  cveId: string;
  imageTag: string;
  verified: boolean;
  mappingId: number | null;
  attempts: number;
  error: string | null;
  spec: Record<string, unknown> | null;
  payload: Record<string, unknown> | null;
  buildLogTail: string[];
  responseStatus: number | null;
  responseBodyPreview: string | null;
}

export interface NoLabDetail {
  code: "no_lab" | "synthesis_failed";
  canSynthesize?: boolean;
  message: string;
}

export function isNoLabDetail(detail: unknown): detail is NoLabDetail {
  if (!detail || typeof detail !== "object") return false;
  const code = (detail as { code?: unknown }).code;
  return code === "no_lab" || code === "synthesis_failed";
}

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

export type TicketStatus = "open" | "in_progress" | "resolved" | "ignored";

export interface Ticket {
  id: number;
  cveId: string;
  status: TicketStatus;
  note: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface TicketListResponse {
  items: Ticket[];
  total: number;
  counts: Record<TicketStatus, number>;
}
