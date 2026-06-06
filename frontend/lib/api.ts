import type { Asset } from "./assets";
import { getClientId } from "./clientId";
import type { SortKey } from "./sort";
import type { SearchFilters, SearchResponse, StatusReport, Vulnerability } from "./types";

const BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000/api/v1";

// 자산 매칭 알림 (PR 10-FB)
export interface NotificationItem {
  id: number;
  cveId: string;
  vendor: string | null;
  product: string | null;
  severity: string | null;
  title: string | null;
  read: boolean;
  createdAt: string;
}
export interface NotificationsResponse {
  items: NotificationItem[];
  unreadCount: number;
}
export interface NotificationChannel {
  id: number;
  kind: "slack" | "discord";
  url: string;
  enabled: boolean;
  createdAt: string;
}

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
    // 쿠키 (access_token) 를 모든 요청에 자동 전송 — auth 의존성 라우트가
    // 401 안 받도록. CORS 는 backend 쪽 allow_credentials=True 로 매칭.
    credentials: "include",
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

// Minimal SSE consumer over fetch (EventSource doesn't support POST). Parses
// `event:` + `data:` line pairs, dispatches each frame as it arrives. Throws
// on HTTP error before the stream opens; once we're in the stream, errors are
// surfaced as an `error` event from the server (then the stream closes).
async function streamSse<E>(
  path: string,
  body: unknown,
  onEvent: (ev: E) => void,
  signal?: AbortSignal,
): Promise<void> {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json", Accept: "text/event-stream" },
    body: JSON.stringify(body),
    signal,
    cache: "no-store",
  });
  if (!res.ok || !res.body) {
    let message = `SSE ${path} failed: ${res.status}`;
    try {
      const text = await res.text();
      if (text) message = text.slice(0, 400);
    } catch {
      /* ignore */
    }
    throw new ApiError(res.status, message);
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    // SSE frames are separated by a blank line. Process all complete frames
    // in the buffer, leave the trailing partial for the next read.
    let sep = buf.indexOf("\n\n");
    while (sep !== -1) {
      const frame = buf.slice(0, sep);
      buf = buf.slice(sep + 2);
      const ev = parseSseFrame(frame);
      if (ev) onEvent(ev as E);
      sep = buf.indexOf("\n\n");
    }
  }
}

function parseSseFrame(frame: string): { event: string; data: unknown } | null {
  let event = "message";
  const dataLines: string[] = [];
  for (const raw of frame.split("\n")) {
    const line = raw.replace(/\r$/, "");
    if (!line || line.startsWith(":")) continue;
    const idx = line.indexOf(":");
    const field = idx === -1 ? line : line.slice(0, idx);
    const value = idx === -1 ? "" : line.slice(idx + 1).replace(/^ /, "");
    if (field === "event") event = value;
    else if (field === "data") dataLines.push(value);
  }
  if (dataLines.length === 0) return null;
  const dataStr = dataLines.join("\n");
  try {
    return { event, data: JSON.parse(dataStr) };
  } catch {
    return { event, data: dataStr };
  }
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

export interface AssetVendorEntry {
  vendor: string;
  cveCount: number;
}
export interface AssetVendorsResponse {
  items: AssetVendorEntry[];
}
export interface AssetProductEntry {
  product: string;
  cveCount: number;
  osFamilies: string[];
}
export interface AssetProductsResponse {
  items: AssetProductEntry[];
}

// ─── Auth / Profile (PR 10-CN) ───────────────────────────────────────
export interface AuthUser {
  id: string;
  email: string;
  username: string;
  nickname: string | null;
  role: "user" | "expert" | "admin";
  isAdmin: boolean;
}

export interface Profile extends AuthUser {
  nickname: string | null;
  bio: string | null;
}

export interface SignupRequest {
  email: string;
  username: string;
  password: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface ProfileUpdate {
  nickname?: string | null;
  bio?: string | null;
}

// ─── Analysis records (PR 10-CN) ─────────────────────────────────────
export interface AnalysisAuthor {
  username: string;
  nickname: string | null;
}

export interface AnalysisSummary {
  id: string;
  cveId: string;
  category: string;
  title: string | null;
  visibility: "public" | "private";
  createdAt: string;
  author: AnalysisAuthor;
  excerpt: string;
  // PR 10-DA: AI 분석 탭 history 형식 통합용.
  payloadCount: number;
  mitigationCount: number;
  attackMethod: string;
  // PR 10-DC: 분석 피드 그룹핑·필터링용 CVE 메타.
  cveSeverity: string | null;
  cveTypes: string[];
}

export interface AnalysisDetail extends AnalysisSummary {
  resultMd: string;
  promptMd: string | null;
}

export interface AnalysisList {
  items: AnalysisSummary[];
  total: number;
}

export const api = {
  searchVulnerabilities: (
    filters: SearchFilters,
    page = 1,
    pageSize = 20,
    sort: SortKey = "newest",
  ) => {
    const params = new URLSearchParams();
    if (filters.query) params.set("q", filters.query);
    filters.severity?.forEach((s) => params.append("severity", s));
    filters.osFamily?.forEach((o) => params.append("os", o));
    filters.types?.forEach((t) => params.append("type", t));
    filters.domains?.forEach((d) => params.append("domain", d));
    if (filters.fromDate) params.set("from", filters.fromDate);
    if (filters.toDate) params.set("to", filters.toDate);
    if (filters.priority) params.set("priority", filters.priority);
    if (sort && sort !== "newest") params.set("sort", sort);
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
  getVersion: () => request<VersionReport>(`/version`),
  getResources: () => request<ResourceReport>(`/resources`),
  flushRedis: () =>
    request<ResourceActionResponse>(`/resources/redis/flush`, {
      method: "POST",
    }),
  analyzeDb: () =>
    request<ResourceActionResponse>(`/resources/db/analyze`, {
      method: "POST",
    }),
  dropMeiliIndex: () =>
    request<ResourceActionResponse>(`/resources/meili/drop`, {
      method: "POST",
    }),
  getClaudeAuthStatus: () =>
    request<ClaudeAuthStatus>(`/settings/claude-auth/status`),
  startClaudeAuth: () =>
    request<ClaudeAuthStart>(`/settings/claude-auth/start`, { method: "POST" }),
  submitClaudeAuthCode: (sessionId: string, code: string) =>
    request<ClaudeAuthAction>(
      `/settings/claude-auth/${encodeURIComponent(sessionId)}/submit`,
      { method: "POST", body: JSON.stringify({ code }) },
    ),
  cancelClaudeAuth: (sessionId: string) =>
    request<ClaudeAuthAction>(
      `/settings/claude-auth/${encodeURIComponent(sessionId)}/cancel`,
      { method: "POST" },
    ),
  logoutClaudeAuth: () =>
    request<ClaudeAuthAction>(`/settings/claude-auth/logout`, {
      method: "POST",
    }),
  saveClaudeCredentials: (credentials: unknown) =>
    request<ClaudeAuthAction>(`/settings/claude-auth/credentials`, {
      method: "POST",
      body: JSON.stringify({ credentials }),
    }),
  mitreBackfill: (body: { mode: "full" | "delta"; sinceDays?: number; maxRecords?: number }) =>
    request<MitreBackfillResponse>(`/admin/mitre-backfill`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
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
  listAssetVendors: (startsWith: string, limit = 300) =>
    request<AssetVendorsResponse>(
      `/assets/vendors?starts_with=${encodeURIComponent(startsWith)}&limit=${limit}`,
    ),
  listAssetProducts: (vendor: string, limit = 300) =>
    request<AssetProductsResponse>(
      `/assets/products?vendor=${encodeURIComponent(vendor)}&limit=${limit}`,
    ),

  // 서버 저장 자산 (로그인 사용자) — 알림 매칭의 전제. (PR 10-FB)
  getSavedAssets: () =>
    request<{ assets: { vendor: string; product: string }[] }>(`/assets/saved`),
  putSavedAssets: (assets: { vendor: string; product: string }[]) =>
    request<{ assets: { vendor: string; product: string }[] }>(`/assets/saved`, {
      method: "PUT",
      body: JSON.stringify({ assets }),
    }),

  // 인앱 알림 피드 (서버 생성).
  getNotifications: (limit = 50) =>
    request<NotificationsResponse>(`/notifications?limit=${limit}`),
  markNotificationsRead: (ids?: number[]) =>
    request<{ marked: number }>(`/notifications/read`, {
      method: "POST",
      body: JSON.stringify({ ids: ids ?? null }),
    }),

  // 알림 채널 (Slack/Discord 웹훅).
  listNotificationChannels: () =>
    request<NotificationChannel[]>(`/notifications/channels`),
  createNotificationChannel: (kind: "slack" | "discord", url: string) =>
    request<NotificationChannel>(`/notifications/channels`, {
      method: "POST",
      body: JSON.stringify({ kind, url }),
    }),
  deleteNotificationChannel: (id: number) =>
    request<{ deleted: boolean }>(`/notifications/channels/${id}`, {
      method: "DELETE",
    }),
  testNotificationChannel: (id: number) =>
    request<{ sent: boolean }>(`/notifications/channels/${id}/test`, {
      method: "POST",
    }),

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
  // ─── 방문자 카운터 (PR 10-CS) ─────────────────────────────────
  // 호출 자체가 자신을 카운트 (X-Client-Id 또는 IP 기반 unique). public.
  getVisitors: () =>
    request<{ today: number; total: number }>(`/stats/visitors`, {
      headers: clientHeaders(),
    }),

  // ─── 외부 데이터 소스 키 (PR 10-CQ) ───────────────────────────
  // GET 은 마스킹된 값만 (`****1234`). PUT 으로 저장·삭제.
  getExternalKeys: () =>
    request<{
      nvdApiKey: string | null;
      githubToken: string | null;
      nvdSet: boolean;
      githubSet: boolean;
    }>(`/admin/external-keys`),
  putExternalKeys: (body: { nvdApiKey?: string; githubToken?: string }) =>
    request<{
      nvdApiKey: string | null;
      githubToken: string | null;
      nvdSet: boolean;
      githubSet: boolean;
    }>(`/admin/external-keys`, { method: "PUT", body: JSON.stringify(body) }),

  refreshIngestion: (
    keys: { nvdApiKey?: string; githubToken?: string },
    fullResync?: Array<"ghsa" | "nvd" | "exploit_db" | "all">,
  ) => {
    const headers: Record<string, string> = {};
    if (keys.nvdApiKey) headers["X-NVD-API-Key"] = keys.nvdApiKey;
    if (keys.githubToken) headers["X-GitHub-Token"] = keys.githubToken;
    if (fullResync && fullResync.length > 0) {
      headers["X-Full-Resync"] = fullResync.join(",");
    }
    return request<{
      queued: boolean;
      usedKeys: { nvd: boolean; github: boolean };
      fullResync?: { nvd: boolean; ghsa: boolean; exploit_db: boolean };
    }>(`/admin/refresh`, { method: "POST", headers });
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
  likePost: (id: number) =>
    request<{ likeCount: number; isLiked: boolean }>(`/community/posts/${id}/like`, {
      method: "POST",
    }),
  unlikePost: (id: number) =>
    request<{ likeCount: number; isLiked: boolean }>(`/community/posts/${id}/like`, {
      method: "DELETE",
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
  pingActiveCredential: () =>
    request<CredentialPingResponse>(`/settings/credentials/ping`, {
      method: "POST",
    }),

  analyzeCve: (
    cveId: string,
    opts?: { category?: string; title?: string; visibility?: "public" | "private" },
  ) =>
    request<AiAnalysisResponse>(`/cves/${encodeURIComponent(cveId)}/analyze`, {
      method: "POST",
      body: JSON.stringify(opts ?? {}),
    }),

  // ─── Auth ─────────────────────────────────────────────────────
  signup: (body: SignupRequest) =>
    request<AuthUser>(`/auth/signup`, { method: "POST", body: JSON.stringify(body) }),
  login: (body: LoginRequest) =>
    request<AuthUser>(`/auth/login`, { method: "POST", body: JSON.stringify(body) }),
  logout: () => request<void>(`/auth/logout`, { method: "POST" }),
  getAuthMe: () => request<AuthUser>(`/auth/me`),
  changePassword: (body: { currentPassword: string; newPassword: string }) =>
    request<void>(`/auth/change-password`, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  // ─── Profile ─────────────────────────────────────────────────
  getProfile: () => request<Profile>(`/me/profile`),
  updateProfile: (body: ProfileUpdate) =>
    request<Profile>(`/me/profile`, { method: "PATCH", body: JSON.stringify(body) }),

  // ─── Analysis records ────────────────────────────────────────
  listMyAnalyses: (opts?: { limit?: number; offset?: number }) => {
    const p = new URLSearchParams();
    if (opts?.limit != null) p.set("limit", String(opts.limit));
    if (opts?.offset != null) p.set("offset", String(opts.offset));
    const qs = p.toString();
    return request<AnalysisList>(`/me/analyses${qs ? `?${qs}` : ""}`);
  },
  listCommunityAnalyses: (opts?: { limit?: number; offset?: number; cveId?: string }) => {
    const p = new URLSearchParams();
    if (opts?.limit != null) p.set("limit", String(opts.limit));
    if (opts?.offset != null) p.set("offset", String(opts.offset));
    if (opts?.cveId) p.set("cve_id", opts.cveId);
    const qs = p.toString();
    return request<AnalysisList>(`/community/analyses${qs ? `?${qs}` : ""}`);
  },
  listCveAnalyses: (cveId: string) =>
    request<AnalysisList>(`/cves/${encodeURIComponent(cveId)}/analyses`),
  getAnalysisRecord: (id: string) =>
    request<AnalysisDetail>(`/analyses/${encodeURIComponent(id)}`),
  updateAnalysisRecord: (
    id: string,
    body: { visibility?: "public" | "private"; title?: string },
  ) =>
    request<AnalysisDetail>(`/analyses/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  deleteAnalysisRecord: (id: string) =>
    request<void>(`/analyses/${encodeURIComponent(id)}`, { method: "DELETE" }),

  askFollowup: (body: AskFollowupRequest) =>
    request<AskFollowupResponse>(`/analysis/ask`, {
      method: "POST",
      body: JSON.stringify({
        cveId: body.cveId,
        question: body.question,
        prior: body.prior,
        history: body.history ?? [],
      }),
    }),

  compareCves: (cveIds: string[]) =>
    request<CompareResponse>(`/analysis/compare`, {
      method: "POST",
      body: JSON.stringify({ cveIds }),
    }),

  startSandbox: (body: {
    cveId: string;
    labKind?: string;
    attemptSynthesis?: boolean;
    mappingId?: number;
  }) =>
    request<SandboxSession>(`/sandbox/sessions`, {
      method: "POST",
      headers: clientHeaders(),
      body: JSON.stringify(body),
    }),
  synthesizeSandbox: (body: { cveId: string; forceRegenerate?: boolean }) =>
    request<SynthesizeResponse>(`/sandbox/synthesize`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  streamSynthesizeSandbox: (
    body: { cveId: string; forceRegenerate?: boolean },
    onEvent: (ev: SynthesizeStreamEvent) => void,
    signal?: AbortSignal,
  ) => streamSse(`/sandbox/synthesize/stream`, body, onEvent, signal),
  getSynthesizerCache: () =>
    request<SynthesizeCacheReport>(`/sandbox/synthesize/cache`),
  getLabKindStats: () =>
    request<LabKindStatsReport>(`/sandbox/lab-kind-stats`),
  getDashboardInsights: (opts?: {
    days?: number;
    vendorLimit?: number;
    recentLimit?: number;
  }) => {
    const params = new URLSearchParams();
    if (opts?.days != null) params.set("days", String(opts.days));
    if (opts?.vendorLimit != null) params.set("vendor_limit", String(opts.vendorLimit));
    if (opts?.recentLimit != null) params.set("recent_limit", String(opts.recentLimit));
    const qs = params.toString();
    return request<DashboardInsightsResponse>(
      `/dashboard/insights${qs ? `?${qs}` : ""}`,
    );
  },

  getDashboardPriorities: (opts?: { perBucket?: number }) => {
    const params = new URLSearchParams();
    if (opts?.perBucket != null) params.set("per_bucket", String(opts.perBucket));
    const qs = params.toString();
    return request<DashboardPrioritiesResponse>(
      `/dashboard/priorities${qs ? `?${qs}` : ""}`,
    );
  },

  getSearchFacets: (
    window?: { from?: string; to?: string },
    filters?: {
      severity?: string;
      source?: string;
      type?: string;
      domain?: string;
    },
  ) => {
    const params = new URLSearchParams();
    if (window?.from) params.set("from", window.from);
    if (window?.to) params.set("to", window.to);
    if (filters?.severity) params.set("severity", filters.severity);
    if (filters?.source) params.set("source", filters.source);
    if (filters?.type) params.set("type", filters.type);
    if (filters?.domain) params.set("domain", filters.domain);
    const qs = params.toString();
    return request<SearchFacetsResponse>(
      `/search/facets${qs ? `?${qs}` : ""}`,
    );
  },
  getAssetNotifications: (
    assets: Asset[],
    sinceDays = 14,
    limit = 50,
  ) =>
    request<SearchResponse>(`/assets/notifications`, {
      method: "POST",
      body: JSON.stringify({
        assets: assets.map(({ vendor, product, version }) => ({
          vendor,
          product,
          version,
        })),
        sinceDays,
        limit,
      }),
    }),
  getSynthCandidates: (cveId: string) =>
    request<SynthCandidatesResponse>(
      `/sandbox/cves/${encodeURIComponent(cveId)}/synth-candidates`,
    ),
  resetSynthCooldown: (cveId: string) =>
    request<void>(
      `/sandbox/cves/${encodeURIComponent(cveId)}/synth-cooldown/reset`,
      { method: "POST" },
    ),
  resumeSynthVerify: (cveId: string) =>
    request<SynthesizeResponse>(
      `/sandbox/cves/${encodeURIComponent(cveId)}/synth-resume-verify`,
      { method: "POST" },
    ),
  triggerSynthesizerGc: (
    body?: {
      targetTotalMb?: number;
      targetMaxCount?: number;
      targetMaxAgeDays?: number;
    },
  ) =>
    request<SynthesizeGcResponse>(`/sandbox/synthesize/gc`, {
      method: "POST",
      body: JSON.stringify(body ?? {}),
    }),
  getSandbox: (sessionId: string) =>
    request<SandboxSession>(`/sandbox/sessions/${encodeURIComponent(sessionId)}`, {
      headers: clientHeaders(),
    }),
  stopSandbox: (sessionId: string) =>
    request<void>(`/sandbox/sessions/${encodeURIComponent(sessionId)}`, {
      method: "DELETE",
    }),
  listSandboxSessions: (opts?: { includeStopped?: boolean; limit?: number }) => {
    const qs = new URLSearchParams();
    if (opts?.includeStopped) qs.set("include_stopped", "true");
    if (opts?.limit) qs.set("limit", String(opts.limit));
    const suffix = qs.toString() ? `?${qs.toString()}` : "";
    return request<SandboxSessionListResponse>(`/sandbox/sessions${suffix}`);
  },
  reapSandboxSessions: () =>
    request<{ reaped: number }>(`/sandbox/sessions/reap`, { method: "POST" }),
  syncVulhub: () =>
    request<VulhubSyncResponse>(`/sandbox/vulhub/sync`, { method: "POST" }),
  execSandbox: (
    sessionId: string,
    body: { genericPayload?: string; forceRegenerate?: boolean },
  ) =>
    request<SandboxExecResponse>(
      `/sandbox/sessions/${encodeURIComponent(sessionId)}/exec`,
      { method: "POST", headers: clientHeaders(), body: JSON.stringify(body) },
    ),
  submitLabFeedback: (
    sessionId: string,
    body: { vote: "up" | "down"; note?: string | null },
  ) =>
    request<LabFeedbackResponse>(
      `/sandbox/sessions/${encodeURIComponent(sessionId)}/feedback`,
      { method: "POST", headers: clientHeaders(), body: JSON.stringify(body) },
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

export interface CredentialPingResponse {
  ok: boolean;
  provider: string | null;
  model: string | null;
  latencyMs: number;
  replyPreview: string | null;
  errorKind: string | null;
  errorDetail: string | null;
  cliVersion: string | null;
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
  payloadExamples: string[];
  mitigations: string[];
  // 분석 저장 후 DB row id — 작성자만 이걸로 visibility 변경/삭제 가능 (PR 10-CN).
  analysisId?: string | null;
}

export interface QaTurn {
  question: string;
  answer: string;
}

export interface AskFollowupRequest {
  cveId: string;
  question: string;
  prior?: AiAnalysisResponse;
  history?: QaTurn[];
}

export interface AskFollowupResponse {
  answer: string;
}

export interface ComparePerCveNote {
  cveId: string;
  note: string;
}

export interface CompareResponse {
  summary: string;
  commonPattern: string;
  differences: string[];
  sharedMitigations: string[];
  perCveNotes: ComparePerCveNote[];
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
  // Empty for vulhub / generic labs; populated by the synthesizer with
  // a one-line summary (base image + injection shape).
  digest: string;
  // Per-mapping vote tally — only meaningful for synthesized labs.
  feedbackUp: number;
  feedbackDown: number;
  // The current client's previous vote on this mapping. null when
  // never voted or when no client header was sent.
  myVote: "up" | "down" | null;
  // True when feedback ratio would currently cause the resolver to
  // refuse this mapping. UI uses this to flag a session whose lab was
  // voted down after starting.
  degraded: boolean;
  // Best-of-N (PR 9-S/9-T): how many synthesized candidates exist for
  // this CVE and which rank the running mapping holds. Both 0 for
  // vulhub / generic labs (no candidate axis).
  candidateCount: number;
  candidateRank: number;
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
  // PR 9-U manual pivot — id of the cve_lab_mappings row currently
  // backing this session. UI marks the matching candidate as "사용중"
  // in the pivot list. null when the resolver couldn't map at GET time.
  mappingId: number | null;
}

// Settings-page lightweight session view (no LabInfo) — see backend
// ``SandboxSessionSummary``. cve_id is pre-resolved so the UI can
// deep-link without an extra fetch.
export interface SandboxSessionSummary {
  id: string;
  cveId: string | null;
  labKind: string;
  labSource: LabSourceKind;
  status: SandboxStatus;
  containerName: string | null;
  targetUrl: string | null;
  createdAt: string;
  expiresAt: string | null;
  error: string | null;
}

export interface SandboxSessionListResponse {
  items: SandboxSessionSummary[];
  runningCount: number;
  total: number;
}

export interface VulhubSyncResponse {
  foldersScanned: number;
  candidates: number;
  upserted: number;
  skipped: number;
  errors: string[];
}

export interface VersionReport {
  gitCommit: string;
  gitCommitShort: string;
  buildTime: string;
  alembicRevision: string | null;
  startedAt: string;
}

export interface TableSize {
  name: string;
  rows: number;
  totalBytes: number;
}

export interface DbResource {
  healthy: boolean;
  pgVersion: string | null;
  dbSizeBytes: number | null;
  tableSizes: TableSize[];
  error: string | null;
}

export interface RedisResource {
  healthy: boolean;
  usedMemoryBytes: number | null;
  keyCount: number | null;
  redisVersion: string | null;
  error: string | null;
}

export interface MeiliResource {
  healthy: boolean;
  indexUid: string;
  documentCount: number | null;
  rawSizeBytes: number | null;
  indexCount: number | null;
  meiliVersion: string | null;
  error: string | null;
}

export interface ResourceReport {
  db: DbResource;
  redis: RedisResource;
  meili: MeiliResource;
}

export interface ResourceActionResponse {
  ok: boolean;
  detail: string;
  payload: Record<string, unknown> | null;
}

// Claude Code OAuth (PR 10-AD): dashboard-driven login flow.
export interface ClaudeAuthStatus {
  loggedIn: boolean;
  expiresAt: number | null; // epoch milliseconds
  // True when the credentials file has a refresh_token alongside the
  // (possibly expired) access_token. Claude CLI uses it to auto-refresh
  // — UI should treat this state as "still connected" even when
  // expiresAt has passed.
  refreshTokenPresent: boolean;
  scopes: string[];
  cliPresent: boolean;
  cliVersion: string | null;
}

export interface ClaudeAuthStart {
  sessionId: string;
  url: string;
  expiresInSeconds: number;
}

export interface ClaudeAuthAction {
  ok: boolean;
  detail: string;
}

export interface MitreBackfillResponse {
  queued: boolean;
  mode: string;
  detail: string;
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

// Phases emitted by /sandbox/synthesize/stream — UI maps to friendly labels.
// Keep in sync with synthesizer.synthesize emit() call sites.
export type SynthesizePhase =
  | "start"
  | "cached_hit"
  | "cooldown"
  | "call_llm"
  | "parsed"
  | "build_started"
  | "build_done"
  | "lab_started"
  | "verifying"
  | "verify_failed"
  | "verify_ok"
  | "cached"
  | "failed";

export interface SynthesizeStepEvent {
  event: "step";
  data: {
    phase: SynthesizePhase;
    message: string;
    payload: Record<string, unknown> | null;
  };
}

export interface SynthesizeDoneEvent {
  event: "done";
  data: SynthesizeResponse;
}

export interface SynthesizeErrorEvent {
  event: "error";
  data: { message: string };
}

export type SynthesizeStreamEvent =
  | SynthesizeStepEvent
  | SynthesizeDoneEvent
  | SynthesizeErrorEvent;

export interface SynthesizeCacheEntry {
  cveId: string;
  imageTag: string;
  labKind: string;
  sizeMb: number;
  inUse: boolean;
  imagePresent: boolean;
  lastUsedAt: string | null;
  lastVerifiedAt: string | null;
  createdAt: string;
  ageDays: number;
}

export interface SynthesizeCacheReport {
  count: number;
  totalMb: number;
  inUseCount: number;
  missingImageCount: number;
  oldestLastUsedAt: string | null;
  maxTotalMb: number;
  maxCount: number;
  maxAgeDays: number;
  entries: SynthesizeCacheEntry[];
}

export interface EvictedImage {
  cveId: string;
  imageTag: string;
  sizeMb: number;
  reason: "age" | "count" | "total_size" | "image_missing" | string;
}

export interface LabKindStatsBucket {
  source: string;
  labKind: string;
  count: number;
  verifiedCount: number;
}

export interface LabKindStatsReport {
  total: number;
  verified: number;
  bySource: LabKindStatsBucket[];
  byKind: LabKindStatsBucket[];
}

export interface FacetBucket {
  value: string;
  count: number;
}

export interface DashboardTimelineDay {
  date: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface DashboardVendorBucket {
  vendor: string;
  count: number;
}

export interface DashboardCvssBucket {
  label: string;
  rangeLo: number;
  rangeHi: number;
  count: number;
}

export interface DashboardCvssHistogramBin {
  lo: number;
  hi: number;
  count: number;
}

export interface DashboardCvssDistribution {
  histogram: DashboardCvssHistogramBin[];
  total: number;
  mean: number | null;
  median: number | null;
  p90: number | null;
  unscored: number;
}

export interface DashboardRecentItem {
  cveId: string;
  title: string;
  severity: string | null;
  cvssScore: number | null;
  publishedAt: string | null;
}

export interface DashboardPrioritySignalCounts {
  cvssCritical: number;
  cvssHigh: number;
  epssHigh: number;
  epssTopPercentile: number;
  kevListed: number;
}

export interface DashboardInsightsResponse {
  timeline: DashboardTimelineDay[];
  topVendors: DashboardVendorBucket[];
  cvssBuckets: DashboardCvssBucket[];
  cvssDistribution: DashboardCvssDistribution;
  recentCritical: DashboardRecentItem[];
  prioritySignals: DashboardPrioritySignalCounts;
  generatedAt: string;
}

export interface DashboardPriorityItem {
  cveId: string;
  title: string;
  severity: string | null;
  cvssScore: number | null;
  epssScore: number | null;
  epssPercentile: number | null;
  kevListed: boolean;
  kevDateAdded: string | null;
  publishedAt: string | null;
}

export interface DashboardPriorityBucket {
  key: "kev" | "epss_high" | "cvss_mid_epss_high" | "cvss_high_epss_low";
  label: string;
  rationale: string;
  count: number;
  items: DashboardPriorityItem[];
}

export interface DashboardPrioritiesResponse {
  buckets: DashboardPriorityBucket[];
  generatedAt: string;
}

export interface SearchFacetsResponse {
  // Authoritative whole-corpus row count. Always render absolute counts
  // against this number — facet bucket sums (severities/types) are
  // unreliable because they exclude NULLs or double-count M:N rows.
  total: number;
  types: FacetBucket[];
  osFamilies: FacetBucket[];
  severities: FacetBucket[];
  sources: FacetBucket[];
  domains: FacetBucket[];
  earliestPublishedAt: string | null;
  latestPublishedAt: string | null;
}

export interface SynthCandidate {
  mappingId: number;
  rank: number;
  labKind: string;
  digest: string;
  verified: boolean;
  feedbackUp: number;
  feedbackDown: number;
  degraded: boolean;
  lastVerifiedAt: string | null;
  createdAt: string | null;
  isPlaceholder: boolean;
}

export interface SynthCandidatesResponse {
  cveId: string;
  candidates: SynthCandidate[];
}

export interface SynthesizeGcResponse {
  scanned: number;
  evicted: EvictedImage[];
  freedMb: number;
  retainedCount: number;
  retainedTotalMb: number;
  skippedInUse: string[];
}

export interface NoLabDetail {
  code: "no_lab" | "synthesis_failed" | "lab_degraded";
  canSynthesize?: boolean;
  feedbackUp?: number;
  feedbackDown?: number;
  message: string;
}

export function isNoLabDetail(detail: unknown): detail is NoLabDetail {
  if (!detail || typeof detail !== "object") return false;
  const code = (detail as { code?: unknown }).code;
  return code === "no_lab" || code === "synthesis_failed" || code === "lab_degraded";
}

export interface LabFeedbackResponse {
  mappingId: number;
  feedbackUp: number;
  feedbackDown: number;
  myVote: "up" | "down" | null;
  degraded: boolean;
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
  // 본인 글이거나 admin 이면 true — 삭제/수정 버튼 노출 기준 (PR 10-CO follow-up).
  canManage: boolean;
  // PR 10-DB — 좋아요.
  likeCount: number;
  isLiked: boolean;
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
  canManage: boolean;
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
