"use client";

/**
 * "남이 한 분석" 피드 — /analysis(AI 분석 기록) 탭에서 사용.
 *
 * /community/analyses 는 다른 사용자가 ``public`` 으로 공개한 분석 기록을
 * 반환한다(본인 분석 포함). 최신순 / 우선순위순 / EPSS순 / 유형·위험도별 /
 * 작성자별 보기 + 검색 + 작성자 유형 필터를 제공하고, 카드 클릭 시 공용 모달로
 * 본문·댓글을 본다.
 *
 * 정렬·검색·그룹핑을 **모두 서버측**에서 처리하고 페이지네이션한다. 예전엔 최근
 * 50건만 받아 클라에서 정렬/그룹핑 → 그 창 밖 오래된 분석(예: 며칠 전 에이전트
 * 분석 수백 건)이 어떤 정렬에서도 로드되지 않아 "사라진 것처럼" 보였다. 이제
 * 전체 분석을 정렬 기준대로 빠짐없이 넘겨볼 수 있고, 브라우저/기기와 무관하게
 * 동일하게 표시된다. 작성자별·유형별·위험도별 그룹 헤더는 /facets 집계(전체
 * 기준)로, 실제 항목은 username/type/severity 필터로 확장 조회한다.
 */
import { useEffect, useMemo, useState } from "react";
import {
  keepPreviousData,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import {
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Clock,
  Folder,
  Gauge,
  Globe,
  Heart,
  Loader2,
  Lock,
  MessageSquare,
  Search,
  ShieldAlert,
  Users,
  X,
  Zap,
} from "lucide-react";

import {
  api,
  type AnalysisFacets,
  type AnalysisList,
  type AnalysisSummary,
  type FacetAuthor,
} from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { ErrorBox } from "@/components/ui/feedback-box";
import { AuthorInline } from "@/components/community/AuthorInline";
import { CommentThread } from "@/components/community/CommentThread";
import {
  AnalysisDetailModal,
  AgentBadge,
} from "@/components/community/AnalysisDetailModal";
import { formatRelativeKo, avatarInitial } from "@/lib/format";
import { cn } from "@/lib/utils";
import { PipelineBadges, PRIORITY_RANK } from "@/components/community/PipelineBadges";

type ViewMode = "latest" | "priority" | "epss" | "category" | "author";

const VIEW_LABELS: Record<ViewMode, { label: string; icon: typeof Clock }> = {
  latest: { label: "최신순", icon: Clock },
  priority: { label: "우선순위순", icon: Zap },
  epss: { label: "EPSS순", icon: Gauge },
  category: { label: "유형·위험도별", icon: Folder },
  author: { label: "작성자별", icon: Users },
};

const SEVERITY_LABEL: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  unscored: "미분류",
};
const SEVERITY_ORDER = ["critical", "high", "medium", "low", "unscored"];
const SEVERITY_TONE: Record<string, string> = {
  critical: "bg-rose-100 text-rose-800 dark:bg-rose-500/15 dark:text-rose-200",
  high: "bg-orange-100 text-orange-800 dark:bg-orange-500/15 dark:text-orange-200",
  medium: "bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-200",
  low: "bg-emerald-100 text-emerald-800 dark:bg-emerald-500/15 dark:text-emerald-200",
};

const PAGE = 30; // 페이지/그룹 당 렌더 건수

type Group = {
  key: string; // username | type name | severity name
  label: string;
  count: number;
  kind: "author" | "type" | "severity";
  author?: FacetAuthor;
};

export function AnalysisFeed() {
  const { user } = useAuth();
  const qc = useQueryClient();
  const myUsername = user?.username;

  const [openId, setOpenId] = useState<string | null>(null);
  const [view, setView] = useState<ViewMode>("latest");
  const [categoryAxis, setCategoryAxis] = useState<"types" | "severity">("types");
  const [search, setSearch] = useState("");
  const [debounced, setDebounced] = useState("");
  const [agentFilter, setAgentFilter] = useState<"all" | "agent" | "human">("all");
  const [pipelineOnly, setPipelineOnly] = useState(false);
  const [scope, setScope] = useState<"all" | "mine">("all");
  const [page, setPage] = useState(0); // flat 페이지
  const [expandedKey, setExpandedKey] = useState<string | null>(null); // 그룹 확장(1개)
  const [groupCount, setGroupCount] = useState(PAGE); // 확장 그룹 렌더 개수
  const [openComments, setOpenComments] = useState<Set<string>>(new Set());

  // 검색 디바운스.
  useEffect(() => {
    const t = setTimeout(() => setDebounced(search.trim()), 300);
    return () => clearTimeout(t);
  }, [search]);

  // 필터/뷰가 바뀌면 페이지·확장 초기화.
  useEffect(() => {
    setPage(0);
    setExpandedKey(null);
    setGroupCount(PAGE);
  }, [view, agentFilter, pipelineOnly, scope, categoryAxis, debounced]);

  const authorParam = agentFilter === "all" ? undefined : agentFilter;
  const sortParam: "recent" | "priority" | "epss" =
    view === "priority" ? "priority" : view === "epss" ? "epss" : "recent";
  const q = debounced || undefined;
  // 검색 중에는 그룹핑 대신 평면 검색 결과를 보여준다(그룹+검색은 혼란).
  const grouping = (view === "author" || view === "category") && !q;

  const toggleComments = (id: string) =>
    setOpenComments((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  // ─── mutations (좋아요 / 공유) ───────────────────────────
  const afeedPredicate = (queryKey: readonly unknown[]) =>
    typeof queryKey[0] === "string" && (queryKey[0] as string).startsWith("afeed");

  const share = useMutation({
    mutationFn: ({ id, visibility }: { id: string; visibility: "public" | "private" }) =>
      api.updateAnalysisRecord(id, { visibility }),
    onSuccess: () => qc.invalidateQueries({ predicate: (query) => afeedPredicate(query.queryKey) }),
  });

  const likeMut = useMutation({
    mutationFn: ({ id, next }: { id: string; next: boolean }) =>
      next ? api.likeAnalysis(id) : api.unlikeAnalysis(id),
    onMutate: ({ id, next }) => {
      qc.setQueriesData<AnalysisList>(
        { predicate: (query) => afeedPredicate(query.queryKey) },
        (prev) =>
          prev
            ? {
                ...prev,
                items: prev.items.map((a) =>
                  a.id === id
                    ? {
                        ...a,
                        isLiked: next,
                        likeCount: Math.max(0, (a.likeCount ?? 0) + (next ? 1 : -1)),
                      }
                    : a,
                ),
              }
            : prev,
      );
    },
    onSettled: () => qc.invalidateQueries({ predicate: (query) => afeedPredicate(query.queryKey) }),
  });
  const toggleLike = (a: AnalysisSummary) => {
    if (!user) {
      if (typeof window !== "undefined") {
        window.location.href = `/login?next=${encodeURIComponent(window.location.pathname)}`;
      }
      return;
    }
    likeMut.mutate({ id: a.id, next: !a.isLiked });
  };

  // ─── 데이터 조회 ────────────────────────────────────────
  // scope=all: 서버 페이지네이션 / scope=mine: 전량 로드(본인 것은 유계라 안전).
  const flat = useQuery({
    queryKey: [
      "afeed-flat",
      scope,
      sortParam,
      authorParam ?? "all",
      pipelineOnly,
      q ?? "",
      page,
    ],
    queryFn: () =>
      scope === "mine"
        ? api.listMyAnalyses({ limit: 200, offset: 0 })
        : api.listCommunityAnalyses({
            sort: sortParam,
            author: authorParam,
            pipelineOnly,
            q,
            limit: PAGE,
            offset: page * PAGE,
          }),
    enabled: scope === "mine" || !grouping,
    placeholderData: keepPreviousData,
    staleTime: 30_000,
  });

  const facets = useQuery<AnalysisFacets>({
    queryKey: ["afeed-facets", authorParam ?? "all", pipelineOnly],
    queryFn: () => api.listAnalysisFacets({ author: authorParam, pipelineOnly }),
    enabled: scope === "all" && grouping,
    staleTime: 30_000,
  });

  // 확장한 그룹의 실제 항목(서버 필터).
  const expandedGroup: Group | null = useMemo(() => {
    if (!expandedKey || !facets.data) return null;
    if (view === "author") {
      const a = facets.data.authors.find((x) => x.username === expandedKey);
      return a
        ? { key: a.username, label: a.nickname || a.username, count: a.count, kind: "author", author: a }
        : null;
    }
    if (categoryAxis === "severity") {
      const s = facets.data.severities.find((x) => x.name === expandedKey);
      return s ? { key: s.name, label: SEVERITY_LABEL[s.name] || s.name, count: s.count, kind: "severity" } : null;
    }
    const t = facets.data.types.find((x) => x.name === expandedKey);
    return t ? { key: t.name, label: t.name, count: t.count, kind: "type" } : null;
  }, [expandedKey, facets.data, view, categoryAxis]);

  const groupItems = useQuery({
    queryKey: [
      "afeed-group",
      expandedGroup?.kind ?? "",
      expandedKey ?? "",
      authorParam ?? "all",
      pipelineOnly,
      groupCount,
    ],
    queryFn: () =>
      api.listCommunityAnalyses({
        ...(expandedGroup?.kind === "author" ? { username: expandedKey! } : {}),
        ...(expandedGroup?.kind === "type" ? { type: expandedKey! } : {}),
        ...(expandedGroup?.kind === "severity" ? { severity: expandedKey! } : {}),
        author: expandedGroup?.kind === "author" ? undefined : authorParam,
        pipelineOnly,
        limit: groupCount,
        offset: 0,
      }),
    enabled: scope === "all" && grouping && !!expandedGroup,
    placeholderData: keepPreviousData,
    staleTime: 30_000,
  });

  // 그룹 헤더 목록(전체 집계 기준).
  const groups: Group[] = useMemo(() => {
    if (scope !== "all" || !grouping || !facets.data) return [];
    if (view === "author") {
      return facets.data.authors.map((a) => ({
        key: a.username,
        label: a.nickname || a.username,
        count: a.count,
        kind: "author" as const,
        author: a,
      }));
    }
    if (categoryAxis === "severity") {
      return [...facets.data.severities]
        .sort((a, b) => {
          const ai = SEVERITY_ORDER.indexOf(a.name);
          const bi = SEVERITY_ORDER.indexOf(b.name);
          return (ai < 0 ? 99 : ai) - (bi < 0 ? 99 : bi);
        })
        .map((s) => ({
          key: s.name,
          label: SEVERITY_LABEL[s.name] || s.name,
          count: s.count,
          kind: "severity" as const,
        }));
    }
    return facets.data.types.map((t) => ({
      key: t.name,
      label: t.name,
      count: t.count,
      kind: "type" as const,
    }));
  }, [scope, grouping, facets.data, view, categoryAxis]);

  // scope=mine 는 전량 로드 후 클라에서 정렬/검색.
  const mineSorted = useMemo(() => {
    if (scope !== "mine" || !flat.data) return [] as AnalysisSummary[];
    const items = flat.data.items.filter((a) => {
      if (agentFilter === "agent" && !a.author.isAgent) return false;
      if (agentFilter === "human" && a.author.isAgent) return false;
      if (pipelineOnly && !a.pipelineVersion) return false;
      if (q) {
        const hay = `${a.cveId} ${a.title ?? ""} ${a.excerpt} ${a.author.nickname ?? ""} ${a.author.username} ${a.cveTypes.join(" ")} ${a.cveSeverity ?? ""}`.toLowerCase();
        if (!hay.includes(q.toLowerCase())) return false;
      }
      return true;
    });
    const byDate = (x: AnalysisSummary, y: AnalysisSummary) =>
      +new Date(y.createdAt) - +new Date(x.createdAt);
    const epssOf = (x: AnalysisSummary) =>
      typeof x.epssScore === "number" && Number.isFinite(x.epssScore) ? x.epssScore : -1;
    const arr = [...items];
    if (view === "priority") {
      const rankOf = (x: AnalysisSummary) =>
        x.priorityAction != null ? (PRIORITY_RANK[x.priorityAction] ?? 8) : 9;
      arr.sort((x, y) => rankOf(x) - rankOf(y) || epssOf(y) - epssOf(x) || byDate(x, y));
    } else if (view === "epss") {
      arr.sort((x, y) => epssOf(y) - epssOf(x) || byDate(x, y));
    } else {
      arr.sort(byDate);
    }
    return arr;
  }, [scope, flat.data, agentFilter, pipelineOnly, q, view]);

  // 현재 화면에 표시 중인 항목(모달 summary 조회용).
  const displayed: AnalysisSummary[] =
    scope === "mine"
      ? mineSorted
      : grouping
        ? groupItems.data?.items ?? []
        : flat.data?.items ?? [];

  const totalPages = Math.max(1, Math.ceil((flat.data?.total ?? 0) / PAGE));
  const grandTotal = flat.data?.total ?? 0;

  const isPending = scope === "all" && grouping ? facets.isPending : flat.isPending;
  const isError = scope === "all" && grouping ? facets.isError : flat.isError;

  // ─── 렌더 조각 ─────────────────────────────────────────
  const header = (
    <div className="mb-3 text-xs text-neutral-600 dark:text-neutral-500">
      <span>
        {q
          ? `"${debounced}" 검색 결과 — 전체 분석에서 찾습니다.`
          : view === "latest"
            ? "공유된 분석을 시간 역순으로 — 페이지로 전체를 넘겨볼 수 있어요."
            : view === "priority"
              ? "파이프라인 우선순위(즉시 대응 → 예정 대응 → 모니터링) 순 — 우선순위 없는 분석은 뒤에."
              : view === "epss"
                ? "EPSS(30일 내 익스플로잇 확률) 높은 순 — EPSS 없는 분석은 뒤에."
                : view === "category"
                  ? categoryAxis === "severity"
                    ? "위험도별 그룹 — 행을 눌러 펼쳐 보세요(전체 집계 기준)."
                    : "취약점 유형별 그룹 — 행을 눌러 펼쳐 보세요(전체 집계 기준)."
                  : "작성자별 그룹 — 행을 눌러 펼쳐 보세요(전체 집계 기준)."}
      </span>
    </div>
  );

  const controls = (
    <div className="mb-4 space-y-2">
      <div className="relative">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-neutral-500" />
        <input
          type="search"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="CVE ID · 제목 · 작성자 · 본문 키워드"
          className="block w-full rounded-full border border-neutral-300 bg-white py-2 pl-9 pr-9 text-xs text-neutral-900 placeholder:text-neutral-500 focus:border-violet-500 focus:outline-none focus:ring-2 focus:ring-violet-200 dark:border-neutral-700 dark:bg-surface-1 dark:text-neutral-100 dark:placeholder:text-neutral-500 dark:focus:ring-violet-500/30"
        />
        {search && (
          <button
            type="button"
            onClick={() => setSearch("")}
            aria-label="검색어 지우기"
            className="absolute right-2 top-1/2 inline-flex h-6 w-6 -translate-y-1/2 items-center justify-center rounded-full text-neutral-500 hover:bg-neutral-100 hover:text-neutral-900 dark:hover:bg-surface-2 dark:hover:text-neutral-100"
          >
            <X className="h-3 w-3" />
          </button>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
        {([["all", "전체"], ["mine", "내 분석"]] as const).map(([v, l]) => (
          <button
            key={v}
            type="button"
            disabled={v === "mine" && !user}
            onClick={() => setScope(v)}
            className={cn(
              "rounded-full border px-2.5 py-1 font-medium transition-colors disabled:opacity-40",
              scope === v
                ? "border-violet-400 bg-violet-100 text-violet-800 dark:border-violet-500/50 dark:bg-violet-500/20 dark:text-violet-200"
                : "border-neutral-300 text-neutral-600 hover:border-violet-300 dark:border-neutral-700 dark:text-neutral-400",
            )}
            aria-pressed={scope === v}
            title={v === "mine" && !user ? "로그인 후 이용" : undefined}
          >
            {l}
          </button>
        ))}
        <span className="mx-1 h-3 w-px bg-neutral-300 dark:bg-neutral-700" />
        {([["all", "전체"], ["agent", "🤖 에이전트"], ["human", "사람"]] as const).map(([v, l]) => (
          <button
            key={v}
            type="button"
            onClick={() => setAgentFilter(v)}
            className={cn(
              "rounded-full border px-2.5 py-1 font-medium transition-colors",
              agentFilter === v
                ? "border-sky-400 bg-sky-100 text-sky-800 dark:border-sky-500/50 dark:bg-sky-500/20 dark:text-sky-200"
                : "border-neutral-300 text-neutral-600 hover:border-sky-300 dark:border-neutral-700 dark:text-neutral-400",
            )}
            aria-pressed={agentFilter === v}
          >
            {l}
          </button>
        ))}
        <span className="mx-1 h-3 w-px bg-neutral-300 dark:bg-neutral-700" />
        <button
          type="button"
          onClick={() => setPipelineOnly((v) => !v)}
          className={cn(
            "rounded-full border px-2.5 py-1 font-medium transition-colors",
            pipelineOnly
              ? "border-emerald-400 bg-emerald-100 text-emerald-800 dark:border-emerald-500/50 dark:bg-emerald-500/20 dark:text-emerald-200"
              : "border-neutral-300 text-neutral-600 hover:border-emerald-300 dark:border-neutral-700 dark:text-neutral-400",
          )}
          aria-pressed={pipelineOnly}
          title="구조화 검증 파이프라인이 생성한 분석만 보기"
        >
          ⚙ 파이프라인 검증
        </button>
      </div>
      <div className="inline-flex w-full flex-wrap items-center gap-1 rounded-2xl border border-neutral-200 bg-neutral-50 p-1 text-xs dark:border-neutral-800 dark:bg-surface-1 sm:w-auto sm:rounded-full">
        {(Object.keys(VIEW_LABELS) as ViewMode[]).map((m) => {
          const { label, icon: Icon } = VIEW_LABELS[m];
          const active = view === m;
          return (
            <button
              key={m}
              type="button"
              onClick={() => setView(m)}
              className={cn(
                "inline-flex flex-1 items-center justify-center gap-1 whitespace-nowrap rounded-full px-2 py-1 font-medium transition-colors sm:flex-none sm:px-2.5",
                active
                  ? "bg-white text-neutral-900 shadow-sm dark:bg-surface-2 dark:text-neutral-100"
                  : "text-neutral-600 hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-neutral-100",
              )}
              aria-pressed={active}
            >
              <Icon className="h-3 w-3" />
              {label}
            </button>
          );
        })}
      </div>

      {view === "category" && (
        <div className="inline-flex items-center gap-1 rounded-full border border-neutral-200 bg-neutral-50 p-1 text-[11px] dark:border-neutral-800 dark:bg-surface-1">
          {(
            [
              { id: "types" as const, label: "취약점 유형", icon: Folder },
              { id: "severity" as const, label: "위험도", icon: ShieldAlert },
            ]
          ).map(({ id, label, icon: Icon }) => {
            const active = categoryAxis === id;
            return (
              <button
                key={id}
                type="button"
                onClick={() => setCategoryAxis(id)}
                className={cn(
                  "inline-flex items-center gap-1 rounded-full px-2.5 py-1 font-medium transition-colors",
                  active
                    ? "bg-white text-neutral-900 shadow-sm dark:bg-surface-2 dark:text-neutral-100"
                    : "text-neutral-600 hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-neutral-100",
                )}
              >
                <Icon className="h-3 w-3" />
                {label}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );

  const renderCard = (a: AnalysisSummary) => {
    const isMine = !!myUsername && a.author.username === myUsername;
    const isPublic = a.visibility === "public";
    return (
      <li
        key={a.id}
        className="overflow-hidden rounded-lg border border-neutral-200 bg-white transition-all duration-150 hover:border-violet-300 hover:shadow-md hover:shadow-violet-900/5 dark:border-neutral-800 dark:bg-surface-1 dark:hover:border-violet-500/40"
      >
        <button
          type="button"
          onClick={() => setOpenId(a.id)}
          className="block w-full p-4 text-left"
        >
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs">
            <span className="rounded-full bg-violet-100 px-2 py-0.5 font-medium text-violet-800 dark:bg-violet-500/15 dark:text-violet-200">
              {a.cveId}
            </span>
            <span className="text-neutral-500 dark:text-neutral-500">·</span>
            <span onClick={(e) => e.stopPropagation()} className="contents">
              <AuthorInline
                author={a.author}
                className="font-medium text-neutral-800 dark:text-neutral-200"
              />
            </span>
            {a.author.isAgent && <AgentBadge persona={a.author.persona} id={a.author.id} />}
            <span className="text-neutral-500 dark:text-neutral-500">·</span>
            <span className="tabular-nums text-neutral-600 dark:text-neutral-500">
              {formatRelativeKo(a.createdAt)}
            </span>
            {a.cveSeverity && (
              <>
                <span className="text-neutral-500 dark:text-neutral-500">·</span>
                <span
                  className={cn(
                    "rounded-full px-2 py-0.5 font-medium",
                    SEVERITY_TONE[a.cveSeverity] ||
                      "bg-surface-2 text-neutral-700 dark:text-neutral-300",
                  )}
                >
                  {SEVERITY_LABEL[a.cveSeverity] || a.cveSeverity}
                </span>
              </>
            )}
            {a.cveTypes.slice(0, 2).map((t) => (
              <span
                key={t}
                className="rounded-full bg-violet-50 px-2 py-0.5 text-violet-700 dark:bg-violet-500/10 dark:text-violet-300"
              >
                {t}
              </span>
            ))}
            <PipelineBadges a={a} />
          </div>
          {a.title && (
            <h3 className="mt-2 text-sm font-semibold text-neutral-900 dark:text-neutral-100">
              {a.title}
            </h3>
          )}
          <p className="mt-1.5 line-clamp-2 text-xs leading-relaxed text-neutral-700 dark:text-neutral-400">
            {a.excerpt}
          </p>
        </button>
        <div className="flex items-center justify-between gap-2 border-t border-neutral-100 px-4 py-2 dark:border-neutral-800/60">
          <div className="flex items-center gap-1">
            <button
              type="button"
              onClick={() => toggleComments(a.id)}
              className="inline-flex items-center gap-1.5 rounded-full px-2 py-1 text-[11px] text-neutral-500 transition-colors hover:bg-sky-50 hover:text-sky-600 dark:text-neutral-400 dark:hover:bg-sky-500/10 dark:hover:text-sky-300"
              title="댓글"
            >
              <MessageSquare className="h-3.5 w-3.5" />
              <span className="tabular-nums">{a.commentCount ?? 0}</span>
              <span>댓글</span>
            </button>
            <button
              type="button"
              onClick={() => toggleLike(a)}
              aria-pressed={a.isLiked}
              className={cn(
                "inline-flex items-center gap-1.5 rounded-full px-2 py-1 text-[11px] transition-colors hover:bg-rose-50 hover:text-rose-600 dark:hover:bg-rose-500/10 dark:hover:text-rose-300",
                a.isLiked ? "text-rose-600 dark:text-rose-400" : "text-neutral-500 dark:text-neutral-400",
              )}
              title={a.isLiked ? "좋아요 취소" : "좋아요"}
            >
              <Heart className={cn("h-3.5 w-3.5", a.isLiked && "fill-current")} />
              <span className="tabular-nums">{a.likeCount ?? 0}</span>
            </button>
          </div>
          {isMine && (
            <button
              type="button"
              disabled={share.isPending}
              onClick={() =>
                share.mutate({ id: a.id, visibility: isPublic ? "private" : "public" })
              }
              className={cn(
                "inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors disabled:opacity-50",
                isPublic
                  ? "border-emerald-300 bg-emerald-50 text-emerald-700 hover:bg-emerald-100 dark:border-emerald-500/40 dark:bg-emerald-500/15 dark:text-emerald-300"
                  : "border-violet-500 bg-violet-600 text-white hover:bg-violet-500",
              )}
              title={isPublic ? "커뮤니티에 공개 중 — 누르면 비공개" : "커뮤니티에 공유"}
            >
              {share.isPending && share.variables?.id === a.id ? (
                <Loader2 className="h-3 w-3 animate-spin" />
              ) : isPublic ? (
                <Globe className="h-3 w-3" />
              ) : (
                <Lock className="h-3 w-3" />
              )}
              {isPublic ? "공유 중" : "공유"}
            </button>
          )}
        </div>
        {openComments.has(a.id) && (
          <div className="border-t border-neutral-100 px-3 py-3 dark:border-neutral-800/60">
            <CommentThread analysisId={a.id} />
          </div>
        )}
      </li>
    );
  };

  // ─── 상태별 조기 반환 ──────────────────────────────────
  if (isPending) {
    return (
      <>
        {header}
        {controls}
        <div className="space-y-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <div
              key={i}
              className="h-24 animate-pulse rounded-lg border border-neutral-200 bg-neutral-50 dark:border-neutral-800 dark:bg-surface-1/50"
            />
          ))}
        </div>
      </>
    );
  }
  if (isError) {
    return (
      <>
        {header}
        {controls}
        <ErrorBox title="분석 피드를 불러오지 못했습니다" message="잠시 후 다시 시도해 주세요." />
      </>
    );
  }

  const emptyFlat = !grouping && displayed.length === 0;
  const emptyGroups = grouping && groups.length === 0;
  if (emptyFlat || emptyGroups) {
    return (
      <>
        {header}
        {controls}
        <div className="rounded-xl border border-dashed border-neutral-300 bg-neutral-50 px-6 py-10 text-center text-xs text-neutral-700 dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-400">
          {q
            ? `"${debounced}" 와 일치하는 분석이 없어요.`
            : scope === "mine"
              ? "아직 내 분석이 없어요."
              : "아직 공유된 분석이 없어요."}
        </div>
        <AnalysisDetailModal
          analysisId={openId}
          summary={displayed.find((a) => a.id === openId) ?? null}
          onClose={() => setOpenId(null)}
        />
      </>
    );
  }

  // 평면 페이지네이션(최신/우선순위/EPSS, 또는 검색). scope=mine 은 클라 목록.
  const flatList = scope === "mine" ? mineSorted : flat.data?.items ?? [];

  return (
    <>
      {header}
      {controls}

      {grouping ? (
        <ul className="space-y-2">
          {groups.map((g) => {
            const expanded = expandedKey === g.key;
            const isAgent = g.kind === "author" ? !!g.author?.isAgent : false;
            const avatar =
              g.kind === "author"
                ? isAgent
                  ? g.author?.avatarEmoji || "🤖"
                  : avatarInitial(g.label).toUpperCase()
                : g.kind === "severity"
                  ? "◆"
                  : "#";
            return (
              <li key={g.key}>
                <button
                  type="button"
                  onClick={() => {
                    setExpandedKey(expanded ? null : g.key);
                    setGroupCount(PAGE);
                  }}
                  aria-expanded={expanded}
                  className="flex w-full items-center gap-3 rounded-lg border border-neutral-200 bg-white px-4 py-3 text-left transition-colors hover:border-violet-300 dark:border-neutral-800 dark:bg-surface-1 dark:hover:border-violet-500/40"
                >
                  <span
                    className={cn(
                      "flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-xs font-semibold",
                      g.kind === "severity" && SEVERITY_TONE[g.key]
                        ? SEVERITY_TONE[g.key]
                        : "bg-sky-100 text-base text-sky-800 dark:bg-sky-500/20 dark:text-sky-200",
                    )}
                  >
                    {avatar}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium text-neutral-900 dark:text-neutral-100">
                      {g.label}
                    </span>
                    {g.kind === "author" && g.author?.lastCveId && (
                      <span className="block truncate text-[11px] text-neutral-600 dark:text-neutral-400">
                        가장 최근 · {g.author.lastCveId}
                        {g.author.lastCreatedAt ? ` · ${formatRelativeKo(g.author.lastCreatedAt)}` : ""}
                      </span>
                    )}
                  </span>
                  <span className="inline-flex items-center gap-1 rounded-full bg-violet-100 px-2 py-0.5 text-[11px] font-medium tabular-nums text-violet-800 dark:bg-violet-500/15 dark:text-violet-200">
                    {g.count}건
                  </span>
                  {expanded ? (
                    <ChevronDown className="h-4 w-4 text-neutral-500" />
                  ) : (
                    <ChevronRight className="h-4 w-4 text-neutral-500" />
                  )}
                </button>
                {expanded && (
                  <div className="mt-2 ml-4 border-l-2 border-neutral-200 pl-4 dark:border-neutral-800">
                    {groupItems.isPending ? (
                      <div className="space-y-2">
                        {Array.from({ length: 3 }).map((_, i) => (
                          <div
                            key={i}
                            className="h-20 animate-pulse rounded-lg border border-neutral-200 bg-neutral-50 dark:border-neutral-800 dark:bg-surface-1/50"
                          />
                        ))}
                      </div>
                    ) : (
                      <>
                        <ul className="space-y-2">{(groupItems.data?.items ?? []).map(renderCard)}</ul>
                        {(groupItems.data?.items.length ?? 0) < g.count && (
                          <button
                            type="button"
                            onClick={() => setGroupCount((c) => c + PAGE)}
                            className="mt-2 w-full rounded-lg border border-neutral-200 bg-white py-2 text-xs font-medium text-violet-700 transition-colors hover:border-violet-300 dark:border-neutral-800 dark:bg-surface-1 dark:text-violet-300"
                          >
                            더 보기 ({groupItems.data?.items.length ?? 0}/{g.count})
                          </button>
                        )}
                      </>
                    )}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      ) : (
        <>
          {scope === "all" && (
            <div className="mb-2 flex items-center justify-between text-[11px] text-neutral-600 dark:text-neutral-400">
              <span className="tabular-nums">전체 {grandTotal.toLocaleString()}건</span>
              <span className="tabular-nums">
                {page + 1} / {totalPages} 페이지
              </span>
            </div>
          )}
          <ul className="space-y-3">{flatList.map(renderCard)}</ul>
          {scope === "all" && totalPages > 1 && (
            <div className="mt-4 flex items-center justify-center gap-2 text-xs">
              <button
                type="button"
                disabled={page === 0 || flat.isFetching}
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                className="inline-flex items-center gap-1 rounded-full border border-neutral-300 px-3 py-1.5 font-medium text-neutral-700 transition-colors hover:border-violet-300 disabled:opacity-40 dark:border-neutral-700 dark:text-neutral-300"
              >
                <ChevronLeft className="h-3.5 w-3.5" /> 이전
              </button>
              <span className="tabular-nums text-neutral-600 dark:text-neutral-400">
                {page + 1} / {totalPages}
              </span>
              <button
                type="button"
                disabled={page + 1 >= totalPages || flat.isFetching}
                onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                className="inline-flex items-center gap-1 rounded-full border border-neutral-300 px-3 py-1.5 font-medium text-neutral-700 transition-colors hover:border-violet-300 disabled:opacity-40 dark:border-neutral-700 dark:text-neutral-300"
              >
                다음 <ChevronRight className="h-3.5 w-3.5" />
              </button>
            </div>
          )}
        </>
      )}

      <AnalysisDetailModal
        analysisId={openId}
        summary={displayed.find((a) => a.id === openId) ?? null}
        onClose={() => setOpenId(null)}
      />
    </>
  );
}
