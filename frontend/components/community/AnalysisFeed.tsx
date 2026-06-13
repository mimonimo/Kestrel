"use client";

/**
 * "남이 한 분석" 피드 — /analysis(AI 분석 기록) 탭에서 사용.
 *
 * /community/analyses 는 다른 사용자가 ``public`` 으로 공개한 분석 기록을
 * 반환한다(본인 분석 자동 제외). 최신순 / 유형·위험도별 / 작성자별 보기 +
 * 검색 + 작성자 유형 필터를 제공하고, 카드 클릭 시 공용 모달로 본문·댓글을 본다.
 */
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ChevronDown,
  ChevronRight,
  Clock,
  Folder,
  Globe,
  Loader2,
  Lock,
  MessageSquare,
  Search,
  ShieldAlert,
  Sparkles,
  Users,
  X,
} from "lucide-react";

import { api, type AnalysisSummary } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { ErrorBox } from "@/components/ui/feedback-box";
import { AuthorInline } from "@/components/community/AuthorInline";
import { CommentThread } from "@/components/community/CommentThread";
import {
  AnalysisDetailModal,
  AgentBadge,
} from "@/components/community/AnalysisDetailModal";
import { formatRelativeKo } from "@/lib/format";
import { cn } from "@/lib/utils";

type ViewMode = "latest" | "category" | "author";

const VIEW_LABELS: Record<ViewMode, { label: string; icon: typeof Clock }> = {
  latest: { label: "최신순", icon: Clock },
  category: { label: "유형·위험도별", icon: Folder },
  author: { label: "작성자별", icon: Users },
};

const SEVERITY_LABEL: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};
const SEVERITY_ORDER = ["critical", "high", "medium", "low"];
const SEVERITY_TONE: Record<string, string> = {
  critical: "bg-rose-100 text-rose-800 dark:bg-rose-500/15 dark:text-rose-200",
  high: "bg-orange-100 text-orange-800 dark:bg-orange-500/15 dark:text-orange-200",
  medium: "bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-200",
  low: "bg-emerald-100 text-emerald-800 dark:bg-emerald-500/15 dark:text-emerald-200",
};

export function AnalysisFeed() {
  const { user } = useAuth();
  const qc = useQueryClient();
  const [openId, setOpenId] = useState<string | null>(null);
  const [view, setView] = useState<ViewMode>("latest");
  const [filterKey, setFilterKey] = useState<string | null>(null);
  const [categoryAxis, setCategoryAxis] = useState<"types" | "severity">("types");
  const [expandedAuthors, setExpandedAuthors] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState("");
  const [agentFilter, setAgentFilter] = useState<"all" | "agent" | "human">("all");
  // 범위: 전체(남 공개 + 내 분석) / 내 분석만.
  const [scope, setScope] = useState<"all" | "mine">("all");
  // 카드별 인라인 댓글 펼침.
  const [openComments, setOpenComments] = useState<Set<string>>(new Set());
  const toggleComments = (id: string) =>
    setOpenComments((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const community = useQuery({
    queryKey: ["community-analyses"],
    queryFn: () => api.listCommunityAnalyses({ limit: 50 }),
    staleTime: 30_000,
  });
  const mine = useQuery({
    queryKey: ["my-analyses"],
    queryFn: () => api.listMyAnalyses({ limit: 100 }),
    staleTime: 30_000,
    enabled: !!user,
  });

  // 내 분석(공개/비공개) + 남의 공개 분석을 합쳐 중복 제거.
  const allItems = useMemo<AnalysisSummary[]>(() => {
    const mineItems = mine.data?.items ?? [];
    if (scope === "mine") return mineItems;
    const seen = new Set(mineItems.map((a) => a.id));
    const others = (community.data?.items ?? []).filter((a) => !seen.has(a.id));
    return [...mineItems, ...others].sort(
      (a, b) => +new Date(b.createdAt) - +new Date(a.createdAt),
    );
  }, [community.data, mine.data, scope]);

  const myUsername = user?.username;
  const share = useMutation({
    mutationFn: ({ id, visibility }: { id: string; visibility: "public" | "private" }) =>
      api.updateAnalysisRecord(id, { visibility }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["community-analyses"] });
      qc.invalidateQueries({ queryKey: ["my-analyses"] });
    },
  });

  const list = scope === "mine" ? mine : community;

  const visibleItems = useMemo(() => {
    const q = search.trim().toLowerCase();
    return allItems.filter((a) => {
      if (agentFilter === "agent" && !a.author.isAgent) return false;
      if (agentFilter === "human" && a.author.isAgent) return false;
      if (q) {
        const hay =
          `${a.cveId} ${a.title ?? ""} ${a.excerpt} ${a.author.nickname ?? ""} ${a.author.username} ${a.cveTypes.join(" ")} ${a.cveSeverity ?? ""}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [allItems, search, agentFilter]);

  const grouped = useMemo(() => {
    const buckets = new Map<string, { label: string; items: AnalysisSummary[] }>();
    const push = (key: string, label: string, a: AnalysisSummary) => {
      if (!buckets.has(key)) buckets.set(key, { label, items: [] });
      buckets.get(key)!.items.push(a);
    };
    for (const a of visibleItems) {
      if (view === "author") {
        push(a.author.username, a.author.nickname || a.author.username, a);
      } else if (categoryAxis === "severity") {
        const sev = (a.cveSeverity || "unscored").toLowerCase();
        push(sev, SEVERITY_LABEL[sev] || "미분류", a);
      } else {
        if (a.cveTypes && a.cveTypes.length > 0) {
          for (const t of a.cveTypes) push(t, t, a);
        } else {
          push("(unclassified)", "분류 없음", a);
        }
      }
    }
    let entries = Array.from(buckets.entries()).map(([key, v]) => ({
      key,
      label: v.label,
      items: v.items,
    }));
    if (view === "category" && categoryAxis === "severity") {
      entries = entries.sort((a, b) => {
        const ai = SEVERITY_ORDER.indexOf(a.key);
        const bi = SEVERITY_ORDER.indexOf(b.key);
        return (ai < 0 ? 99 : ai) - (bi < 0 ? 99 : bi);
      });
    } else {
      entries.sort((a, b) => b.items.length - a.items.length || a.label.localeCompare(b.label));
    }
    return entries;
  }, [visibleItems, view, categoryAxis]);

  const filteredGroups = useMemo(
    () => (filterKey ? grouped.filter((g) => g.key === filterKey) : grouped),
    [grouped, filterKey],
  );

  const toggleAuthor = (key: string) => {
    setExpandedAuthors((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const header = (
    <div className="mb-3 text-xs text-neutral-600 dark:text-neutral-500">
      <span>
        {view === "latest"
          ? "다른 사용자가 공개한 분석을 시간 역순으로 보여줍니다."
          : view === "category"
            ? categoryAxis === "severity"
              ? "위험도별 그룹 — Critical / High / Medium / Low / 미분류 순."
              : "취약점 유형별 그룹 — XSS · SQLi · RCE · 인증 등 한 분석이 여러 유형에 속할 수 있어요."
            : "작성자별 그룹 — 행을 눌러 펼쳐 보세요."}
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
          placeholder="CVE ID · 제목 · 작성자 · 유형 · 본문 키워드"
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
            onClick={() => {
              setScope(v);
              setFilterKey(null);
            }}
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
      </div>
      <div className="inline-flex w-full items-center gap-1 rounded-full border border-neutral-200 bg-neutral-50 p-1 text-xs dark:border-neutral-800 dark:bg-surface-1 sm:w-auto">
        {(Object.keys(VIEW_LABELS) as ViewMode[]).map((m) => {
          const { label, icon: Icon } = VIEW_LABELS[m];
          const active = view === m;
          return (
            <button
              key={m}
              type="button"
              onClick={() => {
                setView(m);
                setFilterKey(null);
              }}
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
                onClick={() => {
                  setCategoryAxis(id);
                  setFilterKey(null);
                }}
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

      {view === "category" && grouped.length > 1 && (
        <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
          <button
            type="button"
            onClick={() => setFilterKey(null)}
            className={cn(
              "rounded-full border px-2.5 py-0.5 transition-colors",
              filterKey === null
                ? "border-violet-400 bg-violet-50 text-violet-800 dark:border-violet-500/50 dark:bg-violet-500/15 dark:text-violet-200"
                : "border-neutral-300 text-neutral-700 hover:border-violet-300 hover:text-violet-700 dark:border-neutral-700 dark:text-neutral-400 dark:hover:border-violet-500/40 dark:hover:text-violet-200",
            )}
          >
            전체 <span className="tabular-nums opacity-70">({allItems.length})</span>
          </button>
          {grouped.map((g) => (
            <button
              key={g.key}
              type="button"
              onClick={() => setFilterKey(g.key === filterKey ? null : g.key)}
              className={cn(
                "rounded-full border px-2.5 py-0.5 transition-colors",
                filterKey === g.key
                  ? "border-violet-400 bg-violet-50 text-violet-800 dark:border-violet-500/50 dark:bg-violet-500/15 dark:text-violet-200"
                  : categoryAxis === "severity" && SEVERITY_TONE[g.key]
                    ? `border-transparent ${SEVERITY_TONE[g.key]} hover:opacity-90`
                    : "border-neutral-300 text-neutral-700 hover:border-violet-300 hover:text-violet-700 dark:border-neutral-700 dark:text-neutral-400 dark:hover:border-violet-500/40 dark:hover:text-violet-200",
              )}
            >
              {g.label}{" "}
              <span className="tabular-nums opacity-70">({g.items.length})</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );

  if (list.isPending) {
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
  if (list.isError) {
    return (
      <>
        {header}
        {controls}
        <ErrorBox title="분석 피드를 불러오지 못했습니다" message="잠시 후 다시 시도해 주세요." />
      </>
    );
  }
  if (!list.data || allItems.length === 0) {
    return (
      <>
        {header}
        {controls}
        <div className="rounded-xl border border-neutral-200 bg-white px-6 py-12 text-center dark:border-neutral-800 dark:bg-surface-1">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-violet-500/15 ring-1 ring-violet-400/30">
            <Sparkles className="h-6 w-6 text-violet-700 dark:text-violet-300" />
          </div>
          <h3 className="text-base font-semibold text-neutral-900 dark:text-neutral-100">
            {scope === "mine" ? "아직 내 분석이 없어요" : "아직 공유된 분석이 없어요"}
          </h3>
          <p className="mt-1 text-sm text-neutral-700 dark:text-neutral-300">
            CVE 상세에서 AI 심층 분석을 실행하면 여기에 모이고, 공유 토글로 커뮤니티에 공개할 수 있어요.
          </p>
        </div>
      </>
    );
  }

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

  return (
    <>
      {header}
      {controls}
      {visibleItems.length === 0 ? (
        <div className="rounded-xl border border-dashed border-neutral-300 bg-neutral-50 px-6 py-10 text-center text-xs text-neutral-700 dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-400">
          {search ? `"${search}" 와 일치하는 분석이 없어요.` : "공유된 분석이 없어요."}
        </div>
      ) : view === "latest" ? (
        <ul className="space-y-3">{visibleItems.map(renderCard)}</ul>
      ) : view === "category" ? (
        <div className="space-y-6">
          {filteredGroups.map((g) => (
            <section key={g.key}>
              <h3 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-neutral-600 dark:text-neutral-400">
                {categoryAxis === "severity" ? (
                  <ShieldAlert className="h-3 w-3" />
                ) : (
                  <Folder className="h-3 w-3" />
                )}
                {g.label}
                <span className="tabular-nums font-normal text-neutral-500 dark:text-neutral-500">
                  · {g.items.length}건
                </span>
              </h3>
              <ul className="space-y-3">{g.items.map(renderCard)}</ul>
            </section>
          ))}
        </div>
      ) : (
        <ul className="space-y-2">
          {filteredGroups.map((g) => {
            const expanded = expandedAuthors.has(g.key);
            const sample = g.items[0];
            const initial = (g.label.trim().charAt(0) || "?").toUpperCase();
            return (
              <li key={g.key}>
                <button
                  type="button"
                  onClick={() => toggleAuthor(g.key)}
                  aria-expanded={expanded}
                  className="flex w-full items-center gap-3 rounded-lg border border-neutral-200 bg-white px-4 py-3 text-left transition-colors hover:border-violet-300 dark:border-neutral-800 dark:bg-surface-1 dark:hover:border-violet-500/40"
                >
                  <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-sky-100 text-xs font-semibold text-sky-800 dark:bg-sky-500/20 dark:text-sky-200">
                    {initial}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium text-neutral-900 dark:text-neutral-100">
                      {g.label}
                    </span>
                    <span className="block truncate text-[11px] text-neutral-600 dark:text-neutral-400">
                      가장 최근 · {sample.cveId} · {formatRelativeKo(sample.createdAt)}
                    </span>
                  </span>
                  <span className="inline-flex items-center gap-1 rounded-full bg-violet-100 px-2 py-0.5 text-[11px] font-medium tabular-nums text-violet-800 dark:bg-violet-500/15 dark:text-violet-200">
                    {g.items.length}건
                  </span>
                  {expanded ? (
                    <ChevronDown className="h-4 w-4 text-neutral-500" />
                  ) : (
                    <ChevronRight className="h-4 w-4 text-neutral-500" />
                  )}
                </button>
                {expanded && (
                  <ul className="mt-2 ml-4 space-y-2 border-l-2 border-neutral-200 pl-4 dark:border-neutral-800">
                    {g.items.map(renderCard)}
                  </ul>
                )}
              </li>
            );
          })}
        </ul>
      )}
      <AnalysisDetailModal
        analysisId={openId}
        summary={allItems.find((a) => a.id === openId) ?? null}
        onClose={() => setOpenId(null)}
      />
    </>
  );
}
