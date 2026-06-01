"use client";

/**
 * 커뮤니티 탭 안의 "남이 한 분석" 피드 (PR 10-CN+CO).
 *
 * /community/analyses 는 다른 사용자가 ``public`` 으로 공개한 분석 기록을
 * 시간 역순으로 반환한다. 본인 분석은 자동 제외 (백엔드에서 처리).
 * 각 카드 클릭 시 본문(result_md) 을 펼친 모달로 보여 준다.
 */
import Link from "next/link";
import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  ChevronDown,
  ChevronRight,
  Clock,
  ExternalLink,
  Folder,
  Loader2,
  Search,
  Share2,
  ShieldAlert,
  Sparkles,
  User as UserIcon,
  Users,
  X,
} from "lucide-react";

import { api, type AnalysisSummary } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { ErrorBox } from "@/components/ui/feedback-box";
import { ShareMyAnalysesModal } from "@/components/community/ShareMyAnalysesModal";
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
  const [openId, setOpenId] = useState<string | null>(null);
  const [shareOpen, setShareOpen] = useState(false);
  const [view, setView] = useState<ViewMode>("latest");
  // 그룹 모드에서 특정 키만 보고 싶을 때 클릭 필터 (null = 전체).
  const [filterKey, setFilterKey] = useState<string | null>(null);
  // 유형별 의 sub-axis: types (취약점 유형) | severity (위험도)
  const [categoryAxis, setCategoryAxis] = useState<"types" | "severity">("types");
  // 작성자별: 그룹별 펼침 상태. 기본 모두 접힘.
  const [expandedAuthors, setExpandedAuthors] = useState<Set<string>>(new Set());
  // 검색어 — CVE ID / 제목 / 작성자 / excerpt 매칭. client-side.
  const [search, setSearch] = useState("");

  const list = useQuery({
    queryKey: ["community-analyses"],
    queryFn: () => api.listCommunityAnalyses({ limit: 50 }),
    staleTime: 30_000,
  });

  // 검색어로 필터링된 items — 모든 view 의 source.
  const visibleItems = useMemo(() => {
    if (!list.data) return [] as AnalysisSummary[];
    const q = search.trim().toLowerCase();
    if (!q) return list.data.items;
    return list.data.items.filter((a) => {
      const hay =
        `${a.cveId} ${a.title ?? ""} ${a.excerpt} ${a.author.nickname ?? ""} ${a.author.username} ${a.cveTypes.join(" ")} ${a.cveSeverity ?? ""}`.toLowerCase();
      return hay.includes(q);
    });
  }, [list.data, search]);

  // 그룹화 — view 가 category(types/severity) / author 일 때 사용.
  // CVE 의 cveTypes 는 array 라 한 분석이 여러 유형 그룹에 동시 속할 수 있음 (의도).
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
        // 유형별 (types). 분석이 attach 된 CVE 의 cveTypes 가 비면 "분류 없음".
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
      // 위험도 순으로 정렬 (critical → low → unscored).
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

  // 헤더 — 로그인 사용자에겐 "내 분석 공유하기" 버튼 노출. 비로그인은 그대로 읽기만.
  const header = (
    <div className="mb-3 flex flex-wrap items-center justify-between gap-2 text-xs text-neutral-600 dark:text-neutral-500">
      <span>
        {view === "latest"
          ? "공개된 분석을 시간 역순으로 보여줍니다."
          : view === "category"
            ? categoryAxis === "severity"
              ? "위험도별 그룹 — Critical / High / Medium / Low / 미분류 순."
              : "취약점 유형별 그룹 — XSS · SQLi · RCE · 인증 등 한 분석이 여러 유형에 속할 수 있어요."
            : "작성자별 그룹 — 행을 눌러 펼쳐 보세요."}
      </span>
      {user && (
        <button
          type="button"
          onClick={() => setShareOpen(true)}
          className="inline-flex items-center gap-1.5 rounded-full bg-violet-600 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-violet-500 dark:bg-violet-500 dark:hover:bg-violet-400"
        >
          <Share2 className="h-3.5 w-3.5" />내 분석 공유하기
        </button>
      )}
    </div>
  );

  // 검색 input + 정렬/그룹 모드 토글 + (그룹 모드) 칩 필터.
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
            전체 <span className="tabular-nums opacity-70">({list.data?.items.length ?? 0})</span>
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
        <ShareMyAnalysesModal open={shareOpen} onClose={() => setShareOpen(false)} />
      </>
    );
  }
  if (list.isError) {
    return (
      <>
        {header}
        {controls}
        <ErrorBox
          title="분석 피드를 불러오지 못했습니다"
          message="잠시 후 다시 시도해 주세요."
        />
        <ShareMyAnalysesModal open={shareOpen} onClose={() => setShareOpen(false)} />
      </>
    );
  }
  if (!list.data || list.data.items.length === 0) {
    return (
      <>
        {header}
        {controls}
        <div className="rounded-xl border border-neutral-200 bg-white px-6 py-12 text-center dark:border-neutral-800 dark:bg-surface-1">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-violet-500/15 ring-1 ring-violet-400/30">
            <Sparkles className="h-6 w-6 text-violet-700 dark:text-violet-300" />
          </div>
          <h3 className="text-base font-semibold text-neutral-900 dark:text-neutral-100">
            아직 공유된 분석이 없어요
          </h3>
          <p className="mt-1 text-sm text-neutral-700 dark:text-neutral-300">
            CVE 상세에서 AI 심층 분석을 실행한 뒤,{" "}
            {user ? "위의 \"내 분석 공유하기\" 버튼" : "로그인 후 공유 버튼"}으로 골라 공개할 수 있어요.
          </p>
        </div>
        <ShareMyAnalysesModal open={shareOpen} onClose={() => setShareOpen(false)} />
      </>
    );
  }

  const renderCard = (a: AnalysisSummary) => (
    <li key={a.id}>
      <button
        type="button"
        onClick={() => setOpenId(a.id)}
        className="block w-full rounded-lg border border-neutral-200 bg-white p-4 text-left transition-all duration-150 hover:-translate-y-0.5 hover:border-violet-300 hover:shadow-md hover:shadow-violet-900/5 active:translate-y-0 dark:border-neutral-800 dark:bg-surface-1 dark:hover:border-violet-500/40"
      >
        <div className="flex flex-wrap items-baseline gap-x-2 text-xs">
          <span className="rounded-full bg-violet-100 px-2 py-0.5 font-medium text-violet-800 dark:bg-violet-500/15 dark:text-violet-200">
            {a.cveId}
          </span>
          <span className="text-neutral-500 dark:text-neutral-500">·</span>
          <span className="font-medium text-neutral-800 dark:text-neutral-200">
            {a.author.nickname || a.author.username}
          </span>
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
                    "bg-neutral-100 text-neutral-700 dark:bg-surface-2 dark:text-neutral-300",
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
    </li>
  );

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
        // 작성자별: 그룹 헤더만 먼저 표시, 클릭 시 펼침.
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
        summary={list.data.items.find((a) => a.id === openId) ?? null}
        onClose={() => setOpenId(null)}
      />
      <ShareMyAnalysesModal open={shareOpen} onClose={() => setShareOpen(false)} />
    </>
  );
}

function AnalysisDetailModal({
  analysisId,
  summary,
  onClose,
}: {
  analysisId: string | null;
  summary: AnalysisSummary | null;
  onClose: () => void;
}) {
  const detail = useQuery({
    queryKey: ["analysis-record", analysisId],
    queryFn: () => api.getAnalysisRecord(analysisId!),
    enabled: !!analysisId,
    staleTime: 60_000,
  });
  if (!analysisId) return null;
  const author = summary?.author;
  const created = summary?.createdAt;

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-neutral-950/60 px-4 py-10 backdrop-blur-sm animate-in fade-in duration-150"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className="relative w-full max-w-3xl rounded-2xl border border-neutral-200 bg-white shadow-2xl shadow-black/20 dark:border-neutral-800 dark:bg-surface-1 dark:shadow-black/50 animate-in zoom-in-95 duration-150"
        onClick={(e) => e.stopPropagation()}
      >
        <button
          type="button"
          onClick={onClose}
          aria-label="닫기"
          className="absolute right-3 top-3 z-10 inline-flex h-8 w-8 items-center justify-center rounded-full text-neutral-500 transition-colors hover:bg-neutral-100 hover:text-neutral-900 dark:hover:bg-surface-2 dark:hover:text-neutral-100"
        >
          <X className="h-4 w-4" />
        </button>

        <article className="px-6 py-7">
          <header className="mb-4 border-b border-neutral-200 pb-4 pr-10 dark:border-neutral-800">
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <Link
                href={`/cve/${summary?.cveId ?? detail.data?.cveId ?? ""}`}
                onClick={onClose}
                className="inline-flex items-center gap-1 rounded-full bg-violet-100 px-2.5 py-0.5 font-medium text-violet-800 hover:bg-violet-200 dark:bg-violet-500/15 dark:text-violet-200 dark:hover:bg-violet-500/25"
              >
                {summary?.cveId ?? detail.data?.cveId}
                <ExternalLink className="h-3 w-3" />
              </Link>
              {author && (
                <span className="inline-flex items-center gap-1 text-neutral-600 dark:text-neutral-400">
                  <UserIcon className="h-3 w-3" />
                  {author.nickname || author.username}
                </span>
              )}
              {created && (
                <span className="tabular-nums text-neutral-600 dark:text-neutral-500">
                  · {formatRelativeKo(created)}
                </span>
              )}
            </div>
            {(summary?.title || detail.data?.title) && (
              <h2 className="mt-2 text-lg font-bold text-neutral-900 dark:text-neutral-100">
                {detail.data?.title ?? summary?.title}
              </h2>
            )}
          </header>

          {detail.isPending ? (
            <div className="flex items-center gap-2 text-sm text-neutral-600 dark:text-neutral-500">
              <Loader2 className="h-4 w-4 animate-spin" /> 본문을 불러오는 중…
            </div>
          ) : detail.isError ? (
            <ErrorBox
              title="분석을 불러오지 못했습니다"
              message="비공개로 전환됐거나 삭제됐을 수 있어요."
            />
          ) : (
            <div className="prose prose-sm max-w-none whitespace-pre-wrap break-words text-sm leading-relaxed text-neutral-800 dark:prose-invert dark:text-neutral-200">
              {detail.data?.resultMd}
            </div>
          )}
        </article>
      </div>
    </div>
  );
}
