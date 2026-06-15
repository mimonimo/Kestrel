"use client";

// 내 프로필에서 "공유한 분석"을 관리 — 단건 공개/비공개 토글·삭제·본문 보기에
// 더해, 체크박스로 여러 건을 골라 일괄 공개/비공개/삭제까지 한다.
// 데이터는 owner 스코프(/me/analyses)라 비공개 분석까지 포함한다.
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckSquare, Globe, Heart, Loader2, Lock, MessageSquare, ScrollText, Search, Square, Trash2, X } from "lucide-react";

import { api, type AnalysisList } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { ErrorBox } from "@/components/ui/feedback-box";
import { AnalysisDetailModal } from "@/components/community/AnalysisDetailModal";
import { formatRelativeKo } from "@/lib/format";
import { cn } from "@/lib/utils";

type BulkAction = "public" | "private" | "delete";
type VisFilter = "all" | "public" | "private";
type SortKey = "new" | "old";

export function MyAnalysesManager() {
  const qc = useQueryClient();
  const [openId, setOpenId] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState("");
  const [vis, setVis] = useState<VisFilter>("all");
  const [sort, setSort] = useState<SortKey>("new");

  const list = useQuery({
    queryKey: ["my-analyses"],
    queryFn: () => api.listMyAnalyses({ limit: 100 }),
    staleTime: 10_000,
  });
  const items = useMemo(() => list.data?.items ?? [], [list.data]);

  // 검색·공개여부·정렬 적용한 표시 목록.
  const visibleItems = useMemo(() => {
    const term = search.trim().toLowerCase();
    let arr = items.filter((a) => {
      if (vis === "public" && a.visibility !== "public") return false;
      if (vis === "private" && a.visibility === "public") return false;
      if (term) {
        const hay = `${a.cveId} ${a.title ?? ""} ${a.excerpt}`.toLowerCase();
        if (!hay.includes(term)) return false;
      }
      return true;
    });
    arr = [...arr].sort((a, b) => {
      const d = +new Date(b.createdAt) - +new Date(a.createdAt);
      return sort === "new" ? d : -d;
    });
    return arr;
  }, [items, search, vis, sort]);
  const publicCount = useMemo(() => items.filter((a) => a.visibility === "public").length, [items]);

  // 토글/삭제 후 공개 프로필·CVE 상세·커뮤니티 피드 표시를 모두 갱신.
  const invalidateSharedViews = () => {
    qc.invalidateQueries({ queryKey: ["community-analyses"] });
    qc.invalidateQueries({ queryKey: ["cve-community-analyses"] });
    qc.invalidateQueries({ queryKey: ["user-profile"] });
  };

  // 단건 토글.
  const toggle = useMutation({
    mutationFn: ({ id, visibility }: { id: string; visibility: "public" | "private" }) =>
      api.updateAnalysisRecord(id, { visibility }),
    onSuccess: (updated) => {
      qc.setQueryData<AnalysisList | undefined>(["my-analyses"], (prev) =>
        prev
          ? {
              ...prev,
              items: prev.items.map((a) =>
                a.id === updated.id ? { ...a, visibility: updated.visibility } : a,
              ),
            }
          : prev,
      );
      invalidateSharedViews();
    },
  });

  // 단건 삭제.
  const remove = useMutation({
    mutationFn: (id: string) => api.deleteAnalysisRecord(id),
    onSuccess: (_v, id) => {
      qc.setQueryData<AnalysisList | undefined>(["my-analyses"], (prev) =>
        prev
          ? { ...prev, items: prev.items.filter((a) => a.id !== id), total: Math.max(0, prev.total - 1) }
          : prev,
      );
      setSelected((s) => {
        const n = new Set(s);
        n.delete(id);
        return n;
      });
      invalidateSharedViews();
    },
  });

  // 일괄 — 단건 엔드포인트를 묶어서 처리(전용 bulk API 없음).
  const bulk = useMutation({
    mutationFn: async ({ ids, action }: { ids: string[]; action: BulkAction }) => {
      if (action === "delete") {
        await Promise.all(ids.map((id) => api.deleteAnalysisRecord(id)));
      } else {
        await Promise.all(ids.map((id) => api.updateAnalysisRecord(id, { visibility: action })));
      }
      return { ids, action };
    },
    onSuccess: ({ ids, action }) => {
      qc.setQueryData<AnalysisList | undefined>(["my-analyses"], (prev) => {
        if (!prev) return prev;
        if (action === "delete") {
          return {
            ...prev,
            items: prev.items.filter((a) => !ids.includes(a.id)),
            total: Math.max(0, prev.total - ids.length),
          };
        }
        return {
          ...prev,
          items: prev.items.map((a) => (ids.includes(a.id) ? { ...a, visibility: action } : a)),
        };
      });
      setSelected(new Set());
      invalidateSharedViews();
    },
  });

  const selectedIds = useMemo(() => Array.from(selected), [selected]);
  const allSelected = visibleItems.length > 0 && visibleItems.every((a) => selected.has(a.id));
  const busy = bulk.isPending;

  const toggleOne = (id: string) =>
    setSelected((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });
  const toggleAll = () =>
    setSelected((s) => {
      const n = new Set(s);
      if (visibleItems.every((a) => n.has(a.id))) {
        visibleItems.forEach((a) => n.delete(a.id));
      } else {
        visibleItems.forEach((a) => n.add(a.id));
      }
      return n;
    });

  const runBulk = (action: BulkAction) => {
    if (selectedIds.length === 0) return;
    if (action === "delete" && !confirm(`선택한 ${selectedIds.length}개 분석을 삭제할까요? 되돌릴 수 없습니다.`))
      return;
    bulk.mutate({ ids: selectedIds, action });
  };

  return (
    <section className="mt-8">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <h2 className="flex items-center gap-1.5 text-sm font-semibold text-neutral-700 dark:text-neutral-300">
          <ScrollText className="h-4 w-4" /> 내 분석 관리 ({items.length})
        </h2>
        {items.length > 0 && (
          <button
            type="button"
            onClick={toggleAll}
            className="inline-flex items-center gap-1.5 rounded-full px-2 py-1 text-xs font-medium text-neutral-600 transition-colors hover:bg-neutral-100 dark:text-neutral-400 dark:hover:bg-surface-2"
          >
            {allSelected ? <CheckSquare className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" /> : <Square className="h-3.5 w-3.5" />}
            전체 선택
          </button>
        )}
      </div>
      <p className="mb-3 text-xs text-neutral-500 dark:text-neutral-500">
        공개로 전환한 분석은 해당 CVE 상세의 “커뮤니티 분석”과 내 프로필에 노출됩니다. 체크해서 여러 건을 한 번에 공개·비공개·삭제할 수 있어요.
      </p>

      {/* 필터 툴바 — 검색 / 공개여부 / 정렬 */}
      {items.length > 0 && (
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <div className="relative min-w-[160px] flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-neutral-400" />
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="CVE · 제목 · 본문 검색"
              className="block w-full rounded-full border border-neutral-300 bg-white py-1.5 pl-8 pr-8 text-xs text-neutral-900 placeholder:text-neutral-500 focus:border-sky-500 focus:outline-none dark:border-neutral-700 dark:bg-surface-1 dark:text-neutral-100"
            />
            {search && (
              <button
                type="button"
                onClick={() => setSearch("")}
                aria-label="검색어 지우기"
                className="absolute right-2 top-1/2 inline-flex h-5 w-5 -translate-y-1/2 items-center justify-center rounded-full text-neutral-400 hover:bg-neutral-100 dark:hover:bg-surface-2"
              >
                <X className="h-3 w-3" />
              </button>
            )}
          </div>
          <div className="inline-flex items-center gap-0.5 rounded-full border border-neutral-200 bg-neutral-50 p-0.5 text-[11px] dark:border-neutral-800 dark:bg-surface-1">
            {(
              [
                ["all", `전체 ${items.length}`],
                ["public", `공개 ${publicCount}`],
                ["private", `비공개 ${items.length - publicCount}`],
              ] as const
            ).map(([v, label]) => (
              <button
                key={v}
                type="button"
                onClick={() => setVis(v)}
                className={cn(
                  "rounded-full px-2.5 py-1 font-medium transition-colors",
                  vis === v
                    ? "bg-white text-neutral-900 shadow-sm dark:bg-surface-2 dark:text-neutral-100"
                    : "text-neutral-600 hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-neutral-100",
                )}
                aria-pressed={vis === v}
              >
                {label}
              </button>
            ))}
          </div>
          <button
            type="button"
            onClick={() => setSort((s) => (s === "new" ? "old" : "new"))}
            className="rounded-full border border-neutral-300 px-2.5 py-1 text-[11px] font-medium text-neutral-600 transition-colors hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-400 dark:hover:bg-surface-2"
            title="정렬 전환"
          >
            {sort === "new" ? "최신순" : "오래된순"}
          </button>
        </div>
      )}

      {/* 일괄 액션 바 — 선택이 있을 때만 */}
      {selected.size > 0 && (
        <div className="sticky top-2 z-10 mb-3 flex flex-wrap items-center gap-2 rounded-xl border border-sky-200 bg-sky-50/90 px-3 py-2 backdrop-blur dark:border-sky-500/30 dark:bg-sky-500/10">
          <span className="text-xs font-medium text-sky-800 dark:text-sky-200">
            {selected.size}개 선택됨
          </span>
          <div className="ml-auto flex flex-wrap items-center gap-1.5">
            <Button
              type="button"
              size="sm"
              onClick={() => runBulk("public")}
              disabled={busy}
              className="gap-1 rounded-full bg-emerald-600 text-white hover:bg-emerald-700 disabled:opacity-60 dark:bg-emerald-600 dark:hover:bg-emerald-500"
            >
              {busy && bulk.variables?.action === "public" ? <Loader2 className="h-3 w-3 animate-spin" /> : <Globe className="h-3 w-3" />}
              일괄 공개
            </Button>
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => runBulk("private")}
              disabled={busy}
              className="gap-1 rounded-full"
            >
              {busy && bulk.variables?.action === "private" ? <Loader2 className="h-3 w-3 animate-spin" /> : <Lock className="h-3 w-3" />}
              일괄 비공개
            </Button>
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => runBulk("delete")}
              disabled={busy}
              className="gap-1 rounded-full border-red-300 text-red-700 hover:bg-red-50 dark:border-red-900/50 dark:text-red-300 dark:hover:bg-red-950/40"
            >
              {busy && bulk.variables?.action === "delete" ? <Loader2 className="h-3 w-3 animate-spin" /> : <Trash2 className="h-3 w-3" />}
              일괄 삭제
            </Button>
            <button
              type="button"
              onClick={() => setSelected(new Set())}
              disabled={busy}
              className="rounded-full px-2 py-1 text-xs text-neutral-600 hover:bg-white/60 disabled:opacity-60 dark:text-neutral-300 dark:hover:bg-white/10"
            >
              선택 해제
            </button>
          </div>
        </div>
      )}

      {list.isPending ? (
        <div className="flex items-center gap-2 py-6 text-sm text-neutral-500">
          <Loader2 className="h-4 w-4 animate-spin" /> 불러오는 중…
        </div>
      ) : list.isError ? (
        <ErrorBox title="내 분석을 불러오지 못했습니다" message="잠시 후 다시 시도해 주세요." />
      ) : items.length === 0 ? (
        <p className="rounded-lg border border-dashed border-neutral-300 px-3 py-6 text-center text-xs text-neutral-500 dark:border-neutral-700">
          아직 분석한 기록이 없어요. CVE 상세에서 AI 심층 분석을 먼저 실행해 주세요.
        </p>
      ) : visibleItems.length === 0 ? (
        <p className="rounded-lg border border-dashed border-neutral-300 px-3 py-6 text-center text-xs text-neutral-500 dark:border-neutral-700">
          조건에 맞는 분석이 없어요. 검색어나 필터를 바꿔 보세요.
        </p>
      ) : (
        <ul className="space-y-2">
          {visibleItems.map((a) => {
            const isPublic = a.visibility === "public";
            const next = isPublic ? "private" : "public";
            const toggling = toggle.isPending && toggle.variables?.id === a.id;
            const deleting = remove.isPending && remove.variables === a.id;
            const checked = selected.has(a.id);
            return (
              <li
                key={a.id}
                className={cn(
                  "flex items-start gap-2 rounded-lg border bg-white p-3 dark:bg-surface-1",
                  checked
                    ? "border-sky-300 ring-1 ring-sky-200 dark:border-sky-500/50 dark:ring-sky-500/20"
                    : "border-neutral-200 dark:border-neutral-800",
                )}
              >
                {/* 선택 체크박스 */}
                <button
                  type="button"
                  onClick={() => toggleOne(a.id)}
                  aria-label={checked ? "선택 해제" : "선택"}
                  aria-pressed={checked}
                  className="mt-0.5 shrink-0 text-neutral-400 transition-colors hover:text-sky-600 dark:hover:text-sky-400"
                >
                  {checked ? (
                    <CheckSquare className="h-4 w-4 text-sky-600 dark:text-sky-400" />
                  ) : (
                    <Square className="h-4 w-4" />
                  )}
                </button>

                {/* 본문 — 클릭 시 상세 모달 */}
                <button
                  type="button"
                  onClick={() => setOpenId(a.id)}
                  className="min-w-0 flex-1 text-left"
                >
                  <div className="flex flex-wrap items-baseline gap-x-2 text-xs">
                    <span className="font-mono font-semibold text-sky-700 dark:text-sky-300">{a.cveId}</span>
                    <span className="text-neutral-400">·</span>
                    <span className="tabular-nums text-neutral-500 dark:text-neutral-500">
                      {formatRelativeKo(a.createdAt)}
                    </span>
                    <span
                      className={cn(
                        "rounded-full px-1.5 py-0.5 text-[10px] font-medium",
                        isPublic
                          ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-500/15 dark:text-emerald-200"
                          : "bg-neutral-100 text-neutral-600 dark:bg-surface-2 dark:text-neutral-400",
                      )}
                    >
                      {isPublic ? "공개" : "비공개"}
                    </span>
                    {!!a.commentCount && (
                      <span className="inline-flex items-center gap-0.5 tabular-nums text-neutral-500 dark:text-neutral-500">
                        <MessageSquare className="h-3 w-3" />
                        {a.commentCount}
                      </span>
                    )}
                    {!!a.likeCount && (
                      <span className="inline-flex items-center gap-0.5 tabular-nums text-rose-500 dark:text-rose-400">
                        <Heart className="h-3 w-3 fill-current" />
                        {a.likeCount}
                      </span>
                    )}
                  </div>
                  {a.title && (
                    <p className="mt-1 truncate text-sm font-medium text-neutral-900 dark:text-neutral-100">
                      {a.title}
                    </p>
                  )}
                  <p className="mt-0.5 line-clamp-2 text-[11px] leading-relaxed text-neutral-600 dark:text-neutral-400">
                    {a.excerpt}
                  </p>
                </button>

                {/* 단건 관리 액션 */}
                <div className="flex shrink-0 flex-col items-stretch gap-1.5">
                  <button
                    type="button"
                    onClick={() => toggle.mutate({ id: a.id, visibility: next })}
                    disabled={toggling}
                    title={isPublic ? "비공개로 전환" : "공개로 전환"}
                    className={cn(
                      "inline-flex items-center justify-center gap-1.5 rounded-full border px-3 py-1.5 text-xs font-medium transition-colors disabled:opacity-60",
                      isPublic
                        ? "border-emerald-300 bg-emerald-50 text-emerald-800 hover:bg-emerald-100 dark:border-emerald-500/40 dark:bg-emerald-500/15 dark:text-emerald-200"
                        : "border-neutral-300 bg-white text-neutral-700 hover:border-violet-400 hover:text-violet-700 dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-300 dark:hover:border-violet-500/60 dark:hover:text-violet-200",
                    )}
                  >
                    {toggling ? (
                      <Loader2 className="h-3 w-3 animate-spin" />
                    ) : isPublic ? (
                      <Globe className="h-3 w-3" />
                    ) : (
                      <Lock className="h-3 w-3" />
                    )}
                    {isPublic ? "공개됨" : "공유"}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      if (confirm("이 분석을 삭제할까요? 되돌릴 수 없습니다.")) remove.mutate(a.id);
                    }}
                    disabled={deleting}
                    title="삭제"
                    className="inline-flex items-center justify-center gap-1 rounded-full border border-red-300 px-3 py-1.5 text-xs font-medium text-red-700 transition-colors hover:bg-red-50 disabled:opacity-60 dark:border-red-900/50 dark:text-red-300 dark:hover:bg-red-950/40"
                  >
                    {deleting ? <Loader2 className="h-3 w-3 animate-spin" /> : <Trash2 className="h-3 w-3" />}
                    삭제
                  </button>
                </div>
              </li>
            );
          })}
        </ul>
      )}

      <AnalysisDetailModal
        analysisId={openId}
        summary={items.find((a) => a.id === openId) ?? null}
        onClose={() => setOpenId(null)}
      />
    </section>
  );
}
