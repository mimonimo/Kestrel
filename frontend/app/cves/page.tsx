"use client";

import { useEffect, useState, Suspense } from "react";
import { useQuery } from "@tanstack/react-query";
import { Star } from "lucide-react";

import { SearchBar } from "@/components/search/SearchBar";
import { FilterPanel, EMPTY_FILTERS } from "@/components/search/FilterPanel";
import { CveListItem } from "@/components/cve/CveListItem";
import { CveListSkeleton } from "@/components/cve/CveListSkeleton";
import { EmptyState, ErrorState } from "@/components/cve/CveListStates";
import { Pagination } from "@/components/search/Pagination";
import { SortSelect } from "@/components/dashboard/SortSelect";
import { DateRangeControl } from "@/components/dashboard/DateRangeControl";
import { useCveSearch } from "@/hooks/useCveSearch";
import { useDebounce } from "@/hooks/useDebounce";
import { useUrlState } from "@/lib/url-state";
import { useBookmarks } from "@/lib/bookmarks";
import { api } from "@/lib/api";
import { sortVulnerabilities } from "@/lib/sort";
import { cn } from "@/lib/utils";

const PAGE_SIZE = 20;

// 취약점 조회 페이지 — 메인 대시보드(시각화 위주)에서 분리된 "리스트/필터"
// 전용 탭. 좌측 FilterPanel (세부 필터: severity, OS, type, domain, 날짜),
// 우측 검색 결과 + 정렬 + 페이지네이션 + 즐겨찾기 토글. 상단 SearchBar 는
// 키워드 검색을 페이지 안에서 직접 처리합니다 (메인에서 라우팅돼 들어올
// 때도 url state 가 그대로 살아나 결과가 즉시 표시).
function CvesList() {
  const url = useUrlState();
  const [queryInput, setQueryInput] = useState(url.query);
  const debouncedQuery = useDebounce(queryInput, 300);
  const [bookmarksOnly, setBookmarksOnly] = useState(false);
  const bookmarks = useBookmarks();

  useEffect(() => {
    if (debouncedQuery !== url.query) {
      url.set({ query: debouncedQuery, page: 1 });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedQuery]);

  const search = useCveSearch(
    {
      query: url.query,
      severity: url.filters.severity,
      osFamily: url.filters.osFamily,
      types: url.filters.types,
      domains: url.filters.domains,
      fromDate: url.filters.fromDate || undefined,
      toDate: url.filters.toDate || undefined,
      priority: url.filters.priority,
    },
    url.page,
    PAGE_SIZE,
    url.sort,
  );

  const PRIORITY_LABELS: Record<string, string> = {
    kev: "KEV 등재",
    epss_high: "EPSS 상위",
    cvss_mid_epss_high: "CVSS 중간 + EPSS 높음",
    cvss_high_epss_low: "CVSS 높음 + EPSS 낮음",
  };
  const activeTier = url.filters.priority;

  const bookmarkIds = [...bookmarks.set];
  const bookmarksQuery = useQuery({
    queryKey: ["bookmarks-batch", bookmarkIds.sort().join(",")],
    queryFn: () => api.batchVulnerabilities(bookmarkIds),
    enabled: bookmarksOnly && bookmarks.ready && bookmarkIds.length > 0,
    staleTime: 30_000,
  });

  const activeData = bookmarksOnly
    ? {
        items: bookmarksQuery.data ?? [],
        total: bookmarksQuery.data?.length ?? bookmarkIds.length,
      }
    : { items: search.data?.items ?? [], total: search.data?.total ?? 0 };

  useEffect(() => {
    if (bookmarksOnly || !search.data || search.data.total === 0) return;
    const totalPages = Math.max(1, Math.ceil(search.data.total / PAGE_SIZE));
    if (url.page > totalPages) {
      url.set({ page: totalPages });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search.data?.total, url.page, bookmarksOnly]);

  const isPending = bookmarksOnly
    ? bookmarksQuery.isLoading && bookmarkIds.length > 0
    : search.isPending;
  const isError = bookmarksOnly ? bookmarksQuery.isError : search.isError;
  const error = bookmarksOnly
    ? (bookmarksQuery.error as Error | undefined)
    : (search.error as Error | undefined);

  return (
    <div className="mx-auto max-w-7xl px-6">
      <section className="pt-8 pb-4">
        <div className="mb-4 flex flex-wrap items-baseline justify-between gap-2">
          <div>
            <h1 className="text-xl font-semibold text-neutral-900 dark:text-neutral-100">
              취약점 조회
            </h1>
            <p className="mt-1 text-xs text-neutral-600 dark:text-neutral-500">
              심각도·운영체제·유형·도메인을 조합해 결과를 좁히고, 카드 클릭으로 상세 진입.
            </p>
          </div>
        </div>
        <SearchBar initialQuery={queryInput} onSearch={(q) => setQueryInput(q)} />
      </section>

      <section className="grid grid-cols-1 lg:grid-cols-[280px_1fr] gap-6 pb-12">
        <FilterPanel
          value={url.filters}
          onChange={(filters) => url.set({ filters, page: 1 })}
        />

        <div className="space-y-4">
          <div className="flex items-baseline justify-between gap-3 border-b border-neutral-200 pb-3 dark:border-neutral-800">
            <h2 className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-neutral-600 dark:text-neutral-400">
              <span>
                총{" "}
                <span className="font-semibold text-neutral-900 dark:text-neutral-100">
                  {activeData.total ?? "—"}
                </span>
                건
              </span>
              <DateRangeControl
                fromDate={url.filters.fromDate}
                toDate={url.filters.toDate}
                onChange={({ fromDate, toDate }) =>
                  url.set({ filters: { ...url.filters, fromDate, toDate }, page: 1 })
                }
              />
              {bookmarksOnly && <span>· 즐겨찾기</span>}
              {url.query && !bookmarksOnly && (
                <span>
                  · 검색어
                  <span className="ml-1 text-neutral-800 dark:text-neutral-200">"{url.query}"</span>
                </span>
              )}
              {activeTier && (
                <span className="inline-flex items-center gap-1 rounded-full bg-violet-100 px-2 py-0.5 text-[11px] font-medium text-violet-800 dark:bg-violet-500/20 dark:text-violet-200">
                  우선순위 · {PRIORITY_LABELS[activeTier]}
                  <button
                    type="button"
                    onClick={() =>
                      url.set({
                        filters: { ...url.filters, priority: undefined },
                        page: 1,
                      })
                    }
                    className="rounded-full p-0.5 hover:bg-violet-200 dark:hover:bg-violet-500/30"
                    aria-label="우선순위 필터 해제"
                  >
                    <span className="text-[11px]">×</span>
                  </button>
                </span>
              )}
            </h2>
            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={() => setBookmarksOnly((v) => !v)}
                className={cn(
                  "inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-xs font-medium transition-colors",
                  bookmarksOnly
                    ? "border-amber-400/60 bg-amber-400/20 text-amber-800 dark:bg-amber-400/15 dark:text-amber-200"
                    : "border-neutral-300 text-neutral-700 hover:border-neutral-500 hover:text-neutral-900 dark:border-neutral-700 dark:text-neutral-400 dark:hover:border-neutral-500 dark:hover:text-neutral-100",
                )}
                aria-pressed={bookmarksOnly}
              >
                <Star className={cn("h-3.5 w-3.5", bookmarksOnly && "fill-amber-300")} />
                즐겨찾기만 ({bookmarks.count})
              </button>
              <SortSelect
                value={url.sort}
                onChange={(next) => url.set({ sort: next, page: 1 })}
              />
            </div>
          </div>

          {isError ? (
            <ErrorState
              error={error as Error}
              onRetry={() =>
                bookmarksOnly ? bookmarksQuery.refetch() : search.refetch()
              }
            />
          ) : isPending ? (
            <CveListSkeleton count={6} />
          ) : activeData.items.length === 0 ? (
            bookmarksOnly ? (
              <div className="rounded-lg border border-dashed border-neutral-300 bg-white/50 py-12 text-center text-sm text-neutral-600 dark:border-neutral-800 dark:bg-surface-1/50 dark:text-neutral-500">
                즐겨찾기에 추가한 CVE 가 아직 없어요. 목록에서 별 아이콘을 눌러 등록할 수 있습니다.
              </div>
            ) : (
              <EmptyState />
            )
          ) : (
            <>
              <div
                className={`grid grid-cols-1 md:grid-cols-2 gap-3 transition-opacity ${
                  !bookmarksOnly && search.isPlaceholderData ? "opacity-60" : ""
                }`}
              >
                {(bookmarksOnly
                  ? sortVulnerabilities(activeData.items, url.sort)
                  : activeData.items
                ).map((v) => (
                  <CveListItem key={v.cveId} vuln={v} />
                ))}
              </div>
              {!bookmarksOnly && (
                <Pagination
                  page={url.page}
                  pageSize={PAGE_SIZE}
                  total={search.data?.total ?? 0}
                  onChange={(page) => url.set({ page })}
                />
              )}
            </>
          )}

          {url.filters !== EMPTY_FILTERS && activeData.items.length === 0 && null}
        </div>
      </section>
    </div>
  );
}

export default function CvesPage() {
  return (
    <Suspense
      fallback={
        <div className="mx-auto max-w-7xl px-6 py-16">
          <CveListSkeleton />
        </div>
      }
    >
      <CvesList />
    </Suspense>
  );
}
