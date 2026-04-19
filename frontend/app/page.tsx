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
import { RefreshBar } from "@/components/dashboard/RefreshBar";
import { MyAssetsPanel } from "@/components/dashboard/MyAssetsPanel";
import { useCveSearch } from "@/hooks/useCveSearch";
import { useDebounce } from "@/hooks/useDebounce";
import { useUrlState } from "@/lib/url-state";
import { useBookmarks } from "@/lib/bookmarks";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

const PAGE_SIZE = 20;

function Dashboard() {
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
      fromDate: url.filters.fromDate || undefined,
      toDate: url.filters.toDate || undefined,
    },
    url.page,
    PAGE_SIZE,
  );

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
  const error = bookmarksOnly ? (bookmarksQuery.error as Error | undefined) : (search.error as Error | undefined);

  return (
    <div className="mx-auto max-w-7xl px-6">
      <section className="pt-16 pb-10 text-center">
        <h1 className="text-4xl sm:text-5xl font-bold tracking-tight mb-3">
          <span className="bg-gradient-to-r from-blue-400 via-sky-300 to-cyan-300 bg-clip-text text-transparent">
            Kestrel
          </span>
        </h1>
        <p className="text-neutral-400 text-sm sm:text-base mb-8">
          NVD · Exploit-DB · GitHub Advisory를 한 화면에서. 실시간 CVE 및 제로데이 모니터링.
        </p>
        <div className="mx-auto max-w-2xl">
          <SearchBar initialQuery={queryInput} onSearch={(q) => setQueryInput(q)} />
        </div>
      </section>

      <div className="mb-6">
        <RefreshBar />
      </div>

      <MyAssetsPanel />

      <section className="grid grid-cols-1 lg:grid-cols-[280px_1fr] gap-6 pb-12">
        <FilterPanel
          value={url.filters}
          onChange={(filters) => url.set({ filters, page: 1 })}
        />

        <div className="space-y-4">
          <div className="flex items-baseline justify-between border-b border-neutral-800 pb-3">
            <h2 className="text-sm text-neutral-400">
              총{" "}
              <span className="text-neutral-100 font-semibold">{activeData.total ?? "—"}</span>
              건
              {bookmarksOnly && " · 즐겨찾기"}
              {url.query && !bookmarksOnly && (
                <>
                  {" "}· "<span className="text-neutral-200">{url.query}</span>" 검색 결과
                </>
              )}
            </h2>
            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={() => setBookmarksOnly((v) => !v)}
                className={cn(
                  "inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-xs font-medium transition-colors",
                  bookmarksOnly
                    ? "border-amber-400/50 bg-amber-400/15 text-amber-200"
                    : "border-neutral-700 text-neutral-400 hover:border-neutral-500 hover:text-neutral-100",
                )}
                aria-pressed={bookmarksOnly}
              >
                <Star className={cn("h-3.5 w-3.5", bookmarksOnly && "fill-amber-300")} />
                즐겨찾기만 ({bookmarks.count})
              </button>
              <span className="text-xs text-neutral-600">최신순</span>
            </div>
          </div>

          {isError ? (
            <ErrorState error={error as Error} onRetry={() => (bookmarksOnly ? bookmarksQuery.refetch() : search.refetch())} />
          ) : isPending ? (
            <CveListSkeleton count={6} />
          ) : activeData.items.length === 0 ? (
            bookmarksOnly ? (
              <div className="rounded-lg border border-dashed border-neutral-800 bg-surface-1/50 py-12 text-center text-sm text-neutral-500">
                아직 즐겨찾기한 CVE가 없습니다. 목록에서 별 아이콘을 눌러 추가하세요.
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
                {activeData.items.map((v) => (
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

export default function DashboardPage() {
  return (
    <Suspense fallback={<div className="mx-auto max-w-7xl px-6 py-16"><CveListSkeleton /></div>}>
      <Dashboard />
    </Suspense>
  );
}
