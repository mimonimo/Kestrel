"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ChevronLeft, ChevronRight, Server, Settings2 } from "lucide-react";
import { api } from "@/lib/api";
import { useAssets } from "@/lib/assets";
import { BookmarkButton } from "@/components/cve/BookmarkButton";
import { SeverityBadge } from "@/components/cve/SeverityBadge";
import { timeAgo } from "@/lib/utils";

const PAGE_SIZE = 1;

export function MyAssetsPanel() {
  const { list, ready } = useAssets();
  const [page, setPage] = useState(0);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["assets-match", list.map((a) => `${a.vendor}:${a.product}:${a.version ?? ""}`).join("|")],
    queryFn: () => api.matchAssets(list, 50),
    enabled: ready && list.length > 0,
    staleTime: 60_000,
  });

  if (!ready) return null;

  if (list.length === 0) {
    return (
      <section className="mb-8 overflow-hidden rounded-xl border border-sky-500/30 bg-gradient-to-br from-sky-500/10 via-blue-500/5 to-transparent p-5 shadow-[0_0_0_1px_rgba(56,189,248,0.05)]">
        <div className="flex items-start gap-4">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-sky-500/15 ring-1 ring-sky-400/30">
            <Server className="h-5 w-5 text-sky-300" />
          </div>
          <div className="min-w-0 flex-1">
            <h2 className="text-base font-semibold text-neutral-100">내 시스템 취약점</h2>
            <p className="mt-1 text-sm text-neutral-300">
              사용 중인 벤더 · 제품을 등록하면 CPE 매칭을 통해 관련 CVE만 별도로 모아볼 수 있습니다.
            </p>
          </div>
          <Link
            href="/settings"
            className="inline-flex shrink-0 items-center gap-1.5 rounded-md bg-sky-500 px-3 py-1.5 text-xs font-medium text-white shadow hover:bg-sky-400"
          >
            <Settings2 className="h-3.5 w-3.5" /> 자산 등록하기
          </Link>
        </div>
      </section>
    );
  }

  const items = data?.items ?? [];
  const total = data?.total ?? 0;
  const pageCount = Math.max(1, Math.ceil(items.length / PAGE_SIZE));
  const safePage = Math.min(page, pageCount - 1);
  const visibleItems = items.slice(safePage * PAGE_SIZE, safePage * PAGE_SIZE + PAGE_SIZE);

  useEffect(() => {
    // Reset when the result set changes (e.g. assets edited) so we never show
    // an out-of-range page.
    setPage(0);
  }, [items.length]);

  return (
    <section className="mb-8 rounded-xl border border-sky-500/20 bg-gradient-to-br from-sky-500/5 to-transparent p-5 shadow-[0_0_0_1px_rgba(56,189,248,0.05)]">
      <header className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-sky-500/15 ring-1 ring-sky-400/30">
            <Server className="h-4 w-4 text-sky-300" />
          </div>
          <h2 className="text-base font-semibold text-neutral-100">내 시스템 취약점</h2>
          <span className="rounded-full bg-sky-500/10 px-2 py-0.5 text-xs font-medium text-sky-200">
            자산 {list.length} · 매칭 {total}
          </span>
        </div>
        <Link
          href="/settings"
          className="inline-flex items-center gap-1 rounded-md border border-neutral-700 px-2.5 py-1 text-xs text-neutral-300 hover:border-sky-400/50 hover:text-neutral-100"
        >
          <Settings2 className="h-3.5 w-3.5" /> 자산 관리
        </Link>
      </header>

      {isLoading ? (
        <p className="text-xs text-neutral-500">매칭 중…</p>
      ) : isError ? (
        <p className="text-xs text-red-400">매칭 API 호출에 실패했습니다.</p>
      ) : items.length === 0 ? (
        <p className="text-xs text-neutral-500">
          등록된 자산과 일치하는 CVE가 아직 수집되지 않았습니다.
        </p>
      ) : (
        <>
          <ul className="divide-y divide-neutral-800">
            {visibleItems.map((v) => (
              <li key={v.cveId} className="flex items-center gap-3 py-2">
                <Link
                  href={`/cve/${v.cveId}`}
                  className="flex min-w-0 flex-1 items-center gap-3 hover:opacity-80"
                >
                  <span className="font-mono text-xs text-neutral-500">{v.cveId}</span>
                  {v.severity && (
                    <SeverityBadge severity={v.severity} score={v.cvssScore ?? undefined} />
                  )}
                  <span className="min-w-0 flex-1 truncate text-sm text-neutral-200">{v.title}</span>
                  {v.publishedAt && (
                    <span className="shrink-0 text-xs text-neutral-500">{timeAgo(v.publishedAt)}</span>
                  )}
                </Link>
                <BookmarkButton cveId={v.cveId} stopPropagation={false} />
              </li>
            ))}
          </ul>
          {pageCount > 1 && (
            <div className="mt-3 flex items-center justify-center gap-3 border-t border-neutral-800 pt-3">
              <button
                type="button"
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                disabled={safePage === 0}
                aria-label="이전 취약점"
                className="inline-flex h-7 w-7 items-center justify-center rounded-md border border-neutral-700 text-neutral-300 hover:border-sky-400/50 hover:text-neutral-100 disabled:cursor-not-allowed disabled:opacity-40"
              >
                <ChevronLeft className="h-4 w-4" />
              </button>
              <span className="font-mono text-xs tabular-nums text-neutral-400">
                <span className="text-neutral-100">{safePage + 1}</span>
                <span className="mx-1 text-neutral-600">/</span>
                <span>{pageCount}</span>
              </span>
              <button
                type="button"
                onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
                disabled={safePage >= pageCount - 1}
                aria-label="다음 취약점"
                className="inline-flex h-7 w-7 items-center justify-center rounded-md border border-neutral-700 text-neutral-300 hover:border-sky-400/50 hover:text-neutral-100 disabled:cursor-not-allowed disabled:opacity-40"
              >
                <ChevronRight className="h-4 w-4" />
              </button>
            </div>
          )}
        </>
      )}
    </section>
  );
}
