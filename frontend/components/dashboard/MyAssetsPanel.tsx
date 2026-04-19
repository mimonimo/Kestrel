"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { Server, Settings2 } from "lucide-react";
import { api } from "@/lib/api";
import { useAssets } from "@/lib/assets";
import { BookmarkButton } from "@/components/cve/BookmarkButton";
import { SeverityBadge } from "@/components/cve/SeverityBadge";
import { timeAgo } from "@/lib/utils";

export function MyAssetsPanel() {
  const { list, ready } = useAssets();

  const { data, isLoading, isError } = useQuery({
    queryKey: ["assets-match", list.map((a) => `${a.vendor}:${a.product}:${a.version ?? ""}`).join("|")],
    queryFn: () => api.matchAssets(list, 50),
    enabled: ready && list.length > 0,
    staleTime: 60_000,
  });

  if (!ready) return null;

  if (list.length === 0) {
    return (
      <section className="mb-8 rounded-lg border border-dashed border-neutral-800 bg-surface-1/50 px-5 py-4 text-xs text-neutral-500">
        <div className="flex items-center gap-2">
          <Server className="h-4 w-4" />
          <span className="text-sm font-medium text-neutral-300">내 시스템 취약점</span>
          <Link
            href="/settings"
            className="ml-auto inline-flex items-center gap-1 text-xs text-neutral-400 hover:text-neutral-100"
          >
            <Settings2 className="h-3.5 w-3.5" /> 자산 등록
          </Link>
        </div>
        <p className="mt-1.5">
          설정 페이지에서 벤더·제품을 등록하면 CPE 매칭으로 관련 CVE만 따로 볼 수 있습니다.
        </p>
      </section>
    );
  }

  const items = data?.items ?? [];
  const total = data?.total ?? 0;

  return (
    <section className="mb-8 rounded-lg border border-neutral-800 bg-surface-1 p-5">
      <header className="mb-3 flex items-baseline justify-between gap-3">
        <div className="flex items-center gap-2">
          <Server className="h-4 w-4 text-sky-300" />
          <h2 className="text-sm font-semibold text-neutral-100">내 시스템 취약점</h2>
          <span className="text-xs text-neutral-500">
            자산 {list.length}건 · 매칭 {total}건
          </span>
        </div>
        <Link
          href="/settings"
          className="inline-flex items-center gap-1 text-xs text-neutral-400 hover:text-neutral-100"
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
        <ul className="divide-y divide-neutral-800">
          {items.slice(0, 8).map((v) => (
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
      )}
    </section>
  );
}
