"use client";

import { Loader2, RefreshCw, Trash2 } from "lucide-react";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { api, type EvictedImage, type SynthesizeCacheEntry } from "@/lib/api";
import { cn } from "@/lib/utils";

const CACHE_KEY = ["sandbox", "synthesizer", "cache"];

function formatRelative(iso: string | null): string {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  const diffMs = Date.now() - then;
  if (diffMs < 0) return "방금";
  const mins = Math.floor(diffMs / 60_000);
  if (mins < 1) return "방금";
  if (mins < 60) return `${mins}분 전`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}시간 전`;
  const days = Math.floor(hours / 24);
  return `${days}일 전`;
}

function pct(num: number, den: number): number {
  if (den <= 0) return 0;
  return Math.min(100, Math.round((num / den) * 100));
}

export function SynthesizerCachePanel() {
  const qc = useQueryClient();
  const [lastGc, setLastGc] = useState<EvictedImage[] | null>(null);
  const [gcError, setGcError] = useState<string | null>(null);

  const cache = useQuery({
    queryKey: CACHE_KEY,
    queryFn: () => api.getSynthesizerCache(),
    staleTime: 10_000,
  });

  const gc = useMutation({
    mutationFn: () => api.triggerSynthesizerGc(),
    onSuccess: (res) => {
      setLastGc(res.evicted);
      setGcError(null);
      qc.invalidateQueries({ queryKey: CACHE_KEY });
    },
    onError: (e: Error) => {
      setGcError(e.message);
      setLastGc(null);
    },
  });

  if (cache.isLoading) {
    return (
      <div className="flex items-center gap-2 text-sm text-neutral-500">
        <Loader2 className="h-4 w-4 animate-spin" /> 캐시 상태 조회 중…
      </div>
    );
  }

  if (cache.error) {
    return (
      <div className="rounded-md border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-300">
        캐시 상태 조회 실패: {(cache.error as Error).message}
      </div>
    );
  }

  const data = cache.data;
  if (!data) return null;

  const sizePct = pct(data.totalMb, data.maxTotalMb);
  const countPct = pct(data.count, data.maxCount);

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2">
        <Stat
          label="합계 디스크 사용량"
          value={`${data.totalMb} / ${data.maxTotalMb} MB`}
          percent={sizePct}
        />
        <Stat
          label="이미지 개수"
          value={`${data.count} / ${data.maxCount}`}
          percent={countPct}
        />
      </div>

      <div className="flex flex-wrap items-center gap-3 text-[11px] text-neutral-400">
        <span>
          최대 보관 기간 <span className="text-neutral-200">{data.maxAgeDays}일</span>
        </span>
        <span>
          사용 중 <span className="text-neutral-200">{data.inUseCount}개</span>
        </span>
        {data.missingImageCount > 0 && (
          <span className="text-amber-300">
            이미지 사라진 row {data.missingImageCount}개 — GC 시 정리됨
          </span>
        )}
        <span>
          가장 오래 사용 안 된 시점 <span className="text-neutral-200">{formatRelative(data.oldestLastUsedAt)}</span>
        </span>
      </div>

      <div className="flex items-center gap-2">
        <Button
          size="sm"
          variant="outline"
          disabled={cache.isFetching}
          onClick={() => cache.refetch()}
        >
          <RefreshCw className={cn("mr-1 h-3.5 w-3.5", cache.isFetching && "animate-spin")} />
          새로고침
        </Button>
        <Button
          size="sm"
          variant="outline"
          className="border-rose-500/40 text-rose-300 hover:bg-rose-500/10"
          disabled={gc.isPending || data.count === 0}
          onClick={() => gc.mutate()}
        >
          <Trash2 className={cn("mr-1 h-3.5 w-3.5", gc.isPending && "animate-pulse")} />
          {gc.isPending ? "GC 진행 중…" : "지금 GC 실행"}
        </Button>
      </div>

      {gcError && (
        <div className="rounded-md border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-300">
          GC 실패: {gcError}
        </div>
      )}
      {lastGc !== null && !gcError && (
        <GcResultBanner evicted={lastGc} />
      )}

      {data.entries.length === 0 ? (
        <div className="rounded-lg border border-dashed border-neutral-700 bg-surface-1 p-6 text-center text-xs text-neutral-500">
          합성된 lab 이미지 없음. AI 합성을 한 번도 사용하지 않았거나 모두 회수됨.
        </div>
      ) : (
        <CacheTable entries={data.entries} />
      )}

      <p className="text-[11px] text-neutral-500">
        오래된 순(LRU) 정렬 — 다음 GC 가 위에서부터 회수합니다. 합성은 매 호출 시 자동으로 GC 가 한 번 돌고, 위 버튼은 즉시 강제 sweep.
      </p>
    </div>
  );
}

function Stat({
  label,
  value,
  percent,
}: {
  label: string;
  value: string;
  percent: number;
}) {
  return (
    <div className="rounded-md border border-neutral-800 bg-surface-1 p-3">
      <div className="flex items-baseline justify-between">
        <span className="text-[11px] text-neutral-500">{label}</span>
        <span className="text-sm font-semibold text-neutral-100">{value}</span>
      </div>
      <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-surface-2">
        <div
          className={cn(
            "h-full rounded-full transition-all",
            percent >= 90
              ? "bg-rose-500"
              : percent >= 70
                ? "bg-amber-400"
                : "bg-emerald-500",
          )}
          style={{ width: `${percent}%` }}
        />
      </div>
    </div>
  );
}

function CacheTable({ entries }: { entries: SynthesizeCacheEntry[] }) {
  return (
    <div className="overflow-hidden rounded-md border border-neutral-800">
      <table className="w-full text-xs">
        <thead className="bg-surface-2 text-[10px] uppercase tracking-wider text-neutral-500">
          <tr>
            <th className="px-3 py-2 text-left">CVE</th>
            <th className="px-3 py-2 text-left">이미지</th>
            <th className="px-3 py-2 text-right">크기</th>
            <th className="px-3 py-2 text-right">마지막 사용</th>
            <th className="px-3 py-2 text-right">상태</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-neutral-800">
          {entries.map((e) => (
            <tr key={`${e.cveId}-${e.imageTag || e.labKind}`} className="bg-surface-1">
              <td className="px-3 py-2 font-mono text-neutral-200">{e.cveId}</td>
              <td className="px-3 py-2 font-mono text-[10px] text-neutral-400">
                {e.imageTag || e.labKind}
              </td>
              <td className="px-3 py-2 text-right text-neutral-200">{e.sizeMb} MB</td>
              <td className="px-3 py-2 text-right text-neutral-400">
                {formatRelative(e.lastUsedAt)}
                <span className="ml-1 text-[10px] text-neutral-600">({e.ageDays}일)</span>
              </td>
              <td className="px-3 py-2 text-right">
                {!e.imagePresent ? (
                  <Badge tone="amber">이미지 없음</Badge>
                ) : e.inUse ? (
                  <Badge tone="sky">사용 중</Badge>
                ) : (
                  <Badge tone="neutral">대기</Badge>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Badge({
  tone,
  children,
}: {
  tone: "amber" | "sky" | "neutral";
  children: React.ReactNode;
}) {
  const cls = {
    amber: "border-amber-500/30 bg-amber-500/10 text-amber-300",
    sky: "border-sky-500/30 bg-sky-500/10 text-sky-300",
    neutral: "border-neutral-700 bg-surface-2 text-neutral-400",
  }[tone];
  return (
    <span className={cn("inline-flex rounded-full border px-2 py-0.5 text-[10px]", cls)}>
      {children}
    </span>
  );
}

function GcResultBanner({ evicted }: { evicted: EvictedImage[] }) {
  if (evicted.length === 0) {
    return (
      <div className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-300">
        GC 완료 — 회수할 항목이 없었습니다 (모든 이미지가 ceiling 이내).
      </div>
    );
  }
  const totalMb = evicted.reduce((s, e) => s + e.sizeMb, 0);
  return (
    <div className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-300">
      GC 완료 — {evicted.length}개 이미지 ({totalMb} MB) 회수.
      <ul className="mt-1 space-y-0.5 text-[11px] text-emerald-200/80">
        {evicted.slice(0, 5).map((e) => (
          <li key={`${e.cveId}-${e.imageTag}`}>
            <span className="font-mono">{e.cveId}</span>{" "}
            <span className="text-neutral-400">·</span>{" "}
            <span>{e.sizeMb} MB</span>{" "}
            <span className="text-neutral-400">·</span>{" "}
            <span className="text-emerald-300/70">reason={e.reason}</span>
          </li>
        ))}
        {evicted.length > 5 && (
          <li className="text-neutral-500">…외 {evicted.length - 5}개</li>
        )}
      </ul>
    </div>
  );
}
