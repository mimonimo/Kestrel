"use client";

import { Loader2, RefreshCw, Trash2 } from "lucide-react";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { ErrorBox } from "@/components/ui/feedback-box";
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
        <Loader2 className="h-4 w-4 animate-spin" /> 저장 공간 사용량을 확인하는 중…
      </div>
    );
  }

  if (cache.error) {
    return (
      <ErrorBox
        title="저장 공간 정보를 불러오지 못했습니다"
        message={(cache.error as Error).message}
        size="sm"
      />
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
          label="총 사용 용량"
          value={`${data.totalMb} / ${data.maxTotalMb} MB`}
          percent={sizePct}
        />
        <Stat
          label="저장된 환경 수"
          value={`${data.count} / ${data.maxCount}`}
          percent={countPct}
        />
      </div>

      <div className="flex flex-wrap items-center gap-3 text-[11px] text-neutral-400">
        <span>
          최대 보관 기간 <span className="text-neutral-800 dark:text-neutral-200">{data.maxAgeDays}일</span>
        </span>
        <span>
          현재 사용 중 <span className="text-neutral-800 dark:text-neutral-200">{data.inUseCount}개</span>
        </span>
        {data.missingImageCount > 0 && (
          <span className="text-amber-700 dark:text-amber-300">
            이미지가 삭제된 항목 {data.missingImageCount}개 — 정리 시 자동 제거됨
          </span>
        )}
        <span>
          가장 오랫동안 사용되지 않은 시점{" "}
          <span className="text-neutral-800 dark:text-neutral-200">{formatRelative(data.oldestLastUsedAt)}</span>
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
          className="border-rose-500/40 text-rose-700 dark:text-rose-300 hover:bg-rose-500/10"
          disabled={gc.isPending || data.count === 0}
          onClick={() => gc.mutate()}
        >
          <Trash2 className={cn("mr-1 h-3.5 w-3.5", gc.isPending && "animate-pulse")} />
          {gc.isPending ? "정리 중…" : "지금 즉시 정리"}
        </Button>
      </div>

      {gcError && (
        <ErrorBox title="정리에 실패했습니다" message={gcError} size="sm" />
      )}
      {lastGc !== null && !gcError && (
        <GcResultBanner evicted={lastGc} />
      )}

      {data.entries.length === 0 ? (
        <div className="rounded-lg border border-dashed border-neutral-700 bg-white dark:bg-surface-1 p-6 text-center text-xs text-neutral-500">
          저장된 합성 환경이 없습니다. AI 합성을 한 번도 사용하지 않았거나 모두
          정리되었습니다.
        </div>
      ) : (
        <CacheTable entries={data.entries} />
      )}

      <p className="text-[11px] text-neutral-500">
        오래된 순으로 정렬되어 있어 위쪽 항목부터 자동 정리됩니다. 새 합성이
        실행될 때마다 자동 정리가 한 번씩 돌고, 위 버튼은 그 정리를 즉시
        실행합니다.
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
    <div className="rounded-md border border-neutral-200 dark:border-neutral-800 bg-white dark:bg-surface-1 p-3">
      <div className="flex items-baseline justify-between">
        <span className="text-[11px] text-neutral-500">{label}</span>
        <span className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">{value}</span>
      </div>
      <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-neutral-50 dark:bg-surface-2">
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
    <div className="overflow-hidden rounded-md border border-neutral-200 dark:border-neutral-800">
      <table className="w-full text-xs">
        <thead className="bg-neutral-50 dark:bg-surface-2 text-[10px] uppercase tracking-wider text-neutral-500">
          <tr>
            <th className="px-3 py-2 text-left">CVE</th>
            <th className="px-3 py-2 text-left">환경 식별자</th>
            <th className="px-3 py-2 text-right">크기</th>
            <th className="px-3 py-2 text-right">마지막 사용</th>
            <th className="px-3 py-2 text-right">상태</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-neutral-800">
          {entries.map((e) => (
            <tr key={`${e.cveId}-${e.imageTag || e.labKind}`} className="bg-white dark:bg-surface-1">
              <td className="px-3 py-2 font-mono text-neutral-800 dark:text-neutral-200">{e.cveId}</td>
              <td className="px-3 py-2 font-mono text-[10px] text-neutral-400">
                {e.imageTag || e.labKind}
              </td>
              <td className="px-3 py-2 text-right text-neutral-800 dark:text-neutral-200">{e.sizeMb} MB</td>
              <td className="px-3 py-2 text-right text-neutral-400">
                {formatRelative(e.lastUsedAt)}
                <span className="ml-1 text-[10px] text-neutral-600">({e.ageDays}일)</span>
              </td>
              <td className="px-3 py-2 text-right">
                {!e.imagePresent ? (
                  <Badge tone="amber">이미지 누락</Badge>
                ) : e.inUse ? (
                  <Badge tone="sky">사용 중</Badge>
                ) : (
                  <Badge tone="neutral">대기 중</Badge>
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
    amber: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300",
    sky: "border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300",
    neutral: "border-neutral-700 bg-neutral-50 dark:bg-surface-2 text-neutral-400",
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
      <div className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-700 dark:text-emerald-300">
        정리 완료 — 정리할 항목이 없었습니다 (모든 항목이 보관 한도 이내).
      </div>
    );
  }
  const totalMb = evicted.reduce((s, e) => s + e.sizeMb, 0);
  return (
    <div className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-700 dark:text-emerald-300">
      정리 완료 — {evicted.length}개 환경 ({totalMb} MB) 회수했습니다.
      <ul className="mt-1 space-y-0.5 text-[11px] text-emerald-800 dark:text-emerald-200/80">
        {evicted.slice(0, 5).map((e) => (
          <li key={`${e.cveId}-${e.imageTag}`}>
            <span className="font-mono">{e.cveId}</span>{" "}
            <span className="text-neutral-400">·</span>{" "}
            <span>{e.sizeMb} MB</span>{" "}
            <span className="text-neutral-400">·</span>{" "}
            <span className="text-emerald-700 dark:text-emerald-300/70">사유: {reasonLabel(e.reason)}</span>
          </li>
        ))}
        {evicted.length > 5 && (
          <li className="text-neutral-500">…외 {evicted.length - 5}개</li>
        )}
      </ul>
    </div>
  );
}

function reasonLabel(reason: string): string {
  switch (reason) {
    case "size":
      return "용량 한도 초과";
    case "count":
      return "개수 한도 초과";
    case "age":
      return "보관 기간 만료";
    case "missing":
      return "이미지 누락";
    default:
      return reason;
  }
}
