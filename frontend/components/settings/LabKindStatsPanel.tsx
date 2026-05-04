"use client";

import { Loader2, RefreshCw } from "lucide-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";

import { Button } from "@/components/ui/button";
import { api, type LabKindStatsBucket } from "@/lib/api";
import { cn } from "@/lib/utils";

const KEY = ["sandbox", "lab-kind-stats"];

// Per-source / per-kind tints. Keep in lockstep with SandboxPanel's
// LabKindBadge palette so the dashboard and the in-session badge feel
// like the same axis. Unknown kinds fall through to neutral grey so
// adding a new catalog entry doesn't break the panel.
const SOURCE_TINT: Record<string, string> = {
  vulhub: "bg-emerald-500/20 text-emerald-200",
  generic: "bg-neutral-700/40 text-neutral-300",
  synthesized: "bg-amber-500/20 text-amber-200",
};

const KIND_TINT: Record<string, string> = {
  xss: "bg-rose-500/20 text-rose-200",
  rce: "bg-red-500/20 text-red-200",
  sqli: "bg-orange-500/20 text-orange-200",
  ssti: "bg-purple-500/20 text-purple-200",
  "path-traversal": "bg-cyan-500/20 text-cyan-200",
  ssrf: "bg-blue-500/20 text-blue-200",
  "synthesized/*": "bg-amber-500/20 text-amber-200",
};

function pct(num: number, den: number): number {
  if (den <= 0) return 0;
  return Math.round((num / den) * 1000) / 10;  // one decimal
}

function Bar({
  buckets,
  total,
  tintMap,
  labelKey,
}: {
  buckets: LabKindStatsBucket[];
  total: number;
  tintMap: Record<string, string>;
  labelKey: "source" | "labKind";
}) {
  if (total === 0 || buckets.length === 0) {
    return <p className="text-xs text-neutral-500">데이터 없음</p>;
  }
  // Cap display to top 8 — anything past the top is rolled into "기타".
  const top = buckets.slice(0, 8);
  const rest = buckets.slice(8);
  const restCount = rest.reduce((s, b) => s + b.count, 0);
  const display = restCount > 0
    ? [...top, { source: "기타", labKind: "기타", count: restCount, verifiedCount: 0 }]
    : top;

  return (
    <div className="space-y-2">
      <div className="flex h-3 w-full overflow-hidden rounded-full bg-neutral-800">
        {display.map((b, i) => {
          const key = b[labelKey];
          const tint = tintMap[key] ?? "bg-neutral-600 text-neutral-200";
          const w = pct(b.count, total);
          return (
            <div
              key={`${key}-${i}`}
              title={`${key}: ${b.count}개 (${w}%)`}
              className={cn("h-full transition-all", tint.split(" ")[0])}
              style={{ width: `${w}%` }}
            />
          );
        })}
      </div>
      <ul className="flex flex-col gap-1 text-xs">
        {display.map((b, i) => {
          const key = b[labelKey];
          const tint = tintMap[key] ?? "bg-neutral-700 text-neutral-300";
          return (
            <li key={`${key}-${i}`} className="flex items-center gap-2">
              <span
                className={cn(
                  "inline-block min-w-[8.5rem] rounded px-2 py-0.5 text-center font-mono text-[11px]",
                  tint,
                )}
              >
                {key}
              </span>
              <span className="tabular-nums text-neutral-300">
                {b.count} <span className="text-neutral-500">({pct(b.count, total)}%)</span>
              </span>
              {b.verifiedCount > 0 && (
                <span className="text-emerald-300/80">· verified {b.verifiedCount}</span>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

export function LabKindStatsPanel() {
  const qc = useQueryClient();
  const stats = useQuery({
    queryKey: KEY,
    queryFn: () => api.getLabKindStats(),
    staleTime: 30_000,
  });

  if (stats.isLoading) {
    return (
      <div className="flex items-center gap-2 text-sm text-neutral-500">
        <Loader2 className="h-4 w-4 animate-spin" /> lab 분포 조회 중…
      </div>
    );
  }
  if (stats.error) {
    return (
      <p className="text-sm text-amber-300">
        lab 분포 조회 실패: {(stats.error as Error).message}
      </p>
    );
  }
  const data = stats.data!;

  return (
    <section className="space-y-5 rounded-lg border border-neutral-800 bg-surface-1 p-5">
      <header className="flex items-baseline justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-neutral-100">CVE → lab 매핑 분포</h2>
          <p className="mt-1 text-xs text-neutral-500">
            cve_lab_mappings 전체 {data.total}개 중 verified {data.verified}개. 한
            클래스로 쏠려있다면 합성 prompt 또는 classifier 룰의 편향 신호.
          </p>
        </div>
        <Button
          size="sm"
          variant="ghost"
          onClick={() => qc.invalidateQueries({ queryKey: KEY })}
          aria-label="새로고침"
          title="새로고침"
        >
          <RefreshCw className="h-3.5 w-3.5" />
        </Button>
      </header>

      <div className="grid gap-5 md:grid-cols-2">
        <div className="space-y-2">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-neutral-500">
            provenance 별 (vulhub / generic / synthesized)
          </h3>
          <Bar
            buckets={data.bySource}
            total={data.total}
            tintMap={SOURCE_TINT}
            labelKey="source"
          />
        </div>
        <div className="space-y-2">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-neutral-500">
            lab kind 별 (top 8)
          </h3>
          <Bar
            buckets={data.byKind}
            total={data.total}
            tintMap={KIND_TINT}
            labelKey="labKind"
          />
        </div>
      </div>
    </section>
  );
}
