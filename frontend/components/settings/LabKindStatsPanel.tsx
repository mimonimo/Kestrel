"use client";

import { Loader2, RefreshCw } from "lucide-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";

import { Button } from "@/components/ui/button";
import { PIE_PALETTE, PieGroup, type PieSlice } from "@/components/ui/pie-chart";
import { api, type LabKindStatsBucket } from "@/lib/api";

const KEY = ["sandbox", "lab-kind-stats"];

// Canonical source palette — keep aligned with SandboxPanel's badges so
// the dashboard chart and in-session chip feel like the same axis.
// Hex (not Tailwind classes) because the SVG ring strokes need raw colors.
const SOURCE_COLOR: Record<string, string> = {
  vulhub: "#34d399",       // emerald-400
  generic: "#a3a3a3",      // neutral-400
  synthesized: "#fbbf24",  // amber-400
};

// Per-kind palette — strong accents so the pie slices read at a glance.
const KIND_COLOR: Record<string, string> = {
  xss: "#f43f5e",            // rose
  rce: "#ef4444",            // red
  sqli: "#fb923c",           // orange
  ssti: "#a78bfa",           // violet
  "path-traversal": "#22d3ee", // cyan
  ssrf: "#38bdf8",           // sky
  "auth-bypass": "#facc15",  // yellow
  xxe: "#14b8a6",            // teal
  "open-redirect": "#818cf8", // indigo
  deserialization: "#e879f9", // fuchsia
};

function buildSlices(
  buckets: LabKindStatsBucket[],
  labelKey: "source" | "labKind",
  palette: Record<string, string>,
  topN = 8,
): PieSlice[] {
  if (buckets.length === 0) return [];
  // Roll any remainder beyond topN into a "기타" bucket so the donut
  // stays readable on a dozen+ kinds.
  const ordered = [...buckets].sort((a, b) => b.count - a.count);
  const top = ordered.slice(0, topN);
  const rest = ordered.slice(topN);
  const restCount = rest.reduce((s, b) => s + b.count, 0);
  const slices: PieSlice[] = top.map((b, i) => {
    const key = b[labelKey];
    return {
      label: key,
      count: b.count,
      color: palette[key] ?? PIE_PALETTE[i % PIE_PALETTE.length],
    };
  });
  if (restCount > 0) {
    slices.push({
      label: "기타",
      count: restCount,
      color: "#a3a3a3",
    });
  }
  return slices;
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
      <div className="flex items-center gap-2 text-sm text-neutral-600 dark:text-neutral-500">
        <Loader2 className="h-4 w-4 animate-spin" /> 실습 환경 분포를 불러오는 중…
      </div>
    );
  }
  if (stats.error) {
    return (
      <p className="text-sm text-amber-700 dark:text-amber-300">
        분포를 불러오지 못했습니다: {(stats.error as Error).message}
      </p>
    );
  }
  const data = stats.data!;

  const sourceSlices = buildSlices(data.bySource, "source", SOURCE_COLOR);
  const kindSlices = buildSlices(data.byKind, "labKind", KIND_COLOR);

  return (
    <section className="space-y-5 rounded-lg border border-neutral-200 bg-white p-5 dark:border-neutral-800 dark:bg-surface-1">
      <header className="flex items-baseline justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-baseline gap-2">
            <h2 className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">
              실습 환경 분포
            </h2>
            <span className="text-xs tabular-nums text-neutral-600 dark:text-neutral-500">
              {data.total.toLocaleString("ko-KR")}개
              {data.verified > 0 && (
                <span className="ml-1 text-emerald-700 dark:text-emerald-400">
                  · 검증 {data.verified.toLocaleString("ko-KR")}
                </span>
              )}
            </span>
          </div>
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

      <div className="grid gap-6 md:grid-cols-2">
        <div className="space-y-2">
          <h3 className="text-[10px] font-semibold uppercase tracking-wider text-neutral-600 dark:text-neutral-500">
            출처별 (vulhub · 표준 · AI 합성)
          </h3>
          <PieGroup slices={sourceSlices} total={data.total} />
        </div>
        <div className="space-y-2">
          <h3 className="text-[10px] font-semibold uppercase tracking-wider text-neutral-600 dark:text-neutral-500">
            취약점 유형별 (상위 8)
          </h3>
          <PieGroup slices={kindSlices} total={data.total} />
        </div>
      </div>
    </section>
  );
}
