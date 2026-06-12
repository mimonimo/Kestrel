"use client";

// 연관 취약점 방사형 노드 그래프 — 컴팩트·정돈 버전.
// 중심=현재 CVE, 주변=연관 CVE. 노드 색=심각도, KEV=로즈 링, 클릭=이동, 호버=툴팁.
// 외부 라이브러리 없이 인라인 SVG.
import { useState } from "react";
import { useRouter } from "next/navigation";
import type { Route } from "next";

import type { RelatedCve } from "@/lib/types";

const SEV_COLOR: Record<string, string> = {
  critical: "#f43f5e",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#10b981",
  none: "#94a3b8",
};
function sevColor(s?: string | null): string {
  return SEV_COLOR[(s ?? "").toLowerCase()] ?? "#94a3b8";
}

const LEGEND: { k: string; l: string }[] = [
  { k: "critical", l: "심각" },
  { k: "high", l: "높음" },
  { k: "medium", l: "보통" },
  { k: "low", l: "낮음" },
];

export function RelatedCvesGraph({ centerId, items }: { centerId: string; items: RelatedCve[] }) {
  const router = useRouter();
  const [hover, setHover] = useState<number | null>(null);

  const W = 320;
  const H = 188;
  const cx = W / 2;
  const cy = H / 2;
  const rx = 118;
  const ry = 64;
  const n = Math.max(items.length, 1);

  const nodes = items.map((it, i) => {
    // 위쪽 중앙에서 시작해 시계방향 균등 배치.
    const angle = (i / n) * Math.PI * 2 - Math.PI / 2;
    return { it, x: cx + rx * Math.cos(angle), y: cy + ry * Math.sin(angle) };
  });

  return (
    <div className="mx-auto w-full max-w-sm">
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="w-full"
        style={{ maxHeight: 210 }}
        role="img"
        aria-label="연관 취약점 노드 그래프"
      >
        {/* 궤도(은은한 가이드) */}
        <ellipse
          cx={cx}
          cy={cy}
          rx={rx}
          ry={ry}
          fill="none"
          stroke="currentColor"
          strokeWidth={1}
          strokeDasharray="2 4"
          className="text-neutral-200 dark:text-neutral-800"
        />

        {/* 엣지 — 중심에서 각 노드로 곡선 */}
        {nodes.map((nd, i) => {
          const active = hover === i;
          const mx = (cx + nd.x) / 2 + (nd.y - cy) * 0.12;
          const my = (cy + nd.y) / 2 - (nd.x - cx) * 0.12;
          return (
            <path
              key={`e-${nd.it.cveId}`}
              d={`M ${cx} ${cy} Q ${mx} ${my} ${nd.x} ${nd.y}`}
              fill="none"
              stroke={active ? sevColor(nd.it.severity) : "currentColor"}
              strokeWidth={active ? 1.6 : 1}
              strokeOpacity={active ? 0.9 : 0.5}
              className={active ? "" : "text-neutral-300 dark:text-neutral-700"}
            />
          );
        })}

        {/* 중심 노드 */}
        <circle cx={cx} cy={cy} r={22} className="fill-sky-500/15" />
        <circle cx={cx} cy={cy} r={15} className="fill-sky-500" />
        <text
          x={cx}
          y={cy}
          textAnchor="middle"
          dominantBaseline="central"
          className="fill-white text-[8px] font-semibold"
        >
          현재
        </text>

        {/* 연관 노드 */}
        {nodes.map((nd, i) => {
          const color = sevColor(nd.it.severity);
          const active = hover === i;
          const kev = nd.it.kevListed;
          return (
            <g
              key={nd.it.cveId}
              transform={`translate(${nd.x},${nd.y})`}
              className="cursor-pointer"
              onMouseEnter={() => setHover(i)}
              onMouseLeave={() => setHover(null)}
              onClick={() => router.push(`/cve/${nd.it.cveId}` as Route)}
            >
              {kev && <circle r={active ? 13 : 11} fill="none" stroke="#f43f5e" strokeWidth={2} />}
              <circle
                r={active ? 9 : 7}
                fill={color}
                stroke="#ffffff"
                strokeWidth={1.5}
                className="transition-all"
                style={{ filter: active ? "drop-shadow(0 1px 2px rgba(0,0,0,.25))" : undefined }}
              />
            </g>
          );
        })}
      </svg>

      {/* 범례 + 안내 */}
      <div className="mt-1 flex flex-wrap items-center justify-center gap-x-2.5 gap-y-1 text-[9px] text-neutral-400 dark:text-neutral-500">
        {LEGEND.map((g) => (
          <span key={g.k} className="inline-flex items-center gap-1">
            <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: SEV_COLOR[g.k] }} />
            {g.l}
          </span>
        ))}
        <span className="inline-flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded-full ring-2 ring-rose-500" />
          KEV
        </span>
        <span className="text-neutral-300 dark:text-neutral-600">· 노드 클릭 시 이동</span>
      </div>

      {/* 호버 툴팁 */}
      {hover !== null && items[hover] && (
        <div className="mt-2 rounded-lg border border-neutral-200 bg-white px-3 py-2 text-[11px] shadow-sm dark:border-neutral-700 dark:bg-surface-2">
          <div className="flex flex-wrap items-center gap-1.5">
            <span
              className="inline-block h-2.5 w-2.5 shrink-0 rounded-full"
              style={{ backgroundColor: sevColor(items[hover].severity) }}
            />
            <span className="font-mono font-semibold text-neutral-900 dark:text-neutral-100">
              {items[hover].cveId}
            </span>
            {items[hover].kevListed && (
              <span className="rounded-full bg-rose-100 px-1.5 py-px text-[9px] font-semibold text-rose-800 dark:bg-rose-500/15 dark:text-rose-200">
                KEV
              </span>
            )}
            <span className="ml-auto rounded-full bg-surface-2 px-1.5 py-px text-[9px] text-neutral-500">
              {items[hover].reason}
            </span>
          </div>
          <p className="mt-1 line-clamp-1 leading-snug text-neutral-600 dark:text-neutral-400">
            {items[hover].title}
          </p>
        </div>
      )}
    </div>
  );
}
