"use client";

// 연관 취약점 방사형 노드 그래프 — 중심=현재 CVE, 주변=연관 CVE.
// 노드 색=심각도, 빨간 테두리=KEV, 클릭=이동, 마우스오버=요약 툴팁.
// 외부 라이브러리 없이 인라인 SVG 로 구현(번들 부담 0).
import { useState } from "react";
import { useRouter } from "next/navigation";
import type { Route } from "next";

import type { RelatedCve } from "@/lib/types";

const SEV_COLOR: Record<string, string> = {
  critical: "#e11d48",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#10b981",
  none: "#64748b",
};
function sevColor(s?: string | null): string {
  return SEV_COLOR[(s ?? "").toLowerCase()] ?? "#64748b";
}

export function RelatedCvesGraph({ centerId, items }: { centerId: string; items: RelatedCve[] }) {
  const router = useRouter();
  const [hover, setHover] = useState<number | null>(null);

  const W = 460;
  const H = 320;
  const cx = W / 2;
  const cy = H / 2;
  const rx = 168;
  const ry = 116;
  const n = Math.max(items.length, 1);

  const nodes = items.map((it, i) => {
    const angle = (i / n) * Math.PI * 2 - Math.PI / 2;
    return { it, x: cx + rx * Math.cos(angle), y: cy + ry * Math.sin(angle) };
  });

  return (
    <div className="relative w-full select-none">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label="연관 취약점 노드 그래프">
        {/* 엣지 */}
        {nodes.map((nd, i) => (
          <line
            key={`e-${nd.it.cveId}`}
            x1={cx}
            y1={cy}
            x2={nd.x}
            y2={nd.y}
            stroke="currentColor"
            strokeWidth={hover === i ? 2 : 1}
            className={hover === i ? "text-sky-400" : "text-neutral-300 dark:text-neutral-700"}
          />
        ))}

        {/* 중심 노드 = 현재 CVE */}
        <circle cx={cx} cy={cy} r={26} className="fill-sky-500" />
        <text
          x={cx}
          y={cy}
          textAnchor="middle"
          dominantBaseline="central"
          className="fill-white text-[9px] font-bold"
        >
          현재
        </text>

        {/* 연관 노드 */}
        {nodes.map((nd, i) => {
          const color = sevColor(nd.it.severity);
          const short = nd.it.cveId.replace(/^CVE-/, "");
          const active = hover === i;
          return (
            <g
              key={nd.it.cveId}
              transform={`translate(${nd.x},${nd.y})`}
              className="cursor-pointer"
              onMouseEnter={() => setHover(i)}
              onMouseLeave={() => setHover(null)}
              onClick={() => router.push(`/cve/${nd.it.cveId}` as Route)}
            >
              <circle
                r={active ? 19 : 15}
                fill={color}
                stroke={nd.it.kevListed ? "#e11d48" : "#ffffff"}
                strokeWidth={nd.it.kevListed ? 3 : 1.5}
                className="transition-all"
              />
              <text
                textAnchor="middle"
                y={31}
                className="fill-neutral-600 text-[8px] font-mono dark:fill-neutral-300"
              >
                {short}
              </text>
            </g>
          );
        })}
      </svg>

      {/* 즉시 표시 툴팁 (호버 노드 정보) */}
      {hover !== null && items[hover] && (
        <div className="pointer-events-none absolute left-1/2 top-1 z-10 w-[88%] max-w-xs -translate-x-1/2 rounded-lg border border-neutral-200 bg-white px-3 py-2 text-[11px] shadow-lg dark:border-neutral-700 dark:bg-surface-3">
          <div className="flex items-center gap-1.5">
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
          <p className="mt-1 line-clamp-2 leading-snug text-neutral-600 dark:text-neutral-400">
            {items[hover].title}
          </p>
          <p className="mt-0.5 text-[9px] text-neutral-400">클릭하면 이동합니다</p>
        </div>
      )}
    </div>
  );
}
