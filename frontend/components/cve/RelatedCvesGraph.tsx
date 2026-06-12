"use client";

// 연관 취약점 방사형 마인드맵(TTA 용어사전 스타일) — 중심=현재 CVE, 스포크 끝에
// 알약 라벨(=노드+텍스트 한 몸). 관계 유형별 색상, 심각도별 크기, 클릭 이동.
// 데스크톱은 방사형, 모바일은 정돈된 그룹 리스트로 반응형 폴백.
import { useState } from "react";
import { useRouter } from "next/navigation";
import type { Route } from "next";

import type { RelatedCve } from "@/lib/types";

// 관계 유형(reason 키워드) → 색상 분류.
interface Cat {
  key: string;
  label: string;
  hex: string;
  pill: string; // 알약 테두리/글자
}
const CATS: Cat[] = [
  { key: "vendor", label: "연관 벤더·제품", hex: "#10b981", pill: "border-emerald-400 text-emerald-700 dark:border-emerald-500/60 dark:text-emerald-300" },
  { key: "weakness", label: "공통 약점", hex: "#6366f1", pill: "border-indigo-400 text-indigo-700 dark:border-indigo-500/60 dark:text-indigo-300" },
  { key: "severity", label: "상위·근접 심각도", hex: "#f59e0b", pill: "border-amber-400 text-amber-700 dark:border-amber-500/60 dark:text-amber-300" },
  { key: "other", label: "기타 연관", hex: "#94a3b8", pill: "border-neutral-300 text-neutral-600 dark:border-neutral-600 dark:text-neutral-300" },
];
function catOf(reason: string): Cat {
  const r = reason || "";
  if (/(벤더|제품|vendor|product)/i.test(r)) return CATS[0];
  if (/(약점|유형|cwe|weakness)/i.test(r)) return CATS[1];
  if (/(심각|상위|근접|cvss|점수|severity)/i.test(r)) return CATS[2];
  return CATS[3];
}
// 심각도 → 크기 등급(분석 시 더 위험한 것이 더 크게).
function sizeOf(sev?: string | null): "lg" | "md" | "sm" {
  const s = (sev ?? "").toLowerCase();
  if (s === "critical") return "lg";
  if (s === "high") return "md";
  return "sm";
}
const SIZE_CLS: Record<"lg" | "md" | "sm", string> = {
  lg: "px-2.5 py-1 text-[11px] font-semibold",
  md: "px-2 py-0.5 text-[11px] font-medium",
  sm: "px-1.5 py-0.5 text-[10px]",
};

export function RelatedCvesGraph({ centerId, items }: { centerId: string; items: RelatedCve[] }) {
  const router = useRouter();
  const [hover, setHover] = useState<string | null>(null);
  const go = (id: string) => router.push(`/cve/${id}` as Route);

  // 방사형 좌표(viewBox 0~100, 퍼센트). 위에서 시작해 시계방향 균등 배치.
  const n = Math.max(items.length, 1);
  const RX = 38;
  const RY = 40;
  const placed = items.map((it, i) => {
    const a = (i / n) * Math.PI * 2 - Math.PI / 2;
    return { it, cat: catOf(it.reason), x: 50 + RX * Math.cos(a), y: 50 + RY * Math.sin(a) };
  });

  return (
    <div>
      {/* ── 데스크톱: 방사형 마인드맵 ── */}
      <div className="relative hidden aspect-[3/2] w-full sm:block">
        {/* 동심원 배경 + 스포크 */}
        <svg
          viewBox="0 0 100 100"
          preserveAspectRatio="none"
          className="absolute inset-0 h-full w-full"
          aria-hidden
        >
          {[46, 34, 22].map((r) => (
            <circle key={r} cx="50" cy="50" r={r} className="fill-neutral-500/[0.04]" />
          ))}
          {placed.map((p) => (
            <line
              key={`s-${p.it.cveId}`}
              x1="50"
              y1="50"
              x2={p.x}
              y2={p.y}
              stroke={p.cat.hex}
              strokeWidth={hover === p.it.cveId ? 1.8 : 1}
              strokeOpacity={hover === p.it.cveId ? 0.95 : 0.45}
              vectorEffect="non-scaling-stroke"
            />
          ))}
        </svg>

        {/* 중심 노드 */}
        <div
          className="absolute left-1/2 top-1/2 flex h-16 w-16 -translate-x-1/2 -translate-y-1/2 flex-col items-center justify-center rounded-full border-2 border-sky-500 bg-white text-center shadow-sm dark:bg-surface-1"
          title={centerId}
        >
          <span className="text-[9px] font-medium text-neutral-400 dark:text-neutral-500">현재</span>
          <span className="px-1 font-mono text-[9px] font-bold leading-tight text-sky-700 dark:text-sky-300">
            {centerId.replace(/^CVE-/, "")}
          </span>
        </div>

        {/* 알약 노드 */}
        {placed.map((p) => (
          <button
            key={p.it.cveId}
            type="button"
            onClick={() => go(p.it.cveId)}
            onMouseEnter={() => setHover(p.it.cveId)}
            onMouseLeave={() => setHover(null)}
            style={{ left: `${p.x}%`, top: `${p.y}%` }}
            className={`absolute z-10 -translate-x-1/2 -translate-y-1/2 whitespace-nowrap rounded-full border bg-white shadow-sm transition-transform hover:scale-105 dark:bg-surface-1 ${p.cat.pill} ${SIZE_CLS[sizeOf(p.it.severity)]} ${hover === p.it.cveId ? "ring-2 ring-sky-300 dark:ring-sky-500/40" : ""}`}
            title={`${p.it.cveId} · ${p.it.reason}${p.it.cvssScore != null ? ` · CVSS ${p.it.cvssScore}` : ""}\n${p.it.title}`}
          >
            {p.it.kevListed && <span className="mr-1 inline-block h-1.5 w-1.5 rounded-full bg-rose-500 align-middle" />}
            <span className="font-mono">{p.it.cveId}</span>
          </button>
        ))}
      </div>

      {/* 데스크톱 범례 */}
      <div className="mt-2 hidden flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-neutral-500 sm:flex dark:text-neutral-400">
        {CATS.map((c) => (
          <span key={c.key} className="inline-flex items-center gap-1">
            <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: c.hex }} />
            {c.label}
          </span>
        ))}
        <span className="inline-flex items-center gap-1">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-rose-500" /> KEV
        </span>
        <span className="text-neutral-400 dark:text-neutral-500">· 크기=심각도 · 클릭 시 이동</span>
      </div>

      {/* ── 모바일: 그룹 리스트 폴백 ── */}
      <ul className="space-y-1.5 sm:hidden">
        {items.map((it) => {
          const cat = catOf(it.reason);
          return (
            <li key={it.cveId}>
              <button
                type="button"
                onClick={() => go(it.cveId)}
                className="flex w-full items-center gap-2 rounded-lg border border-neutral-200 bg-white px-2.5 py-1.5 text-left dark:border-neutral-800 dark:bg-surface-1"
              >
                <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ backgroundColor: cat.hex }} />
                <span className="font-mono text-[11px] font-semibold text-neutral-900 dark:text-neutral-100">{it.cveId}</span>
                {it.cvssScore != null && (
                  <span className="font-mono text-[10px] font-bold tabular-nums text-neutral-500">{it.cvssScore.toFixed(1)}</span>
                )}
                <span className="ml-auto rounded-full bg-surface-2 px-1.5 py-px text-[9px] text-neutral-500">{it.reason}</span>
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
