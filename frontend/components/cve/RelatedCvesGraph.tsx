"use client";

// 연관 취약점 관계 맵 — 관계 유형(reason)별로 묶고, 그룹 안에서 심각도(CVSS)
// 순으로 정렬해 상·하위 연관을 한눈에 분석. 왼쪽 레일 + 분기로 노드와 텍스트를
// 한 몸으로 배치(떠다니는 원 대신 구조적 트리). 외부 라이브러리 없음.
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
function scoreOf(it: RelatedCve): number {
  return it.cvssScore ?? -1;
}

export function RelatedCvesGraph({ centerId, items }: { centerId: string; items: RelatedCve[] }) {
  const router = useRouter();

  // 관계 유형(reason)별 그룹핑.
  const groupMap = new Map<string, RelatedCve[]>();
  for (const it of items) {
    const key = it.reason || "연관";
    (groupMap.get(key) ?? groupMap.set(key, []).get(key)!).push(it);
  }
  // 그룹: 내부는 점수 내림차순, 그룹 순서는 그룹 내 최고점 내림차순.
  const groups = [...groupMap.entries()]
    .map(([reason, list]) => ({
      reason,
      list: [...list].sort((a, b) => scoreOf(b) - scoreOf(a)),
    }))
    .sort((a, b) => scoreOf(b.list[0]) - scoreOf(a.list[0]));

  return (
    <div className="text-xs">
      {/* 현재 CVE — 루트 노드 */}
      <div className="flex items-center gap-2">
        <span className="inline-flex items-center gap-1.5 rounded-lg bg-sky-500 px-2.5 py-1 font-mono text-[11px] font-semibold text-white shadow-sm">
          <span className="h-1.5 w-1.5 rounded-full bg-white/90" />
          {centerId}
        </span>
        <span className="text-[10px] text-neutral-400 dark:text-neutral-500">현재 취약점</span>
      </div>

      {/* 관계 그룹들 — 왼쪽 레일로 연결 */}
      <div className="ml-[9px] border-l border-neutral-200 pl-4 dark:border-neutral-800">
        {groups.map((g) => (
          <div key={g.reason} className="relative pt-3">
            {/* 그룹 분기점 + 라벨 */}
            <div className="relative flex items-center gap-1.5">
              <span className="absolute -left-4 top-1/2 h-px w-3 -translate-y-1/2 bg-neutral-200 dark:bg-neutral-800" />
              <span className="rounded-md bg-neutral-100 px-1.5 py-0.5 text-[10px] font-medium text-neutral-600 dark:bg-surface-3 dark:text-neutral-300">
                {g.reason}
              </span>
              <span className="text-[10px] tabular-nums text-neutral-400">{g.list.length}</span>
            </div>

            {/* 그룹 내 연관 CVE — 노드 칩(텍스트와 한 몸) */}
            <ul className="mt-1.5 space-y-1">
              {g.list.map((it) => {
                const color = sevColor(it.severity);
                return (
                  <li key={it.cveId}>
                    <button
                      type="button"
                      onClick={() => router.push(`/cve/${it.cveId}` as Route)}
                      className="group flex w-full items-center gap-2 rounded-lg border border-neutral-200 bg-white px-2.5 py-1.5 text-left transition-colors hover:border-sky-300 hover:bg-sky-50/50 dark:border-neutral-800 dark:bg-surface-1 dark:hover:border-sky-500/40 dark:hover:bg-surface-2"
                    >
                      {/* 심각도 점 = 노드 */}
                      <span
                        className="h-2.5 w-2.5 shrink-0 rounded-full ring-2 ring-white dark:ring-surface-1"
                        style={{ backgroundColor: color, boxShadow: it.kevListed ? "0 0 0 2px #f43f5e" : undefined }}
                        title={it.kevListed ? "KEV 등재" : undefined}
                      />
                      {/* CVSS 점수 */}
                      <span
                        className="w-9 shrink-0 text-right font-mono text-[11px] font-bold tabular-nums"
                        style={{ color }}
                      >
                        {it.cvssScore != null ? it.cvssScore.toFixed(1) : "—"}
                      </span>
                      {/* CVE + 제목 */}
                      <span className="min-w-0 flex-1">
                        <span className="font-mono text-[11px] font-semibold text-neutral-900 group-hover:text-sky-700 dark:text-neutral-100 dark:group-hover:text-sky-300">
                          {it.cveId}
                        </span>
                        <span className="ml-1.5 text-[10px] text-neutral-500 dark:text-neutral-400">
                          {it.title}
                        </span>
                      </span>
                      {it.kevListed && (
                        <span className="shrink-0 rounded-full bg-rose-100 px-1.5 py-px text-[9px] font-semibold text-rose-700 dark:bg-rose-500/15 dark:text-rose-200">
                          KEV
                        </span>
                      )}
                    </button>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </div>

      {/* 범례 */}
      <div className="mt-3 flex flex-wrap items-center gap-x-2.5 gap-y-1 border-t border-neutral-100 pt-2 text-[9px] text-neutral-400 dark:border-neutral-800/60 dark:text-neutral-500">
        점 = 심각도
        {(["critical", "high", "medium", "low"] as const).map((k) => (
          <span key={k} className="inline-flex items-center gap-1">
            <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: SEV_COLOR[k] }} />
            {k === "critical" ? "심각" : k === "high" ? "높음" : k === "medium" ? "보통" : "낮음"}
          </span>
        ))}
        <span className="inline-flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded-full ring-2 ring-rose-500" /> KEV
        </span>
        <span className="text-neutral-300 dark:text-neutral-600">· 숫자=CVSS · 클릭 시 이동</span>
      </div>
    </div>
  );
}
