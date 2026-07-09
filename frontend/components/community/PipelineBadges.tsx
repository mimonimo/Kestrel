/**
 * 파이프라인 구조화 메타 뱃지 (PR 10-FC).
 *
 * 외부 에이전트의 검증 파이프라인(CVSS+EPSS+KEV 융합·교차검증·우선순위 산출)이
 * 게시한 분석에만 붙는 뱃지 줄. pipelineVersion 이 없으면(기존/자유 게시 분석)
 * 아무것도 렌더하지 않는다 — 기존 카드 모습 무영향.
 *
 * 시각 위계: 우선순위·KEV·EPSS 는 기존 Critical/RCE pill 과 같은 크기로 눈에
 * 띄게, 검증 신뢰도·공급망·파이프라인 마커는 한 단계 작고 옅게(보조 정보).
 */
import { cn } from "@/lib/utils";
import type { AnalysisSummary } from "@/lib/api";

export const PRIORITY_RANK: Record<string, number> = {
  immediate: 0,
  scheduled: 1,
  monitor: 2,
};

const PRIORITY_META: Record<string, { label: string; dot: string; tone: string }> = {
  immediate: {
    label: "즉시 대응",
    dot: "🔴",
    tone: "bg-rose-100 text-rose-800 dark:bg-rose-500/15 dark:text-rose-200",
  },
  scheduled: {
    label: "예정 대응",
    dot: "🟡",
    tone: "bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-200",
  },
  monitor: {
    label: "모니터링",
    dot: "⚪",
    tone: "bg-surface-2 text-neutral-700 dark:text-neutral-300",
  },
};

/** qualityFlags 는 dict({likely_supply_chain: true}) / 배열(["likely_supply_chain"]) 둘 다 방어. */
function hasFlag(flags: AnalysisSummary["qualityFlags"], name: string): boolean {
  if (!flags) return false;
  if (Array.isArray(flags)) return flags.includes(name);
  if (typeof flags === "object") return !!(flags as Record<string, unknown>)[name];
  return false;
}

const pct = (v: number, digits = 1) => `${(v * 100).toFixed(digits).replace(/\.0$/, "")}%`;

export function PipelineBadges({ a }: { a: AnalysisSummary }) {
  // 파이프라인産이 아니면 전체 미렌더 — 기존 분석(전부 null) 무영향.
  if (!a?.pipelineVersion) return null;

  const priority = a.priorityAction ? PRIORITY_META[a.priorityAction] : undefined;
  const epss = typeof a.epssScore === "number" && Number.isFinite(a.epssScore) ? a.epssScore : null;
  const conf =
    typeof a.validationConfidence === "number" && Number.isFinite(a.validationConfidence)
      ? a.validationConfidence
      : null;
  const supplyChain = hasFlag(a.qualityFlags, "likely_supply_chain");

  return (
    <>
      {priority && (
        <span
          className={cn("rounded-full px-2 py-0.5 font-semibold", priority.tone)}
          title={a.priorityReasoning || undefined}
        >
          {priority.dot} {priority.label}
        </span>
      )}
      {a.kevListed === true && (
        <span
          className="rounded-full bg-rose-100 px-2 py-0.5 font-semibold text-rose-800 dark:bg-rose-500/15 dark:text-rose-200"
          title="CISA KEV — 실제 악용이 확인된 취약점"
        >
          KEV
        </span>
      )}
      {epss !== null && (
        <span
          className={cn(
            "rounded-full px-2 py-0.5 font-medium tabular-nums",
            epss >= 0.5
              ? "bg-orange-100 text-orange-800 dark:bg-orange-500/15 dark:text-orange-200"
              : "bg-sky-100 text-sky-800 dark:bg-sky-500/15 dark:text-sky-200",
          )}
          title="EPSS — 30일 내 익스플로잇 관측 확률"
        >
          EPSS {pct(epss)}
        </span>
      )}
      {conf !== null && (
        <span
          className="rounded-full bg-surface-2 px-1.5 py-0.5 text-[10px] text-neutral-600 dark:text-neutral-400"
          title="파이프라인 교차검증 신뢰도"
        >
          검증 {pct(conf, 0)}
        </span>
      )}
      {supplyChain && (
        <span
          className="rounded-full bg-violet-50 px-1.5 py-0.5 text-[10px] text-violet-700 dark:bg-violet-500/10 dark:text-violet-300"
          title="공급망 취약점 가능성 플래그"
        >
          공급망
        </span>
      )}
      <span
        className="rounded-full bg-surface-2 px-1.5 py-0.5 text-[10px] text-neutral-600 dark:text-neutral-400"
        title={`검증 파이프라인 생성: ${a.pipelineVersion}`}
      >
        ⚙ 파이프라인 검증
      </span>
    </>
  );
}
