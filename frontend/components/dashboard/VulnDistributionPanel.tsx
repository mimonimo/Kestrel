"use client";

import Link from "next/link";
import type { UrlObject } from "url";
import { BarChart3, Loader2 } from "lucide-react";
import { useQuery } from "@tanstack/react-query";

import { api, type FacetBucket } from "@/lib/api";
import { cn } from "@/lib/utils";

const SEV_ORDER = ["critical", "high", "medium", "low"] as const;
const SEV_LABEL: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};
const SEV_BAR_TINT: Record<string, string> = {
  critical: "bg-rose-500/80",
  high: "bg-orange-400/80",
  medium: "bg-amber-300/70",
  low: "bg-emerald-400/70",
};
const SEV_TEXT: Record<string, string> = {
  critical: "text-rose-300",
  high: "text-orange-300",
  medium: "text-amber-300",
  low: "text-emerald-300",
};

const SOURCE_LABEL: Record<string, string> = {
  mitre: "MITRE",
  nvd: "NVD",
  github_advisory: "GHSA",
  exploit_db: "Exploit-DB",
};
const SOURCE_TINT: Record<string, string> = {
  mitre: "bg-violet-500/80",
  nvd: "bg-sky-500/80",
  github_advisory: "bg-emerald-500/80",
  exploit_db: "bg-amber-500/80",
};

function formatNumber(n: number): string {
  return n.toLocaleString("ko-KR");
}

function formatDay(iso: string | null | undefined): string | null {
  if (!iso) return null;
  return iso.slice(0, 10).replace(/-/g, ".");
}

function topN(buckets: FacetBucket[] | undefined, n: number): FacetBucket[] {
  if (!buckets) return [];
  return [...buckets]
    .filter((b) => b.count > 0)
    .sort((a, b) => b.count - a.count)
    .slice(0, n);
}

export function VulnDistributionPanel() {
  const facets = useQuery({
    queryKey: ["search", "facets"],
    queryFn: () => api.getSearchFacets(),
    staleTime: 60_000,
  });

  if (facets.isLoading) {
    return (
      <section className="mb-8 rounded-xl border border-sky-500/20 bg-gradient-to-br from-sky-500/5 to-transparent p-5">
        <div className="flex items-center gap-2 text-sm text-neutral-500">
          <Loader2 className="h-4 w-4 animate-spin" /> 수집 분포 집계 중…
        </div>
      </section>
    );
  }
  if (facets.error || !facets.data) {
    return null;
  }
  const data = facets.data;
  const total = (data.severities ?? []).reduce((s, b) => s + b.count, 0);

  // Build severity rows in canonical order even if backend omits some.
  const sevByValue = new Map(data.severities?.map((b) => [b.value, b.count]) ?? []);
  const sevRows = SEV_ORDER.map((k) => ({
    key: k,
    count: sevByValue.get(k) ?? 0,
  }));

  const topTypes = topN(data.types, 8);
  const topDomains = topN(data.domains, 8);
  const sourcesList = topN(data.sources, 4);

  const dayLo = formatDay(data.earliestPublishedAt);
  const dayHi = formatDay(data.latestPublishedAt);

  return (
    <section className="mb-8 rounded-xl border border-sky-500/20 bg-gradient-to-br from-sky-500/5 to-transparent p-5">
      <header className="mb-4 flex flex-wrap items-baseline justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-sky-500/15 ring-1 ring-sky-400/30">
            <BarChart3 className="h-4 w-4 text-sky-300" />
          </div>
          <h2 className="text-base font-semibold text-neutral-100">
            수집된 취약점 분포
          </h2>
          <span className="rounded-full bg-sky-500/10 px-2 py-0.5 text-xs font-medium text-sky-200">
            총 {formatNumber(total)}건
          </span>
        </div>
        {dayLo && dayHi && (
          <span className="text-xs text-neutral-500">
            데이터 {dayLo} ~ {dayHi}
          </span>
        )}
      </header>

      <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
        {/* ── 심각도 ─────────────────────────────────────────────── */}
        <Group title="심각도" total={total}>
          <ul className="space-y-1.5">
            {sevRows.map((row) => (
              <DistRow
                key={row.key}
                label={SEV_LABEL[row.key]}
                href={{ pathname: "/", query: { severity: row.key } }}
                count={row.count}
                total={total}
                barTint={SEV_BAR_TINT[row.key]}
                textTint={SEV_TEXT[row.key]}
              />
            ))}
          </ul>
        </Group>

        {/* ── 출처 ───────────────────────────────────────────────── */}
        <Group title="출처">
          {sourcesList.length === 0 ? (
            <p className="text-xs text-neutral-500">집계할 출처가 없습니다.</p>
          ) : (
            <ul className="space-y-1.5">
              {sourcesList.map((b) => (
                <DistRow
                  key={b.value}
                  label={SOURCE_LABEL[b.value] ?? b.value}
                  count={b.count}
                  total={total}
                  barTint={SOURCE_TINT[b.value] ?? "bg-neutral-500/60"}
                />
              ))}
            </ul>
          )}
        </Group>

        {/* ── 취약점 유형 ────────────────────────────────────────── */}
        <Group title="취약점 유형 (상위 8)">
          {topTypes.length === 0 ? (
            <p className="text-xs text-neutral-500">집계할 유형이 없습니다.</p>
          ) : (
            <ul className="space-y-1.5">
              {topTypes.map((b) => (
                <DistRow
                  key={b.value}
                  label={b.value}
                  href={{ pathname: "/", query: { type: b.value } }}
                  count={b.count}
                  total={total}
                  barTint="bg-fuchsia-500/70"
                />
              ))}
            </ul>
          )}
        </Group>

        {/* ── 도메인 ─────────────────────────────────────────────── */}
        <Group title="도메인 (상위 8)">
          {topDomains.length === 0 ? (
            <p className="text-xs text-neutral-500">집계할 도메인이 없습니다.</p>
          ) : (
            <ul className="space-y-1.5">
              {topDomains.map((b) => (
                <DistRow
                  key={b.value}
                  label={b.value}
                  href={{ pathname: "/", query: { domain: b.value } }}
                  count={b.count}
                  total={total}
                  barTint="bg-cyan-500/70"
                />
              ))}
            </ul>
          )}
        </Group>
      </div>
    </section>
  );
}

function Group({
  title,
  total,
  children,
}: {
  title: string;
  total?: number;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-2">
      <div className="flex items-baseline justify-between gap-2">
        <h3 className="text-[11px] font-semibold uppercase tracking-wider text-neutral-500">
          {title}
        </h3>
        {typeof total === "number" && total > 0 && (
          <span className="text-[10px] tabular-nums text-neutral-600">
            합계 {formatNumber(total)}
          </span>
        )}
      </div>
      {children}
    </div>
  );
}

function DistRow({
  label,
  count,
  total,
  barTint,
  textTint,
  href,
}: {
  label: string;
  count: number;
  total: number;
  barTint: string;
  textTint?: string;
  // Object form so Next.js typed routes accept query strings without
  // having to register every (`/?severity=...`) variant.
  href?: UrlObject;
}) {
  const pct = total > 0 ? Math.max(0.5, (count / total) * 100) : 0;
  const inner = (
    <>
      <div className="flex items-baseline justify-between gap-2 text-[11px]">
        <span className={cn("truncate font-medium", textTint ?? "text-neutral-300")}>
          {label}
        </span>
        <span className="shrink-0 tabular-nums text-neutral-400">
          {formatNumber(count)}
          <span className="ml-1 text-neutral-600">({pct.toFixed(pct < 10 ? 1 : 0)}%)</span>
        </span>
      </div>
      <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-neutral-800/70">
        <div
          className={cn("h-full rounded-full transition-[width]", barTint)}
          style={{ width: `${pct}%` }}
        />
      </div>
    </>
  );
  return (
    <li>
      {href ? (
        <Link
          href={href}
          className="block rounded-md px-1 py-1 transition-colors hover:bg-sky-500/5"
          title={`${label} 필터 적용`}
        >
          {inner}
        </Link>
      ) : (
        <div className="px-1 py-1">{inner}</div>
      )}
    </li>
  );
}
