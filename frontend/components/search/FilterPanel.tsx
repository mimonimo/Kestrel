"use client";

import { useQuery } from "@tanstack/react-query";
import { cn } from "@/lib/utils";
import { api } from "@/lib/api";
import type { Domain, OsFamily, Severity, VulnType } from "@/lib/types";
import { DOMAINS } from "@/lib/types";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const OS_FAMILIES: OsFamily[] = ["windows", "linux", "macos", "android", "ios", "other"];

// Filter-chip labels are kept in canonical English to match the rest
// of the panel — mixing 경로순회 / RCE / SSRF in the same row felt
// inconsistent and the standard CVE taxonomy is English anyway. An
// empty map keeps the lookup site working as a no-op; if we ever want
// localized aliases we can re-populate selectively.
const VULN_TYPE_LABELS: Partial<Record<string, string>> = {};

function _formatCount(n: number): string {
  if (n >= 10000) return `${(n / 1000).toFixed(0)}k`;
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
  return String(n);
}

const OS_LABELS: Record<OsFamily, string> = {
  windows: "Windows",
  linux: "Linux",
  macos: "macOS",
  android: "Android",
  ios: "iOS",
  other: "Other",
};

// Canonical English labels for the domain chips. The underlying value
// sent to the API is the lowercase string from `DOMAINS`; we keep
// label and key separate so future renames don't touch URL state or
// backend filter vocab.
const DOMAIN_LABELS: Record<Domain, string> = {
  kernel: "Kernel",
  os: "OS",
  browser: "Browser",
  "web-server": "Web Server",
  "web-framework": "Web Framework",
  database: "Database",
  media: "Media",
  network: "Network",
  mail: "Mail",
  auth: "Auth",
  crypto: "Crypto",
  runtime: "Runtime",
  mobile: "Mobile",
  virtualization: "Virtualization",
  office: "Office",
  enterprise: "Enterprise",
  iot: "IoT",
  messaging: "Messaging",
};

// Date filter (presets + custom inputs) lives inline next to the result
// count via ``DateRangeControl``. The state is still part of FilterState
// because the URL serializer + backend hook expect ``fromDate``/``toDate``
// keys; the sidebar just no longer renders the controls.

// Tier filter (KEV / EPSS상위 / CVSS·EPSS 조합) lives in URL state but
// the FilterPanel sidebar doesn't render chips for it — entry is always
// via the PriorityOverviewPanel drilldown, and the active tier is
// surfaced inline next to the result count instead.
export type PriorityTierKey =
  | "kev"
  | "epss_high"
  | "cvss_mid_epss_high"
  | "cvss_high_epss_low";

export interface FilterState {
  severity: Severity[];
  osFamily: OsFamily[];
  types: VulnType[];
  domains: Domain[];
  fromDate: string;
  toDate: string;
  priority?: PriorityTierKey;
}

export const EMPTY_FILTERS: FilterState = {
  severity: [],
  osFamily: [],
  types: [],
  domains: [],
  fromDate: "",
  toDate: "",
};

interface Props {
  value: FilterState;
  onChange: (next: FilterState) => void;
}

export function FilterPanel({ value, onChange }: Props) {
  const toggle = <K extends "severity" | "osFamily" | "types" | "domains">(
    key: K,
    item: FilterState[K][number],
  ) => {
    const list = value[key] as FilterState[K];
    const next = list.includes(item as never)
      ? (list.filter((v) => v !== item) as FilterState[K])
      : ([...list, item] as FilterState[K]);
    onChange({ ...value, [key]: next });
  };

  const hasFilters =
    value.severity.length > 0 ||
    value.osFamily.length > 0 ||
    value.types.length > 0 ||
    value.domains.length > 0 ||
    value.fromDate !== "" ||
    value.toDate !== "";

  // Pull facet counts so chips reflect what's actually in the parsed
  // corpus. Fetched once per session (60s staleTime) — small payload,
  // doesn't change between user clicks. Pre-PR the chip lists were
  // hardcoded and 7 of the 16 vuln-type chips matched zero rows.
  const facets = useQuery({
    queryKey: ["search", "facets"],
    queryFn: () => api.getSearchFacets(),
    staleTime: 60_000,
  });

  // Stable count lookup — facets may still be loading; we render the
  // chip list anyway and just hide the count suffix until it arrives.
  const typeCount = (name: string): number | undefined =>
    facets.data?.types.find((b) => b.value === name)?.count;
  const osCount = (name: string): number | undefined =>
    facets.data?.osFamilies.find((b) => b.value === name)?.count;
  const sevCount = (name: string): number | undefined =>
    facets.data?.severities.find((b) => b.value === name)?.count;
  const domCount = (name: string): number | undefined =>
    facets.data?.domains.find((b) => b.value === name)?.count;

  // Type chips come from facets — each name in DB becomes one chip,
  // sorted by count desc. Always include any currently-active type
  // even if it's not in the facets response (so an old URL with a
  // selected type that has 0 rows still shows the chip in active state).
  const dynamicTypes = facets.data?.types.map((b) => b.value) ?? [];
  const typesToRender = Array.from(
    new Set([...dynamicTypes, ...value.types]),
  );

  return (
    // ``lg:sticky`` 으로 스크롤해도 필터가 좌측에 따라옴. 헤더 높이(h-14)
    // 만큼 ``top-20`` 으로 띄우고, 패널 자체가 뷰포트보다 길어지면 칩 영역
    // 만 내부에서 스크롤되도록 ``overflow-y-auto + max-h``. ``self-start``
    // 가 없으면 부모 grid 가 row 높이로 stretch 시켜 sticky 가 무력화됨.
    <aside className="space-y-6 rounded-lg border border-neutral-200 bg-white p-5 dark:border-neutral-800 dark:bg-surface-1 lg:sticky lg:top-20 lg:self-start lg:max-h-[calc(100vh-6rem)] lg:overflow-y-auto">
      <FilterGroup title="심각도">
        {SEVERITIES.map((s) => (
          <Chip
            key={s}
            active={value.severity.includes(s)}
            onClick={() => toggle("severity", s)}
            variant="upper"
            count={sevCount(s)}
          >
            {s}
          </Chip>
        ))}
      </FilterGroup>

      <FilterGroup title="OS">
        {OS_FAMILIES.map((o) => (
          <Chip
            key={o}
            active={value.osFamily.includes(o)}
            onClick={() => toggle("osFamily", o)}
            count={osCount(o)}
          >
            {OS_LABELS[o]}
          </Chip>
        ))}
      </FilterGroup>

      <FilterGroup title="취약점 유형">
        {typesToRender.length === 0 && facets.isLoading && (
          <span className="text-xs text-neutral-600 dark:text-neutral-500">로딩중…</span>
        )}
        {typesToRender.map((t) => (
          <Chip
            key={t}
            active={value.types.includes(t as VulnType)}
            onClick={() => toggle("types", t as VulnType)}
            title={VULN_TYPE_LABELS[t]}
            count={typeCount(t)}
          >
            {t}
          </Chip>
        ))}
      </FilterGroup>

      <FilterGroup title="도메인">
        {DOMAINS.map((d) => (
          <Chip
            key={d}
            active={value.domains.includes(d)}
            onClick={() => toggle("domains", d)}
            title={d}
            count={domCount(d)}
          >
            {DOMAIN_LABELS[d]}
          </Chip>
        ))}
      </FilterGroup>

      <button
        type="button"
        onClick={() => onChange(EMPTY_FILTERS)}
        disabled={!hasFilters}
        className="text-xs text-neutral-600 hover:text-neutral-900 hover:underline disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:no-underline dark:text-neutral-500 dark:hover:text-neutral-200"
      >
        전체 초기화
      </button>
    </aside>
  );
}

function FilterGroup({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-neutral-600 dark:text-neutral-500">
        {title}
      </h3>
      <div className="flex flex-wrap gap-1.5">{children}</div>
    </div>
  );
}

function Chip({
  active,
  onClick,
  children,
  variant = "default",
  title,
  count,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
  variant?: "default" | "upper";
  title?: string;
  // When provided, rendered as a small dimmed suffix `(123)`. ``undefined``
  // hides the suffix (used while facets are still loading or for facets
  // not yet wired through). Zero shows as `(0)` so users see *empty*
  // categories explicitly rather than wondering why a chip silently
  // returns nothing.
  count?: number;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={title ? `${title}${count !== undefined ? ` — ${count}` : ""}` : undefined}
      className={cn(
        "rounded-full border px-2.5 py-1 text-xs font-medium transition-all duration-150 active:scale-95",
        variant === "upper" && "uppercase",
        count === 0 && "opacity-50",
        active
          ? "border-sky-500 bg-sky-100 text-sky-800 shadow-sm shadow-sky-500/20 dark:bg-sky-500/20 dark:text-sky-200"
          : "border-neutral-300 bg-white text-neutral-700 hover:-translate-y-0.5 hover:border-neutral-500 hover:text-neutral-900 hover:shadow-sm dark:border-neutral-700 dark:bg-transparent dark:text-neutral-300 dark:hover:border-neutral-500 dark:hover:text-neutral-100",
      )}
    >
      {children}
      {count !== undefined && (
        <span
          className={cn(
            "ml-1 text-[10px] font-normal tabular-nums",
            active
              ? "text-sky-700/80 dark:text-sky-200/70"
              : "text-neutral-500 dark:text-neutral-500",
          )}
        >
          ({_formatCount(count)})
        </span>
      )}
    </button>
  );
}

