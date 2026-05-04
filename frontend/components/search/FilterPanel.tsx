"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { cn } from "@/lib/utils";
import { api } from "@/lib/api";
import type { Domain, OsFamily, Severity, VulnType } from "@/lib/types";
import { DOMAINS } from "@/lib/types";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const OS_FAMILIES: OsFamily[] = ["windows", "linux", "macos", "android", "ios", "other"];

// Korean labels for the long English vuln-type names. Anything missing
// from this map is rendered as-is. Generated dynamically from /search/facets
// so chips that have 0 rows in DB simply don't appear (was a bug pre-PR
// where 7 hardcoded chips never matched anything).
const VULN_TYPE_LABELS: Partial<Record<string, string>> = {
  "Path-Traversal": "경로순회",
  Deserialization: "역직렬화",
  "Open-Redirect": "오픈리다이렉트",
  "Privilege-Escalation": "권한상승",
  "Info-Disclosure": "정보노출",
  "Memory-Corruption": "메모리손상",
};

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
  other: "기타",
};

// Korean labels for the domain chips. The chip itself shows the label,
// the underlying value sent to the API is the canonical lowercase
// English string from `DOMAINS`. Keeping label and key separate so we
// can rename the UI without churning URL state or backend filter
// vocab.
const DOMAIN_LABELS: Record<Domain, string> = {
  kernel: "커널",
  os: "OS",
  browser: "브라우저",
  "web-server": "웹서버",
  "web-framework": "웹프레임워크",
  database: "DB",
  media: "미디어",
  network: "네트워크",
  mail: "메일",
  auth: "인증",
  crypto: "암호",
  runtime: "런타임",
  mobile: "모바일",
  virtualization: "가상화",
  office: "오피스",
  enterprise: "엔터프라이즈",
  iot: "IoT",
  messaging: "메신저",
};

// Date presets. ``days`` is "from = today - N days, to = open-ended"; the
// special ``today`` preset narrows to a single day so users can quickly
// pull up "what dropped today". ``custom`` clears the preset highlight
// so the raw inputs become the source of truth.
type PresetKey = "today" | "7d" | "30d" | "90d" | "365d" | "custom";

interface DatePreset {
  key: PresetKey;
  label: string;
}

const DATE_PRESETS: DatePreset[] = [
  { key: "today", label: "오늘" },
  { key: "7d", label: "7일" },
  { key: "30d", label: "30일" },
  { key: "90d", label: "90일" },
  { key: "365d", label: "1년" },
  { key: "custom", label: "직접 입력" },
];

function todayIso(): string {
  // Local date (not UTC) so a Korean user clicking "오늘" at 1AM KST
  // doesn't accidentally fetch yesterday's UTC date.
  const now = new Date();
  const tz = now.getTimezoneOffset();
  return new Date(now.getTime() - tz * 60_000).toISOString().slice(0, 10);
}

function isoDaysAgo(days: number): string {
  const now = new Date();
  now.setDate(now.getDate() - days);
  const tz = now.getTimezoneOffset();
  return new Date(now.getTime() - tz * 60_000).toISOString().slice(0, 10);
}

function presetForDates(from: string, to: string): PresetKey | null {
  if (!from && !to) return null;
  const today = todayIso();
  if (from === today && to === today) return "today";
  if (to && to !== today) return null;
  if (from === isoDaysAgo(7)) return "7d";
  if (from === isoDaysAgo(30)) return "30d";
  if (from === isoDaysAgo(90)) return "90d";
  if (from === isoDaysAgo(365)) return "365d";
  return null;
}

export interface FilterState {
  severity: Severity[];
  osFamily: OsFamily[];
  types: VulnType[];
  domains: Domain[];
  fromDate: string;
  toDate: string;
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

  // ``custom`` is sticky — users who click it expect the raw inputs to
  // stay editable even if from/to happen to coincide with a preset.
  const matchedPreset = presetForDates(value.fromDate, value.toDate);
  const [customMode, setCustomMode] = useState(false);
  const activePreset: PresetKey | null = customMode ? "custom" : matchedPreset;

  const applyPreset = (key: PresetKey) => {
    if (key === "custom") {
      setCustomMode(true);
      return;
    }
    setCustomMode(false);
    if (key === "today") {
      const t = todayIso();
      onChange({ ...value, fromDate: t, toDate: t });
      return;
    }
    const days = key === "7d" ? 7 : key === "30d" ? 30 : key === "90d" ? 90 : 365;
    onChange({ ...value, fromDate: isoDaysAgo(days), toDate: "" });
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
    <aside className="space-y-6 rounded-lg border border-neutral-800 bg-surface-1 p-5">
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
          <span className="text-xs text-neutral-500">로딩중…</span>
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

      <FilterGroup title="기간">
        <div className="flex w-full flex-col gap-3">
          <div className="flex flex-wrap gap-1.5">
            {DATE_PRESETS.map((p) => (
              <Chip
                key={p.key}
                active={activePreset === p.key}
                onClick={() => applyPreset(p.key)}
              >
                {p.label}
              </Chip>
            ))}
          </div>
          {(activePreset === "custom" || (activePreset === null && (value.fromDate || value.toDate))) && (
            <div className="flex w-full flex-col gap-2">
              <DateInput
                label="시작"
                value={value.fromDate}
                onChange={(v) => {
                  setCustomMode(true);
                  onChange({ ...value, fromDate: v });
                }}
              />
              <DateInput
                label="종료"
                value={value.toDate}
                onChange={(v) => {
                  setCustomMode(true);
                  onChange({ ...value, toDate: v });
                }}
              />
            </div>
          )}
        </div>
      </FilterGroup>

      <button
        type="button"
        onClick={() => {
          setCustomMode(false);
          onChange(EMPTY_FILTERS);
        }}
        disabled={!hasFilters}
        className="text-xs text-neutral-500 hover:text-neutral-200 hover:underline disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:no-underline"
      >
        전체 초기화
      </button>
    </aside>
  );
}

function FilterGroup({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-neutral-500">
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
        "rounded-full border px-2.5 py-1 text-xs font-medium transition-colors",
        variant === "upper" && "uppercase",
        count === 0 && "opacity-50",
        active
          ? "bg-neutral-100 text-neutral-900 border-neutral-100"
          : "bg-transparent text-neutral-300 border-neutral-700 hover:border-neutral-500 hover:text-neutral-100",
      )}
    >
      {children}
      {count !== undefined && (
        <span
          className={cn(
            "ml-1 text-[10px] font-normal tabular-nums",
            active ? "text-neutral-600" : "text-neutral-500",
          )}
        >
          ({_formatCount(count)})
        </span>
      )}
    </button>
  );
}

function DateInput({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
}) {
  const [local, setLocal] = useState(value);
  return (
    <label className="flex items-center gap-2 text-xs text-neutral-500">
      <span className="w-8 shrink-0">{label}</span>
      <input
        type="date"
        value={local}
        onChange={(e) => {
          setLocal(e.target.value);
          onChange(e.target.value);
        }}
        className="min-w-0 flex-1 rounded-md border border-neutral-700 bg-surface-2 px-2 py-1 text-xs text-neutral-100 focus:border-neutral-500 focus:outline-none [color-scheme:dark]"
      />
    </label>
  );
}
