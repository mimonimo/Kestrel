"use client";

import { useState } from "react";
import { cn } from "@/lib/utils";
import type { OsFamily, Severity, VulnType } from "@/lib/types";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const OS_FAMILIES: OsFamily[] = ["windows", "linux", "macos", "android", "ios", "other"];

// Mechanism-class chips. Order: most-common (RCE/XSS/SQLi) first, then
// the rest in roughly decreasing frequency. Backend stores these as
// free-form strings on `vulnerability_types.name`, so adding/removing
// chips here doesn't need a migration — but the parser must populate
// matching names for the chip to actually filter anything.
const VULN_TYPES: VulnType[] = [
  "RCE",
  "XSS",
  "SQLi",
  "CSRF",
  "XXE",
  "SSRF",
  "LFI",
  "Path-Traversal",
  "Deserialization",
  "Open-Redirect",
  "Privilege-Escalation",
  "Info-Disclosure",
  "Memory-Corruption",
  "DoS",
  "Auth",
  "Other",
];

const VULN_TYPE_LABELS: Partial<Record<VulnType, string>> = {
  "Path-Traversal": "경로순회",
  "Deserialization": "역직렬화",
  "Open-Redirect": "오픈리다이렉트",
  "Privilege-Escalation": "권한상승",
  "Info-Disclosure": "정보노출",
  "Memory-Corruption": "메모리손상",
};

const OS_LABELS: Record<OsFamily, string> = {
  windows: "Windows",
  linux: "Linux",
  macos: "macOS",
  android: "Android",
  ios: "iOS",
  other: "기타",
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
  fromDate: string;
  toDate: string;
}

export const EMPTY_FILTERS: FilterState = {
  severity: [],
  osFamily: [],
  types: [],
  fromDate: "",
  toDate: "",
};

interface Props {
  value: FilterState;
  onChange: (next: FilterState) => void;
}

export function FilterPanel({ value, onChange }: Props) {
  const toggle = <K extends "severity" | "osFamily" | "types">(
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
    value.fromDate !== "" ||
    value.toDate !== "";

  return (
    <aside className="space-y-6 rounded-lg border border-neutral-800 bg-surface-1 p-5">
      <FilterGroup title="심각도">
        {SEVERITIES.map((s) => (
          <Chip
            key={s}
            active={value.severity.includes(s)}
            onClick={() => toggle("severity", s)}
            variant="upper"
          >
            {s}
          </Chip>
        ))}
      </FilterGroup>

      <FilterGroup title="OS">
        {OS_FAMILIES.map((o) => (
          <Chip key={o} active={value.osFamily.includes(o)} onClick={() => toggle("osFamily", o)}>
            {OS_LABELS[o]}
          </Chip>
        ))}
      </FilterGroup>

      <FilterGroup title="취약점 유형">
        {VULN_TYPES.map((t) => (
          <Chip
            key={t}
            active={value.types.includes(t)}
            onClick={() => toggle("types", t)}
            title={VULN_TYPE_LABELS[t]}
          >
            {t}
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
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
  variant?: "default" | "upper";
  title?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      className={cn(
        "rounded-full border px-2.5 py-1 text-xs font-medium transition-colors",
        variant === "upper" && "uppercase",
        active
          ? "bg-neutral-100 text-neutral-900 border-neutral-100"
          : "bg-transparent text-neutral-300 border-neutral-700 hover:border-neutral-500 hover:text-neutral-100",
      )}
    >
      {children}
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
