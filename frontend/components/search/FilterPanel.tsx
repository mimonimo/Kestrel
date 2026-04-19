"use client";

import { useState } from "react";
import { cn } from "@/lib/utils";
import type { OsFamily, Severity, VulnType } from "@/lib/types";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const OS_FAMILIES: OsFamily[] = ["windows", "linux", "macos", "android", "ios"];
const VULN_TYPES: VulnType[] = ["RCE", "XSS", "SQLi", "CSRF", "SSRF", "Auth", "DoS"];

const OS_LABELS: Record<OsFamily, string> = {
  windows: "Windows",
  linux: "Linux",
  macos: "macOS",
  android: "Android",
  ios: "iOS",
  other: "기타",
};

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
          <Chip key={t} active={value.types.includes(t)} onClick={() => toggle("types", t)}>
            {t}
          </Chip>
        ))}
      </FilterGroup>

      <FilterGroup title="기간">
        <div className="flex w-full flex-col gap-2">
          <DateInput
            label="시작"
            value={value.fromDate}
            onChange={(v) => onChange({ ...value, fromDate: v })}
          />
          <DateInput
            label="종료"
            value={value.toDate}
            onChange={(v) => onChange({ ...value, toDate: v })}
          />
        </div>
      </FilterGroup>

      <button
        type="button"
        onClick={() => onChange(EMPTY_FILTERS)}
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
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
  variant?: "default" | "upper";
}) {
  return (
    <button
      type="button"
      onClick={onClick}
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
