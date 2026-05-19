"use client";

import { CalendarRange, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

// Preset shortcuts. ``today`` clamps both endpoints to the current day so
// "오늘" gives a single-day slice. The day-count presets leave ``to`` empty
// (=open-ended toward now) which matches what an analyst expects from a
// "지난 7일" filter.
type PresetKey = "today" | "7d" | "30d" | "90d" | "365d";

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
];

function todayIso(): string {
  // Local-date ISO (YYYY-MM-DD) so a user clicking "오늘" at 1AM KST does
  // not accidentally fetch yesterday's UTC date.
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

function fmtIso(iso: string | null | undefined): string | null {
  if (!iso) return null;
  // Take only the YYYY-MM-DD prefix so timezone-suffixed timestamps
  // (e.g. "2026-05-09T01:16:09Z") render as "2026.05.09" — operator
  // cares about the *day* of the corpus boundary, not the second.
  return iso.slice(0, 10).replace(/-/g, ".");
}

interface Props {
  fromDate: string;
  toDate: string;
  onChange: (next: { fromDate: string; toDate: string }) => void;
}

// Inline date-range control rendered next to the result count. When no
// filter is active we show the full corpus range as an "info" hint; when
// a filter is active we show the active range highlighted. Clicking opens
// a popover with presets + custom date inputs that apply immediately.
export function DateRangeControl({ fromDate, toDate, onChange }: Props) {
  const [open, setOpen] = useState(false);
  const wrapperRef = useRef<HTMLDivElement | null>(null);

  // Corpus min/max for the placeholder hint. Cheap query (60s TTL on the
  // backend + 60s staleTime here) so we don't refetch on every open.
  const facets = useQuery({
    queryKey: ["search", "facets"],
    queryFn: () => api.getSearchFacets(),
    staleTime: 60_000,
  });
  const corpusLo = facets.data?.earliestPublishedAt ?? null;
  const corpusHi = facets.data?.latestPublishedAt ?? null;

  // Close on outside click + Esc — standard popover ergonomics.
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!wrapperRef.current) return;
      if (!wrapperRef.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("mousedown", onDown);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onDown);
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const active = Boolean(fromDate || toDate);
  const matchedPreset = presetForDates(fromDate, toDate);

  const applyPreset = (key: PresetKey) => {
    if (key === "today") {
      const t = todayIso();
      onChange({ fromDate: t, toDate: t });
      return;
    }
    const days = key === "7d" ? 7 : key === "30d" ? 30 : key === "90d" ? 90 : 365;
    onChange({ fromDate: isoDaysAgo(days), toDate: "" });
  };

  // Trigger label — "기간 ..." when filtered, "데이터 ..." (corpus range)
  // when unfiltered. Keeps the operator's at-a-glance read intact even
  // before they touch the control.
  let triggerLabel: string;
  if (active) {
    const a = fmtIso(fromDate) || "처음";
    const b = fmtIso(toDate) || "오늘";
    triggerLabel = `기간 ${a} ~ ${b}`;
  } else if (corpusLo && corpusHi) {
    triggerLabel = `데이터 ${fmtIso(corpusLo)} ~ ${fmtIso(corpusHi)}`;
  } else {
    triggerLabel = "기간 설정";
  }

  return (
    <div ref={wrapperRef} className="relative inline-block">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className={cn(
          "inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-[11px] transition-colors",
          active
            ? "border-amber-500/40 bg-amber-500/10 text-amber-800 dark:text-amber-200 hover:border-amber-400/60"
            : "border-neutral-800 bg-surface-2 text-neutral-400 hover:border-neutral-600 hover:text-neutral-200",
        )}
        title={
          active
            ? "기간 필터 적용 중 — 클릭하여 변경"
            : "수집된 CVE의 publishedAt 범위 — 클릭하여 기간 필터 적용"
        }
        aria-haspopup="dialog"
        aria-expanded={open}
      >
        <CalendarRange className="h-3 w-3" />
        {triggerLabel}
        {active && (
          <span
            role="button"
            tabIndex={0}
            onClick={(e) => {
              e.stopPropagation();
              onChange({ fromDate: "", toDate: "" });
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.stopPropagation();
                e.preventDefault();
                onChange({ fromDate: "", toDate: "" });
              }
            }}
            className="ml-0.5 inline-flex h-3 w-3 items-center justify-center rounded-full hover:bg-amber-400/20"
            aria-label="기간 필터 해제"
          >
            <X className="h-2.5 w-2.5" />
          </span>
        )}
      </button>

      {open && (
        <div
          role="dialog"
          aria-label="기간 필터"
          className="absolute left-0 top-[calc(100%+6px)] z-30 w-[300px] rounded-lg border border-neutral-700 bg-surface-1 p-3 text-xs shadow-lg"
        >
          <div className="mb-2 flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wide text-neutral-400">
              빠른 선택
            </span>
            {matchedPreset && (
              <span className="text-[10px] text-amber-700 dark:text-amber-300">현재: {DATE_PRESETS.find((p) => p.key === matchedPreset)?.label}</span>
            )}
          </div>
          <div className="mb-3 flex flex-wrap gap-1.5">
            {DATE_PRESETS.map((p) => (
              <button
                key={p.key}
                type="button"
                onClick={() => applyPreset(p.key)}
                className={cn(
                  "rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors",
                  matchedPreset === p.key
                    ? "border-neutral-100 bg-neutral-100 text-neutral-900"
                    : "border-neutral-700 text-neutral-300 hover:border-neutral-500 hover:text-neutral-100",
                )}
              >
                {p.label}
              </button>
            ))}
          </div>

          <div className="mb-3 space-y-2 border-t border-neutral-800 pt-3">
            <span className="text-[11px] font-semibold uppercase tracking-wide text-neutral-400">
              직접 입력
            </span>
            <div className="grid grid-cols-2 gap-2">
              <DateField
                label="시작"
                value={fromDate}
                min={corpusLo ?? undefined}
                max={toDate || corpusHi || undefined}
                onChange={(v) => onChange({ fromDate: v, toDate })}
              />
              <DateField
                label="종료"
                value={toDate}
                min={fromDate || corpusLo || undefined}
                max={corpusHi ?? undefined}
                onChange={(v) => onChange({ fromDate, toDate: v })}
              />
            </div>
            {corpusLo && corpusHi && (
              <p className="text-[10px] text-neutral-500">
                전체 데이터 범위 {fmtIso(corpusLo)} ~ {fmtIso(corpusHi)}
              </p>
            )}
          </div>

          <div className="flex items-center justify-between border-t border-neutral-800 pt-2">
            <button
              type="button"
              onClick={() => onChange({ fromDate: "", toDate: "" })}
              disabled={!active}
              className="text-[11px] text-neutral-400 hover:text-neutral-100 disabled:cursor-not-allowed disabled:opacity-40"
            >
              초기화
            </button>
            <button
              type="button"
              onClick={() => setOpen(false)}
              className="rounded border border-neutral-700 px-2.5 py-1 text-[11px] text-neutral-200 hover:border-neutral-500"
            >
              완료
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function DateField({
  label,
  value,
  min,
  max,
  onChange,
}: {
  label: string;
  value: string;
  min?: string;
  max?: string;
  onChange: (v: string) => void;
}) {
  return (
    <label className="flex flex-col gap-1 text-[11px] text-neutral-500">
      <span>{label}</span>
      <input
        type="date"
        value={value}
        min={min}
        max={max}
        onChange={(e) => onChange(e.target.value)}
        className="rounded border border-neutral-700 bg-surface-2 px-2 py-1 text-[11px] text-neutral-100 focus:border-neutral-400 focus:outline-none [color-scheme:dark]"
      />
    </label>
  );
}
