"use client";

import { ArrowUpDown } from "lucide-react";
import { SORT_OPTIONS, type SortKey } from "@/lib/sort";

interface Props {
  value: SortKey;
  onChange: (next: SortKey) => void;
}

export function SortSelect({ value, onChange }: Props) {
  return (
    <label className="inline-flex items-center gap-1.5 rounded-md border border-neutral-700 bg-surface-2 px-2 py-1 text-xs text-neutral-300 hover:border-neutral-500">
      <ArrowUpDown className="h-3.5 w-3.5 text-neutral-500" />
      <select
        value={value}
        onChange={(e) => onChange(e.target.value as SortKey)}
        className="bg-transparent text-xs text-neutral-200 focus:outline-none"
        aria-label="정렬 기준"
      >
        {SORT_OPTIONS.map((opt) => (
          <option key={opt.value} value={opt.value} className="bg-surface-2 text-neutral-100">
            {opt.label}
          </option>
        ))}
      </select>
    </label>
  );
}
