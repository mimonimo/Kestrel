"use client";

import { ArrowUpDown } from "lucide-react";
import { SORT_OPTIONS, type SortKey } from "@/lib/sort";

interface Props {
  value: SortKey;
  onChange: (next: SortKey) => void;
}

export function SortSelect({ value, onChange }: Props) {
  return (
    <label className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full border border-neutral-300 bg-white px-2.5 py-1 text-xs text-neutral-700 hover:border-neutral-500 dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-300">
      <ArrowUpDown className="h-3.5 w-3.5 text-neutral-500 dark:text-neutral-500" />
      <select
        value={value}
        onChange={(e) => onChange(e.target.value as SortKey)}
        className="bg-transparent text-xs text-neutral-800 focus:outline-none dark:text-neutral-200"
        aria-label="정렬 기준"
      >
        {SORT_OPTIONS.map((opt) => (
          <option
            key={opt.value}
            value={opt.value}
            className="bg-white text-neutral-900 dark:bg-surface-2 dark:text-neutral-100"
          >
            {opt.label}
          </option>
        ))}
      </select>
    </label>
  );
}
