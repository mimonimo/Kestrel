"use client";

import { useEffect, useState } from "react";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";

interface Props {
  page: number;
  pageSize: number;
  total: number;
  onChange: (next: number) => void;
}

export function Pagination({ page, pageSize, total, onChange }: Props) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const canPrev = page > 1;
  const canNext = page < totalPages;

  const [draft, setDraft] = useState(String(page));
  useEffect(() => {
    setDraft(String(page));
  }, [page]);

  const submit = () => {
    const n = Number.parseInt(draft, 10);
    if (!Number.isFinite(n)) {
      setDraft(String(page));
      return;
    }
    const clamped = Math.min(totalPages, Math.max(1, n));
    if (clamped !== page) onChange(clamped);
    setDraft(String(clamped));
  };

  return (
    <div className="flex items-center justify-center gap-3 pt-6">
      <Button
        variant="outline"
        size="sm"
        disabled={!canPrev}
        onClick={() => onChange(page - 1)}
        aria-label="이전 페이지"
      >
        <ChevronLeft className="h-4 w-4" />
      </Button>

      <div className="flex items-center gap-1.5 text-xs text-neutral-400 tabular-nums">
        <input
          type="number"
          inputMode="numeric"
          min={1}
          max={totalPages}
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onBlur={submit}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              (e.target as HTMLInputElement).blur();
            }
            if (e.key === "Escape") {
              setDraft(String(page));
              (e.target as HTMLInputElement).blur();
            }
          }}
          aria-label="페이지 직접 입력"
          className="h-7 w-14 rounded border border-neutral-700 bg-surface-2 px-1.5 text-center text-neutral-100 focus:border-blue-500 focus:outline-none [appearance:textfield] [&::-webkit-inner-spin-button]:appearance-none [&::-webkit-outer-spin-button]:appearance-none"
        />
        <span className="text-neutral-500">/</span>
        <span className="font-medium text-neutral-300">{totalPages}</span>
      </div>

      <Button
        variant="outline"
        size="sm"
        disabled={!canNext}
        onClick={() => onChange(page + 1)}
        aria-label="다음 페이지"
      >
        <ChevronRight className="h-4 w-4" />
      </Button>
    </div>
  );
}
