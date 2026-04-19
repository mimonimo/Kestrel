"use client";

import { Star } from "lucide-react";
import { useBookmarks } from "@/lib/bookmarks";
import { cn } from "@/lib/utils";

interface Props {
  cveId: string;
  size?: "sm" | "md";
  stopPropagation?: boolean;
  className?: string;
}

export function BookmarkButton({ cveId, size = "sm", stopPropagation = true, className }: Props) {
  const { has, toggle, ready } = useBookmarks();
  const active = ready && has(cveId);
  const dim = size === "sm" ? "h-4 w-4" : "h-5 w-5";

  return (
    <button
      type="button"
      aria-pressed={active}
      aria-label={active ? "즐겨찾기 해제" : "즐겨찾기 추가"}
      onClick={(e) => {
        if (stopPropagation) {
          e.preventDefault();
          e.stopPropagation();
        }
        toggle(cveId);
      }}
      className={cn(
        "inline-flex items-center justify-center rounded p-1 transition-colors",
        active
          ? "text-amber-300 hover:text-amber-200"
          : "text-neutral-500 hover:text-neutral-200",
        className,
      )}
    >
      <Star className={cn(dim, active && "fill-amber-300")} />
    </button>
  );
}
