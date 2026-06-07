"use client";

import type { MouseEvent } from "react";
import { useState } from "react";
import { Check, Share2 } from "lucide-react";
import { cn } from "@/lib/utils";

/** 현재 origin + path 를 클립보드로 복사하는 공유 버튼. 라이트·다크 대비 확보. */
export function CopyLinkButton({
  path,
  label = "공유",
  className,
  stopPropagation = false,
}: {
  path: string;
  label?: string;
  className?: string;
  stopPropagation?: boolean;
}) {
  const [copied, setCopied] = useState(false);

  const onClick = async (e: MouseEvent) => {
    if (stopPropagation) {
      e.preventDefault();
      e.stopPropagation();
    }
    const url = `${window.location.origin}${path}`;
    try {
      await navigator.clipboard.writeText(url);
    } catch {
      const ta = document.createElement("textarea");
      ta.value = url;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand("copy");
      } catch {
        /* 무시 */
      }
      ta.remove();
    }
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  };

  return (
    <button
      type="button"
      onClick={onClick}
      aria-label="링크 복사"
      className={cn(
        "inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors",
        copied
          ? "border-emerald-300 text-emerald-700 dark:border-emerald-500/40 dark:text-emerald-300"
          : "border-neutral-300 text-neutral-700 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-surface-3",
        className,
      )}
    >
      {copied ? <Check className="h-3.5 w-3.5" /> : <Share2 className="h-3.5 w-3.5" />}
      {copied ? "링크 복사됨" : label}
    </button>
  );
}
