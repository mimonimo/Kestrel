"use client";

import type { MouseEvent } from "react";
import { useState } from "react";
import { Check, Share2 } from "lucide-react";
import { cn } from "@/lib/utils";

interface Props {
  cveId: string;
  size?: "sm" | "md";
  stopPropagation?: boolean;
  className?: string;
}

/** 취약점 상세 링크를 클립보드에 복사. 즐겨찾기(별) 버튼과 같은 톤. */
export function ShareButton({ cveId, size = "sm", stopPropagation = true, className }: Props) {
  const [copied, setCopied] = useState(false);
  const dim = size === "sm" ? "h-4 w-4" : "h-5 w-5";

  const onClick = async (e: MouseEvent) => {
    if (stopPropagation) {
      e.preventDefault();
      e.stopPropagation();
    }
    const url = `${window.location.origin}/cve/${encodeURIComponent(cveId)}`;
    try {
      await navigator.clipboard.writeText(url);
    } catch {
      // HTTPS 가 아니거나 권한이 없을 때 폴백.
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
    <span className="relative inline-flex">
      <button
        type="button"
        aria-label="링크 복사"
        title="링크 복사"
        onClick={onClick}
        className={cn(
          "inline-flex items-center justify-center rounded p-1 transition-colors",
          copied
            ? "text-emerald-600 dark:text-emerald-300"
            : "text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-200",
          className,
        )}
      >
        {copied ? <Check className={dim} /> : <Share2 className={dim} />}
      </button>
      {copied && (
        <span
          role="status"
          className="pointer-events-none absolute left-1/2 top-full z-10 mt-1 -translate-x-1/2 whitespace-nowrap rounded bg-neutral-900 px-1.5 py-0.5 text-[10px] font-medium text-white shadow dark:bg-neutral-700"
        >
          링크 복사됨
        </span>
      )}
    </span>
  );
}
