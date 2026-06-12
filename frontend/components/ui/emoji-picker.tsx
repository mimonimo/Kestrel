"use client";

// 에이전트 아바타용 이모지 선택기 — 직접 입력 대신 추려둔 세트에서 클릭 선택.
import { useEffect, useRef, useState } from "react";
import { cn } from "@/lib/utils";

// 보안·분석 에이전트 테마로 추린 아바타 후보.
export const AGENT_EMOJIS = [
  "🤖", "🛡️", "🦅", "🔐", "🔎", "🕵️", "⚔️",
  "🧠", "👾", "🐉", "🦾", "🚨", "🔥", "⚡",
  "🧪", "🐛", "🦠", "🎯", "📡", "🧭", "🛰️",
  "🐺", "🦊", "🦉", "🐙", "💀", "🧿", "🌐",
];

export function EmojiPicker({
  value,
  onChange,
}: {
  value: string;
  onChange: (emoji: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    window.addEventListener("mousedown", onDoc);
    return () => window.removeEventListener("mousedown", onDoc);
  }, [open]);

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-label="아바타 이모지 선택"
        aria-expanded={open}
        className="flex h-10 w-12 items-center justify-center rounded-md border border-neutral-300 bg-white text-xl transition-colors hover:bg-neutral-50 dark:border-neutral-700 dark:bg-surface-0 dark:hover:bg-surface-2"
      >
        {value || "🤖"}
      </button>
      {open && (
        <div className="absolute left-0 top-12 z-50 w-[15.5rem] rounded-lg border border-neutral-200 bg-white p-2 shadow-lg dark:border-neutral-800 dark:bg-surface-1">
          <div className="grid grid-cols-7 gap-1">
            {AGENT_EMOJIS.map((em) => (
              <button
                key={em}
                type="button"
                onClick={() => {
                  onChange(em);
                  setOpen(false);
                }}
                className={cn(
                  "flex h-8 w-8 items-center justify-center rounded-md text-lg transition-colors hover:bg-neutral-100 dark:hover:bg-surface-2",
                  value === em && "bg-sky-100 ring-1 ring-sky-400 dark:bg-sky-500/20",
                )}
              >
                {em}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
