"use client";

import type { ReactNode } from "react";
import { AlertCircle } from "lucide-react";

import { cn } from "@/lib/utils";

// Shared "boxed message" component used by every error/notice surface
// across the app — sandbox panel, AI analysis panel, list-states, etc.
// Keeping the shape in one place lets all panels render the same
// border/icon/title/body/actions layout, so users see consistent
// hierarchy regardless of which feature failed.

interface FeedbackBoxProps {
  title: string;
  message: string;
  hint?: string;
  actions?: ReactNode;
  size?: "sm" | "md";
}

const TONE: Record<
  "error" | "notice",
  { wrap: string; icon: string; title: string; body: string; hint: string; actionBtn: string }
> = {
  error: {
    wrap: "border-rose-500/40 bg-rose-500/10",
    icon: "text-rose-300",
    title: "text-rose-200",
    body: "text-neutral-100",
    hint: "text-neutral-300",
    actionBtn: "border-rose-500/40 text-rose-100 hover:bg-rose-500/15",
  },
  notice: {
    wrap: "border-amber-500/40 bg-surface-2",
    icon: "text-amber-300",
    title: "text-amber-200",
    body: "text-neutral-100",
    hint: "text-neutral-300",
    actionBtn: "border-amber-500/40 text-amber-100 hover:bg-amber-500/15",
  },
};

function _Box({
  tone,
  title,
  message,
  hint,
  actions,
  size = "md",
}: FeedbackBoxProps & { tone: "error" | "notice" }) {
  const t = TONE[tone];
  return (
    <div
      role={tone === "error" ? "alert" : "status"}
      className={cn(
        "space-y-1.5 rounded-md border",
        t.wrap,
        size === "sm" ? "p-2.5 text-[11px]" : "p-3 text-xs",
      )}
    >
      <div className={cn("flex items-center gap-1.5 font-medium", t.title)}>
        <AlertCircle className={cn("h-3.5 w-3.5 shrink-0", t.icon)} />
        <span>{title}</span>
      </div>
      <p className={cn("break-words leading-relaxed", t.body)}>{message}</p>
      {hint && <p className={cn("leading-relaxed", t.hint)}>{hint}</p>}
      {actions && <div className="flex flex-wrap items-center gap-1.5 pt-1">{actions}</div>}
    </div>
  );
}

export function ErrorBox(props: FeedbackBoxProps) {
  return <_Box {...props} tone="error" />;
}

export function NoticeBox(props: FeedbackBoxProps) {
  return <_Box {...props} tone="notice" />;
}

// Small button matching ErrorBox / NoticeBox tone — replaces the old
// "underlined link" pattern we used for "다시 시도" actions. Keeps the
// box compact (px-2 py-0.5) so it doesn't dominate the message.
export function FeedbackBoxButton({
  onClick,
  children,
  tone = "error",
  href,
}: {
  onClick?: () => void;
  children: ReactNode;
  tone?: "error" | "notice";
  href?: string;
}) {
  const cls = cn(
    "inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[11px] font-medium transition-colors",
    TONE[tone].actionBtn,
  );
  if (href) {
    return (
      <a href={href} className={cls}>
        {children}
      </a>
    );
  }
  return (
    <button type="button" onClick={onClick} className={cls}>
      {children}
    </button>
  );
}
