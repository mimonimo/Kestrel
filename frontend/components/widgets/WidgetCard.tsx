"use client";

// Shared chrome for dashboard widgets so they share spacing, typography,
// and loading/error semantics. Each widget gets a title + optional
// description + slot for header actions (e.g. range toggle) and a body.
// Keeping the chrome external makes it trivial to wrap any widget for
// drag-and-drop / resize / hide-add later.

import { AlertCircle, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";

interface Props {
  title: string;
  description?: string;
  actions?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  isLoading?: boolean;
  error?: Error | null;
  // Density toggle — "comfortable" gives more breathing room (default),
  // "compact" trims padding for widgets that pack tight content.
  density?: "comfortable" | "compact";
}

export function WidgetCard({
  title,
  description,
  actions,
  children,
  className,
  isLoading,
  error,
  density = "comfortable",
}: Props) {
  return (
    <section
      className={cn(
        "rounded-xl border border-neutral-200 bg-white shadow-sm shadow-black/5 dark:border-neutral-800 dark:bg-surface-1 dark:shadow-black/20",
        className,
      )}
    >
      <header
        className={cn(
          "flex items-start justify-between gap-3 border-b border-neutral-200 dark:border-neutral-800",
          density === "compact" ? "px-4 py-2.5" : "px-5 py-3",
        )}
      >
        <div className="min-w-0">
          <h3 className="truncate text-sm font-semibold text-neutral-900 dark:text-neutral-100">
            {title}
          </h3>
          {description && (
            <p className="mt-0.5 text-[11px] text-neutral-600 dark:text-neutral-500">
              {description}
            </p>
          )}
        </div>
        {actions && <div className="shrink-0 flex items-center gap-1.5">{actions}</div>}
      </header>
      <div className={cn(density === "compact" ? "p-4" : "p-5")}>
        {error ? (
          <div className="flex items-center gap-2 text-sm text-rose-700 dark:text-rose-300">
            <AlertCircle className="h-4 w-4" />
            {error.message || "위젯을 불러오지 못했어요."}
          </div>
        ) : isLoading ? (
          <div className="flex items-center gap-2 text-sm text-neutral-600 dark:text-neutral-500">
            <Loader2 className="h-4 w-4 animate-spin" /> 불러오는 중…
          </div>
        ) : (
          children
        )}
      </div>
    </section>
  );
}
