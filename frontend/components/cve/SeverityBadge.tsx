import { cn } from "@/lib/utils";
import type { Severity } from "@/lib/types";

const LABELS: Record<Severity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
};

// Pair each severity color with explicit light/dark text shades. Light
// mode needs the *darker* shade (700) to read on the soft alpha bg; dark
// mode keeps the brighter shade (400) that pops on the dark surface.
const STYLES: Record<Severity, string> = {
  critical:
    "bg-red-600/15 text-red-700 dark:text-red-400 border border-red-600/40",
  high:
    "bg-orange-600/15 text-orange-700 dark:text-orange-400 border border-orange-600/40",
  medium:
    "bg-yellow-600/15 text-yellow-700 dark:text-yellow-400 border border-yellow-600/40",
  low:
    "bg-green-600/15 text-green-700 dark:text-green-400 border border-green-600/40",
};

const UNKNOWN_STYLE =
  "bg-neutral-200 text-neutral-700 border border-neutral-300 dark:bg-neutral-700/30 dark:text-neutral-400 dark:border-neutral-600/40";

export function SeverityBadge({
  severity,
  score,
}: {
  severity: Severity | null | undefined;
  score?: number | null;
}) {
  const label = severity ? LABELS[severity] : "UNKNOWN";
  const style = severity ? STYLES[severity] : UNKNOWN_STYLE;
  const scoreLabel =
    typeof score === "number" && Number.isFinite(score) ? score.toFixed(1) : null;

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-bold tracking-wide",
        style,
      )}
    >
      {label}
      {scoreLabel && <span className="font-mono opacity-90">· {scoreLabel}</span>}
    </span>
  );
}
