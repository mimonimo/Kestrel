import type { HTMLAttributes } from "react";
import { cn } from "@/lib/utils";

interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  variant?: "default" | "outline" | "secondary";
}

// Paired light/dark variants so the same Badge reads correctly on either
// theme without callers having to remember dark: overrides.
export function Badge({ className, variant = "default", ...props }: BadgeProps) {
  const variants = {
    default:
      "bg-neutral-900 text-neutral-50 dark:bg-neutral-100 dark:text-neutral-900",
    outline:
      "border border-neutral-300 text-neutral-700 dark:border-neutral-700 dark:text-neutral-300",
    secondary:
      "bg-neutral-100 text-neutral-700 dark:bg-neutral-800 dark:text-neutral-200",
  };
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium",
        variants[variant],
        className,
      )}
      {...props}
    />
  );
}
