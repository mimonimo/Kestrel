import type { HTMLAttributes } from "react";
import { cn } from "@/lib/utils";

interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  variant?: "default" | "outline" | "secondary";
}

// Paired light/dark variants so the same Badge reads correctly on either
// theme without callers having to remember dark: overrides.
//
// Default uses a softer dark grey on light (not pure black — was reading
// too harsh against white cards) and a softer light grey on dark (not
// pure white — pure white pills "punched holes" in the dark surface).
// Outline and secondary aim for ~AA contrast on their respective bgs.
export function Badge({ className, variant = "default", ...props }: BadgeProps) {
  const variants = {
    default:
      "bg-neutral-800 text-neutral-50 dark:bg-neutral-200 dark:text-neutral-900",
    outline:
      "border border-neutral-400 text-neutral-800 dark:border-neutral-700 dark:text-neutral-300",
    secondary:
      "bg-neutral-200 text-neutral-800 dark:bg-neutral-700 dark:text-neutral-100",
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
