import type { HTMLAttributes } from "react";
import { cn } from "@/lib/utils";

// Base card surface — paired light/dark with tactile hover feedback.
// Hover bumps the border tone AND adds a subtle shadow lift so cards
// inside a list (CveListItem, settings panels) feel clickable without
// being garish. Active state retracts the lift for a press feel.
export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "rounded-lg border border-neutral-200 bg-white transition-all duration-150",
        "hover:-translate-y-0.5 hover:border-neutral-300 hover:shadow-md hover:shadow-neutral-900/5",
        "active:translate-y-0 active:shadow-sm",
        "dark:border-neutral-800 dark:bg-surface-1 dark:hover:border-neutral-700 dark:hover:shadow-black/30",
        className,
      )}
      {...props}
    />
  );
}

export function CardHeader({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("p-5 pb-3", className)} {...props} />;
}

export function CardContent({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("p-5 pt-0", className)} {...props} />;
}

export function CardFooter({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "border-t border-neutral-200 p-5 pt-3 dark:border-neutral-800",
        className,
      )}
      {...props}
    />
  );
}
