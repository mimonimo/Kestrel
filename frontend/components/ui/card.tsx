import type { HTMLAttributes } from "react";
import { cn } from "@/lib/utils";

// Base card surface — paired light/dark. Hover bumps the border tone one
// step so the card feels interactive when wrapped in a Link.
export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "rounded-lg border border-neutral-200 bg-white transition-colors",
        "hover:border-neutral-300",
        "dark:border-neutral-800 dark:bg-surface-1 dark:hover:border-neutral-700",
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
