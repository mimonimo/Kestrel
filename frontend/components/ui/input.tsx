import { forwardRef, type InputHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      className={cn(
        "flex h-10 w-full rounded-md border px-3 py-2 text-sm",
        // Light: white bg, neutral border, dark text.
        // Dark: surface-1 bg, neutral-800 border, neutral-100 text.
        "border-neutral-300 bg-white text-neutral-900 placeholder:text-neutral-500",
        "dark:border-neutral-800 dark:bg-surface-1 dark:text-neutral-100 dark:placeholder:text-neutral-500",
        "focus-visible:border-neutral-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-400",
        "dark:focus-visible:border-neutral-600 dark:focus-visible:ring-neutral-600",
        "disabled:cursor-not-allowed disabled:opacity-50",
        className,
      )}
      {...props}
    />
  ),
);
Input.displayName = "Input";
