import { forwardRef, type ButtonHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

type Variant = "default" | "outline" | "ghost";
type Size = "sm" | "md" | "lg";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
}

// Paired light/dark variants. Default is a sky-accent solid (matches the
// dashboard's active-state pill / filter chip / search button family) so
// the primary CTA reads at the same brand color across all surfaces.
// Outline and ghost stay near-neutral with subtle hover so they don't
// compete with the primary CTA.
//
// Interactive feedback: active:scale-[0.98] for tactile press, slight
// shadow on rest → larger shadow on hover, lift back on press.
const variants: Record<Variant, string> = {
  default:
    "bg-sky-500 text-white shadow-sm shadow-sky-500/20 hover:bg-sky-600 hover:shadow-md hover:shadow-sky-500/30 active:scale-[0.98] dark:bg-sky-500 dark:hover:bg-sky-400 dark:shadow-sky-500/30",
  outline:
    "border border-neutral-300 bg-white text-neutral-900 hover:border-neutral-400 hover:bg-neutral-50 active:scale-[0.98] dark:border-neutral-700 dark:bg-transparent dark:text-neutral-100 dark:hover:border-neutral-500 dark:hover:bg-neutral-800",
  ghost:
    "text-neutral-700 hover:bg-neutral-100 hover:text-neutral-900 active:scale-[0.98] dark:text-neutral-300 dark:hover:bg-neutral-800 dark:hover:text-neutral-100",
};

const sizes: Record<Size, string> = {
  sm: "h-8 px-3 text-sm",
  md: "h-10 px-4 text-sm",
  lg: "h-12 px-6 text-base",
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "default", size = "md", ...props }, ref) => (
    <button
      ref={ref}
      className={cn(
        // rounded-full base — pill 형태로 통일 (사용자 선호). 검색·로그인·메모
        // 저장 등 이미 pill 이던 버튼들과 새글·설정 액션 버튼을 한 톤으로.
        // transition-all (not -colors) so scale, shadow, and color animate
        // together for tactile feel.
        "inline-flex shrink-0 items-center justify-center whitespace-nowrap rounded-full font-medium transition-all duration-150",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500/60 focus-visible:ring-offset-2 focus-visible:ring-offset-white dark:focus-visible:ring-offset-surface-0",
        "disabled:pointer-events-none disabled:opacity-50 disabled:active:scale-100",
        variants[variant],
        sizes[size],
        className,
      )}
      {...props}
    />
  ),
);
Button.displayName = "Button";
