"use client";

import { Moon, Sun, Monitor } from "lucide-react";
import { cn } from "@/lib/utils";
import { useTheme, type Theme } from "@/lib/theme";

const OPTIONS: { value: Theme; label: string; icon: typeof Sun }[] = [
  { value: "light", label: "라이트", icon: Sun },
  { value: "dark", label: "다크", icon: Moon },
  { value: "system", label: "시스템", icon: Monitor },
];

export function ThemeSwitcher() {
  const { theme, setTheme, resolved } = useTheme();

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-3 gap-2">
        {OPTIONS.map(({ value, label, icon: Icon }) => {
          const active = theme === value;
          return (
            <button
              key={value}
              type="button"
              onClick={() => setTheme(value)}
              className={cn(
                "flex flex-col items-center gap-2 rounded-md border p-4 text-sm transition-colors",
                active
                  ? "border-neutral-100 bg-surface-2 text-neutral-100"
                  : "border-neutral-800 bg-surface-1 text-neutral-400 hover:border-neutral-600 hover:text-neutral-200",
              )}
            >
              <Icon className="h-5 w-5" />
              <span>{label}</span>
            </button>
          );
        })}
      </div>
      <p className="text-xs text-neutral-500">
        현재 적용: <span className="text-neutral-300">{resolved === "dark" ? "다크" : "라이트"}</span>
        {theme === "system" && " (시스템 설정 따라감)"}
      </p>
    </div>
  );
}
