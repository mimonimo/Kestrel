"use client";

import { Search } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

interface Props {
  initialQuery?: string;
  onSearch?: (q: string) => void;
  size?: "hero" | "compact";
}

export function SearchBar({ initialQuery = "", onSearch, size = "hero" }: Props) {
  const [value, setValue] = useState(initialQuery);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    onSearch?.(value.trim());
  };

  const hero = size === "hero";
  return (
    <form onSubmit={submit} className="w-full">
      <div className="relative flex items-center">
        <Search
          className={`pointer-events-none absolute text-neutral-500 dark:text-neutral-500 ${
            hero ? "left-3.5 h-4 w-4" : "left-3 h-4 w-4"
          }`}
        />
        <Input
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="CVE-ID · 제품명 · 설명 · 취약점 유형 검색"
          className={
            hero
              ? "h-11 rounded-lg border-neutral-300 bg-white pl-10 pr-24 text-sm dark:border-neutral-800 dark:bg-surface-1"
              : "h-10 pl-9 pr-24"
          }
        />
        <Button
          type="submit"
          // Sky accent so the primary action pops off the white/dark input
          // (the default neutral inversion blends in too much).
          className={cn(
            "absolute right-1.5 h-8 bg-sky-600 text-white hover:bg-sky-700 dark:bg-sky-500 dark:text-white dark:hover:bg-sky-400",
          )}
          size="sm"
        >
          검색
        </Button>
      </div>
    </form>
  );
}
