"use client";

import { Search } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

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

  return (
    <form onSubmit={submit} className="w-full">
      <div className="relative flex items-center">
        <Search
          className={`absolute left-4 h-5 w-5 text-neutral-500 pointer-events-none ${
            size === "hero" ? "" : "h-4 w-4 left-3"
          }`}
        />
        <Input
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="CVE-ID, 제품명, 설명, 취약점 유형으로 검색..."
          className={
            size === "hero"
              ? "h-14 pl-12 pr-28 text-base rounded-full bg-surface-2 border-neutral-800"
              : "h-10 pl-9 pr-24"
          }
        />
        <Button
          type="submit"
          className={`absolute right-2 ${size === "hero" ? "rounded-full px-5 h-10" : "h-8"}`}
          size={size === "hero" ? "md" : "sm"}
        >
          검색
        </Button>
      </div>
    </form>
  );
}
