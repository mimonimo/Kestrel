"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { Route } from "next";
import { Bird, Settings } from "lucide-react";

import { cn } from "@/lib/utils";

import { NotificationBell } from "./NotificationBell";

// Top-level nav routes. Active-state derived from pathname so user knows
// where they are without needing to remember the title — a Linear/Vercel
// pattern that scales to many more sections later.
const NAV_LINKS: { href: Route; label: string; match: (p: string) => boolean }[] = [
  { href: "/" as Route, label: "대시보드", match: (p) => p === "/" },
  { href: "/community" as Route, label: "커뮤니티", match: (p) => p.startsWith("/community") },
];

export function Header() {
  const pathname = usePathname() ?? "/";
  return (
    <header className="sticky top-0 z-40 border-b border-neutral-200 bg-white/85 backdrop-blur dark:border-neutral-800 dark:bg-surface-0/80">
      <div className="mx-auto flex h-14 max-w-7xl items-center justify-between gap-4 px-6">
        <Link
          href="/"
          className="flex shrink-0 items-center gap-2 font-semibold text-neutral-900 dark:text-neutral-100"
        >
          <Bird className="h-5 w-5 text-blue-600 dark:text-blue-500" />
          <span className="tracking-tight">Kestrel</span>
        </Link>
        <nav className="flex items-center gap-1 text-sm text-neutral-600 dark:text-neutral-400">
          {NAV_LINKS.map((link) => {
            const active = link.match(pathname);
            return (
              <Link
                key={link.href}
                href={link.href}
                aria-current={active ? "page" : undefined}
                className={cn(
                  "rounded-full px-3 py-1.5 transition-colors",
                  active
                    ? "bg-neutral-900 text-neutral-50 dark:bg-neutral-100 dark:text-neutral-900"
                    : "hover:bg-neutral-100 hover:text-neutral-900 dark:hover:bg-surface-2 dark:hover:text-neutral-100",
                )}
              >
                {link.label}
              </Link>
            );
          })}
          <a
            href="https://nvd.nist.gov/"
            target="_blank"
            rel="noopener noreferrer"
            className="hidden rounded-full px-3 py-1.5 transition-colors hover:bg-neutral-100 hover:text-neutral-900 dark:hover:bg-surface-2 dark:hover:text-neutral-100 sm:inline-block"
          >
            NVD ↗
          </a>
          <span className="mx-1 hidden h-5 w-px bg-neutral-200 dark:bg-neutral-800 sm:inline-block" />
          <NotificationBell />
          <Link
            href="/settings"
            className={cn(
              "flex h-8 items-center gap-1.5 rounded-full px-3 transition-colors",
              pathname.startsWith("/settings")
                ? "bg-neutral-900 text-neutral-50 dark:bg-neutral-100 dark:text-neutral-900"
                : "text-neutral-600 hover:bg-neutral-100 hover:text-neutral-900 dark:text-neutral-400 dark:hover:bg-surface-2 dark:hover:text-neutral-100",
            )}
            aria-label="설정"
          >
            <Settings className="h-4 w-4" />
            <span className="hidden sm:inline">설정</span>
          </Link>
        </nav>
      </div>
    </header>
  );
}
