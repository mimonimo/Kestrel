"use client";

/**
 * Header — 모바일 반응형 (PR 10-DF).
 *
 * 데스크탑(md+): 모든 nav 링크 + bell + user menu 한 줄.
 * 모바일(<md): 햄버거 버튼 → 패널 슬라이드 다운으로 nav 링크 + NVD 외부 링크.
 * Bell + UserMenu 는 우측에 항상 노출.
 */
import Link from "next/link";
import { usePathname } from "next/navigation";
import type { Route } from "next";
import { useEffect, useRef, useState } from "react";
import { Bird, Menu, X } from "lucide-react";

import { cn } from "@/lib/utils";

import { NotificationBell } from "./NotificationBell";
import { UserMenu } from "./UserMenu";

const NAV_LINKS: { href: Route; label: string; match: (p: string) => boolean }[] = [
  { href: "/" as Route, label: "대시보드", match: (p) => p === "/" },
  { href: "/cves" as Route, label: "취약점 조회", match: (p) => p.startsWith("/cves") },
  { href: "/analysis" as Route, label: "AI 분석", match: (p) => p.startsWith("/analysis") },
  { href: "/community" as Route, label: "커뮤니티", match: (p) => p.startsWith("/community") },
];

export function Header() {
  const pathname = usePathname() ?? "/";
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLDivElement>(null);

  // 경로 바뀌면 자동 닫힘.
  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  // 외부 클릭 닫기.
  useEffect(() => {
    if (!open) return;
    const onClick = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("mousedown", onClick);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onClick);
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <header
      ref={wrapRef}
      className="sticky top-0 z-40 border-b border-neutral-200 bg-white/85 backdrop-blur dark:border-neutral-800 dark:bg-surface-0/80"
    >
      <div className="mx-auto flex h-14 max-w-7xl items-center justify-between gap-3 px-4 sm:px-6">
        <Link
          href="/"
          className="flex shrink-0 items-center gap-2 font-semibold text-neutral-900 dark:text-neutral-100"
        >
          <Bird className="h-5 w-5 text-blue-600 dark:text-blue-500" />
          <span className="tracking-tight">Kestrel</span>
        </Link>

        {/* ── 데스크탑 nav (md+) ──────────────────────── */}
        <nav className="hidden items-center gap-1 text-sm text-neutral-600 dark:text-neutral-400 md:flex">
          {NAV_LINKS.map((link) => {
            const active = link.match(pathname);
            return (
              <Link
                key={link.href}
                href={link.href}
                aria-current={active ? "page" : undefined}
                className={cn(
                  "rounded-full px-3 py-1.5 transition-all duration-150 active:scale-95",
                  active
                    ? "bg-sky-100 font-medium text-sky-800 dark:bg-sky-500/20 dark:text-sky-200"
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
            className="hidden rounded-full px-3 py-1.5 transition-colors hover:bg-neutral-100 hover:text-neutral-900 dark:hover:bg-surface-2 dark:hover:text-neutral-100 lg:inline-block"
          >
            NVD ↗
          </a>
          <span className="mx-1 h-5 w-px bg-neutral-200 dark:bg-neutral-800" />
          <NotificationBell />
          <span className="mx-1 h-5 w-px bg-neutral-200 dark:bg-neutral-800" />
          <UserMenu />
        </nav>

        {/* ── 모바일 우측 (bell + user + 햄버거) ───────── */}
        <div className="flex items-center gap-1 md:hidden">
          <NotificationBell />
          <UserMenu />
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            aria-label={open ? "메뉴 닫기" : "메뉴 열기"}
            aria-expanded={open}
            className="inline-flex h-8 w-8 items-center justify-center rounded-full text-neutral-700 hover:bg-neutral-100 dark:text-neutral-300 dark:hover:bg-surface-2"
          >
            {open ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
          </button>
        </div>
      </div>

      {/* ── 모바일 슬라이드 nav 패널 ───────────────────── */}
      {open && (
        <nav
          aria-label="모바일 네비게이션"
          className="border-t border-neutral-200 bg-white px-4 py-2 dark:border-neutral-800 dark:bg-surface-0 md:hidden"
        >
          <ul className="space-y-1 text-sm">
            {NAV_LINKS.map((link) => {
              const active = link.match(pathname);
              return (
                <li key={link.href}>
                  <Link
                    href={link.href}
                    onClick={() => setOpen(false)}
                    aria-current={active ? "page" : undefined}
                    className={cn(
                      "block rounded-md px-3 py-2 transition-colors",
                      active
                        ? "bg-sky-100 font-medium text-sky-800 dark:bg-sky-500/20 dark:text-sky-200"
                        : "text-neutral-700 hover:bg-neutral-100 hover:text-neutral-900 dark:text-neutral-300 dark:hover:bg-surface-2 dark:hover:text-neutral-100",
                    )}
                  >
                    {link.label}
                  </Link>
                </li>
              );
            })}
            <li>
              <a
                href="https://nvd.nist.gov/"
                target="_blank"
                rel="noopener noreferrer"
                onClick={() => setOpen(false)}
                className="block rounded-md px-3 py-2 text-neutral-700 hover:bg-neutral-100 hover:text-neutral-900 dark:text-neutral-300 dark:hover:bg-surface-2 dark:hover:text-neutral-100"
              >
                NVD ↗
              </a>
            </li>
          </ul>
        </nav>
      )}
    </header>
  );
}
