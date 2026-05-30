"use client";

/**
 * Header 우측의 로그인/사용자 메뉴.
 * - 비로그인: "로그인" 버튼
 * - 로그인: 아바타 (이메일 이니셜) → 드롭다운: 닉네임·이메일·role·내 활동·설정·로그아웃
 */
import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { LogIn, LogOut, ShieldCheck, User as UserIcon } from "lucide-react";

import { useAuth } from "@/lib/auth-context";
import { cn } from "@/lib/utils";

function initial(label: string): string {
  const ch = label.trim().charAt(0);
  return ch ? ch.toUpperCase() : "?";
}

export function UserMenu() {
  const { user, loading, logout } = useAuth();
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function onClick(e: MouseEvent) {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    window.addEventListener("mousedown", onClick);
    return () => window.removeEventListener("mousedown", onClick);
  }, [open]);

  if (loading) {
    return (
      <div
        aria-hidden
        className="h-8 w-8 animate-pulse rounded-full bg-neutral-200 dark:bg-surface-2"
      />
    );
  }

  if (!user) {
    return (
      <Link
        href={"/login" as never}
        className="inline-flex h-8 items-center gap-1.5 rounded-full bg-sky-600 px-3 text-sm font-medium text-white transition-colors hover:bg-sky-500 dark:bg-sky-500 dark:hover:bg-sky-400"
      >
        <LogIn className="h-3.5 w-3.5" />
        로그인
      </Link>
    );
  }

  const label = user.username || user.email;

  return (
    <div ref={wrapRef} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className={cn(
          "inline-flex h-8 items-center gap-2 rounded-full border border-neutral-200 bg-white pl-1 pr-3 text-sm font-medium text-neutral-800 transition-colors hover:bg-neutral-50",
          "dark:border-neutral-700 dark:bg-surface-1 dark:text-neutral-100 dark:hover:bg-surface-2",
        )}
        aria-expanded={open}
        aria-haspopup="menu"
      >
        <span
          className={cn(
            "flex h-6 w-6 items-center justify-center rounded-full text-[11px] font-semibold",
            user.isAdmin
              ? "bg-amber-100 text-amber-800 dark:bg-amber-500/20 dark:text-amber-200"
              : "bg-sky-100 text-sky-800 dark:bg-sky-500/20 dark:text-sky-200",
          )}
        >
          {initial(label)}
        </span>
        <span className="max-w-[8rem] truncate">{label}</span>
      </button>
      {open && (
        <div
          role="menu"
          className="absolute right-0 top-10 z-50 w-64 overflow-hidden rounded-lg border border-neutral-200 bg-white shadow-lg dark:border-neutral-800 dark:bg-surface-1"
        >
          <div className="border-b border-neutral-200 bg-neutral-50 px-4 py-3 dark:border-neutral-800 dark:bg-surface-2/60">
            <p className="truncate text-sm font-medium text-neutral-900 dark:text-neutral-100">
              {label}
            </p>
            <p className="truncate text-xs text-neutral-600 dark:text-neutral-400">{user.email}</p>
            {user.isAdmin && (
              <p className="mt-1 inline-flex items-center gap-1 rounded-full bg-amber-100 px-2 py-0.5 text-[11px] font-medium text-amber-800 dark:bg-amber-500/15 dark:text-amber-200">
                <ShieldCheck className="h-3 w-3" />
                관리자
              </p>
            )}
          </div>
          <Link
            href={"/settings" as never}
            onClick={() => setOpen(false)}
            className="flex items-center gap-2 px-4 py-2 text-sm text-neutral-800 transition-colors hover:bg-neutral-100 dark:text-neutral-100 dark:hover:bg-surface-2"
          >
            <UserIcon className="h-4 w-4" /> 내 설정
          </Link>
          <button
            type="button"
            onClick={async () => {
              setOpen(false);
              await logout();
              router.refresh();
            }}
            className="flex w-full items-center gap-2 border-t border-neutral-200 px-4 py-2 text-left text-sm text-neutral-800 transition-colors hover:bg-neutral-100 dark:border-neutral-800 dark:text-neutral-100 dark:hover:bg-surface-2"
          >
            <LogOut className="h-4 w-4" /> 로그아웃
          </button>
        </div>
      )}
    </div>
  );
}
