"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Bird, LogIn } from "lucide-react";

import { ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { cn } from "@/lib/utils";

function readNextParam(): string | null {
  if (typeof window === "undefined") return null;
  try {
    const p = new URLSearchParams(window.location.search).get("next");
    return p && p.startsWith("/") ? p : null;
  } catch {
    return null;
  }
}

export default function LoginPage() {
  const router = useRouter();
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await login(email.trim(), password);
      const next = readNextParam();
      router.replace((next ?? "/") as never);
    } catch (err) {
      const msg =
        err instanceof ApiError && err.status === 401
          ? "이메일 또는 비밀번호가 일치하지 않습니다."
          : err instanceof Error
            ? err.message
            : "로그인에 실패했습니다.";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="mx-auto flex w-full max-w-md flex-col gap-6 px-6 py-16">
      <div className="flex items-center justify-center gap-2 text-neutral-900 dark:text-neutral-100">
        <Bird className="h-5 w-5 text-blue-600 dark:text-blue-500" />
        <h1 className="text-lg font-semibold tracking-tight">로그인</h1>
      </div>
      <form
        onSubmit={onSubmit}
        className="flex flex-col gap-4 rounded-xl border border-neutral-200 bg-white p-6 shadow-sm dark:border-neutral-800 dark:bg-surface-1"
      >
        <label className="flex flex-col gap-1.5 text-sm">
          <span className="text-neutral-700 dark:text-neutral-300">이메일</span>
          <input
            type="email"
            autoComplete="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="rounded-md border border-neutral-300 bg-white px-3 py-2 text-neutral-900 outline-none transition-colors focus:border-sky-500 focus:ring-2 focus:ring-sky-200 dark:border-neutral-700 dark:bg-surface-0 dark:text-neutral-100 dark:focus:ring-sky-500/30"
          />
        </label>
        <label className="flex flex-col gap-1.5 text-sm">
          <span className="text-neutral-700 dark:text-neutral-300">비밀번호</span>
          <input
            type="password"
            autoComplete="current-password"
            required
            minLength={8}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="rounded-md border border-neutral-300 bg-white px-3 py-2 text-neutral-900 outline-none transition-colors focus:border-sky-500 focus:ring-2 focus:ring-sky-200 dark:border-neutral-700 dark:bg-surface-0 dark:text-neutral-100 dark:focus:ring-sky-500/30"
          />
        </label>

        {error && (
          <p className="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-300">
            {error}
          </p>
        )}

        <button
          type="submit"
          disabled={loading}
          className={cn(
            "inline-flex items-center justify-center gap-2 rounded-md bg-sky-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-sky-500 disabled:cursor-not-allowed disabled:bg-sky-600/60",
            "dark:bg-sky-500 dark:hover:bg-sky-400",
          )}
        >
          <LogIn className="h-4 w-4" />
          {loading ? "로그인 중…" : "로그인"}
        </button>
      </form>
      <p className="text-center text-sm text-neutral-600 dark:text-neutral-400">
        계정이 없으신가요?{" "}
        <Link
          href={"/signup" as never}
          className="font-medium text-sky-600 hover:underline dark:text-sky-400"
        >
          회원가입
        </Link>
      </p>
    </div>
  );
}
