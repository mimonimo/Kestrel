"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { AlertTriangle, CheckCircle2, KeyRound, Loader2 } from "lucide-react";

import { ApiError, api } from "@/lib/api";
import { cn } from "@/lib/utils";

function readToken(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return new URLSearchParams(window.location.search).get("token");
  } catch {
    return null;
  }
}

export default function ResetPasswordPage() {
  const router = useRouter();
  const [token, setToken] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const [password2, setPassword2] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  // 진입 시 토큰 사전 검증 — null=확인 중, true/false=결과.
  const [tokenValid, setTokenValid] = useState<boolean | null>(null);

  useEffect(() => {
    const t = readToken();
    setToken(t);
    if (!t) {
      setTokenValid(false);
      return;
    }
    let cancelled = false;
    api
      .validateResetToken(t)
      .then((r) => {
        if (!cancelled) setTokenValid(r.valid);
      })
      .catch(() => {
        if (!cancelled) setTokenValid(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!token) {
      setError("재설정 링크가 올바르지 않습니다. 비밀번호 찾기를 다시 요청해 주세요.");
      return;
    }
    if (password !== password2) {
      setError("비밀번호 확인이 일치하지 않습니다.");
      return;
    }
    setLoading(true);
    try {
      await api.resetPassword(token, password);
      setDone(true);
      setTimeout(() => router.replace("/login" as never), 1800);
    } catch (err) {
      setError(
        err instanceof ApiError && err.message
          ? err.message
          : "비밀번호 재설정에 실패했습니다.",
      );
    } finally {
      setLoading(false);
    }
  }

  if (done) {
    return (
      <div className="mx-auto flex w-full max-w-md flex-col items-center gap-6 px-6 py-20 text-center">
        <CheckCircle2 className="h-10 w-10 text-emerald-500" />
        <h1 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">
          비밀번호 변경 완료
        </h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          새 비밀번호로 로그인해 주세요. 잠시 후 로그인 화면으로 이동합니다.
        </p>
      </div>
    );
  }

  if (tokenValid === null) {
    return (
      <div className="mx-auto flex w-full max-w-md flex-col items-center gap-3 px-6 py-20 text-center">
        <Loader2 className="h-6 w-6 animate-spin text-sky-500" />
        <p className="text-sm text-neutral-600 dark:text-neutral-400">링크 확인 중…</p>
      </div>
    );
  }

  if (tokenValid === false) {
    return (
      <div className="mx-auto flex w-full max-w-md flex-col items-center gap-5 px-6 py-20 text-center">
        <AlertTriangle className="h-10 w-10 text-amber-500" />
        <h1 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">
          만료되었거나 사용된 링크예요
        </h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          비밀번호 재설정 링크는 보안을 위해 발급 후 1시간 동안만, 한 번만 사용할 수 있어요.
          아래에서 재설정을 다시 요청해 주세요.
        </p>
        <Link
          href={"/forgot-password" as never}
          className="inline-flex items-center gap-2 rounded-full bg-sky-500 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-sky-600 dark:hover:bg-sky-400"
        >
          비밀번호 재설정 다시 요청
        </Link>
        <Link
          href={"/login" as never}
          className="text-sm font-medium text-sky-600 hover:underline dark:text-sky-400"
        >
          로그인으로 돌아가기
        </Link>
      </div>
    );
  }

  return (
    <div className="mx-auto flex w-full max-w-md flex-col gap-6 px-6 py-16">
      <div className="flex items-center justify-center gap-2 text-neutral-900 dark:text-neutral-100">
        <KeyRound className="h-5 w-5 text-blue-600 dark:text-blue-500" />
        <h1 className="text-lg font-semibold tracking-tight">새 비밀번호 설정</h1>
      </div>
      <form
        onSubmit={onSubmit}
        className="flex flex-col gap-4 rounded-xl border border-neutral-200 bg-white p-6 shadow-sm dark:border-neutral-800 dark:bg-surface-1"
      >
        <label className="flex flex-col gap-1.5 text-sm">
          <span className="text-neutral-700 dark:text-neutral-300">
            새 비밀번호 <span className="text-neutral-500 dark:text-neutral-500">(8자 이상)</span>
          </span>
          <input
            type="password"
            autoComplete="new-password"
            required
            minLength={8}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="rounded-md border border-neutral-300 bg-white px-3 py-2 text-neutral-900 outline-none transition-colors focus:border-sky-500 focus:ring-2 focus:ring-sky-200 dark:border-neutral-700 dark:bg-surface-0 dark:text-neutral-100 dark:focus:ring-sky-500/30"
          />
        </label>
        <label className="flex flex-col gap-1.5 text-sm">
          <span className="text-neutral-700 dark:text-neutral-300">새 비밀번호 확인</span>
          <input
            type="password"
            autoComplete="new-password"
            required
            minLength={8}
            value={password2}
            onChange={(e) => setPassword2(e.target.value)}
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
            "inline-flex items-center justify-center gap-2 rounded-full bg-sky-500 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-sky-600 disabled:cursor-not-allowed disabled:bg-sky-500/60",
            "dark:bg-sky-500 dark:hover:bg-sky-400",
          )}
        >
          {loading ? "변경 중…" : "비밀번호 변경"}
        </button>
      </form>
      <p className="text-center text-sm text-neutral-600 dark:text-neutral-400">
        <Link
          href={"/login" as never}
          className="font-medium text-sky-600 hover:underline dark:text-sky-400"
        >
          로그인으로 돌아가기
        </Link>
      </p>
    </div>
  );
}
