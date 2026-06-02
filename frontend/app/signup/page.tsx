"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Bird, UserPlus } from "lucide-react";

import { ApiError, api } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { cn } from "@/lib/utils";

export default function SignupPage() {
  const router = useRouter();
  const { refresh } = useAuth();
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [password2, setPassword2] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (password !== password2) {
      setError("비밀번호 확인이 일치하지 않습니다.");
      return;
    }
    setLoading(true);
    try {
      await api.signup({ email: email.trim(), username: username.trim(), password });
      await refresh();
      router.replace("/" as never);
    } catch (err) {
      const msg =
        err instanceof ApiError && err.detail
          ? typeof err.detail === "string"
            ? err.detail
            : err.message
          : err instanceof Error
            ? err.message
            : "회원가입에 실패했습니다.";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="mx-auto flex w-full max-w-md flex-col gap-6 px-6 py-16">
      <div className="flex items-center justify-center gap-2 text-neutral-900 dark:text-neutral-100">
        <Bird className="h-5 w-5 text-blue-600 dark:text-blue-500" />
        <h1 className="text-lg font-semibold tracking-tight">회원가입</h1>
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
          <span className="text-neutral-700 dark:text-neutral-300">
            사용자명{" "}
            <span className="text-neutral-500 dark:text-neutral-500">(2-64자, 한/영/숫자/_-.)</span>
          </span>
          <input
            type="text"
            autoComplete="username"
            required
            minLength={2}
            maxLength={64}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="rounded-md border border-neutral-300 bg-white px-3 py-2 text-neutral-900 outline-none transition-colors focus:border-sky-500 focus:ring-2 focus:ring-sky-200 dark:border-neutral-700 dark:bg-surface-0 dark:text-neutral-100 dark:focus:ring-sky-500/30"
          />
        </label>
        <label className="flex flex-col gap-1.5 text-sm">
          <span className="text-neutral-700 dark:text-neutral-300">
            비밀번호 <span className="text-neutral-500 dark:text-neutral-500">(8자 이상)</span>
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
          <span className="text-neutral-700 dark:text-neutral-300">비밀번호 확인</span>
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
          <UserPlus className="h-4 w-4" />
          {loading ? "가입 중…" : "회원가입"}
        </button>
      </form>
      <p className="text-center text-sm text-neutral-600 dark:text-neutral-400">
        이미 계정이 있으신가요?{" "}
        <Link
          href={"/login" as never}
          className="font-medium text-sky-600 hover:underline dark:text-sky-400"
        >
          로그인
        </Link>
      </p>
    </div>
  );
}
