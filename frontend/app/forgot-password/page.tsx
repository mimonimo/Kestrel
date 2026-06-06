"use client";

import Link from "next/link";
import { useState } from "react";
import { KeyRound, MailCheck } from "lucide-react";

import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [sent, setSent] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    try {
      await api.forgotPassword(email.trim());
    } catch {
      /* 존재 노출 방지 — 성공/실패 동일 처리 */
    } finally {
      setLoading(false);
      setSent(true);
    }
  }

  if (sent) {
    return (
      <div className="mx-auto flex w-full max-w-md flex-col gap-6 px-6 py-16">
        <div className="flex items-center justify-center gap-2 text-neutral-900 dark:text-neutral-100">
          <MailCheck className="h-5 w-5 text-emerald-600 dark:text-emerald-500" />
          <h1 className="text-lg font-semibold tracking-tight">메일을 확인해 주세요</h1>
        </div>
        <div className="rounded-xl border border-neutral-200 bg-white p-6 text-sm text-neutral-700 shadow-sm dark:border-neutral-800 dark:bg-surface-1 dark:text-neutral-300">
          입력하신 이메일로 가입된 계정이 있으면 비밀번호 재설정 링크를 보냈습니다.
          메일이 보이지 않으면 스팸함도 확인해 주세요. 링크는 잠시 후 만료됩니다.
        </div>
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

  return (
    <div className="mx-auto flex w-full max-w-md flex-col gap-6 px-6 py-16">
      <div className="flex items-center justify-center gap-2 text-neutral-900 dark:text-neutral-100">
        <KeyRound className="h-5 w-5 text-blue-600 dark:text-blue-500" />
        <h1 className="text-lg font-semibold tracking-tight">비밀번호 찾기</h1>
      </div>
      <form
        onSubmit={onSubmit}
        className="flex flex-col gap-4 rounded-xl border border-neutral-200 bg-white p-6 shadow-sm dark:border-neutral-800 dark:bg-surface-1"
      >
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          가입한 이메일을 입력하면 비밀번호 재설정 링크를 보내드립니다.
        </p>
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
        <button
          type="submit"
          disabled={loading}
          className={cn(
            "inline-flex items-center justify-center gap-2 rounded-full bg-sky-500 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-sky-600 disabled:cursor-not-allowed disabled:bg-sky-500/60",
            "dark:bg-sky-500 dark:hover:bg-sky-400",
          )}
        >
          {loading ? "전송 중…" : "재설정 메일 보내기"}
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
