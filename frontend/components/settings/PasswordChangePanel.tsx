"use client";

import { useState } from "react";
import { Check, Loader2, ShieldCheck, X } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

// 비밀번호 변경 — 현재 비밀번호 재확인 + 새 비밀번호(8자+) + 확인 일치.
// 서버가 현재 비밀번호를 다시 검증하므로, 세션 탈취만으로는 비번을 못 바꾼다.
// 2단 레이아웃: 좌(폼) / 우(실시간 요구사항 + 보안 팁) 로 공간을 채운다.
export function PasswordChangePanel() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const len8 = next.length >= 8;
  const differs = next.length > 0 && next !== current;
  const matches = confirm.length > 0 && next === confirm;
  const tooShort = next.length > 0 && !len8;
  const mismatch = confirm.length > 0 && next !== confirm;
  const canSubmit = !!current && len8 && differs && matches && !busy;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    setDone(false);
    try {
      await api.changePassword({ currentPassword: current, newPassword: next });
      setDone(true);
      setCurrent("");
      setNext("");
      setConfirm("");
      window.setTimeout(() => setDone(false), 4000);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "비밀번호 변경에 실패했어요.");
    } finally {
      setBusy(false);
    }
  };

  const inputCls =
    "block w-full rounded-lg border border-neutral-300 bg-white px-3 py-2 text-sm text-neutral-900 placeholder:text-neutral-400 focus:border-sky-500 focus:outline-none focus:ring-2 focus:ring-sky-200 dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-100 dark:placeholder:text-neutral-500 dark:focus:ring-sky-500/30";

  return (
    <form
      onSubmit={submit}
      className="grid gap-6 rounded-xl border border-neutral-200 bg-white p-5 md:grid-cols-2 dark:border-neutral-800 dark:bg-surface-1"
    >
      {/* 좌: 입력 폼 */}
      <div className="space-y-3">
        <div className="space-y-1">
          <label className="text-xs font-medium text-neutral-700 dark:text-neutral-300">
            현재 비밀번호
          </label>
          <input
            type="password"
            autoComplete="current-password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            className={inputCls}
            placeholder="현재 비밀번호"
          />
        </div>

        <div className="space-y-1">
          <label className="text-xs font-medium text-neutral-700 dark:text-neutral-300">
            새 비밀번호
          </label>
          <input
            type="password"
            autoComplete="new-password"
            value={next}
            onChange={(e) => setNext(e.target.value)}
            className={inputCls}
            placeholder="새 비밀번호 (8자 이상)"
          />
          {tooShort && (
            <p className="text-[11px] text-rose-600 dark:text-rose-400">
              8자 이상이어야 합니다.
            </p>
          )}
        </div>

        <div className="space-y-1">
          <label className="text-xs font-medium text-neutral-700 dark:text-neutral-300">
            새 비밀번호 확인
          </label>
          <input
            type="password"
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            className={inputCls}
            placeholder="새 비밀번호 다시 입력"
          />
          {mismatch && (
            <p className="text-[11px] text-rose-600 dark:text-rose-400">
              새 비밀번호가 일치하지 않습니다.
            </p>
          )}
        </div>

        {error && (
          <p className="rounded-md border border-rose-300 bg-rose-50 px-3 py-2 text-xs text-rose-700 dark:border-rose-500/40 dark:bg-rose-500/10 dark:text-rose-300">
            {error}
          </p>
        )}

        <div className="flex items-center gap-2 pt-1">
          <Button type="submit" size="sm" disabled={!canSubmit}>
            {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : "비밀번호 변경"}
          </Button>
          {done && (
            <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-700 dark:text-emerald-300">
              <Check className="h-3.5 w-3.5" /> 변경되었습니다
            </span>
          )}
        </div>
      </div>

      {/* 우: 실시간 요구사항 + 보안 팁 */}
      <div className="rounded-lg border border-neutral-200 bg-neutral-50 p-4 dark:border-neutral-800 dark:bg-surface-2/50">
        <div className="mb-3 flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-sky-700 dark:text-sky-300" />
          <h4 className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">
            새 비밀번호 조건
          </h4>
        </div>
        <ul className="space-y-2">
          <Req ok={len8} label="8자 이상" />
          <Req ok={differs} label="현재 비밀번호와 다름" />
          <Req ok={matches} label="확인란과 일치" />
        </ul>

        <div className="mt-4 border-t border-neutral-200 pt-3 dark:border-neutral-800">
          <p className="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-neutral-500 dark:text-neutral-500">
            안전한 비밀번호 팁
          </p>
          <ul className="space-y-1 text-[11px] leading-relaxed text-neutral-600 dark:text-neutral-400">
            <li>· 다른 사이트와 겹치지 않는 고유한 비밀번호를 쓰세요.</li>
            <li>· 영문 대소문자·숫자·기호를 섞으면 더 안전합니다.</li>
            <li>· 변경 후에도 현재 기기 로그인은 유지됩니다.</li>
          </ul>
        </div>
      </div>
    </form>
  );
}

function Req({ ok, label }: { ok: boolean; label: string }) {
  return (
    <li className="flex items-center gap-2 text-xs">
      <span
        className={cn(
          "inline-flex h-4 w-4 shrink-0 items-center justify-center rounded-full",
          ok
            ? "bg-emerald-100 text-emerald-700 dark:bg-emerald-500/20 dark:text-emerald-300"
            : "bg-neutral-200 text-neutral-400 dark:bg-surface-3 dark:text-neutral-500",
        )}
      >
        {ok ? <Check className="h-2.5 w-2.5" /> : <X className="h-2.5 w-2.5" />}
      </span>
      <span
        className={cn(
          ok
            ? "text-neutral-800 dark:text-neutral-200"
            : "text-neutral-500 dark:text-neutral-500",
        )}
      >
        {label}
      </span>
    </li>
  );
}
