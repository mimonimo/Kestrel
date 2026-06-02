"use client";

import { useState } from "react";
import { Check, KeyRound, Loader2 } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import { Button } from "@/components/ui/button";

// 비밀번호 변경 — 현재 비밀번호 재확인 + 새 비밀번호(8자+) + 확인 일치.
// 서버가 현재 비밀번호를 다시 검증하므로, 세션 탈취만으로는 비번을 못 바꾼다.
export function PasswordChangePanel() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const tooShort = next.length > 0 && next.length < 8;
  const mismatch = confirm.length > 0 && next !== confirm;
  const canSubmit =
    !!current && next.length >= 8 && next === confirm && !busy;

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
      className="max-w-md space-y-3 rounded-xl border border-neutral-200 bg-white p-5 dark:border-neutral-800 dark:bg-surface-1"
    >
      <div className="flex items-center gap-2">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-sky-500/15 ring-1 ring-sky-500/30">
          <KeyRound className="h-4 w-4 text-sky-700 dark:text-sky-300" />
        </div>
        <div>
          <h4 className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">
            비밀번호 변경
          </h4>
          <p className="text-[11px] text-neutral-600 dark:text-neutral-500">
            현재 비밀번호 확인 후 새 비밀번호(8자 이상)로 변경합니다
          </p>
        </div>
      </div>

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
    </form>
  );
}
