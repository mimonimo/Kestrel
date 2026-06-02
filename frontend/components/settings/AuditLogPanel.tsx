"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Clock, Loader2, ScrollText } from "lucide-react";

import { ApiError } from "@/lib/api";
import { formatRelativeKo } from "@/lib/format";
import { cn } from "@/lib/utils";

interface AuditLog {
  id: number;
  action: string;
  actionLabel: string | null;
  actorLabel: string | null;
  actorUserId: string | null;
  target: string | null;
  detail: string | null;
  ip: string | null;
  createdAt: string;
}

const BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000/api/v1";

async function fetchAuditLogs(action: string): Promise<{ items: AuditLog[]; total: number }> {
  const qs = new URLSearchParams({ limit: "100" });
  if (action) qs.set("action", action);
  const res = await fetch(`${BASE}/admin/audit/logs?${qs.toString()}`, {
    credentials: "include",
    cache: "no-store",
  });
  if (!res.ok) throw new ApiError(res.status, `감사 로그를 불러오지 못했습니다 (${res.status})`);
  return res.json();
}

async function fetchActions(): Promise<Record<string, string>> {
  const res = await fetch(`${BASE}/admin/audit/actions`, {
    credentials: "include",
    cache: "no-store",
  });
  if (!res.ok) return {};
  const body = await res.json();
  return body.actions ?? {};
}

// 액션별 칩 톤 — 라이트/다크 양쪽 변형 ([[feedback_light_dark_parity]]).
function actionTone(action: string): string {
  if (action === "login.success")
    return "bg-emerald-100 text-emerald-800 dark:bg-emerald-500/15 dark:text-emerald-200";
  if (action === "login.failure")
    return "bg-rose-100 text-rose-800 dark:bg-rose-500/15 dark:text-rose-200";
  if (action === "signup")
    return "bg-sky-100 text-sky-800 dark:bg-sky-500/15 dark:text-sky-200";
  if (action === "password.change")
    return "bg-violet-100 text-violet-800 dark:bg-violet-500/15 dark:text-violet-200";
  if (action === "user.role_change")
    return "bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-200";
  if (action === "user.delete")
    return "bg-red-100 text-red-800 dark:bg-red-500/15 dark:text-red-200";
  return "bg-slate-200 text-slate-800 dark:bg-slate-500/25 dark:text-slate-100";
}

export function AuditLogPanel() {
  const [action, setAction] = useState("");

  const actionsQ = useQuery({
    queryKey: ["admin-audit-actions"],
    queryFn: fetchActions,
    staleTime: 5 * 60_000,
  });
  const logs = useQuery({
    queryKey: ["admin-audit-logs", action],
    queryFn: () => fetchAuditLogs(action),
    staleTime: 15_000,
  });

  const actionMap = actionsQ.data ?? {};

  return (
    <div className="space-y-3 rounded-lg border border-neutral-200 bg-white p-5 dark:border-neutral-800 dark:bg-surface-1">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <ScrollText className="h-4 w-4 text-sky-700 dark:text-sky-300" />
          <p className="text-xs text-neutral-600 dark:text-neutral-400">
            로그인 성공·실패, 가입, 비밀번호 변경, 역할 변경, 사용자 삭제, 외부 키 변경 이력을
            시간 역순으로 보여줍니다.
          </p>
        </div>
        <select
          value={action}
          onChange={(e) => setAction(e.target.value)}
          aria-label="이벤트 종류 필터"
          className="shrink-0 rounded-full border border-neutral-300 bg-white px-2.5 py-1 text-xs text-neutral-800 focus:border-sky-500 focus:outline-none dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-200"
        >
          <option value="">전체 이벤트</option>
          {Object.entries(actionMap).map(([code, label]) => (
            <option key={code} value={code}>
              {label}
            </option>
          ))}
        </select>
      </div>

      {logs.isPending ? (
        <p className="flex items-center gap-2 text-xs text-neutral-600 dark:text-neutral-500">
          <Loader2 className="h-3 w-3 animate-spin" /> 불러오는 중…
        </p>
      ) : logs.isError ? (
        <p className="text-xs text-rose-700 dark:text-rose-300">
          {(logs.error as Error).message || "감사 로그를 불러오지 못했습니다."}
        </p>
      ) : !logs.data || logs.data.items.length === 0 ? (
        <p className="rounded-lg border border-dashed border-neutral-300 bg-neutral-50 px-3 py-6 text-center text-xs text-neutral-700 dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-400">
          기록된 이벤트가 없습니다.
        </p>
      ) : (
        <ul className="max-h-[28rem] space-y-1.5 overflow-y-auto">
          {logs.data.items.map((l) => (
            <li
              key={l.id}
              className="flex flex-wrap items-center gap-x-2 gap-y-1 rounded-lg border border-neutral-200 bg-white px-3 py-2 text-xs dark:border-neutral-800 dark:bg-surface-1"
            >
              <span
                className={cn(
                  "shrink-0 rounded-full px-2 py-0.5 text-[10px] font-medium",
                  actionTone(l.action),
                )}
              >
                {l.actionLabel || l.action}
              </span>
              {l.actorLabel && (
                <span className="font-medium text-neutral-800 dark:text-neutral-200">
                  {l.actorLabel}
                </span>
              )}
              {l.target && (
                <span className="text-neutral-600 dark:text-neutral-400">
                  → {l.target}
                </span>
              )}
              {l.detail && (
                <span className="text-neutral-500 dark:text-neutral-500">({l.detail})</span>
              )}
              {l.ip && (
                <span className="tabular-nums text-neutral-500 dark:text-neutral-500">
                  {l.ip}
                </span>
              )}
              <span className="ml-auto inline-flex shrink-0 items-center gap-1 tabular-nums text-[10px] text-neutral-500 dark:text-neutral-500">
                <Clock className="h-2.5 w-2.5" />
                {formatRelativeKo(l.createdAt)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
