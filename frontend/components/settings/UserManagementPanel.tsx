"use client";

/**
 * 사용자 추적 패널 — admin 전용 (PR 10-CR).
 *
 * "어드민 계정이 여러개일 필요는 없긴 해 근데 사용자 추적은 하면 좋을듯"
 * 라는 요구에 따라 role 변경 UI 는 최소화하고 활동 통계 + 마지막 활동 시간
 * 추적을 핵심으로. 삭제는 본인이 아니고 부트스트랩 admin 이 아닐 때만.
 */
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, ChevronRight, Clock, Loader2, Search, ShieldCheck, Trash2, User as UserIcon } from "lucide-react";

import { ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { formatRelativeKo } from "@/lib/format";
import { cn } from "@/lib/utils";

interface UserStats {
  analyses: number;
  posts: number;
  comments: number;
  bookmarks: number;
  lastActivityAt: string | null;
}

interface AdminUser {
  id: string;
  email: string;
  username: string;
  nickname: string | null;
  role: "user" | "expert" | "admin";
  isAdmin: boolean;
  createdAt: string;
  updatedAt: string;
  lastLoginAt: string | null;
  lastActiveAt: string | null;
  stats: UserStats;
}

interface LoginLog {
  id: number;
  userId: string;
  ip: string | null;
  userAgent: string | null;
  osName: string | null;
  osVersion: string | null;
  browserName: string | null;
  browserVersion: string | null;
  deviceKind: string | null;
  createdAt: string;
}

async function fetchUsers(q: string): Promise<{ items: AdminUser[]; total: number }> {
  const BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000/api/v1";
  const url = `${BASE}/admin/users${q ? `?q=${encodeURIComponent(q)}` : ""}`;
  const res = await fetch(url, { credentials: "include", cache: "no-store" });
  if (!res.ok) {
    throw new ApiError(res.status, `사용자 목록을 불러오지 못했습니다 (${res.status})`);
  }
  return res.json();
}

async function fetchLoginLogs(id: string): Promise<{ items: LoginLog[] }> {
  const BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000/api/v1";
  const res = await fetch(`${BASE}/admin/users/${encodeURIComponent(id)}/login-logs?limit=20`, {
    credentials: "include",
    cache: "no-store",
  });
  if (!res.ok) throw new ApiError(res.status, `접속 로그 로딩 실패 (${res.status})`);
  return res.json();
}

async function deleteUserApi(id: string): Promise<void> {
  const BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000/api/v1";
  const res = await fetch(`${BASE}/admin/users/${encodeURIComponent(id)}`, {
    method: "DELETE",
    credentials: "include",
  });
  if (!res.ok && res.status !== 204) {
    let detail = `삭제 실패 (${res.status})`;
    try {
      const body = await res.json();
      if (body?.detail) detail = String(body.detail);
    } catch {
      /* ignore */
    }
    throw new ApiError(res.status, detail);
  }
}

export function UserManagementPanel() {
  const { user: me } = useAuth();
  const qc = useQueryClient();
  const [q, setQ] = useState("");
  const [debounced, setDebounced] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // 200ms debounce
  useState(() => {
    const t = setTimeout(() => setDebounced(q), 200);
    return () => clearTimeout(t);
  });

  const list = useQuery({
    queryKey: ["admin-users", debounced],
    queryFn: () => fetchUsers(debounced),
    staleTime: 30_000,
  });

  const remove = useMutation({
    mutationFn: (id: string) => deleteUserApi(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["admin-users"] }),
  });

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-end">
        <span className="text-[11px] tabular-nums text-neutral-500 dark:text-neutral-500">
          {list.data ? `${list.data.total}명` : "—"}
        </span>
      </div>

      <div className="relative">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-neutral-500" />
        <input
          value={q}
          onChange={(e) => {
            setQ(e.target.value);
            setDebounced(e.target.value);
          }}
          placeholder="이메일·사용자명·닉네임 검색"
          className="block w-full rounded-md border border-neutral-300 bg-white py-1.5 pl-8 pr-3 text-xs text-neutral-900 placeholder:text-neutral-500 focus:border-sky-500 focus:outline-none dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-100"
        />
      </div>

      {list.isPending ? (
        <p className="flex items-center gap-2 text-xs text-neutral-600 dark:text-neutral-500">
          <Loader2 className="h-3 w-3 animate-spin" /> 불러오는 중…
        </p>
      ) : list.isError ? (
        <p className="text-xs text-rose-700 dark:text-rose-300">
          {(list.error as Error).message || "사용자 목록을 불러오지 못했습니다."}
        </p>
      ) : !list.data || list.data.items.length === 0 ? (
        <p className="rounded-lg border border-dashed border-neutral-300 bg-neutral-50 px-3 py-6 text-center text-xs text-neutral-700 dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-400">
          조건에 맞는 사용자가 없습니다.
        </p>
      ) : (
        <ul className="space-y-2">
          {list.data.items.map((u) => {
            const isMe = me?.id === u.id;
            const display = u.nickname || u.username;
            const initial = display.trim().charAt(0).toUpperCase() || "?";
            return (
              <li
                key={u.id}
                className="flex items-start gap-3 rounded-lg border border-neutral-200 bg-white p-3 dark:border-neutral-800 dark:bg-surface-1"
              >
                <span
                  className={cn(
                    "mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-xs font-semibold",
                    u.isAdmin
                      ? "bg-amber-100 text-amber-800 dark:bg-amber-500/20 dark:text-amber-200"
                      : "bg-sky-100 text-sky-800 dark:bg-sky-500/20 dark:text-sky-200",
                  )}
                >
                  {initial}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-baseline gap-x-2 text-sm">
                    <span className="truncate font-medium text-neutral-900 dark:text-neutral-100">
                      {display}
                    </span>
                    {u.isAdmin && (
                      <span className="inline-flex items-center gap-1 rounded-full bg-amber-100 px-2 py-0.5 text-[10px] font-medium text-amber-800 dark:bg-amber-500/15 dark:text-amber-200">
                        <ShieldCheck className="h-3 w-3" />
                        관리자
                      </span>
                    )}
                    {isMe && (
                      <span className="inline-flex items-center rounded-full bg-emerald-100 px-2 py-0.5 text-[10px] font-medium text-emerald-800 dark:bg-emerald-500/15 dark:text-emerald-200">
                        나
                      </span>
                    )}
                    <span className="text-xs text-neutral-500 dark:text-neutral-500">·</span>
                    <span className="truncate text-xs text-neutral-600 dark:text-neutral-400">
                      {u.email}
                    </span>
                  </div>
                  <dl className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-neutral-600 dark:text-neutral-400">
                    <Stat label="분석" value={u.stats.analyses} />
                    <Stat label="글" value={u.stats.posts} />
                    <Stat label="댓글" value={u.stats.comments} />
                    <Stat label="즐겨찾기" value={u.stats.bookmarks} />
                  </dl>
                  <p className="mt-1.5 text-[10px] tabular-nums text-neutral-500 dark:text-neutral-500">
                    가입 {formatRelativeKo(u.createdAt)} · 최근 활동{" "}
                    {u.lastActiveAt
                      ? formatRelativeKo(u.lastActiveAt)
                      : u.stats.lastActivityAt
                        ? formatRelativeKo(u.stats.lastActivityAt)
                        : "없음"}
                  </p>
                  <button
                    type="button"
                    onClick={() => setExpandedId(expandedId === u.id ? null : u.id)}
                    className="mt-2 inline-flex items-center gap-1 rounded-full border border-neutral-300 px-2 py-0.5 text-[10px] text-neutral-700 hover:border-sky-300 hover:text-sky-700 dark:border-neutral-700 dark:text-neutral-300 dark:hover:border-sky-500/40 dark:hover:text-sky-200"
                  >
                    {expandedId === u.id ? (
                      <ChevronDown className="h-3 w-3" />
                    ) : (
                      <ChevronRight className="h-3 w-3" />
                    )}
                    접속 로그
                  </button>
                  {expandedId === u.id && <LoginLogList userId={u.id} />}
                </div>
                <button
                  type="button"
                  disabled={isMe || remove.isPending}
                  onClick={() => {
                    if (
                      confirm(
                        `${display} 계정을 삭제할까요? 이 사용자가 쓴 글·분석·댓글·즐겨찾기도 같이 삭제됩니다.`,
                      )
                    ) {
                      remove.mutate(u.id);
                    }
                  }}
                  title={isMe ? "본인은 삭제할 수 없습니다" : "사용자 삭제"}
                  className={cn(
                    "shrink-0 inline-flex items-center gap-1 rounded-full border px-2 py-1 text-[11px] transition-colors",
                    "border-red-300 text-red-700 hover:bg-red-50",
                    "dark:border-red-900/50 dark:text-red-300 dark:hover:bg-red-950/40",
                    "disabled:cursor-not-allowed disabled:opacity-40",
                  )}
                >
                  {remove.isPending && remove.variables === u.id ? (
                    <Loader2 className="h-3 w-3 animate-spin" />
                  ) : (
                    <Trash2 className="h-3 w-3" />
                  )}
                  삭제
                </button>
              </li>
            );
          })}
        </ul>
      )}
      {remove.isError && (
        <p className="text-xs text-rose-700 dark:text-rose-300">
          {(remove.error as Error).message || "삭제에 실패했습니다."}
        </p>
      )}
    </div>
  );
}

function LoginLogList({ userId }: { userId: string }) {
  const { data, isPending, isError } = useQuery({
    queryKey: ["admin-user-login-logs", userId],
    queryFn: () => fetchLoginLogs(userId),
    staleTime: 30_000,
  });
  if (isPending) {
    return (
      <p className="mt-2 inline-flex items-center gap-1.5 text-[10px] text-neutral-500 dark:text-neutral-500">
        <Loader2 className="h-3 w-3 animate-spin" /> 로그 불러오는 중…
      </p>
    );
  }
  if (isError) {
    return (
      <p className="mt-2 text-[10px] text-rose-700 dark:text-rose-300">
        접속 로그를 가져오지 못했어요.
      </p>
    );
  }
  if (!data || data.items.length === 0) {
    return (
      <p className="mt-2 text-[10px] text-neutral-500 dark:text-neutral-500">
        기록된 접속이 없어요.
      </p>
    );
  }
  return (
    <ul className="mt-2 max-h-64 space-y-1.5 overflow-y-auto border-l-2 border-neutral-200 pl-3 dark:border-neutral-800">
      {data.items.map((log) => {
        const browser = log.browserName
          ? `${log.browserName}${log.browserVersion ? " " + log.browserVersion : ""}`
          : null;
        const os = log.osName
          ? `${log.osName}${log.osVersion ? " " + log.osVersion : ""}`
          : null;
        // desktop 도 다른 디바이스 칩과 동일한 saturated 톤(slate) 으로 통일.
        // 이전엔 neutral-100/dark:bg-surface-2 였는데, 라이트에선 회색 칸이 까맣게
        // 떠 보이고 다크에선 surface 와 같은 색이라 칩이 안 보이는 회귀가 반복됨
        // ([[feedback_light_dark_parity]]).
        const kindTone =
          log.deviceKind === "mobile"
            ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-500/15 dark:text-emerald-200"
            : log.deviceKind === "tablet"
              ? "bg-sky-100 text-sky-800 dark:bg-sky-500/15 dark:text-sky-200"
              : log.deviceKind === "bot"
                ? "bg-rose-100 text-rose-800 dark:bg-rose-500/15 dark:text-rose-200"
                : log.deviceKind === "desktop"
                  ? "bg-slate-200 text-slate-800 dark:bg-slate-500/25 dark:text-slate-100"
                  : "bg-neutral-200 text-neutral-800 dark:bg-neutral-500/25 dark:text-neutral-100";
        return (
          <li key={log.id} className="text-[10px] text-neutral-600 dark:text-neutral-400">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="inline-flex items-center gap-1 text-neutral-800 dark:text-neutral-200">
                <Clock className="h-2.5 w-2.5" />
                {formatRelativeKo(log.createdAt)}
              </span>
              {log.deviceKind && (
                <span
                  className={`rounded-full px-1.5 py-px text-[9px] font-medium ${kindTone}`}
                >
                  {log.deviceKind}
                </span>
              )}
              {browser && (
                <span className="rounded-full bg-violet-100 px-1.5 py-px text-[9px] font-medium text-violet-800 dark:bg-violet-500/15 dark:text-violet-200">
                  {browser}
                </span>
              )}
              {os && (
                <span className="rounded-full bg-amber-100 px-1.5 py-px text-[9px] font-medium text-amber-800 dark:bg-amber-500/15 dark:text-amber-200">
                  {os}
                </span>
              )}
              {log.ip && (
                <span className="tabular-nums text-neutral-700 dark:text-neutral-300">
                  {log.ip}
                </span>
              )}
            </div>
            {log.userAgent && (
              <p
                className="mt-0.5 truncate text-[9px] text-neutral-500 dark:text-neutral-500"
                title={log.userAgent}
              >
                {log.userAgent}
              </p>
            )}
          </li>
        );
      })}
    </ul>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <span className="inline-flex items-center gap-1">
      <span className="text-neutral-500 dark:text-neutral-500">{label}</span>
      <span className="font-medium tabular-nums text-neutral-800 dark:text-neutral-200">
        {value}
      </span>
    </span>
  );
}
