"use client";

import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  Clock,
  LogIn,
  ScrollText,
  Loader2,
  X,
} from "lucide-react";

import { ApiError } from "@/lib/api";
import { formatRelativeKo } from "@/lib/format";
import { cn } from "@/lib/utils";

const BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000/api/v1";

async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { credentials: "include", cache: "no-store" });
  if (!res.ok) throw new ApiError(res.status, `로그를 불러오지 못했습니다 (${res.status})`);
  return res.json();
}

type Which = "access" | "activity" | "audit";

const META: Record<Which, { label: string; desc: string; icon: typeof LogIn }> = {
  access: { label: "접속 로그", desc: "전체 사용자 로그인 기록", icon: LogIn },
  activity: { label: "활동 로그", desc: "글·댓글·분석·즐겨찾기 활동", icon: Activity },
  audit: { label: "감사 로그", desc: "로그인·가입·권한 변경 등 보안 이벤트", icon: ScrollText },
};

export function AdminLogsButtons() {
  const [open, setOpen] = useState<Which | null>(null);
  return (
    <>
      <div className="grid gap-3 sm:grid-cols-3">
        {(Object.keys(META) as Which[]).map((w) => {
          const { label, desc, icon: Icon } = META[w];
          return (
            <button
              key={w}
              type="button"
              onClick={() => setOpen(w)}
              className="group flex items-center gap-3 rounded-lg border border-neutral-200 bg-white p-4 text-left transition-colors hover:border-sky-400 hover:bg-sky-50/40 dark:border-neutral-800 dark:bg-surface-1 dark:hover:border-sky-500/40 dark:hover:bg-surface-2"
            >
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-sky-500/15 text-sky-700 ring-1 ring-sky-500/30 dark:text-sky-300">
                <Icon className="h-4 w-4" />
              </div>
              <div className="min-w-0">
                <div className="text-sm font-medium text-neutral-900 dark:text-neutral-100">
                  {label}
                </div>
                <p className="mt-0.5 truncate text-[11px] text-neutral-600 dark:text-neutral-500">
                  {desc}
                </p>
              </div>
            </button>
          );
        })}
      </div>
      {open && <LogModal which={open} onClose={() => setOpen(null)} />}
    </>
  );
}

function LogModal({ which, onClose }: { which: Which; onClose: () => void }) {
  const { label, icon: Icon } = META[which];
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prev;
    };
  }, [onClose]);

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={label}
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-neutral-950/60 px-4 py-10 backdrop-blur-sm animate-in fade-in duration-150"
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div
        className="relative w-full max-w-3xl rounded-2xl border border-neutral-200 bg-white shadow-2xl shadow-black/20 dark:border-neutral-800 dark:bg-surface-1 dark:shadow-black/50 animate-in zoom-in-95 duration-150"
        onClick={(e) => e.stopPropagation()}
      >
        <header className="flex items-center gap-2 border-b border-neutral-200 px-5 py-4 dark:border-neutral-800">
          <Icon className="h-4 w-4 text-sky-700 dark:text-sky-300" />
          <h3 className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">{label}</h3>
          <button
            type="button"
            onClick={onClose}
            aria-label="닫기"
            className="ml-auto inline-flex h-8 w-8 items-center justify-center rounded-full text-neutral-500 transition-colors hover:bg-neutral-100 hover:text-neutral-900 dark:hover:bg-surface-2 dark:hover:text-neutral-100"
          >
            <X className="h-4 w-4" />
          </button>
        </header>
        <div className="max-h-[70vh] overflow-y-auto px-5 py-4">
          {which === "access" && <AccessFeed />}
          {which === "activity" && <ActivityFeed />}
          {which === "audit" && <AuditFeed />}
        </div>
      </div>
    </div>
  );
}

function FeedState({ q, empty }: { q: { isPending: boolean; isError: boolean; error: unknown }; empty: boolean }) {
  if (q.isPending)
    return (
      <p className="flex items-center gap-2 text-xs text-neutral-600 dark:text-neutral-500">
        <Loader2 className="h-3 w-3 animate-spin" /> 불러오는 중…
      </p>
    );
  if (q.isError)
    return (
      <p className="text-xs text-rose-700 dark:text-rose-300">
        {(q.error as Error)?.message || "불러오지 못했습니다."}
      </p>
    );
  if (empty)
    return (
      <p className="rounded-lg border border-dashed border-neutral-300 bg-neutral-50 px-3 py-6 text-center text-xs text-neutral-700 dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-400">
        기록이 없습니다.
      </p>
    );
  return null;
}

// ─── 접속 로그 ───────────────────────────────────────────
interface AccessLog {
  id: number;
  userLabel: string | null;
  ip: string | null;
  osName: string | null;
  osVersion: string | null;
  browserName: string | null;
  browserVersion: string | null;
  deviceKind: string | null;
  createdAt: string;
}

function deviceTone(kind: string | null): string {
  if (kind === "mobile") return "bg-emerald-100 text-emerald-800 dark:bg-emerald-500/15 dark:text-emerald-200";
  if (kind === "tablet") return "bg-sky-100 text-sky-800 dark:bg-sky-500/15 dark:text-sky-200";
  if (kind === "bot") return "bg-rose-100 text-rose-800 dark:bg-rose-500/15 dark:text-rose-200";
  if (kind === "desktop") return "bg-slate-200 text-slate-800 dark:bg-slate-500/25 dark:text-slate-100";
  return "bg-neutral-200 text-neutral-800 dark:bg-neutral-500/25 dark:text-neutral-100";
}

function AccessFeed() {
  const q = useQuery({
    queryKey: ["admin-access-logs"],
    queryFn: () => getJSON<{ items: AccessLog[] }>("/admin/access-logs?limit=150"),
    staleTime: 15_000,
  });
  const items = q.data?.items ?? [];
  const state = <FeedState q={q} empty={items.length === 0} />;
  if (q.isPending || q.isError || items.length === 0) return state;
  return (
    <ul className="space-y-1.5">
      {items.map((l) => {
        const browser = l.browserName ? `${l.browserName}${l.browserVersion ? " " + l.browserVersion : ""}` : null;
        const os = l.osName ? `${l.osName}${l.osVersion ? " " + l.osVersion : ""}` : null;
        return (
          <li key={l.id} className="flex flex-wrap items-center gap-x-2 gap-y-1 rounded-lg border border-neutral-200 px-3 py-2 text-xs dark:border-neutral-800">
            <span className="font-medium text-neutral-900 dark:text-neutral-100">
              {l.userLabel || "(삭제된 사용자)"}
            </span>
            {l.deviceKind && (
              <span className={cn("rounded-full px-1.5 py-px text-[9px] font-medium", deviceTone(l.deviceKind))}>
                {l.deviceKind}
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
            {l.ip && <span className="tabular-nums text-neutral-500 dark:text-neutral-500">{l.ip}</span>}
            <span className="ml-auto inline-flex shrink-0 items-center gap-1 tabular-nums text-[10px] text-neutral-500 dark:text-neutral-500">
              <Clock className="h-2.5 w-2.5" />
              {formatRelativeKo(l.createdAt)}
            </span>
          </li>
        );
      })}
    </ul>
  );
}

// ─── 활동 로그 ───────────────────────────────────────────
interface ActivityLog {
  kind: string;
  kindLabel: string;
  actorLabel: string | null;
  ref: string | null;
  createdAt: string;
}

function activityTone(kind: string): string {
  if (kind === "post") return "bg-sky-100 text-sky-800 dark:bg-sky-500/15 dark:text-sky-200";
  if (kind === "comment") return "bg-violet-100 text-violet-800 dark:bg-violet-500/15 dark:text-violet-200";
  if (kind === "analysis") return "bg-emerald-100 text-emerald-800 dark:bg-emerald-500/15 dark:text-emerald-200";
  if (kind === "bookmark") return "bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-200";
  return "bg-slate-200 text-slate-800 dark:bg-slate-500/25 dark:text-slate-100";
}

const ACTIVITY_FILTERS: { value: string; label: string }[] = [
  { value: "", label: "전체" },
  { value: "post", label: "글 작성" },
  { value: "comment", label: "댓글" },
  { value: "analysis", label: "AI 분석" },
  { value: "bookmark", label: "즐겨찾기" },
];

function ActivityFeed() {
  const [kind, setKind] = useState("");
  const q = useQuery({
    queryKey: ["admin-activity-logs", kind],
    queryFn: () =>
      getJSON<{ items: ActivityLog[] }>(`/admin/activity-logs?limit=150${kind ? `&kind=${kind}` : ""}`),
    staleTime: 15_000,
  });
  const items = q.data?.items ?? [];
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-1.5">
        {ACTIVITY_FILTERS.map((f) => (
          <button
            key={f.value}
            type="button"
            onClick={() => setKind(f.value)}
            className={cn(
              "rounded-full border px-2.5 py-0.5 text-[11px] font-medium transition-colors",
              kind === f.value
                ? "border-sky-400 bg-sky-100 text-sky-800 dark:border-sky-500/50 dark:bg-sky-500/20 dark:text-sky-200"
                : "border-neutral-300 text-neutral-600 hover:border-sky-300 hover:text-sky-700 dark:border-neutral-700 dark:text-neutral-400 dark:hover:text-sky-200",
            )}
          >
            {f.label}
          </button>
        ))}
      </div>
      <FeedState q={q} empty={items.length === 0} />
      {!q.isPending && !q.isError && items.length > 0 && (
        <ul className="space-y-1.5">
          {items.map((a, i) => (
            <li key={i} className="flex flex-wrap items-center gap-x-2 gap-y-1 rounded-lg border border-neutral-200 px-3 py-2 text-xs dark:border-neutral-800">
              <span className={cn("shrink-0 rounded-full px-2 py-0.5 text-[10px] font-medium", activityTone(a.kind))}>
                {a.kindLabel}
              </span>
              <span className="font-medium text-neutral-800 dark:text-neutral-200">
                {a.actorLabel || "(삭제된 사용자)"}
              </span>
              {a.ref && <span className="min-w-0 truncate text-neutral-600 dark:text-neutral-400">{a.ref}</span>}
              <span className="ml-auto inline-flex shrink-0 items-center gap-1 tabular-nums text-[10px] text-neutral-500 dark:text-neutral-500">
                <Clock className="h-2.5 w-2.5" />
                {formatRelativeKo(a.createdAt)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ─── 감사 로그 ───────────────────────────────────────────
interface AuditLog {
  id: number;
  action: string;
  actionLabel: string | null;
  actorLabel: string | null;
  target: string | null;
  detail: string | null;
  ip: string | null;
  createdAt: string;
}

function auditTone(action: string): string {
  if (action === "login.success") return "bg-emerald-100 text-emerald-800 dark:bg-emerald-500/15 dark:text-emerald-200";
  if (action === "login.failure") return "bg-rose-100 text-rose-800 dark:bg-rose-500/15 dark:text-rose-200";
  if (action === "signup") return "bg-sky-100 text-sky-800 dark:bg-sky-500/15 dark:text-sky-200";
  if (action === "password.change") return "bg-violet-100 text-violet-800 dark:bg-violet-500/15 dark:text-violet-200";
  if (action === "user.role_change") return "bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-200";
  if (action === "user.delete") return "bg-red-100 text-red-800 dark:bg-red-500/15 dark:text-red-200";
  return "bg-slate-200 text-slate-800 dark:bg-slate-500/25 dark:text-slate-100";
}

function AuditFeed() {
  const [action, setAction] = useState("");
  const actionsQ = useQuery({
    queryKey: ["admin-audit-actions"],
    queryFn: () => getJSON<{ actions: Record<string, string> }>("/admin/audit/actions"),
    staleTime: 5 * 60_000,
  });
  const q = useQuery({
    queryKey: ["admin-audit-logs", action],
    queryFn: () =>
      getJSON<{ items: AuditLog[] }>(`/admin/audit/logs?limit=150${action ? `&action=${action}` : ""}`),
    staleTime: 15_000,
  });
  const items = q.data?.items ?? [];
  const actionMap = actionsQ.data?.actions ?? {};
  return (
    <div className="space-y-3">
      <select
        value={action}
        onChange={(e) => setAction(e.target.value)}
        aria-label="이벤트 종류 필터"
        className="rounded-full border border-neutral-300 bg-white px-2.5 py-1 text-xs text-neutral-800 focus:border-sky-500 focus:outline-none dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-200"
      >
        <option value="">전체 이벤트</option>
        {Object.entries(actionMap).map(([code, label]) => (
          <option key={code} value={code}>
            {label}
          </option>
        ))}
      </select>
      <FeedState q={q} empty={items.length === 0} />
      {!q.isPending && !q.isError && items.length > 0 && (
        <ul className="space-y-1.5">
          {items.map((l) => (
            <li key={l.id} className="flex flex-wrap items-center gap-x-2 gap-y-1 rounded-lg border border-neutral-200 px-3 py-2 text-xs dark:border-neutral-800">
              <span className={cn("shrink-0 rounded-full px-2 py-0.5 text-[10px] font-medium", auditTone(l.action))}>
                {l.actionLabel || l.action}
              </span>
              {l.actorLabel && <span className="font-medium text-neutral-800 dark:text-neutral-200">{l.actorLabel}</span>}
              {l.target && <span className="text-neutral-600 dark:text-neutral-400">→ {l.target}</span>}
              {l.detail && <span className="text-neutral-500 dark:text-neutral-500">({l.detail})</span>}
              {l.ip && <span className="tabular-nums text-neutral-500 dark:text-neutral-500">{l.ip}</span>}
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
