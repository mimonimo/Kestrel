"use client";

import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  Clock,
  LogIn,
  ScrollText,
  Loader2,
  Users as UsersIcon,
  X,
} from "lucide-react";

import { ApiError } from "@/lib/api";
import { formatRelativeKo } from "@/lib/format";
import { cn } from "@/lib/utils";
import { UserManagementPanel } from "@/components/settings/UserManagementPanel";

const BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000/api/v1";

async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { credentials: "include", cache: "no-store" });
  if (!res.ok) throw new ApiError(res.status, `불러오지 못했습니다 (${res.status})`);
  return res.json();
}

type Which = "users" | "access" | "activity" | "audit";

const META: Record<Which, { label: string; icon: typeof LogIn }> = {
  users: { label: "이용자 조회·관리", icon: UsersIcon },
  access: { label: "접속 로그", icon: LogIn },
  activity: { label: "활동 로그", icon: Activity },
  audit: { label: "감사 로그", icon: ScrollText },
};

export function AdminUsersConsole() {
  const [open, setOpen] = useState<Which | null>(null);
  return (
    <div className="space-y-6">
      <Overview />
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {(Object.keys(META) as Which[]).map((w) => {
          const { label, icon: Icon } = META[w];
          return (
            <button
              key={w}
              type="button"
              onClick={() => setOpen(w)}
              className="group flex items-center gap-2.5 rounded-lg border border-neutral-200 bg-white px-4 py-3 text-left transition-colors hover:border-sky-400 hover:bg-sky-50/40 dark:border-neutral-800 dark:bg-surface-1 dark:hover:border-sky-500/40 dark:hover:bg-surface-2"
            >
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-sky-500/15 text-sky-700 ring-1 ring-sky-500/30 dark:text-sky-300">
                <Icon className="h-4 w-4" />
              </div>
              <span className="text-sm font-medium text-neutral-900 dark:text-neutral-100">
                {label}
              </span>
            </button>
          );
        })}
      </div>
      {open && <ConsoleModal which={open} onClose={() => setOpen(null)} />}
    </div>
  );
}

// ─── 개요 시각화 ─────────────────────────────────────────
interface VisitDay {
  date: string;
  total: number;
  member: number;
  anon: number;
}

interface Overview {
  totalUsers: number;
  adminUsers: number;
  newUsers7d: number;
  logins7d: number;
  activity: { post: number; comment: number; analysis: number; bookmark: number };
  visits: {
    total: number;
    today: number;
    memberTotal: number;
    anonTotal: number;
    daily: VisitDay[];
  };
}

function mdLabel(iso: string): string {
  const [, m, d] = iso.split("-");
  return `${parseInt(m, 10)}/${parseInt(d, 10)}`;
}

const ACTIVITY_BARS: { key: keyof Overview["activity"]; label: string; bar: string }[] = [
  { key: "post", label: "글", bar: "bg-sky-500" },
  { key: "comment", label: "댓글", bar: "bg-violet-500" },
  { key: "analysis", label: "AI 분석", bar: "bg-emerald-500" },
  { key: "bookmark", label: "즐겨찾기", bar: "bg-amber-500" },
];

function Overview() {
  const q = useQuery({
    queryKey: ["admin-overview"],
    queryFn: () => getJSON<Overview>("/admin/overview"),
    staleTime: 60_000,
  });
  if (q.isPending)
    return (
      <p className="flex items-center gap-2 text-xs text-neutral-600 dark:text-neutral-500">
        <Loader2 className="h-3 w-3 animate-spin" /> 개요 불러오는 중…
      </p>
    );
  if (q.isError || !q.data) return null;
  const d = q.data;
  const maxAct = Math.max(1, ...ACTIVITY_BARS.map((b) => d.activity[b.key]));
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-3">
        <StatCard label="총 이용자" value={d.totalUsers} tint="text-sky-700 dark:text-sky-300" />
        <StatCard label="최근 7일 신규" value={d.newUsers7d} tint="text-emerald-700 dark:text-emerald-300" />
        <StatCard label="최근 7일 로그인" value={d.logins7d} tint="text-violet-700 dark:text-violet-300" />
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-surface-1">
          <p className="mb-3 text-xs font-semibold text-neutral-700 dark:text-neutral-300">
            활동 분포 (누적)
          </p>
          <div className="space-y-2">
            {ACTIVITY_BARS.map((b) => {
              const v = d.activity[b.key];
              return (
                <div key={b.key} className="flex items-center gap-2 text-[11px]">
                  <span className="w-14 shrink-0 text-neutral-600 dark:text-neutral-400">{b.label}</span>
                  <div className="h-2.5 flex-1 overflow-hidden rounded-full bg-neutral-200 dark:bg-neutral-800">
                    <div
                      className={cn("h-full rounded-full", b.bar)}
                      style={{ width: `${Math.max((v / maxAct) * 100, v > 0 ? 4 : 0)}%` }}
                    />
                  </div>
                  <span className="w-12 shrink-0 text-right tabular-nums font-medium text-neutral-900 dark:text-neutral-100">
                    {v.toLocaleString("ko-KR")}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        <VisitTrend visits={d.visits} />
      </div>
    </div>
  );
}

function VisitTrend({ visits }: { visits: Overview["visits"] }) {
  const daily = visits?.daily ?? [];
  const maxTotal = Math.max(1, ...daily.map((x) => x.total));
  return (
    <div className="rounded-xl border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-surface-1">
      <div className="mb-1 flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
        <p className="text-xs font-semibold text-neutral-700 dark:text-neutral-300">
          방문 추이 (최근 7일 · 순방문자)
        </p>
        <span className="text-[11px] text-neutral-500 dark:text-neutral-500">
          누적{" "}
          <span className="font-semibold tabular-nums text-neutral-900 dark:text-neutral-100">
            {(visits?.total ?? 0).toLocaleString("ko-KR")}
          </span>
        </span>
      </div>
      <div className="mb-2 flex items-center gap-3 text-[10px] text-neutral-500 dark:text-neutral-500">
        <span className="inline-flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded-sm bg-sky-500" /> 회원{" "}
          {(visits?.memberTotal ?? 0).toLocaleString("ko-KR")}
        </span>
        <span className="inline-flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded-sm bg-slate-400 dark:bg-slate-500" /> 비회원{" "}
          {(visits?.anonTotal ?? 0).toLocaleString("ko-KR")}
        </span>
      </div>
      {daily.length === 0 ? (
        <p className="text-[11px] text-neutral-500 dark:text-neutral-500">방문 데이터가 없습니다.</p>
      ) : (
        <div className="space-y-1.5">
          {daily.map((x) => (
            <div key={x.date} className="flex items-center gap-2 text-[11px]">
              <span className="w-8 shrink-0 tabular-nums text-neutral-500 dark:text-neutral-500">
                {mdLabel(x.date)}
              </span>
              <div className="flex h-2.5 flex-1 overflow-hidden rounded-full bg-neutral-200 dark:bg-neutral-800">
                <div
                  className="h-full bg-sky-500"
                  style={{ width: `${(x.member / maxTotal) * 100}%` }}
                />
                <div
                  className="h-full bg-slate-400 dark:bg-slate-500"
                  style={{ width: `${(x.anon / maxTotal) * 100}%` }}
                />
              </div>
              <span className="w-10 shrink-0 text-right tabular-nums font-medium text-neutral-900 dark:text-neutral-100">
                {x.total.toLocaleString("ko-KR")}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value, tint }: { label: string; value: number; tint: string }) {
  return (
    <div className="rounded-xl border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-surface-1">
      <div className="text-[10px] font-semibold uppercase tracking-wider text-neutral-500 dark:text-neutral-500">
        {label}
      </div>
      <div className={cn("mt-1 text-2xl font-bold tabular-nums", tint)}>
        {value.toLocaleString("ko-KR")}
      </div>
    </div>
  );
}

// ─── 모달 ────────────────────────────────────────────────
function ConsoleModal({ which, onClose }: { which: Which; onClose: () => void }) {
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
        className="relative w-full max-w-4xl rounded-2xl border border-neutral-200 bg-white shadow-2xl shadow-black/20 dark:border-neutral-800 dark:bg-surface-1 dark:shadow-black/50 animate-in zoom-in-95 duration-150"
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
        <div className="max-h-[72vh] overflow-y-auto px-5 py-4">
          {which === "users" && <UserManagementPanel />}
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
  if (q.isPending || q.isError || items.length === 0) return <FeedState q={q} empty={items.length === 0} />;
  return (
    <ul className="space-y-1.5">
      {items.map((l) => {
        const browser = l.browserName ? `${l.browserName}${l.browserVersion ? " " + l.browserVersion : ""}` : null;
        const os = l.osName ? `${l.osName}${l.osVersion ? " " + l.osVersion : ""}` : null;
        return (
          <li key={l.id} className="flex flex-wrap items-center gap-x-2 gap-y-1 rounded-lg border border-neutral-200 px-3 py-2 text-xs dark:border-neutral-800">
            <span className="font-medium text-neutral-900 dark:text-neutral-100">{l.userLabel || "(삭제된 사용자)"}</span>
            {l.deviceKind && (
              <span className={cn("rounded-full px-1.5 py-px text-[9px] font-medium", deviceTone(l.deviceKind))}>{l.deviceKind}</span>
            )}
            {browser && (
              <span className="rounded-full bg-violet-100 px-1.5 py-px text-[9px] font-medium text-violet-800 dark:bg-violet-500/15 dark:text-violet-200">{browser}</span>
            )}
            {os && (
              <span className="rounded-full bg-amber-100 px-1.5 py-px text-[9px] font-medium text-amber-800 dark:bg-amber-500/15 dark:text-amber-200">{os}</span>
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

const ACTIVITY_FILTERS = [
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
    queryFn: () => getJSON<{ items: ActivityLog[] }>(`/admin/activity-logs?limit=150${kind ? `&kind=${kind}` : ""}`),
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
              <span className={cn("shrink-0 rounded-full px-2 py-0.5 text-[10px] font-medium", activityTone(a.kind))}>{a.kindLabel}</span>
              <span className="font-medium text-neutral-800 dark:text-neutral-200">{a.actorLabel || "(삭제된 사용자)"}</span>
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
    queryFn: () => getJSON<{ items: AuditLog[] }>(`/admin/audit/logs?limit=150${action ? `&action=${action}` : ""}`),
    staleTime: 15_000,
  });
  const items = q.data?.items ?? [];
  const actionMap = actionsQ.data?.actions ?? {};
  // 필터 버튼 — 역할 변경/사용자 삭제는 제외(운영상 드물어 노이즈).
  const HIDDEN = new Set(["user.role_change", "user.delete"]);
  const filterOptions = [
    { value: "", label: "전체" },
    ...Object.entries(actionMap)
      .filter(([code]) => !HIDDEN.has(code))
      .map(([value, label]) => ({ value, label })),
  ];
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-1.5">
        {filterOptions.map((f) => (
          <button
            key={f.value}
            type="button"
            onClick={() => setAction(f.value)}
            className={cn(
              "rounded-full border px-2.5 py-0.5 text-[11px] font-medium transition-colors",
              action === f.value
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
          {items.map((l) => (
            <li key={l.id} className="flex flex-wrap items-center gap-x-2 gap-y-1 rounded-lg border border-neutral-200 px-3 py-2 text-xs dark:border-neutral-800">
              <span className={cn("shrink-0 rounded-full px-2 py-0.5 text-[10px] font-medium", auditTone(l.action))}>{l.actionLabel || l.action}</span>
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
