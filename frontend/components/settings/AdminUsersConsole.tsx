"use client";

import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  ArrowDownWideNarrow,
  ArrowUpNarrowWide,
  CheckSquare,
  ChevronLeft,
  Clock,
  Download,
  Filter,
  Globe,
  ListChecks,
  LogIn,
  ScrollText,
  Loader2,
  Search,
  Square,
  Trash2,
  Users as UsersIcon,
  X,
} from "lucide-react";

import { ApiError } from "@/lib/api";
import { formatRelativeKo } from "@/lib/format";
import { cn } from "@/lib/utils";
import { useBodyScrollLock } from "@/lib/use-body-scroll-lock";
import { UserManagementPanel } from "@/components/settings/UserManagementPanel";

const BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000/api/v1";

async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { credentials: "include", cache: "no-store" });
  if (!res.ok) throw new ApiError(res.status, `불러오지 못했습니다 (${res.status})`);
  return res.json();
}

// ─── 로그 공용: 기간 필터 + CSV 내보내기 ─────────────────
type Period = "all" | "1d" | "7d" | "30d";
const PERIODS: { v: Period; l: string }[] = [
  { v: "all", l: "전체" },
  { v: "1d", l: "오늘" },
  { v: "7d", l: "7일" },
  { v: "30d", l: "30일" },
];
function periodCutoffMs(p: Period): number {
  if (p === "all") return 0;
  const days = p === "1d" ? 1 : p === "7d" ? 7 : 30;
  return Date.now() - days * 86_400_000;
}
function downloadCsv(filename: string, rows: (string | number | null | undefined)[][]): void {
  const esc = (c: string | number | null | undefined) =>
    `"${String(c ?? "").replace(/"/g, '""')}"`;
  const body = rows.map((r) => r.map(esc).join(",")).join("\r\n");
  // BOM 으로 Excel 한글 깨짐 방지.
  const blob = new Blob(["\uFEFF" + body], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// ─── 로그 공용: 정렬 ─────────────────────────────────────
type SortDir = "asc" | "desc";
interface SortOption {
  key: string;
  label: string;
}
// accessors 의 키로 값을 뽑아 정렬. 숫자는 수치, 그 외는 한글 로케일 비교.
function sortRows<T>(
  rows: T[],
  key: string,
  dir: SortDir,
  accessors: Record<string, (r: T) => string | number>,
): T[] {
  const acc = accessors[key];
  if (!acc) return rows;
  const sign = dir === "asc" ? 1 : -1;
  return [...rows].sort((a, b) => {
    const va = acc(a);
    const vb = acc(b);
    if (typeof va === "number" && typeof vb === "number") return (va - vb) * sign;
    return String(va).localeCompare(String(vb), "ko") * sign;
  });
}

// 공용 로그 툴바 — 검색 + 기간 토글 + 건수 + CSV. category 필터칩은 children.
function LogToolbar({
  search,
  onSearch,
  period,
  onPeriod,
  count,
  onCsv,
  placeholder,
  sortOptions,
  sortKey,
  sortDir,
  onSortKey,
  onToggleDir,
  children,
}: {
  search: string;
  onSearch: (v: string) => void;
  period: Period;
  onPeriod: (p: Period) => void;
  count: number;
  onCsv: () => void;
  placeholder: string;
  sortOptions?: SortOption[];
  sortKey?: string;
  sortDir?: SortDir;
  onSortKey?: (k: string) => void;
  onToggleDir?: () => void;
  children?: React.ReactNode;
}) {
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-[180px] flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-neutral-500" />
          <input
            type="search"
            value={search}
            onChange={(e) => onSearch(e.target.value)}
            placeholder={placeholder}
            className="block w-full rounded-full border border-neutral-300 bg-white py-1.5 pl-8 pr-3 text-xs text-neutral-900 placeholder:text-neutral-500 focus:border-sky-500 focus:outline-none focus:ring-2 focus:ring-sky-200 dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-100 dark:focus:ring-sky-500/30"
          />
        </div>
        <div className="inline-flex shrink-0 overflow-hidden rounded-full border border-neutral-300 text-[11px] dark:border-neutral-700">
          {PERIODS.map((p) => (
            <button
              key={p.v}
              type="button"
              onClick={() => onPeriod(p.v)}
              className={cn(
                "px-2 py-1 transition-colors",
                period === p.v
                  ? "bg-sky-100 font-medium text-sky-800 dark:bg-sky-500/20 dark:text-sky-200"
                  : "text-neutral-600 hover:bg-neutral-100 dark:text-neutral-400 dark:hover:bg-surface-3",
              )}
            >
              {p.l}
            </button>
          ))}
        </div>
        {sortOptions && sortOptions.length > 0 && (
          <div className="inline-flex shrink-0 items-center overflow-hidden rounded-full border border-neutral-300 dark:border-neutral-700">
            <select
              value={sortKey}
              onChange={(e) => onSortKey?.(e.target.value)}
              aria-label="정렬 기준"
              className="border-0 bg-white py-1 pl-2 pr-1 text-[11px] text-neutral-700 focus:outline-none dark:bg-surface-2 dark:text-neutral-300"
            >
              {sortOptions.map((o) => (
                <option key={o.key} value={o.key}>
                  {o.label}
                </option>
              ))}
            </select>
            <button
              type="button"
              onClick={onToggleDir}
              title={sortDir === "asc" ? "오름차순 (클릭하면 내림차순)" : "내림차순 (클릭하면 오름차순)"}
              aria-label={sortDir === "asc" ? "오름차순" : "내림차순"}
              className="border-l border-neutral-300 px-1.5 py-1 text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-400 dark:hover:bg-surface-3"
            >
              {sortDir === "asc" ? (
                <ArrowUpNarrowWide className="h-3.5 w-3.5" />
              ) : (
                <ArrowDownWideNarrow className="h-3.5 w-3.5" />
              )}
            </button>
          </div>
        )}
        <span className="shrink-0 text-[11px] tabular-nums text-neutral-600 dark:text-neutral-400">
          {count.toLocaleString("ko-KR")}건
        </span>
        <button
          type="button"
          onClick={onCsv}
          disabled={count === 0}
          title="현재 표시된 로그를 CSV 로 내보내기"
          className="inline-flex shrink-0 items-center gap-1 rounded-full border border-neutral-300 px-2.5 py-1 text-[11px] font-medium text-neutral-700 hover:bg-neutral-100 disabled:opacity-50 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-surface-3"
        >
          <Download className="h-3 w-3" />
          CSV
        </button>
      </div>
      {children && <div className="flex flex-wrap gap-1.5">{children}</div>}
    </div>
  );
}

type Which = "users" | "access" | "activity" | "audit";

const META: Record<Which, { label: string; icon: typeof LogIn }> = {
  users: { label: "이용자 조회·관리", icon: UsersIcon },
  access: { label: "접속 로그", icon: Globe },
  activity: { label: "활동 로그", icon: Activity },
  audit: { label: "감사 로그", icon: ScrollText },
};

export function AdminUsersConsole() {
  const [open, setOpen] = useState<Which | null>(null);
  return (
    <div className="space-y-6">
      <Overview />
      <button
        type="button"
        onClick={() => setOpen("users")}
        className="group flex w-full items-center gap-3 rounded-lg border border-neutral-200 bg-white px-4 py-3 text-left transition-colors hover:border-sky-400 hover:bg-sky-50/40 dark:border-neutral-800 dark:bg-surface-1 dark:hover:border-sky-500/40 dark:hover:bg-surface-2"
      >
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-sky-500/15 text-sky-700 ring-1 ring-sky-500/30 dark:text-sky-300">
          <UsersIcon className="h-4 w-4" />
        </div>
        <div className="min-w-0">
          <p className="text-sm font-medium text-neutral-900 dark:text-neutral-100">
            이용자 조회 및 감사 열기
          </p>
          <p className="text-[11px] text-neutral-500 dark:text-neutral-500">
            이용자 · 접속 로그 · 활동 로그 · 감사 로그 (한 창에서 탭 전환)
          </p>
        </div>
        <span className="ml-auto shrink-0 text-xs text-neutral-400 transition-colors group-hover:text-sky-600 dark:group-hover:text-sky-300">
          열기 →
        </span>
      </button>
      {open && <ConsoleModal initial={open} onClose={() => setOpen(null)} />}
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
function ConsoleModal({ initial, onClose }: { initial: Which; onClose: () => void }) {
  const [tab, setTab] = useState<Which>(initial);
  const { label } = META[tab];
  useBodyScrollLock(true);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
    };
  }, [onClose]);

  if (typeof document === "undefined") return null;
  return createPortal(
    <div
      role="dialog"
      aria-modal="true"
      aria-label={label}
      className="fixed inset-0 z-[60] flex items-start justify-center overflow-y-auto bg-neutral-950/45 px-4 py-10 backdrop-blur-sm animate-in fade-in duration-150"
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div
        className="relative flex max-h-[88vh] w-full max-w-4xl flex-col rounded-2xl border border-neutral-200 bg-white shadow-2xl shadow-black/20 dark:border-neutral-800 dark:bg-surface-1 dark:shadow-black/50 animate-in zoom-in-95 duration-150"
        onClick={(e) => e.stopPropagation()}
      >
        <header className="shrink-0 border-b border-neutral-200 dark:border-neutral-800">
          <div className="flex items-center gap-2 px-5 pt-4">
            <h3 className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">
              이용자 조회 및 감사
            </h3>
            <button
              type="button"
              onClick={onClose}
              aria-label="닫기"
              className="ml-auto inline-flex h-8 w-8 items-center justify-center rounded-full text-neutral-500 transition-colors hover:bg-neutral-100 hover:text-neutral-900 dark:hover:bg-surface-2 dark:hover:text-neutral-100"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
          {/* 탭 — 모달을 닫지 않고 이용자/접속/활동/감사 를 즉시 전환 */}
          <div className="flex gap-0.5 overflow-x-auto px-3 pb-px [-ms-overflow-style:none] [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
            {(Object.keys(META) as Which[]).map((w) => {
              const { label: l, icon: TabIcon } = META[w];
              const active = tab === w;
              return (
                <button
                  key={w}
                  type="button"
                  onClick={() => setTab(w)}
                  className={cn(
                    "inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap border-b-2 px-3 py-2 text-xs font-medium transition-colors",
                    active
                      ? "border-sky-500 text-sky-700 dark:border-sky-400 dark:text-sky-300"
                      : "border-transparent text-neutral-600 hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-neutral-100",
                  )}
                  aria-pressed={active}
                >
                  <TabIcon className="h-3.5 w-3.5" />
                  {l}
                </button>
              );
            })}
          </div>
        </header>
        <div className="flex-1 overflow-y-auto px-5 py-4">
          {tab === "users" && <UserManagementPanel />}
          {tab === "access" && <AccessFeed />}
          {tab === "activity" && <ActivityFeed />}
          {tab === "audit" && <AuditFeed />}
        </div>
      </div>
    </div>,
    document.body,
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

// ─── 접속 로그 (요청 기반: 회원=사용자별 / 비회원=IP별 + 드릴다운) ────────
function deviceTone(kind: string | null): string {
  if (kind === "mobile") return "bg-emerald-100 text-emerald-800 dark:bg-emerald-500/15 dark:text-emerald-200";
  if (kind === "tablet") return "bg-sky-100 text-sky-800 dark:bg-sky-500/15 dark:text-sky-200";
  if (kind === "bot") return "bg-rose-100 text-rose-800 dark:bg-rose-500/15 dark:text-rose-200";
  if (kind === "desktop") return "bg-slate-200 text-slate-800 dark:bg-slate-500/25 dark:text-slate-100";
  return "bg-neutral-200 text-neutral-800 dark:bg-neutral-500/25 dark:text-neutral-100";
}

function relFromEpoch(sec: number): string {
  return formatRelativeKo(new Date(sec * 1000).toISOString());
}

type Drill = { kind: "user" | "ip"; key: string; label: string };

const SUMMARY_SORTS: SortOption[] = [
  { key: "count", label: "요청수" },
  { key: "recent", label: "최근요청" },
  { key: "label", label: "대상" },
  { key: "paths", label: "경로수" },
];
const DRILL_SORTS: SortOption[] = [
  { key: "time", label: "시각" },
  { key: "status", label: "상태" },
  { key: "path", label: "경로" },
  { key: "method", label: "메서드" },
];
const STATUS_FILTERS = [
  { value: "all", label: "전체" },
  { value: "2", label: "2xx" },
  { value: "3", label: "3xx" },
  { value: "4", label: "4xx" },
  { value: "5", label: "5xx" },
] as const;

function AccessFeed() {
  const qc = useQueryClient();
  const [who, setWho] = useState<"member" | "anon">("member");
  const [drill, setDrill] = useState<Drill | null>(null);
  const [search, setSearch] = useState("");
  const [period, setPeriod] = useState<Period>("all");
  const [sumSortKey, setSumSortKey] = useState("count");
  const [sumSortDir, setSumSortDir] = useState<SortDir>("desc");
  const [drillSortKey, setDrillSortKey] = useState("time");
  const [drillSortDir, setDrillSortDir] = useState<SortDir>("desc");
  const [statusFilter, setStatusFilter] = useState<"all" | "2" | "3" | "4" | "5">("all");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [selectMode, setSelectMode] = useState(false);
  // 뷰 전환 시 선택 초기화 — 회원=uid / 비회원=ip 로 키 의미가 달라짐.
  useEffect(() => {
    setSelected(new Set());
    setSelectMode(false);
  }, [who, drill]);

  const summaryQ = useQuery({
    queryKey: ["admin-access-summary", who],
    queryFn: () => {
      const p = new URLSearchParams({ limit: "300" });
      if (who === "member") p.set("group", "user");
      else {
        p.set("group", "ip");
        p.set("who", "anon");
      }
      return getJSON<{ items: AccessSummary[] }>(`/admin/access-summary?${p.toString()}`);
    },
    staleTime: 10_000,
    enabled: !drill,
  });

  const drillQ = useQuery({
    queryKey: ["admin-access-drill", drill?.kind, drill?.key],
    queryFn: () => {
      const p = new URLSearchParams({ limit: "200" });
      if (drill?.kind === "user") p.set("uid", drill.key);
      else if (drill?.kind === "ip") p.set("ip", drill.key);
      return getJSON<{ items: WebAccessLog[] }>(`/admin/web-access-log?${p.toString()}`);
    },
    enabled: !!drill,
    staleTime: 10_000,
  });

  const clearLogs = async () => {
    const scoped = drill
      ? drill.kind === "ip"
        ? `IP ${drill.label}`
        : `${drill.label} 회원`
      : null;
    const msg = scoped
      ? `${scoped} 의 접속 로그만 삭제할까요?`
      : "접속 로그(웹·비회원)를 모두 삭제할까요? 되돌릴 수 없습니다.";
    if (!confirm(msg)) return;
    const p = new URLSearchParams();
    if (drill?.kind === "ip") p.set("ip", drill.key);
    else if (drill?.kind === "user") p.set("uid", drill.key);
    const qs = p.toString();
    await fetch(`${BASE}/admin/access-logs${qs ? `?${qs}` : ""}`, {
      method: "DELETE",
      credentials: "include",
    });
    qc.invalidateQueries({ queryKey: ["admin-access-summary"] });
    qc.invalidateQueries({ queryKey: ["admin-access-drill"] });
  };

  const selField = who === "member" ? "uid" : "ip";
  const selKeyOf = (s: AccessSummary) => (who === "member" ? s.userId || "" : s.ip);
  const toggleSel = (k: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      return next;
    });
  const deleteSelected = async () => {
    if (selected.size === 0) return;
    if (!confirm(`선택한 ${selected.size}건의 접속 로그를 삭제할까요? 되돌릴 수 없습니다.`)) return;
    const p = new URLSearchParams();
    selected.forEach((k) => k && p.append(selField, k));
    await fetch(`${BASE}/admin/access-logs?${p.toString()}`, { method: "DELETE", credentials: "include" });
    setSelected(new Set());
    qc.invalidateQueries({ queryKey: ["admin-access-summary"] });
    qc.invalidateQueries({ queryKey: ["admin-access-drill"] });
  };
  const purgeNoise = async () => {
    if (!confirm("내부 호출·헬스체크 등 노이즈 로그를 정리할까요?")) return;
    await fetch(`${BASE}/admin/access-logs?noise=true`, { method: "DELETE", credentials: "include" });
    qc.invalidateQueries({ queryKey: ["admin-access-summary"] });
    qc.invalidateQueries({ queryKey: ["admin-access-drill"] });
  };

  const allSummary = summaryQ.data?.items ?? [];
  const allDrill = drillQ.data?.items ?? [];
  const cutoff = periodCutoffMs(period);
  const ql = search.trim().toLowerCase();
  const summaryF = allSummary.filter((s) => {
    if (cutoff && s.lastAt > 0 && s.lastAt * 1000 < cutoff) return false;
    if (ql && !`${s.label} ${s.topPath ?? ""} ${s.browserName ?? ""} ${s.osName ?? ""}`.toLowerCase().includes(ql))
      return false;
    return true;
  });
  const summary = sortRows(summaryF, sumSortKey, sumSortDir, {
    count: (s) => s.requestCount,
    recent: (s) => s.lastAt,
    label: (s) => s.label,
    paths: (s) => s.distinctPaths,
  });
  const drillF = allDrill.filter((l) => {
    if (cutoff && l.createdAt * 1000 < cutoff) return false;
    if (statusFilter !== "all" && Math.floor(l.status / 100) !== Number(statusFilter)) return false;
    if (ql && !`${l.method} ${l.status} ${l.path} ${l.ip ?? ""}`.toLowerCase().includes(ql)) return false;
    return true;
  });
  const drillItems = sortRows(drillF, drillSortKey, drillSortDir, {
    time: (l) => l.createdAt,
    status: (l) => l.status,
    path: (l) => l.path,
    method: (l) => l.method,
  });
  const exportCsv = () => {
    const stamp = new Date().toISOString().slice(0, 10);
    if (drill) {
      downloadCsv(`access-${drill.kind}-${stamp}.csv`, [
        ["method", "status", "path", "ip", "시각"],
        ...drillItems.map((l) => [
          l.method,
          l.status,
          l.path,
          l.ip ?? "",
          new Date(l.createdAt * 1000).toISOString(),
        ]),
      ]);
    } else {
      downloadCsv(`access-summary-${who}-${stamp}.csv`, [
        ["대상", "요청수", "경로수", "기기", "브라우저", "최근요청"],
        ...summary.map((s) => [
          s.label,
          s.requestCount,
          s.distinctPaths,
          s.deviceKind ?? "",
          s.browserName ?? "",
          s.lastAt > 0 ? new Date(s.lastAt * 1000).toISOString() : "",
        ]),
      ]);
    }
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        {drill ? (
          <button
            type="button"
            onClick={() => setDrill(null)}
            className="inline-flex items-center gap-1 rounded-full px-2 py-1 text-[11px] text-neutral-500 transition-colors hover:bg-neutral-100 hover:text-sky-700 dark:hover:bg-surface-3 dark:hover:text-sky-300"
          >
            <ChevronLeft className="h-3.5 w-3.5" />
            목록
            <span className="font-mono text-neutral-700 dark:text-neutral-300">· {drill.label}</span>
          </button>
        ) : (
          <div className="inline-flex shrink-0 overflow-hidden rounded-full border border-neutral-300 text-[11px] dark:border-neutral-700">
            {([
              ["member", "회원별"],
              ["anon", "비회원(IP)"],
            ] as const).map(([v, l]) => (
              <button
                key={v}
                type="button"
                onClick={() => setWho(v)}
                className={cn(
                  "px-3 py-1 transition-colors",
                  who === v
                    ? "bg-sky-100 font-medium text-sky-800 dark:bg-sky-500/20 dark:text-sky-200"
                    : "text-neutral-600 hover:bg-neutral-100 dark:text-neutral-400 dark:hover:bg-surface-3",
                )}
                aria-pressed={who === v}
              >
                {l}
              </button>
            ))}
          </div>
        )}

        <div className="ml-auto flex flex-wrap items-center gap-1.5">
          {!drill && selectMode ? (
            <>
              <span className="text-[11px] tabular-nums text-neutral-500 dark:text-neutral-400">
                {selected.size}개 선택
              </span>
              <button
                type="button"
                onClick={() => setSelected(new Set(summary.map(selKeyOf).filter(Boolean)))}
                className="rounded-full px-2.5 py-1 text-[11px] font-medium text-neutral-600 transition-colors hover:bg-neutral-100 dark:text-neutral-400 dark:hover:bg-surface-3"
              >
                전체 선택
              </button>
              <button
                type="button"
                onClick={deleteSelected}
                disabled={selected.size === 0}
                className="inline-flex items-center gap-1 rounded-full bg-rose-600 px-3 py-1 text-[11px] font-medium text-white transition-colors hover:bg-rose-500 disabled:opacity-40"
              >
                <Trash2 className="h-3 w-3" />
                삭제
              </button>
              <button
                type="button"
                onClick={() => {
                  setSelectMode(false);
                  setSelected(new Set());
                }}
                className="rounded-full px-2.5 py-1 text-[11px] font-medium text-neutral-600 transition-colors hover:bg-neutral-100 dark:text-neutral-400 dark:hover:bg-surface-3"
              >
                취소
              </button>
            </>
          ) : (
            <>
              {!drill && (
                <button
                  type="button"
                  onClick={() => setSelectMode(true)}
                  disabled={summary.length === 0}
                  className="inline-flex items-center gap-1 rounded-full border border-neutral-300 px-2.5 py-1 text-[11px] font-medium text-neutral-700 transition-colors hover:bg-neutral-100 disabled:opacity-40 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-surface-3"
                >
                  <ListChecks className="h-3.5 w-3.5" />
                  선택
                </button>
              )}
              {!drill && (
                <button
                  type="button"
                  onClick={purgeNoise}
                  title="내부 호출·헬스체크 등 의미 없는 로그를 정리"
                  className="inline-flex items-center gap-1 rounded-full border border-neutral-300 px-2.5 py-1 text-[11px] font-medium text-neutral-700 transition-colors hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-surface-3"
                >
                  <Filter className="h-3.5 w-3.5" />
                  노이즈 정리
                </button>
              )}
              <button
                type="button"
                onClick={clearLogs}
                className="inline-flex items-center gap-1 rounded-full border border-rose-300 px-2.5 py-1 text-[11px] font-medium text-rose-700 transition-colors hover:bg-rose-50 dark:border-rose-900/50 dark:text-rose-300 dark:hover:bg-rose-950/40"
              >
                <Trash2 className="h-3.5 w-3.5" />
                {drill ? (drill.kind === "ip" ? "이 IP 비우기" : "이 회원 비우기") : "전체 비우기"}
              </button>
            </>
          )}
        </div>
      </div>

      <LogToolbar
        search={search}
        onSearch={setSearch}
        period={period}
        onPeriod={setPeriod}
        count={drill ? drillItems.length : summary.length}
        onCsv={exportCsv}
        placeholder={drill ? "경로·IP·메서드로 검색" : "대상·경로·브라우저로 검색"}
        sortOptions={drill ? DRILL_SORTS : SUMMARY_SORTS}
        sortKey={drill ? drillSortKey : sumSortKey}
        sortDir={drill ? drillSortDir : sumSortDir}
        onSortKey={drill ? setDrillSortKey : setSumSortKey}
        onToggleDir={() =>
          drill
            ? setDrillSortDir((d) => (d === "asc" ? "desc" : "asc"))
            : setSumSortDir((d) => (d === "asc" ? "desc" : "asc"))
        }
      >
        {drill &&
          STATUS_FILTERS.map((f) => (
            <button
              key={f.value}
              type="button"
              onClick={() => setStatusFilter(f.value)}
              className={cn(
                "rounded-full border px-2.5 py-0.5 text-[11px] font-medium transition-colors",
                statusFilter === f.value
                  ? "border-sky-400 bg-sky-100 text-sky-800 dark:border-sky-500/50 dark:bg-sky-500/20 dark:text-sky-200"
                  : "border-neutral-300 text-neutral-600 hover:border-sky-300 hover:text-sky-700 dark:border-neutral-700 dark:text-neutral-400 dark:hover:text-sky-200",
              )}
            >
              {f.label}
            </button>
          ))}
      </LogToolbar>

      {/* 드릴다운: 특정 회원/IP 의 요청 기록 */}
      {drill ? (
        <>
          <FeedState q={drillQ} empty={drillItems.length === 0} />
          {!drillQ.isPending && !drillQ.isError && drillItems.length > 0 && (
            <ul className="space-y-1 font-mono">
              {drillItems.map((l, i) => (
                <li key={i} className="flex flex-wrap items-center gap-x-2 gap-y-0.5 rounded-lg border border-neutral-200 px-3 py-1.5 text-[11px] dark:border-neutral-800">
                  <span className={cn("shrink-0 rounded px-1.5 py-px text-[9px] font-semibold", methodTone(l.method))}>{l.method}</span>
                  <span className={cn("shrink-0 font-semibold tabular-nums", statusTone(l.status))}>{l.status}</span>
                  <span className="min-w-0 flex-1 truncate text-neutral-800 dark:text-neutral-200">{l.path}</span>
                  {l.ip && <span className="shrink-0 tabular-nums text-neutral-500 dark:text-neutral-500">{l.ip}</span>}
                  <span className="shrink-0 tabular-nums text-[10px] text-neutral-500 dark:text-neutral-500">{relFromEpoch(l.createdAt)}</span>
                </li>
              ))}
            </ul>
          )}
        </>
      ) : (
        <>
          <p className="text-[10px] text-neutral-500 dark:text-neutral-500">
            {who === "member"
              ? "회원별 요청 요약 — 행을 누르면 해당 회원의 요청 기록을 봅니다. 시간은 마지막 요청(활동) 기준."
              : "모르는 외부/비회원 IP 별 요청 — 요청 많은 순. 행을 누르면 해당 IP 요청 기록."}
          </p>
          <FeedState q={summaryQ} empty={summary.length === 0} />
          {!summaryQ.isPending && !summaryQ.isError && summary.length > 0 && (
            <ul className="space-y-1.5">
              {summary.map((s) => (
                <li key={s.userId || s.ip} className="flex items-center gap-2">
                  {selectMode && (
                    <button
                      type="button"
                      onClick={() => toggleSel(selKeyOf(s))}
                      aria-label={selected.has(selKeyOf(s)) ? "선택 해제" : "선택"}
                      className="shrink-0"
                    >
                      {selected.has(selKeyOf(s)) ? (
                        <CheckSquare className="h-4 w-4 text-sky-600 dark:text-sky-400" />
                      ) : (
                        <Square className="h-4 w-4 text-neutral-400 dark:text-neutral-600" />
                      )}
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() =>
                      selectMode
                        ? toggleSel(selKeyOf(s))
                        : setDrill(
                            who === "member"
                              ? { kind: "user", key: s.userId || "", label: s.label }
                              : { kind: "ip", key: s.ip, label: s.ip },
                          )
                    }
                    className={cn(
                      "flex w-full flex-wrap items-center gap-x-2 gap-y-1 rounded-lg border px-3 py-2 text-left text-xs transition-colors",
                      selectMode && selected.has(selKeyOf(s))
                        ? "border-sky-400 bg-sky-50/60 ring-1 ring-sky-300 dark:border-sky-500/60 dark:bg-sky-500/10 dark:ring-sky-500/40"
                        : "border-neutral-200 hover:border-sky-300 hover:bg-sky-50/40 dark:border-neutral-800 dark:hover:border-sky-500/40 dark:hover:bg-surface-2",
                    )}
                  >
                    <span className="font-medium text-neutral-900 dark:text-neutral-100">{s.label}</span>
                    {s.deviceKind && (
                      <span className={cn("rounded-full px-1.5 py-px text-[9px] font-medium", deviceTone(s.deviceKind))}>{s.deviceKind}</span>
                    )}
                    {s.browserName && (
                      <span className="rounded-full bg-violet-100 px-1.5 py-px text-[9px] font-medium text-violet-800 dark:bg-violet-500/15 dark:text-violet-200">{s.browserName}</span>
                    )}
                    {s.topPath && (
                      <span className="min-w-0 truncate font-mono text-[10px] text-neutral-500 dark:text-neutral-500">{s.topPath}</span>
                    )}
                    <span className="ml-auto inline-flex shrink-0 items-center gap-2">
                      {s.lastAt > 0 && (
                        <span className="tabular-nums text-[10px] text-neutral-500 dark:text-neutral-500">{relFromEpoch(s.lastAt)}</span>
                      )}
                      <span className={cn("tabular-nums font-semibold", countTone(s.requestCount))}>{s.requestCount.toLocaleString("ko-KR")}건</span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </div>
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

const ACTIVITY_SORTS: SortOption[] = [
  { key: "time", label: "시각" },
  { key: "kind", label: "유형" },
  { key: "actor", label: "사용자" },
];

function ActivityFeed() {
  const [kind, setKind] = useState("");
  const [search, setSearch] = useState("");
  const [period, setPeriod] = useState<Period>("all");
  const [limit, setLimit] = useState(150);
  const [sortKey, setSortKey] = useState("time");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const q = useQuery({
    queryKey: ["admin-activity-logs", kind, limit],
    queryFn: () => getJSON<{ items: ActivityLog[] }>(`/admin/activity-logs?limit=${limit}${kind ? `&kind=${kind}` : ""}`),
    staleTime: 15_000,
  });
  const all = q.data?.items ?? [];
  const cutoff = periodCutoffMs(period);
  const ql = search.trim().toLowerCase();
  const itemsF = all.filter((a) => {
    if (cutoff && new Date(a.createdAt).getTime() < cutoff) return false;
    if (ql && !`${a.kindLabel} ${a.actorLabel ?? ""} ${a.ref ?? ""}`.toLowerCase().includes(ql))
      return false;
    return true;
  });
  const items = sortRows(itemsF, sortKey, sortDir, {
    time: (a) => new Date(a.createdAt).getTime(),
    kind: (a) => a.kindLabel,
    actor: (a) => a.actorLabel ?? "",
  });
  const canMore = all.length >= limit && limit < 300;
  const exportCsv = () =>
    downloadCsv(`activity-logs-${new Date().toISOString().slice(0, 10)}.csv`, [
      ["유형", "사용자", "대상", "시각"],
      ...items.map((a) => [a.kindLabel, a.actorLabel ?? "", a.ref ?? "", a.createdAt]),
    ]);
  return (
    <div className="space-y-3">
      <LogToolbar
        search={search}
        onSearch={setSearch}
        period={period}
        onPeriod={setPeriod}
        count={items.length}
        onCsv={exportCsv}
        placeholder="사용자·대상·유형으로 검색"
        sortOptions={ACTIVITY_SORTS}
        sortKey={sortKey}
        sortDir={sortDir}
        onSortKey={setSortKey}
        onToggleDir={() => setSortDir((d) => (d === "asc" ? "desc" : "asc"))}
      >
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
      </LogToolbar>
      <FeedState q={q} empty={items.length === 0} />
      {!q.isPending && !q.isError && items.length > 0 && (
        <>
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
          {canMore && (
            <button
              type="button"
              onClick={() => setLimit((l) => Math.min(300, l + 150))}
              className="mx-auto block rounded-full border border-neutral-300 px-3 py-1 text-[11px] text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-400 dark:hover:bg-surface-3"
            >
              더 보기
            </button>
          )}
        </>
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

const AUDIT_SORTS: SortOption[] = [
  { key: "time", label: "시각" },
  { key: "action", label: "액션" },
  { key: "actor", label: "행위자" },
];

function AuditFeed() {
  const qc = useQueryClient();
  const [action, setAction] = useState("");
  const [search, setSearch] = useState("");
  const [debounced, setDebounced] = useState("");
  const [period, setPeriod] = useState<Period>("all");
  const [limit, setLimit] = useState(150);
  const [sortKey, setSortKey] = useState("time");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [selectMode, setSelectMode] = useState(false);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const t = setTimeout(() => setDebounced(search.trim()), 300);
    return () => clearTimeout(t);
  }, [search]);
  useEffect(() => {
    setSelected(new Set());
  }, [action, debounced, period]);

  const afterIso = (() => {
    const c = periodCutoffMs(period);
    return c ? new Date(c).toISOString() : "";
  })();
  const actionsQ = useQuery({
    queryKey: ["admin-audit-actions"],
    queryFn: () => getJSON<{ actions: Record<string, string> }>("/admin/audit/actions"),
    staleTime: 5 * 60_000,
  });
  const q = useQuery({
    queryKey: ["admin-audit-logs", action, debounced, afterIso, limit],
    queryFn: () => {
      const p = new URLSearchParams({ limit: String(limit) });
      if (action) p.set("action", action);
      if (debounced) p.set("q", debounced);
      if (afterIso) p.set("after", afterIso);
      return getJSON<{ items: AuditLog[]; total: number }>(`/admin/audit/logs?${p.toString()}`);
    },
    staleTime: 15_000,
  });
  const all = q.data?.items ?? [];
  const total = q.data?.total ?? all.length;
  // 서버에서 action·검색(q)·기간(after) 필터 후 받은 페이지를 화면 정렬만 한다.
  const items = sortRows(all, sortKey, sortDir, {
    time: (l) => new Date(l.createdAt).getTime(),
    action: (l) => l.actionLabel ?? l.action,
    actor: (l) => l.actorLabel ?? "",
  });
  const canMore = all.length < total && limit < 500;

  const toggleSel = (id: number) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  const allChecked = items.length > 0 && items.every((l) => selected.has(l.id));
  const toggleAll = () =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (items.every((l) => next.has(l.id))) items.forEach((l) => next.delete(l.id));
      else items.forEach((l) => next.add(l.id));
      return next;
    });
  const deleteSelected = async () => {
    if (selected.size === 0) return;
    if (!confirm(`선택한 ${selected.size}건의 감사 로그를 삭제할까요? 되돌릴 수 없습니다.`)) return;
    setBusy(true);
    try {
      await fetch(`${BASE}/admin/audit/logs`, {
        method: "DELETE",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ids: Array.from(selected) }),
      });
      setSelected(new Set());
      qc.invalidateQueries({ queryKey: ["admin-audit-logs"] });
    } finally {
      setBusy(false);
    }
  };
  const cleanup = async (days: number) => {
    const scope = action ? `'${actionMap[action] ?? action}' ` : "";
    if (!confirm(`${days}일 이전 ${scope}감사 로그를 모두 정리할까요? 되돌릴 수 없습니다.`)) return;
    setBusy(true);
    try {
      await fetch(`${BASE}/admin/audit/logs/cleanup`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ olderThanDays: days, ...(action ? { action } : {}) }),
      });
      qc.invalidateQueries({ queryKey: ["admin-audit-logs"] });
    } finally {
      setBusy(false);
    }
  };
  const actionMap = actionsQ.data?.actions ?? {};
  // 필터 버튼 — 역할 변경/사용자 삭제는 제외(운영상 드물어 노이즈).
  const HIDDEN = new Set(["user.role_change", "user.delete"]);
  const filterOptions = [
    { value: "", label: "전체" },
    ...Object.entries(actionMap)
      .filter(([code]) => !HIDDEN.has(code))
      .map(([value, label]) => ({ value, label })),
  ];
  const exportCsv = () =>
    downloadCsv(`audit-logs-${new Date().toISOString().slice(0, 10)}.csv`, [
      ["액션", "행위자", "대상", "상세", "IP", "시각"],
      ...items.map((l) => [
        l.actionLabel || l.action,
        l.actorLabel ?? "",
        l.target ?? "",
        l.detail ?? "",
        l.ip ?? "",
        l.createdAt,
      ]),
    ]);
  return (
    <div className="space-y-3">
      <LogToolbar
        search={search}
        onSearch={setSearch}
        period={period}
        onPeriod={setPeriod}
        count={items.length}
        onCsv={exportCsv}
        placeholder="행위자·대상·상세·IP·액션으로 검색"
        sortOptions={AUDIT_SORTS}
        sortKey={sortKey}
        sortDir={sortDir}
        onSortKey={setSortKey}
        onToggleDir={() => setSortDir((d) => (d === "asc" ? "desc" : "asc"))}
      >
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
      </LogToolbar>

      {/* 관리 바 — 선택 삭제 / 기간 정리 */}
      <div className="flex flex-wrap items-center gap-2 rounded-lg border border-neutral-200 bg-neutral-50 px-3 py-2 text-[11px] dark:border-neutral-800 dark:bg-surface-2">
        <button
          type="button"
          onClick={() => {
            setSelectMode((v) => !v);
            setSelected(new Set());
          }}
          className={cn(
            "inline-flex items-center gap-1 rounded-full border px-2.5 py-1 font-medium transition-colors",
            selectMode
              ? "border-sky-400 bg-sky-100 text-sky-800 dark:border-sky-500/50 dark:bg-sky-500/20 dark:text-sky-200"
              : "border-neutral-300 text-neutral-600 hover:text-neutral-900 dark:border-neutral-700 dark:text-neutral-400",
          )}
        >
          <ListChecks className="h-3 w-3" />
          {selectMode ? "선택 취소" : "선택 삭제"}
        </button>
        {selectMode && (
          <button
            type="button"
            disabled={busy || selected.size === 0}
            onClick={deleteSelected}
            className="inline-flex items-center gap-1 rounded-full border border-red-300 px-2.5 py-1 font-medium text-red-700 transition-colors hover:bg-red-50 disabled:opacity-50 dark:border-red-900/50 dark:text-red-300 dark:hover:bg-red-950/40"
          >
            {busy ? <Loader2 className="h-3 w-3 animate-spin" /> : <Trash2 className="h-3 w-3" />}
            선택 {selected.size}건 삭제
          </button>
        )}
        <span className="ml-auto inline-flex items-center gap-1.5 text-neutral-500 dark:text-neutral-500">
          정리:
          {[30, 90, 180].map((d) => (
            <button
              key={d}
              type="button"
              disabled={busy}
              onClick={() => cleanup(d)}
              className="rounded-full border border-neutral-300 px-2 py-0.5 font-medium text-neutral-600 transition-colors hover:border-amber-400 hover:text-amber-700 disabled:opacity-50 dark:border-neutral-700 dark:text-neutral-400 dark:hover:text-amber-300"
              title={`${d}일 이전 ${action ? "해당 액션 " : ""}감사 로그 삭제`}
            >
              {d}일 이전
            </button>
          ))}
        </span>
      </div>

      {selectMode && items.length > 0 && (
        <button
          type="button"
          onClick={toggleAll}
          className="inline-flex items-center gap-1 text-[11px] font-medium text-neutral-600 dark:text-neutral-400"
        >
          {allChecked ? <CheckSquare className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" /> : <Square className="h-3.5 w-3.5" />}
          이 페이지 전체 선택
        </button>
      )}

      <FeedState q={q} empty={items.length === 0} />
      {!q.isPending && !q.isError && items.length > 0 && (
        <>
          <ul className="space-y-1.5">
            {items.map((l) => (
              <li key={l.id} className="flex flex-wrap items-center gap-x-2 gap-y-1 rounded-lg border border-neutral-200 px-3 py-2 text-xs dark:border-neutral-800">
                {selectMode && (
                  <button
                    type="button"
                    onClick={() => toggleSel(l.id)}
                    aria-label={selected.has(l.id) ? "선택 해제" : "선택"}
                    className="shrink-0 text-neutral-400 hover:text-sky-600 dark:hover:text-sky-400"
                  >
                    {selected.has(l.id) ? <CheckSquare className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" /> : <Square className="h-3.5 w-3.5" />}
                  </button>
                )}
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
          {canMore && (
            <button
              type="button"
              onClick={() => setLimit((l) => Math.min(500, l + 150))}
              className="mx-auto block rounded-full border border-neutral-300 px-3 py-1 text-[11px] text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-400 dark:hover:bg-surface-3"
            >
              더 보기
            </button>
          )}
        </>
      )}
    </div>
  );
}

// ─── 웹 접속 로그 (Apache 스타일) ────────────────────────
interface WebAccessLog {
  method: string;
  path: string;
  status: number;
  durationMs: number | null;
  ip: string | null;
  userLabel: string | null;
  deviceKind: string | null;
  createdAt: number; // epoch seconds
}

function methodTone(m: string): string {
  if (m === "GET") return "bg-sky-100 text-sky-800 dark:bg-sky-500/15 dark:text-sky-200";
  if (m === "POST") return "bg-emerald-100 text-emerald-800 dark:bg-emerald-500/15 dark:text-emerald-200";
  if (m === "PUT" || m === "PATCH") return "bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-200";
  if (m === "DELETE") return "bg-rose-100 text-rose-800 dark:bg-rose-500/15 dark:text-rose-200";
  return "bg-slate-200 text-slate-800 dark:bg-slate-500/25 dark:text-slate-100";
}

function statusTone(s: number): string {
  if (s >= 500) return "text-rose-700 dark:text-rose-300";
  if (s >= 400) return "text-amber-700 dark:text-amber-300";
  if (s >= 300) return "text-sky-700 dark:text-sky-300";
  return "text-emerald-700 dark:text-emerald-300";
}

interface AccessSummary {
  ip: string;
  userId: string | null;
  label: string;
  requestCount: number;
  distinctPaths: number;
  isAnon: boolean;
  memberLabels: string[];
  topPath: string | null;
  osName: string | null;
  browserName: string | null;
  deviceKind: string | null;
  lastAt: number;
}

function countTone(n: number): string {
  if (n >= 300) return "text-rose-700 dark:text-rose-300";
  if (n >= 80) return "text-amber-700 dark:text-amber-300";
  return "text-neutral-900 dark:text-neutral-100";
}
