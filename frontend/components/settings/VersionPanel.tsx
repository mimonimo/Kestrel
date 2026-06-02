"use client";

import { ExternalLink, Loader2 } from "lucide-react";
import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import { ErrorBox } from "@/components/ui/feedback-box";

function formatRelative(iso: string): string {
  const then = new Date(iso).getTime();
  const diffMs = Date.now() - then;
  if (diffMs < 0) return "방금";
  const mins = Math.floor(diffMs / 60_000);
  if (mins < 1) return "방금";
  if (mins < 60) return `${mins}분 전`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}시간 전`;
  const days = Math.floor(hours / 24);
  return `${days}일 전`;
}

function formatBuildTime(s: string): string {
  if (s === "unknown") return "기록 없음";
  const ts = new Date(s).getTime();
  if (!Number.isFinite(ts)) return s;
  const d = new Date(ts);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function VersionPanel() {
  const version = useQuery({
    queryKey: ["version"],
    queryFn: () => api.getVersion(),
    staleTime: 60_000,
  });

  if (version.isLoading) {
    return (
      <div className="flex items-center gap-2 text-sm text-neutral-600 dark:text-neutral-500">
        <Loader2 className="h-4 w-4 animate-spin" /> 버전 정보를 불러오는 중…
      </div>
    );
  }
  if (version.error) {
    return (
      <ErrorBox
        title="버전 정보를 불러오지 못했습니다"
        message={(version.error as Error).message}
        size="sm"
      />
    );
  }
  const data = version.data;
  if (!data) return null;

  const isUnknownCommit = data.gitCommit === "unknown";

  return (
    <div className="space-y-4">
      {/* Stat 카드 — 다른 분포 패널과 같은 white card surface + tabular-nums hierarchy */}
      <div className="grid gap-3 sm:grid-cols-2">
        <Stat
          label="현재 빌드"
          value={
            isUnknownCommit ? (
              <span className="text-amber-700 dark:text-amber-300">기록 없음 (수동 빌드)</span>
            ) : (
              <a
                href={`https://github.com/mimonimo/Kestrel/commit/${data.gitCommit}`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 font-mono text-sky-700 hover:underline dark:text-sky-300"
              >
                {data.gitCommitShort}
                <ExternalLink className="h-3 w-3" />
              </a>
            )
          }
          hint={`빌드 시각: ${formatBuildTime(data.buildTime)}`}
        />
        <Stat
          label="DB 마이그레이션"
          value={
            <span className="font-mono text-neutral-900 dark:text-neutral-100">
              {data.alembicRevision ?? "—"}
            </span>
          }
          hint={`프로세스 시작: ${formatRelative(data.startedAt)}`}
        />
      </div>
    </div>
  );
}

function Stat({
  label,
  value,
  hint,
}: {
  label: string;
  value: React.ReactNode;
  hint?: string;
}) {
  return (
    <div className="rounded-xl border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-surface-1">
      <div className="text-[10px] font-semibold uppercase tracking-wider text-neutral-600 dark:text-neutral-500">
        {label}
      </div>
      <div className="mt-1.5 text-sm">{value}</div>
      {hint && (
        <div className="mt-1.5 text-[11px] tabular-nums text-neutral-600 dark:text-neutral-500">
          {hint}
        </div>
      )}
    </div>
  );
}
