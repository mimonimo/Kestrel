"use client";

import Link from "next/link";
import {
  CheckCircle2,
  ExternalLink,
  Loader2,
  RefreshCw,
  Square,
  Sparkles,
  Trash2,
  XCircle,
} from "lucide-react";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  api,
  type LabSourceKind,
  type SandboxSessionSummary,
  type SandboxStatus,
} from "@/lib/api";
import { Button } from "@/components/ui/button";
import { ErrorBox, NoticeBox } from "@/components/ui/feedback-box";
import { cn } from "@/lib/utils";

const SESSIONS_KEY = ["sandbox", "sessions", "settings-list"];

function formatRelative(iso: string | null): string {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  const diffMs = Date.now() - then;
  const past = diffMs >= 0;
  const abs = Math.abs(diffMs);
  const mins = Math.floor(abs / 60_000);
  if (mins < 1) return past ? "방금" : "곧";
  if (mins < 60) return past ? `${mins}분 전` : `${mins}분 후`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return past ? `${hours}시간 전` : `${hours}시간 후`;
  const days = Math.floor(hours / 24);
  return past ? `${days}일 전` : `${days}일 후`;
}

const STATUS_LABEL: Record<SandboxStatus, string> = {
  pending: "대기",
  running: "실행 중",
  stopped: "정지",
  expired: "만료됨",
  failed: "실패",
};

const STATUS_TONE: Record<SandboxStatus, string> = {
  pending: "border-neutral-700 bg-neutral-700/30 text-neutral-700 dark:text-neutral-300",
  running: "border-emerald-500/40 bg-emerald-500/10 text-emerald-800 dark:text-emerald-200",
  stopped: "border-neutral-700 bg-neutral-50 dark:bg-surface-2 text-neutral-400",
  expired: "border-amber-500/40 bg-amber-500/10 text-amber-800 dark:text-amber-200",
  failed: "border-rose-500/40 bg-rose-500/10 text-rose-800 dark:text-rose-200",
};

const SOURCE_LABEL: Record<LabSourceKind, string> = {
  vulhub: "vulhub",
  generic: "표준",
  synthesized: "AI 합성",
};

export function SandboxSessionsPanel() {
  const qc = useQueryClient();
  const [includeStopped, setIncludeStopped] = useState(false);

  const sessions = useQuery({
    queryKey: [...SESSIONS_KEY, includeStopped],
    queryFn: () => api.listSandboxSessions({ includeStopped, limit: 50 }),
    staleTime: 10_000,
    refetchInterval: 30_000,
  });

  const stop = useMutation({
    mutationFn: (id: string) => api.stopSandbox(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: SESSIONS_KEY }),
  });

  const reap = useMutation({
    mutationFn: () => api.reapSandboxSessions(),
    onSuccess: () => qc.invalidateQueries({ queryKey: SESSIONS_KEY }),
  });

  const sync = useMutation({
    mutationFn: () => api.syncVulhub(),
    onSuccess: () => qc.invalidateQueries({ queryKey: SESSIONS_KEY }),
  });

  if (sessions.isLoading) {
    return (
      <div className="flex items-center gap-2 text-sm text-neutral-500">
        <Loader2 className="h-4 w-4 animate-spin" /> 세션 목록을 불러오는 중…
      </div>
    );
  }

  if (sessions.error) {
    return (
      <ErrorBox
        title="세션 목록을 불러오지 못했습니다"
        message={(sessions.error as Error).message}
        size="sm"
        actions={
          <Button size="sm" variant="ghost" onClick={() => sessions.refetch()}>
            <RefreshCw className="mr-1 h-3 w-3" /> 다시 시도
          </Button>
        }
      />
    );
  }

  const data = sessions.data;
  if (!data) return null;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-neutral-200 dark:border-neutral-800 bg-white dark:bg-surface-1 px-3 py-2 text-xs">
        <div className="flex flex-wrap items-center gap-3 text-neutral-400">
          <span>
            현재 실행 중{" "}
            <span className="font-semibold text-emerald-700 dark:text-emerald-300">{data.runningCount}</span>개
          </span>
          <span>
            목록 표시 <span className="text-neutral-800 dark:text-neutral-200">{data.total}</span>개
          </span>
          <label className="flex cursor-pointer items-center gap-1.5 text-neutral-400 hover:text-neutral-800 dark:hover:text-neutral-200">
            <input
              type="checkbox"
              checked={includeStopped}
              onChange={(e) => setIncludeStopped(e.target.checked)}
              className="h-3.5 w-3.5 accent-sky-500"
            />
            정지·만료된 세션도 보기
          </label>
        </div>
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="outline"
            disabled={sessions.isFetching}
            onClick={() => sessions.refetch()}
          >
            <RefreshCw className={cn("mr-1 h-3.5 w-3.5", sessions.isFetching && "animate-spin")} />
            새로고침
          </Button>
          <Button
            size="sm"
            variant="outline"
            disabled={reap.isPending}
            onClick={() => reap.mutate()}
            title="만료 시각이 지난 세션을 즉시 정리합니다."
          >
            <Trash2 className={cn("mr-1 h-3.5 w-3.5", reap.isPending && "animate-pulse")} />
            만료 세션 정리
          </Button>
        </div>
      </div>

      {reap.data && (
        <NoticeBox
          title={
            reap.data.reaped > 0
              ? `${reap.data.reaped}개 세션이 정리되었습니다`
              : "정리할 세션이 없습니다 — 모두 유효한 상태입니다"
          }
          message=""
          size="sm"
        />
      )}

      {data.items.length === 0 ? (
        <div className="rounded-lg border border-dashed border-neutral-700 bg-white dark:bg-surface-1 p-6 text-center text-xs text-neutral-500">
          {includeStopped
            ? "표시할 세션이 없습니다."
            : "현재 실행 중인 샌드박스 세션이 없습니다."}
        </div>
      ) : (
        <ul className="divide-y divide-neutral-800 overflow-hidden rounded-lg border border-neutral-200 dark:border-neutral-800">
          {data.items.map((item) => (
            <SessionRow
              key={item.id}
              item={item}
              onStop={() => stop.mutate(item.id)}
              stopping={stop.isPending && stop.variables === item.id}
            />
          ))}
        </ul>
      )}

      <div className="space-y-2 border-t border-neutral-200 dark:border-neutral-800 pt-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">
              vulhub 공식 환경 동기화
            </h3>
            <p className="mt-0.5 text-xs text-neutral-500">
              vulhub 저장소에서 새로 추가된 공식 재현 환경을 받아와 등록합니다.
              AI 호출 없이 정적 메타데이터만 갱신하므로 안전하게 자주 실행할 수 있습니다.
            </p>
          </div>
          <Button
            size="md"
            variant="outline"
            disabled={sync.isPending}
            onClick={() => sync.mutate()}
          >
            {sync.isPending ? (
              <Loader2 className="mr-1 h-4 w-4 animate-spin" />
            ) : (
              <Sparkles className="mr-1 h-4 w-4" />
            )}
            {sync.isPending ? "동기화 중…" : "지금 동기화"}
          </Button>
        </div>
        {sync.data && (
          <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-800 dark:text-emerald-200">
            <CheckCircle2 className="mr-1 inline h-3 w-3" />
            동기화 완료 — 폴더 {sync.data.foldersScanned}개 검사,{" "}
            {sync.data.upserted}개 환경 갱신, 후보 {sync.data.candidates}개,{" "}
            건너뜀 {sync.data.skipped}개.
            {sync.data.errors.length > 0 && (
              <details className="mt-1">
                <summary className="cursor-pointer text-amber-700 dark:text-amber-300">
                  오류 {sync.data.errors.length}건
                </summary>
                <ul className="mt-1 list-disc space-y-0.5 pl-5 text-amber-800 dark:text-amber-200/80">
                  {sync.data.errors.slice(0, 5).map((e, i) => (
                    <li key={i}>{e}</li>
                  ))}
                  {sync.data.errors.length > 5 && (
                    <li>…외 {sync.data.errors.length - 5}건</li>
                  )}
                </ul>
              </details>
            )}
          </div>
        )}
        {sync.error && (
          <ErrorBox
            title="동기화 실패"
            message={(sync.error as Error).message}
            size="sm"
          />
        )}
      </div>
    </div>
  );
}

function SessionRow({
  item,
  onStop,
  stopping,
}: {
  item: SandboxSessionSummary;
  onStop: () => void;
  stopping: boolean;
}) {
  const stoppable = item.status === "running" || item.status === "pending";
  return (
    <li className="flex flex-wrap items-center gap-3 bg-white dark:bg-surface-1 px-3 py-2.5 text-xs">
      <span
        className={cn(
          "inline-flex shrink-0 items-center gap-1 rounded border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide",
          STATUS_TONE[item.status],
        )}
      >
        {item.status === "failed" ? (
          <XCircle className="h-3 w-3" />
        ) : item.status === "running" ? (
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
        ) : null}
        {STATUS_LABEL[item.status]}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          {item.cveId ? (
            <Link
              href={`/cve/${item.cveId}`}
              className="inline-flex items-center gap-1 font-mono text-sm text-neutral-900 dark:text-neutral-100 hover:text-sky-700 dark:hover:text-sky-300 hover:underline"
              title="이 세션이 연결된 CVE 상세 페이지로 이동"
            >
              {item.cveId}
              <ExternalLink className="h-3 w-3" />
            </Link>
          ) : (
            <span className="font-mono text-sm text-neutral-500">CVE 정보 없음</span>
          )}
          <span className="rounded border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-surface-2 px-1.5 py-0.5 text-[10px] text-neutral-400">
            {SOURCE_LABEL[item.labSource]}
          </span>
          <span className="font-mono text-[10px] text-neutral-500">{item.labKind}</span>
        </div>
        <div className="mt-1 flex flex-wrap items-center gap-3 text-[11px] text-neutral-500">
          <span>시작 {formatRelative(item.createdAt)}</span>
          {item.expiresAt && item.status === "running" && (
            <span>만료 {formatRelative(item.expiresAt)}</span>
          )}
          {item.containerName && (
            <span className="font-mono">{item.containerName}</span>
          )}
        </div>
        {item.error && (
          <p className="mt-1 break-words text-[11px] text-rose-700 dark:text-rose-300">{item.error}</p>
        )}
      </div>
      {stoppable && (
        <Button
          size="sm"
          variant="ghost"
          onClick={onStop}
          disabled={stopping}
          className="text-rose-700 dark:text-rose-300 hover:bg-rose-500/10"
        >
          {stopping ? (
            <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />
          ) : (
            <Square className="mr-1 h-3.5 w-3.5" />
          )}
          정지
        </Button>
      )}
    </li>
  );
}
