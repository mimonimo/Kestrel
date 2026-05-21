"use client";

import {
  AlertTriangle,
  Database,
  HardDrive,
  Loader2,
  RefreshCw,
  Search,
  Trash2,
  Zap,
} from "lucide-react";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  api,
  type DbResource,
  type MeiliResource,
  type RedisResource,
  type ResourceActionResponse,
  type TableSize,
} from "@/lib/api";
import { Button } from "@/components/ui/button";
import { ErrorBox, NoticeBox } from "@/components/ui/feedback-box";
import { cn } from "@/lib/utils";

const RESOURCES_KEY = ["resources"];

function formatBytes(n: number | null | undefined): string {
  if (n == null) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  const decimals = i >= 2 ? 1 : 0;
  return `${v.toFixed(decimals)} ${units[i]}`;
}

function formatNumber(n: number | null | undefined): string {
  if (n == null || n < 0) return "—";
  return n.toLocaleString("ko-KR");
}

export function ResourcesPanel() {
  const qc = useQueryClient();
  const resources = useQuery({
    queryKey: RESOURCES_KEY,
    queryFn: () => api.getResources(),
    staleTime: 30_000,
    refetchInterval: 60_000,
  });

  const refresh = () => qc.invalidateQueries({ queryKey: RESOURCES_KEY });

  if (resources.isLoading) {
    return (
      <div className="flex items-center gap-2 text-sm text-neutral-500">
        <Loader2 className="h-4 w-4 animate-spin" /> 자원 현황을 조회하는 중…
      </div>
    );
  }
  if (resources.error) {
    return (
      <ErrorBox
        title="자원 정보를 불러오지 못했습니다"
        message={(resources.error as Error).message}
        actions={
          <Button size="sm" variant="ghost" onClick={() => resources.refetch()}>
            <RefreshCw className="mr-1 h-3 w-3" /> 다시 시도
          </Button>
        }
      />
    );
  }
  const data = resources.data;
  if (!data) return null;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-end">
        <Button
          size="sm"
          variant="outline"
          disabled={resources.isFetching}
          onClick={() => resources.refetch()}
        >
          <RefreshCw
            className={cn("mr-1 h-3.5 w-3.5", resources.isFetching && "animate-spin")}
          />
          새로고침
        </Button>
      </div>

      <DbCard res={data.db} onRefresh={refresh} />
      <RedisCard res={data.redis} onRefresh={refresh} />
      <MeiliCard res={data.meili} onRefresh={refresh} />
    </div>
  );
}

function CardShell({
  icon: Icon,
  title,
  subtitle,
  healthy,
  children,
}: {
  icon: typeof Database;
  title: string;
  subtitle: string;
  healthy: boolean;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-lg border border-neutral-200 dark:border-neutral-800 bg-white dark:bg-surface-1 p-5">
      <header className="mb-4 flex items-start justify-between gap-3">
        <div className="flex items-start gap-3">
          <div
            className={cn(
              "flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ring-1",
              healthy
                ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 ring-emerald-500/30"
                : "bg-rose-500/10 text-rose-700 dark:text-rose-300 ring-rose-500/40",
            )}
          >
            <Icon className="h-4 w-4" />
          </div>
          <div>
            <h2 className="text-base font-semibold text-neutral-900 dark:text-neutral-100">{title}</h2>
            <p className="mt-0.5 text-xs text-neutral-500">{subtitle}</p>
          </div>
        </div>
        <span
          className={cn(
            "inline-flex shrink-0 items-center gap-1 rounded border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide",
            healthy
              ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-800 dark:text-emerald-200"
              : "border-rose-500/40 bg-rose-500/10 text-rose-800 dark:text-rose-200",
          )}
        >
          <span
            className={cn(
              "h-1.5 w-1.5 rounded-full",
              healthy ? "bg-emerald-400" : "bg-rose-400",
            )}
          />
          {healthy ? "정상" : "오류"}
        </span>
      </header>
      {children}
    </section>
  );
}

function StatChip({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-surface-2 px-3 py-2">
      <div className="text-[10px] uppercase tracking-wide text-neutral-500">
        {label}
      </div>
      <div className="mt-0.5 font-mono text-sm text-neutral-900 dark:text-neutral-100">{value}</div>
    </div>
  );
}

function DbCard({ res, onRefresh }: { res: DbResource; onRefresh: () => void }) {
  const analyze = useMutation({
    mutationFn: () => api.analyzeDb(),
    onSuccess: onRefresh,
  });
  return (
    <CardShell
      icon={Database}
      title="PostgreSQL — CVE 데이터베이스"
      subtitle="CVE 본문 / 자산 매핑 / 사용자 평가 등 모든 영구 데이터의 저장소"
      healthy={res.healthy}
    >
      {res.error && (
        <ErrorBox title="DB 조회 오류" message={res.error} size="sm" />
      )}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        <StatChip label="버전" value={res.pgVersion ?? "—"} />
        <StatChip label="DB 총 크기" value={formatBytes(res.dbSizeBytes)} />
        <StatChip label="추적 테이블 수" value={String(res.tableSizes.length)} />
      </div>

      {res.tableSizes.length > 0 && (
        <details className="mt-4 rounded-lg border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-surface-2">
          <summary className="cursor-pointer px-3 py-2 text-xs text-neutral-700 dark:text-neutral-300 hover:text-neutral-900 dark:hover:text-neutral-100">
            테이블별 크기 ({res.tableSizes.length}개)
          </summary>
          <table className="w-full text-xs">
            <thead className="bg-surface-3 text-[10px] uppercase tracking-wide text-neutral-500">
              <tr>
                <th className="px-3 py-1.5 text-left">테이블</th>
                <th className="px-3 py-1.5 text-right">행 수 (추정)</th>
                <th className="px-3 py-1.5 text-right">크기</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-800">
              {res.tableSizes.map((t: TableSize) => (
                <tr key={t.name} className="bg-white dark:bg-surface-1">
                  <td className="px-3 py-1.5 font-mono text-neutral-800 dark:text-neutral-200">
                    {t.name}
                  </td>
                  <td className="px-3 py-1.5 text-right text-neutral-700 dark:text-neutral-300">
                    {formatNumber(t.rows)}
                  </td>
                  <td className="px-3 py-1.5 text-right text-neutral-800 dark:text-neutral-200">
                    {formatBytes(t.totalBytes)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      )}

      <div className="mt-4 space-y-2">
        <ActionRow
          icon={Zap}
          label="통계 갱신 (ANALYZE)"
          description="쿼리 플래너 통계 갱신 · 큰 수집 직후 권장 · 잠금 없음"
          confirmText={null}
          mutation={analyze}
        />
      </div>
    </CardShell>
  );
}

function RedisCard({ res, onRefresh }: { res: RedisResource; onRefresh: () => void }) {
  const flush = useMutation({
    mutationFn: () => api.flushRedis(),
    onSuccess: onRefresh,
  });
  return (
    <CardShell
      icon={HardDrive}
      title="Redis — 캐시 / ETag 저장소"
      subtitle="외부 API 응답 캐시와 수집기 cursor 가 보관되는 단기 저장소"
      healthy={res.healthy}
    >
      {res.error && (
        <ErrorBox title="Redis 조회 오류" message={res.error} size="sm" />
      )}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        <StatChip label="버전" value={res.redisVersion ?? "—"} />
        <StatChip label="사용 중 메모리" value={formatBytes(res.usedMemoryBytes)} />
        <StatChip label="저장된 키" value={formatNumber(res.keyCount)} />
      </div>

      <div className="mt-4 space-y-2">
        <ActionRow
          icon={Trash2}
          label="캐시 비우기 (FLUSHDB)"
          description="모든 캐시 키 삭제 · 잘못된 cursor 로 수집 멈춤 시 복구용"
          confirmText={`Redis 캐시를 모두 비웁니다. 현재 ${formatNumber(res.keyCount)}개의 키가 삭제됩니다. 계속할까요?`}
          mutation={flush}
        />
      </div>
    </CardShell>
  );
}

function MeiliCard({ res, onRefresh }: { res: MeiliResource; onRefresh: () => void }) {
  const drop = useMutation({
    mutationFn: () => api.dropMeiliIndex(),
    onSuccess: onRefresh,
  });
  return (
    <CardShell
      icon={Search}
      title="Meilisearch — 검색 인덱스"
      subtitle="대시보드 검색·정렬·자동완성을 처리하는 인덱스 (Postgres 본문에서 파생)"
      healthy={res.healthy}
    >
      {res.error && (
        <ErrorBox title="Meili 조회 오류" message={res.error} size="sm" />
      )}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        <StatChip label="버전" value={res.meiliVersion ?? "—"} />
        <StatChip label="인덱스 ID" value={res.indexUid} />
        <StatChip label="문서 수" value={formatNumber(res.documentCount)} />
        <StatChip label="저장 용량" value={formatBytes(res.rawSizeBytes)} />
        <StatChip label="총 인덱스 수" value={String(res.indexCount ?? "—")} />
      </div>

      <div className="mt-4 space-y-2">
        <ActionRow
          icon={Trash2}
          label="인덱스 초기화"
          description="검색 인덱스 삭제 · 별도 재색인 명령 필요 · CVE 원본은 안전"
          confirmText={`검색 인덱스를 삭제하시겠습니까? 현재 ${formatNumber(res.documentCount)}개의 문서가 있으며, 재색인 명령을 별도로 실행해야 검색이 다시 동작합니다.`}
          mutation={drop}
          destructive
        />
      </div>
    </CardShell>
  );
}

function ActionRow({
  icon: Icon,
  label,
  description,
  confirmText,
  mutation,
  destructive = false,
}: {
  icon: typeof Zap;
  label: string;
  description: string;
  confirmText: string | null;
  mutation: ReturnType<typeof useMutation<ResourceActionResponse, Error>>;
  destructive?: boolean;
}) {
  const [confirmOpen, setConfirmOpen] = useState(false);
  const onClick = () => {
    if (confirmText && !confirmOpen) {
      setConfirmOpen(true);
      return;
    }
    setConfirmOpen(false);
    mutation.mutate();
  };
  return (
    <div className="rounded-lg border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-surface-2 p-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 text-sm font-medium text-neutral-900 dark:text-neutral-100">
            <Icon
              className={cn(
                "h-4 w-4",
                destructive ? "text-rose-700 dark:text-rose-300" : "text-sky-700 dark:text-sky-300",
              )}
            />
            {label}
          </div>
          <p className="mt-1 text-xs text-neutral-400">{description}</p>
        </div>
        {confirmOpen && confirmText ? (
          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setConfirmOpen(false)}
            >
              취소
            </Button>
            <Button
              size="sm"
              variant="outline"
              className={cn(
                destructive
                  ? "border-rose-500/40 text-rose-800 dark:text-rose-200 hover:bg-rose-500/10"
                  : "border-amber-500/40 text-amber-800 dark:text-amber-200 hover:bg-amber-500/10",
              )}
              onClick={onClick}
            >
              <AlertTriangle className="mr-1 h-3 w-3" /> 확인하고 실행
            </Button>
          </div>
        ) : (
          <Button
            size="sm"
            variant="outline"
            disabled={mutation.isPending}
            onClick={onClick}
            className={cn(
              destructive && "border-rose-500/40 text-rose-800 dark:text-rose-200 hover:bg-rose-500/10",
            )}
          >
            {mutation.isPending ? (
              <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />
            ) : (
              <Icon className="mr-1 h-3.5 w-3.5" />
            )}
            {mutation.isPending ? "실행 중…" : "실행"}
          </Button>
        )}
      </div>
      {confirmOpen && confirmText && (
        <p className="mt-2 rounded border border-amber-500/30 bg-amber-500/10 p-2 text-[11px] text-amber-800 dark:text-amber-200">
          {confirmText}
        </p>
      )}
      {mutation.data && (
        <NoticeBox
          title="완료"
          message={mutation.data.detail}
          size="sm"
          className="mt-2"
        />
      )}
      {mutation.error && (
        <ErrorBox
          title="실패"
          message={(mutation.error as Error).message}
          size="sm"
          className="mt-2"
        />
      )}
    </div>
  );
}
