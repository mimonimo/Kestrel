"use client";

import { Check, Copy, ExternalLink, Loader2, Terminal } from "lucide-react";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import { ErrorBox } from "@/components/ui/feedback-box";
import { cn } from "@/lib/utils";

const UPDATE_COMMAND = "bash scripts/update.sh";

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

  const [copied, setCopied] = useState(false);
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(UPDATE_COMMAND);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
  };

  if (version.isLoading) {
    return (
      <div className="flex items-center gap-2 text-sm text-neutral-500">
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
                className="inline-flex items-center gap-1 font-mono text-sky-700 dark:text-sky-300 hover:underline"
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
            <span className="font-mono text-neutral-100">
              {data.alembicRevision ?? "—"}
            </span>
          }
          hint={`프로세스 시작: ${formatRelative(data.startedAt)}`}
        />
      </div>

      <div className="rounded-lg border border-neutral-800 bg-surface-2 p-4 text-xs">
        <h4 className="mb-2 flex items-center gap-1.5 text-sm font-semibold text-neutral-100">
          <Terminal className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
          최신 버전으로 업데이트
        </h4>
        <p className="mb-3 text-neutral-400">
          저장소를 클론한 디렉터리에서 아래 한 줄을 실행하면 최신 코드를 받아
          이미지를 재빌드하고 DB 마이그레이션까지 자동으로 적용합니다. 작업
          트리에 커밋되지 않은 변경이 있으면 안전하게 중단됩니다.
        </p>
        <div className="flex items-center gap-2">
          <code className="flex-1 select-all overflow-x-auto rounded border border-neutral-800 bg-neutral-900 px-3 py-2 font-mono text-[12px] text-emerald-700 dark:text-emerald-300">
            {UPDATE_COMMAND}
          </code>
          <button
            type="button"
            onClick={onCopy}
            className="inline-flex items-center gap-1 rounded border border-neutral-700 px-2 py-1.5 text-[11px] text-neutral-300 hover:border-neutral-500 hover:text-neutral-100"
          >
            {copied ? (
              <Check className="h-3 w-3 text-emerald-600 dark:text-emerald-400" />
            ) : (
              <Copy className="h-3 w-3" />
            )}
            {copied ? "복사됨" : "복사"}
          </button>
        </div>
        <details className="mt-3 text-neutral-500">
          <summary className="cursor-pointer hover:text-neutral-300">
            추가 옵션
          </summary>
          <ul className="mt-2 space-y-1 pl-4 font-mono text-[11px]">
            <li>
              <span className="text-neutral-300">--reindex-meili</span> — 검색
              인덱스 스키마가 바뀐 릴리스에서 사용 (기존 문서를 새 스키마로
              재색인)
            </li>
            <li>
              <span className="text-neutral-300">--skip-build</span> — 의존성
              변화 없이 코드만 받았을 때 (이미지 재빌드 생략)
            </li>
            <li>
              <span className="text-neutral-300">--no-pull</span> — 이미 git
              pull 한 경우 (이미지 재빌드만 수행)
            </li>
          </ul>
        </details>
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
    <div className={cn("rounded-md border border-neutral-800 bg-surface-1 p-3")}>
      <div className="text-[11px] uppercase tracking-wide text-neutral-500">
        {label}
      </div>
      <div className="mt-1 text-sm">{value}</div>
      {hint && <div className="mt-1 text-[11px] text-neutral-500">{hint}</div>}
    </div>
  );
}
