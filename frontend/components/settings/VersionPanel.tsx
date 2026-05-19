"use client";

import { Check, Copy, ExternalLink, Loader2, Terminal } from "lucide-react";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import { ErrorBox } from "@/components/ui/feedback-box";

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

      {/* 업데이트 명령 카드 — terminal block + copy 버튼 */}
      <div className="rounded-xl border border-neutral-200 bg-white p-5 dark:border-neutral-800 dark:bg-surface-1">
        <div className="mb-3 flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-500/15 ring-1 ring-emerald-500/30">
            <Terminal className="h-4 w-4 text-emerald-700 dark:text-emerald-300" />
          </div>
          <div>
            <h4 className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">
              최신 버전으로 업데이트
            </h4>
            <p className="text-[11px] text-neutral-600 dark:text-neutral-500">
              호스트의 저장소 디렉터리에서 실행. 작업 트리에 미커밋 변경이 있으면 안전 중단.
            </p>
          </div>
        </div>

        <div className="flex items-stretch gap-2">
          <code className="flex-1 select-all overflow-x-auto rounded-lg border border-neutral-200 bg-neutral-50 px-3 py-2 font-mono text-[12px] leading-6 text-emerald-700 dark:border-neutral-800 dark:bg-surface-2 dark:text-emerald-300">
            {UPDATE_COMMAND}
          </code>
          <button
            type="button"
            onClick={onCopy}
            className="inline-flex shrink-0 items-center gap-1 rounded-lg border border-neutral-300 px-3 text-[11px] text-neutral-700 transition-colors hover:border-neutral-400 hover:bg-neutral-50 hover:text-neutral-900 dark:border-neutral-700 dark:text-neutral-300 dark:hover:border-neutral-500 dark:hover:bg-surface-2 dark:hover:text-neutral-100"
          >
            {copied ? (
              <Check className="h-3 w-3 text-emerald-700 dark:text-emerald-400" />
            ) : (
              <Copy className="h-3 w-3" />
            )}
            {copied ? "복사됨" : "복사"}
          </button>
        </div>

        <details className="mt-3 text-neutral-700 dark:text-neutral-500">
          <summary className="cursor-pointer text-[11px] hover:text-neutral-900 dark:hover:text-neutral-300">
            추가 옵션
          </summary>
          <ul className="mt-2 space-y-1 pl-4 font-mono text-[11px]">
            <li>
              <span className="text-neutral-900 dark:text-neutral-300">--reindex-meili</span>{" "}
              <span className="text-neutral-600 dark:text-neutral-500">
                — 검색 인덱스 스키마가 바뀐 릴리스에서 사용
              </span>
            </li>
            <li>
              <span className="text-neutral-900 dark:text-neutral-300">--skip-build</span>{" "}
              <span className="text-neutral-600 dark:text-neutral-500">
                — 의존성 변경 없이 코드만 받았을 때
              </span>
            </li>
            <li>
              <span className="text-neutral-900 dark:text-neutral-300">--no-pull</span>{" "}
              <span className="text-neutral-600 dark:text-neutral-500">
                — 이미 git pull 한 경우 (이미지 재빌드만)
              </span>
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
