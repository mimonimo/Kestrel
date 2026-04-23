"use client";

import {
  AlertCircle,
  CheckCircle2,
  FlaskConical,
  Loader2,
  Play,
  Square,
  XCircle,
} from "lucide-react";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import {
  ApiError,
  api,
  type SandboxExecResponse,
  type SandboxSession,
} from "@/lib/api";
import { cn } from "@/lib/utils";

function VerdictBadge({ ok, confidence }: { ok: boolean; confidence: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide",
        ok
          ? "border border-emerald-500/40 bg-emerald-500/10 text-emerald-200"
          : "border border-amber-500/40 bg-amber-500/10 text-amber-200",
      )}
    >
      {ok ? <CheckCircle2 className="h-3 w-3" /> : <XCircle className="h-3 w-3" />}
      {ok ? "성공" : "실패"} · {confidence}
    </span>
  );
}

function RunResult({ result }: { result: SandboxExecResponse }) {
  const { adapted, exchange, verdict } = result;
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <VerdictBadge ok={verdict.success} confidence={verdict.confidence} />
        <span className="font-mono text-[11px] text-neutral-500">
          {adapted.method} {adapted.path} ({adapted.location}:{adapted.parameter})
        </span>
        <span className="font-mono text-[11px] text-neutral-500">
          → HTTP {exchange.statusCode}
        </span>
      </div>

      <div>
        <div className="text-[10px] font-semibold uppercase tracking-wider text-neutral-500">
          AI 판정
        </div>
        <p className="mt-1 text-sm text-neutral-200">{verdict.summary}</p>
        {verdict.evidence && (
          <p className="mt-1 text-xs text-neutral-400">근거: {verdict.evidence}</p>
        )}
        {verdict.nextStep && (
          <p className="mt-1 text-xs text-neutral-400">
            다음 시도: {verdict.nextStep}
          </p>
        )}
        <p className="mt-1 text-[10px] uppercase tracking-wide text-neutral-600">
          휴리스틱: {verdict.heuristicSignal}
        </p>
      </div>

      <div>
        <div className="text-[10px] font-semibold uppercase tracking-wider text-neutral-500">
          전송된 페이로드
        </div>
        <pre className="mt-1 overflow-x-auto rounded border border-neutral-800 bg-surface-2 p-2 font-mono text-[11px] text-neutral-100">
          {adapted.payload}
        </pre>
        {adapted.rationale && (
          <p className="mt-1 text-[11px] text-neutral-500">
            적응 근거: {adapted.rationale}
          </p>
        )}
      </div>

      <div>
        <div className="text-[10px] font-semibold uppercase tracking-wider text-neutral-500">
          응답 본문 (앞부분{exchange.bodyTruncated ? ", 잘림" : ""})
        </div>
        <pre className="mt-1 max-h-64 overflow-auto rounded border border-neutral-800 bg-surface-2 p-2 font-mono text-[11px] text-neutral-100">
          {exchange.body || "(빈 응답)"}
        </pre>
      </div>
    </div>
  );
}

export function SandboxPanel({ cveId }: { cveId: string }) {
  const qc = useQueryClient();
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<SandboxExecResponse | null>(null);

  const sessionQuery = useQuery({
    queryKey: ["sandbox-session", sessionId],
    queryFn: () => api.getSandbox(sessionId!),
    enabled: sessionId != null,
    refetchInterval: (q) =>
      q.state.data && q.state.data.status === "running" ? 30_000 : false,
  });

  const start = useMutation({
    mutationFn: () => api.startSandbox({ cveId }),
    onSuccess: (s: SandboxSession) => {
      setSessionId(s.id);
      setLastResult(null);
      qc.setQueryData(["sandbox-session", s.id], s);
    },
  });

  const stop = useMutation({
    mutationFn: () => api.stopSandbox(sessionId!),
    onSuccess: () => {
      setSessionId(null);
      setLastResult(null);
    },
  });

  const exec = useMutation({
    mutationFn: () => api.execSandbox(sessionId!, {}),
    onSuccess: (r: SandboxExecResponse) => {
      setLastResult(r);
      qc.setQueryData(["sandbox-session", r.session.id], r.session);
    },
  });

  const session = sessionQuery.data;
  const startError = start.error as Error | undefined;
  const execError = exec.error as Error | undefined;
  const isKeyMissing =
    (execError instanceof ApiError && execError.status === 400) ||
    (startError instanceof ApiError && startError.status === 400);

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <FlaskConical className="h-4 w-4 text-emerald-400" />
          <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-500">
            취약점 샌드박스
          </h2>
        </div>
        {session && session.status === "running" && (
          <Button
            type="button"
            onClick={() => stop.mutate()}
            disabled={stop.isPending}
            size="md"
            variant="ghost"
            className="text-neutral-400"
          >
            <Square className="mr-1 h-3.5 w-3.5" />
            정지
          </Button>
        )}
      </CardHeader>

      <CardContent className="space-y-4">
        {!session && !start.isPending && !startError && (
          <div className="space-y-2">
            <p className="text-sm text-neutral-400">
              CVE 분류에 맞는 격리된 실습 컨테이너를 띄우고, AI가 만든 페이로드를
              실제 환경에 맞춰 적응시킨 뒤 직접 실행합니다. 컨테이너는 인터넷
              차단된 내부 네트워크에서만 동작하며 30분 후 자동 회수됩니다.
            </p>
            <Button
              type="button"
              onClick={() => start.mutate()}
              size="md"
              className="mt-1"
            >
              <Play className="mr-1.5 h-4 w-4" />
              샌드박스 시작
            </Button>
          </div>
        )}

        {start.isPending && (
          <div className="flex items-center gap-2 py-2 text-sm text-neutral-400">
            <Loader2 className="h-4 w-4 animate-spin text-emerald-400" />
            랩 컨테이너 시작 중…
          </div>
        )}

        {startError && (
          <div className="space-y-1 rounded border border-red-500/30 bg-red-500/10 p-3 text-xs">
            <div className="flex items-center gap-1.5 text-red-300">
              <AlertCircle className="h-3.5 w-3.5" />
              <span className="font-medium">샌드박스 시작 실패</span>
            </div>
            <p className="text-red-200/90">{startError.message}</p>
            {isKeyMissing && (
              <p className="text-red-200/70">
                AI 키가 필요한 단계가 있을 수 있습니다. 설정에서 활성 키를 확인하세요.
              </p>
            )}
          </div>
        )}

        {session && (
          <div className="space-y-3">
            <div className="rounded border border-neutral-800 bg-surface-2 p-3 text-xs">
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={cn(
                    "inline-flex items-center rounded px-2 py-0.5 font-medium uppercase tracking-wide",
                    session.status === "running"
                      ? "bg-emerald-500/15 text-emerald-300"
                      : session.status === "failed"
                      ? "bg-red-500/15 text-red-300"
                      : "bg-neutral-700/40 text-neutral-300",
                  )}
                >
                  {session.status}
                </span>
                <span className="font-mono text-neutral-500">{session.labKind}</span>
                {session.containerName && (
                  <span className="font-mono text-neutral-500">
                    {session.containerName}
                  </span>
                )}
              </div>
              {session.targetUrl && (
                <p className="mt-2 break-all font-mono text-neutral-400">
                  타깃 (내부 전용): {session.targetUrl}
                </p>
              )}
              {session.lab?.injectionPoints && session.lab.injectionPoints.length > 0 && (
                <details className="mt-2">
                  <summary className="cursor-pointer text-neutral-400 hover:text-neutral-200">
                    주입 지점 {session.lab.injectionPoints.length}개
                  </summary>
                  <ul className="mt-2 space-y-1 font-mono text-[11px] text-neutral-400">
                    {session.lab.injectionPoints.map((ip) => (
                      <li key={ip.name}>
                        {ip.method} {ip.path} ({ip.location}:{ip.parameter}) — {ip.notes}
                      </li>
                    ))}
                  </ul>
                </details>
              )}
              {session.error && (
                <p className="mt-2 text-red-300">오류: {session.error}</p>
              )}
            </div>

            {session.status === "running" && (
              <div className="flex items-center gap-2">
                <Button
                  type="button"
                  onClick={() => exec.mutate()}
                  disabled={exec.isPending}
                  size="md"
                >
                  {exec.isPending ? (
                    <Loader2 className="mr-1.5 h-4 w-4 animate-spin" />
                  ) : (
                    <Play className="mr-1.5 h-4 w-4" />
                  )}
                  AI 페이로드 적응 + 실행
                </Button>
                <span className="text-[11px] text-neutral-500">
                  CVE → 적응 → 전송 → AI 판정까지 한 번에
                </span>
              </div>
            )}

            {execError && (
              <div className="rounded border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-200">
                실행 실패: {execError.message}
              </div>
            )}

            {lastResult && <RunResult result={lastResult} />}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
