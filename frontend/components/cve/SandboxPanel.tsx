"use client";

import {
  AlertCircle,
  CheckCircle2,
  Circle,
  FlaskConical,
  Loader2,
  Play,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Square,
  ThumbsDown,
  ThumbsUp,
  XCircle,
} from "lucide-react";
import { useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import {
  ApiError,
  api,
  isNoLabDetail,
  type LabFeedbackResponse,
  type LabSourceKind,
  type NoLabDetail,
  type SandboxExecResponse,
  type SandboxSession,
  type SynthesizePhase,
  type SynthesizeStreamEvent,
} from "@/lib/api";
import { cn } from "@/lib/utils";

// Friendly labels keyed by phase. Order matters when we render the *expected*
// timeline ahead of any real events — we pre-fill an empty checklist and let
// arrived events tick boxes off as they come in.
const PHASE_LABEL: Record<SynthesizePhase, string> = {
  start: "준비",
  cached_hit: "기존 검증된 캐시 발견",
  cooldown: "최근 실패로 24시간 cooldown 중",
  call_llm: "LLM 호출 (Dockerfile + 앱 코드 + 페이로드 생성)",
  parsed: "AI 응답 파싱 + 스키마 검증",
  build_started: "docker 이미지 빌드",
  build_done: "이미지 빌드 완료",
  lab_started: "검증 컨테이너 기동",
  verifying: "페이로드 전송 + 응답 확인",
  verify_failed: "응답 본문에서 success_indicator 찾지 못함",
  verify_ok: "취약점 트리거 확인됨",
  cached: "매핑 row 캐시 — 다음 호출은 즉시 사용",
  failed: "실패",
};

// Default timeline shown before any events arrive. cached_hit / cooldown are
// short-circuit terminals — they replace the timeline at runtime, not part of
// the happy path.
const DEFAULT_TIMELINE: SynthesizePhase[] = [
  "start",
  "call_llm",
  "parsed",
  "build_started",
  "build_done",
  "lab_started",
  "verify_ok",
  "cached",
];

interface SynthLogEntry {
  phase: SynthesizePhase;
  message: string;
  ts: number;
}

function SourceBadge({
  source,
  verified,
}: {
  source: LabSourceKind;
  verified: boolean;
}) {
  // Three flavors of provenance — UI distinguishes "검증된 vulhub reproducer"
  // (highest trust) from a "일반 클래스" lab and from an AI-synthesized one.
  const map: Record<
    LabSourceKind,
    { label: string; cls: string; Icon: typeof ShieldCheck }
  > = {
    vulhub: {
      label: "vulhub reproducer",
      cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-200",
      Icon: ShieldCheck,
    },
    generic: {
      label: "일반 클래스 lab",
      cls: "border-neutral-600 bg-neutral-700/30 text-neutral-300",
      Icon: FlaskConical,
    },
    synthesized: {
      label: "AI 생성 lab",
      cls: "border-amber-500/40 bg-amber-500/10 text-amber-200",
      Icon: Sparkles,
    },
  };
  const m = map[source];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide",
        m.cls,
      )}
      title={
        verified
          ? "이전 실행에서 페이로드가 동작함이 확인됨 (캐시 보유)"
          : "아직 검증되지 않은 lab — 첫 exec에서 결과를 확인하세요"
      }
    >
      <m.Icon className="h-3 w-3" />
      {m.label}
      {verified && <span className="ml-0.5 text-emerald-300">· 검증됨</span>}
    </span>
  );
}

// Friendly per-class label + tinted chip for the generic LAB_CATALOG kinds.
// The raw labKind string still appears (font-mono) for the operator who
// needs to grep image tags / docker ps; the chip is for the reader who
// just wants to know "what kind of lab am I in".
const LAB_KIND_META: Record<
  string,
  { label: string; cls: string }
> = {
  xss: {
    label: "XSS · 입력 reflect",
    cls: "border-rose-500/40 bg-rose-500/10 text-rose-200",
  },
  rce: {
    label: "RCE · 셸 명령 실행",
    cls: "border-red-500/40 bg-red-500/10 text-red-200",
  },
  sqli: {
    label: "SQLi · 쿼리 합성",
    cls: "border-orange-500/40 bg-orange-500/10 text-orange-200",
  },
  ssti: {
    label: "SSTI · 템플릿 평가",
    cls: "border-purple-500/40 bg-purple-500/10 text-purple-200",
  },
  "path-traversal": {
    label: "Path Traversal · 임의 파일 읽기",
    cls: "border-cyan-500/40 bg-cyan-500/10 text-cyan-200",
  },
  ssrf: {
    label: "SSRF · 외부 URL fetch",
    cls: "border-blue-500/40 bg-blue-500/10 text-blue-200",
  },
  "auth-bypass": {
    label: "Auth Bypass · 권한 우회",
    cls: "border-yellow-500/40 bg-yellow-500/10 text-yellow-200",
  },
  xxe: {
    label: "XXE · XML 외부 엔티티",
    cls: "border-teal-500/40 bg-teal-500/10 text-teal-200",
  },
  "open-redirect": {
    label: "Open Redirect · URL 우회",
    cls: "border-indigo-500/40 bg-indigo-500/10 text-indigo-200",
  },
  deserialization: {
    label: "Deserialization · pickle/object 주입",
    cls: "border-fuchsia-500/40 bg-fuchsia-500/10 text-fuchsia-200",
  },
};

function LabKindBadge({ labKind }: { labKind: string }) {
  // Synthesized labs have ``synthesized/<cve>/<sha>`` shape; vulhub labs
  // use the vulhub directory path. Generic catalog labs are bare kind
  // strings — we only friendly-label the latter.
  if (!labKind || labKind.includes("/")) return null;
  const meta = LAB_KIND_META[labKind.toLowerCase()];
  if (!meta) return null;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[10px] font-medium tracking-wide",
        meta.cls,
      )}
      title={`generic lab class: ${labKind}`}
    >
      {meta.label}
    </span>
  );
}

// Manual best-of-N pivot — operator picks a non-default candidate to
// run against. Hidden when there's only one (or zero) verified candidate;
// the auto-pick is then trivially "the only one".
function CandidatePivotList({
  cveId,
  currentMappingId,
  pinning,
  onPick,
}: {
  cveId: string;
  currentMappingId: number | null;
  pinning: boolean;
  onPick: (mappingId: number) => void;
}) {
  const [open, setOpen] = useState(false);
  const list = useQuery({
    queryKey: ["sandbox", "synth-candidates", cveId],
    queryFn: () => api.getSynthCandidates(cveId),
    staleTime: 15_000,
    enabled: open,
  });

  // Don't even render the toggle until we know there's >1 verified.
  // Use a quick probe by always-on cheap query? No — defer until panel
  // is open. Show toggle unconditionally as long as a session exists;
  // empty list inside collapses the body.
  return (
    <div className="mt-2 rounded border border-neutral-800 bg-surface-2/40">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center justify-between gap-2 px-3 py-2 text-left text-xs text-neutral-300 hover:text-neutral-100"
      >
        <span>합성 후보 목록 — 다른 후보로 시작</span>
        <span className="text-neutral-500">{open ? "▴" : "▾"}</span>
      </button>
      {open && (
        <div className="border-t border-neutral-800 px-3 py-2">
          {list.isLoading && (
            <p className="text-xs text-neutral-500">조회 중…</p>
          )}
          {list.error && (
            <p className="text-xs text-amber-300">
              조회 실패: {(list.error as Error).message}
            </p>
          )}
          {list.data && list.data.candidates.length === 0 && (
            <p className="text-xs text-neutral-500">합성 후보 없음.</p>
          )}
          {list.data && list.data.candidates.length > 0 && (
            <ul className="space-y-1.5">
              {list.data.candidates.map((c) => {
                const isCurrent = c.mappingId === currentMappingId;
                const sha = c.labKind.split("/").pop() ?? c.labKind;
                return (
                  <li
                    key={c.mappingId}
                    className={cn(
                      "flex items-center justify-between gap-3 rounded px-2 py-1.5 text-xs",
                      isCurrent
                        ? "bg-amber-500/15 text-amber-100"
                        : "bg-surface-1 text-neutral-300",
                    )}
                  >
                    <div className="flex min-w-0 flex-col gap-0.5">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[10px] text-neutral-400">
                          #{c.rank}
                        </span>
                        <span className="font-mono text-[10px] text-neutral-500">
                          {sha}
                        </span>
                        {c.isPlaceholder && (
                          <span className="rounded border border-neutral-700 px-1.5 text-[9px] text-neutral-500">
                            placeholder
                          </span>
                        )}
                        {!c.isPlaceholder && c.verified && (
                          <span className="rounded border border-emerald-500/40 bg-emerald-500/10 px-1.5 text-[9px] text-emerald-200">
                            verified
                          </span>
                        )}
                        {c.degraded && (
                          <span className="rounded border border-rose-500/40 bg-rose-500/10 px-1.5 text-[9px] text-rose-200">
                            degraded
                          </span>
                        )}
                        <span className="text-[10px] text-neutral-500">
                          👍{c.feedbackUp} 👎{c.feedbackDown}
                        </span>
                      </div>
                      {c.digest && (
                        <span className="truncate text-[10px] text-neutral-500">
                          {c.digest}
                        </span>
                      )}
                    </div>
                    {isCurrent ? (
                      <span className="text-[10px] uppercase text-amber-200">사용중</span>
                    ) : c.isPlaceholder || !c.verified ? (
                      <span className="text-[10px] text-neutral-600">실행 불가</span>
                    ) : (
                      <button
                        type="button"
                        disabled={pinning}
                        onClick={() => onPick(c.mappingId)}
                        className="rounded border border-neutral-600 px-2 py-0.5 text-[10px] font-medium text-neutral-200 hover:border-neutral-400 hover:text-neutral-100 disabled:opacity-40"
                      >
                        {pinning ? "…" : "이 후보로 시작"}
                      </button>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}


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
        {adapted.fromCache && (
          <span
            className="inline-flex items-center gap-1 rounded border border-sky-500/40 bg-sky-500/10 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide text-sky-200"
            title="캐시된 known-good 페이로드를 그대로 재생했습니다 (LLM 호출 0회)"
          >
            <RefreshCw className="h-3 w-3" />
            캐시 사용
          </span>
        )}
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

  // Synthesis stream state — lives in the panel because the stream is
  // bidirectional with React state (each event updates the timeline) and
  // outlives any single mutation.
  const [synthLog, setSynthLog] = useState<SynthLogEntry[]>([]);
  const [synthError, setSynthError] = useState<string | null>(null);
  const [synthRunning, setSynthRunning] = useState(false);
  const synthAbort = useRef<AbortController | null>(null);

  const sessionQuery = useQuery({
    queryKey: ["sandbox-session", sessionId],
    queryFn: () => api.getSandbox(sessionId!),
    enabled: sessionId != null,
    refetchInterval: (q) =>
      q.state.data && q.state.data.status === "running" ? 30_000 : false,
  });

  const start = useMutation({
    mutationFn: (opts?: { attemptSynthesis?: boolean; mappingId?: number }) =>
      api.startSandbox({
        cveId,
        attemptSynthesis: opts?.attemptSynthesis,
        mappingId: opts?.mappingId,
      }),
    onSuccess: (s: SandboxSession) => {
      setSessionId(s.id);
      setLastResult(null);
      qc.setQueryData(["sandbox-session", s.id], s);
    },
  });

  const startSynthesis = async () => {
    setSynthLog([]);
    setSynthError(null);
    setSynthRunning(true);
    start.reset();
    const ctrl = new AbortController();
    synthAbort.current = ctrl;
    try {
      await api.streamSynthesizeSandbox(
        { cveId },
        (ev: SynthesizeStreamEvent) => {
          if (ev.event === "step") {
            setSynthLog((prev) => [
              ...prev,
              { phase: ev.data.phase, message: ev.data.message, ts: Date.now() },
            ]);
          } else if (ev.event === "done") {
            if (ev.data.verified) {
              // Synthesis cached the mapping; resolver chain will hit it now
              // without needing the consent flag again.
              start.mutate(undefined);
            } else {
              setSynthError(ev.data.error ?? "합성 실패");
            }
            setSynthRunning(false);
          } else if (ev.event === "error") {
            setSynthError(ev.data.message);
            setSynthRunning(false);
          }
        },
        ctrl.signal,
      );
    } catch (e) {
      if ((e as Error).name === "AbortError") return;
      setSynthError((e as Error).message);
      setSynthRunning(false);
    }
  };

  const cancelSynthesis = () => {
    // Aborts the SSE stream on the client side. Backend keeps running until
    // the synthesis completes — tokens are already spent and we want the row
    // cached, even if the user closed the panel.
    synthAbort.current?.abort();
    synthAbort.current = null;
    setSynthRunning(false);
    setSynthLog([]);
    setSynthError(null);
  };

  const stop = useMutation({
    mutationFn: () => api.stopSandbox(sessionId!),
    onSuccess: () => {
      setSessionId(null);
      setLastResult(null);
    },
  });

  const exec = useMutation({
    mutationFn: (opts?: { force?: boolean }) =>
      api.execSandbox(sessionId!, { forceRegenerate: opts?.force }),
    onSuccess: (r: SandboxExecResponse) => {
      setLastResult(r);
      qc.setQueryData(["sandbox-session", r.session.id], r.session);
    },
  });

  const feedback = useMutation({
    mutationFn: (vote: "up" | "down") =>
      api.submitLabFeedback(sessionId!, { vote }),
    onSuccess: (r: LabFeedbackResponse) => {
      // Patch the cached session in place — saves a round-trip and keeps the
      // toggled-state visible immediately after the click.
      qc.setQueryData(
        ["sandbox-session", sessionId],
        (prev: SandboxSession | undefined) =>
          prev && prev.lab
            ? {
                ...prev,
                lab: {
                  ...prev.lab,
                  feedbackUp: r.feedbackUp,
                  feedbackDown: r.feedbackDown,
                  myVote: r.myVote,
                  degraded: r.degraded,
                },
              }
            : prev,
      );
    },
  });

  const session = sessionQuery.data;
  const startError = start.error as Error | undefined;
  const execError = exec.error as Error | undefined;
  const isKeyMissing =
    (execError instanceof ApiError && execError.status === 400) ||
    (startError instanceof ApiError && startError.status === 400);
  // Backend returns 422 with `{code, canSynthesize, message}` when no
  // curated/generic lab covers this CVE. We render an inline consent prompt
  // (not a modal — keeps the panel layout intact) before spending tokens.
  const noLabDetail: NoLabDetail | null =
    startError instanceof ApiError &&
    startError.status === 422 &&
    isNoLabDetail(startError.detail)
      ? (startError.detail as NoLabDetail)
      : null;

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
              onClick={() => start.mutate(undefined)}
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

        {/* Consent gate: backend says no curated lab exists — invite the user
            to opt into AI synthesis. Hidden once the synthesis stream starts. */}
        {noLabDetail &&
          noLabDetail.code === "no_lab" &&
          noLabDetail.canSynthesize &&
          !synthRunning &&
          synthLog.length === 0 && (
            <div className="space-y-2 rounded border border-amber-500/30 bg-amber-500/10 p-3 text-xs">
              <div className="flex items-center gap-1.5 text-amber-200">
                <Sparkles className="h-3.5 w-3.5" />
                <span className="font-medium">등록된 lab 이 없습니다</span>
              </div>
              <p className="text-amber-100/90">{noLabDetail.message}</p>
              <p className="text-amber-100/60">
                합성은 LLM 토큰을 사용하고 빌드 시간이 걸립니다. 24시간 내 합성에 실패하면
                같은 CVE 에 대해 자동 재시도가 차단됩니다 (캐시 보존).
              </p>
              <div className="flex gap-2 pt-1">
                <Button
                  type="button"
                  onClick={startSynthesis}
                  size="md"
                  className="bg-amber-500 text-black hover:bg-amber-400"
                >
                  <Sparkles className="mr-1.5 h-4 w-4" />
                  AI 합성으로 시도
                </Button>
                <Button
                  type="button"
                  onClick={() => start.reset()}
                  size="md"
                  variant="ghost"
                  className="text-amber-200/70"
                >
                  취소
                </Button>
              </div>
            </div>
          )}

        {/* Degraded gate: existing synthesized lab was voted down enough
            times that the resolver refuses it. Offer fresh re-synthesis. */}
        {noLabDetail &&
          noLabDetail.code === "lab_degraded" &&
          !synthRunning &&
          synthLog.length === 0 && (
            <div className="space-y-2 rounded border border-rose-500/30 bg-rose-500/10 p-3 text-xs">
              <div className="flex items-center gap-1.5 text-rose-200">
                <ShieldAlert className="h-3.5 w-3.5" />
                <span className="font-medium">
                  사용자 평가로 격하된 lab 입니다
                </span>
              </div>
              <p className="text-rose-100/90">{noLabDetail.message}</p>
              <p className="text-rose-100/70">
                현재 평가 — 👍 {noLabDetail.feedbackUp ?? 0} · 👎{" "}
                {noLabDetail.feedbackDown ?? 0}. 이 매핑은 더 이상 자동
                선택되지 않습니다. 새로 합성하면 새 매핑(빈 평가)으로
                대체됩니다.
              </p>
              <div className="flex gap-2 pt-1">
                {noLabDetail.canSynthesize && (
                  <Button
                    type="button"
                    onClick={startSynthesis}
                    size="md"
                    className="bg-amber-500 text-black hover:bg-amber-400"
                  >
                    <Sparkles className="mr-1.5 h-4 w-4" />
                    새로 합성으로 시도
                  </Button>
                )}
                <Button
                  type="button"
                  onClick={() => start.reset()}
                  size="md"
                  variant="ghost"
                  className="text-rose-200/70"
                >
                  취소
                </Button>
              </div>
            </div>
          )}

        {(synthRunning || synthLog.length > 0 || synthError) && (
          <SynthesisTimeline
            log={synthLog}
            running={synthRunning}
            error={synthError}
            onCancel={cancelSynthesis}
            onRetry={startSynthesis}
          />
        )}

        {startError && !noLabDetail && (
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
                <SourceBadge
                  source={session.labSource}
                  verified={session.verified}
                />
                <LabKindBadge labKind={session.labKind} />
                {session.lab && session.lab.candidateCount > 1 && (
                  <span
                    className="inline-flex items-center gap-1 rounded border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-[10px] font-medium tracking-wide text-amber-200"
                    title="동일 CVE 에 대해 합성된 후보 spec 수와 현재 사용 중인 후보 순위 (1=최우수). 👎 로 격하되면 자동으로 다음 후보로 폴백됩니다."
                  >
                    후보 {session.lab.candidateCount}개 중 {session.lab.candidateRank}번째
                  </span>
                )}
                <span className="font-mono text-neutral-500">{session.labKind}</span>
                {session.containerName && (
                  <span className="font-mono text-neutral-500">
                    {session.containerName}
                  </span>
                )}
              </div>
              {session.lab?.digest && (
                <p className="mt-2 flex items-start gap-1.5 text-amber-200/90">
                  <Sparkles className="mt-0.5 h-3 w-3 shrink-0 text-amber-300" />
                  <span>{session.lab.digest}</span>
                </p>
              )}
              {session.lab?.degraded && (
                <p className="mt-2 flex items-start gap-1.5 text-rose-300">
                  <ShieldAlert className="mt-0.5 h-3 w-3 shrink-0" />
                  <span>
                    사용자 평가로 격하된 lab 입니다 — 다음 시작 시 다른 매핑이
                    선택됩니다.
                  </span>
                </p>
              )}
              {session.lab && session.labSource === "synthesized" && (
                <LabFeedbackButtons
                  up={session.lab.feedbackUp}
                  down={session.lab.feedbackDown}
                  myVote={session.lab.myVote}
                  pending={feedback.isPending}
                  onVote={(v) => feedback.mutate(v)}
                />
              )}
              {session.labSource === "synthesized" && (
                <CandidatePivotList
                  cveId={cveId}
                  currentMappingId={session.mappingId}
                  pinning={start.isPending}
                  onPick={(id) => start.mutate({ mappingId: id })}
                />
              )}
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
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  type="button"
                  onClick={() => exec.mutate(undefined)}
                  disabled={exec.isPending}
                  size="md"
                >
                  {exec.isPending ? (
                    <Loader2 className="mr-1.5 h-4 w-4 animate-spin" />
                  ) : (
                    <Play className="mr-1.5 h-4 w-4" />
                  )}
                  {session.verified ? "캐시된 페이로드 재생" : "AI 페이로드 적응 + 실행"}
                </Button>
                {session.verified && (
                  <Button
                    type="button"
                    onClick={() => exec.mutate({ force: true })}
                    disabled={exec.isPending}
                    size="md"
                    variant="ghost"
                    title="캐시 무시하고 LLM에 다시 적응 요청 (다른 기법으로 재시도)"
                  >
                    <RefreshCw className="mr-1.5 h-4 w-4" />
                    재생성
                  </Button>
                )}
                <span className="text-[11px] text-neutral-500">
                  {session.verified
                    ? "이전 실행에서 검증된 페이로드 — LLM 호출 없이 즉시 재생"
                    : "CVE → 적응 → 전송 → AI 판정까지 한 번에"}
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

function SynthesisTimeline({
  log,
  running,
  error,
  onCancel,
  onRetry,
}: {
  log: SynthLogEntry[];
  running: boolean;
  error: string | null;
  onCancel: () => void;
  onRetry: () => void;
}) {
  const seen = new Set(log.map((e) => e.phase));
  // If the backend short-circuited (cooldown / cached_hit), the default
  // timeline doesn't apply — render only the events we received.
  const shortCircuit = seen.has("cooldown") || seen.has("cached_hit");
  const failed = seen.has("failed") || error !== null;
  const verifyFailed = seen.has("verify_failed");
  const phases: SynthesizePhase[] = shortCircuit
    ? log.map((e) => e.phase)
    : DEFAULT_TIMELINE;
  // Latest event the user can see — drives the spinner row.
  const lastSeenIdx = (() => {
    let idx = -1;
    for (let i = 0; i < phases.length; i++) {
      if (seen.has(phases[i])) idx = i;
    }
    return idx;
  })();

  return (
    <div className="space-y-3 rounded border border-amber-500/30 bg-amber-500/5 p-3 text-xs">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5 text-amber-200">
          <Sparkles className="h-3.5 w-3.5" />
          <span className="font-medium">AI 합성 진행 상황</span>
        </div>
        {running && (
          <Button
            type="button"
            onClick={onCancel}
            size="sm"
            variant="ghost"
            className="h-7 px-2 text-amber-200/70"
          >
            연결 끊기
          </Button>
        )}
        {!running && (failed || verifyFailed) && (
          <Button
            type="button"
            onClick={onRetry}
            size="sm"
            variant="ghost"
            className="h-7 px-2 text-amber-200"
          >
            <RefreshCw className="mr-1 h-3 w-3" />
            재시도
          </Button>
        )}
      </div>

      <ul className="space-y-1">
        {phases.map((phase, i) => {
          const entry = log.find((e) => e.phase === phase);
          const done = seen.has(phase);
          const isCurrent = running && i === lastSeenIdx + 1 && !done;
          const isFailedHere = phase === "failed" || phase === "verify_failed";
          return (
            <li key={`${phase}-${i}`} className="flex items-start gap-2">
              <span className="mt-0.5">
                {done ? (
                  isFailedHere ? (
                    <XCircle className="h-3.5 w-3.5 text-rose-400" />
                  ) : (
                    <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                  )
                ) : isCurrent ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-amber-300" />
                ) : (
                  <Circle className="h-3.5 w-3.5 text-neutral-700" />
                )}
              </span>
              <div className="flex-1">
                <div
                  className={cn(
                    "font-medium",
                    done
                      ? isFailedHere
                        ? "text-rose-200"
                        : "text-amber-100"
                      : isCurrent
                        ? "text-amber-200"
                        : "text-neutral-500",
                  )}
                >
                  {PHASE_LABEL[phase] ?? phase}
                </div>
                {entry?.message && (
                  <div
                    className={cn(
                      "mt-0.5 break-words",
                      isFailedHere ? "text-rose-200/80" : "text-amber-100/70",
                    )}
                  >
                    {entry.message}
                  </div>
                )}
              </div>
            </li>
          );
        })}
      </ul>

      {error && (
        <div className="rounded border border-rose-500/30 bg-rose-500/10 p-2 text-rose-200">
          {error}
        </div>
      )}

      {running && (
        <p className="text-[11px] text-amber-200/60">
          빌드 중 연결을 끊어도 백엔드 합성은 계속 진행됩니다 (캐시까지 완료).
        </p>
      )}
    </div>
  );
}

function LabFeedbackButtons({
  up,
  down,
  myVote,
  pending,
  onVote,
}: {
  up: number;
  down: number;
  myVote: "up" | "down" | null;
  pending: boolean;
  onVote: (v: "up" | "down") => void;
}) {
  return (
    <div className="mt-2 flex items-center gap-2 text-[11px] text-neutral-400">
      <span className="uppercase tracking-wide text-neutral-500">
        이 lab 정확도
      </span>
      <button
        type="button"
        onClick={() => onVote("up")}
        disabled={pending}
        className={cn(
          "inline-flex items-center gap-1 rounded border px-1.5 py-0.5 transition",
          myVote === "up"
            ? "border-emerald-500/60 bg-emerald-500/15 text-emerald-200"
            : "border-neutral-700 hover:border-emerald-500/40 hover:text-emerald-200",
          pending && "opacity-50",
        )}
        title="페이로드/주입 지점이 CVE 와 정확히 맞다"
      >
        <ThumbsUp className="h-3 w-3" />
        {up}
      </button>
      <button
        type="button"
        onClick={() => onVote("down")}
        disabled={pending}
        className={cn(
          "inline-flex items-center gap-1 rounded border px-1.5 py-0.5 transition",
          myVote === "down"
            ? "border-rose-500/60 bg-rose-500/15 text-rose-200"
            : "border-neutral-700 hover:border-rose-500/40 hover:text-rose-200",
          pending && "opacity-50",
        )}
        title="잘못된 lab — 다른 CVE를 흉내내거나 동작하지 않음"
      >
        <ThumbsDown className="h-3 w-3" />
        {down}
      </button>
      {myVote && (
        <span className="text-neutral-500">한 번 더 누르면 변경됩니다</span>
      )}
    </div>
  );
}
