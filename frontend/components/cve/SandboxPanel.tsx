"use client";

import {
  AlertCircle,
  Check,
  CheckCircle2,
  Circle,
  Copy,
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
import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { ErrorBox, FeedbackBoxButton, NoticeBox } from "@/components/ui/feedback-box";
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

// User-facing labels for each synthesis phase. We render the *expected*
// timeline ahead of any real events so the operator can see how long it'll
// take and which step is in flight. Order matters — checklist top→bottom.
const PHASE_LABEL: Record<SynthesizePhase, string> = {
  start: "CVE 정보와 이전 시도 기록을 모으는 중",
  cached_hit: "이미 검증된 실습 환경을 찾았습니다 — 곧바로 사용",
  cooldown: "24시간 안에 같은 CVE 합성이 실패해 잠시 멈춰 있습니다",
  call_llm: "AI가 격리된 실습 환경 명세와 공격 페이로드를 작성 중",
  parsed: "AI가 만든 명세를 검증하고 가짜 응답인지 가려내는 중",
  build_started: "격리된 네트워크 안에 실습 컨테이너 이미지를 만드는 중",
  build_done: "실습 환경 이미지 준비 완료",
  lab_started: "실습 컨테이너를 띄우고 안전한 검증 도구를 연결하는 중",
  verifying: "공격 페이로드를 보내 실제로 취약점이 발현되는지 확인하는 중",
  verify_failed: "취약점이 실제로 발현되지 않았습니다 (가짜 응답 가능성)",
  verify_ok: "검증 통과 — 실제 취약점 발현을 확인했습니다",
  cached: "검증된 실습 환경을 저장 — 다음부터는 즉시 사용 가능합니다",
  failed: "합성 실패 — 모든 후보가 검증을 통과하지 못했습니다",
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
  // 출처별 신뢰도가 다르므로 UI 에서 구분 — 사용자가 "이 환경이 어디서
  // 왔는지" 한눈에 파악할 수 있도록 색·아이콘·라벨을 구분.
  const map: Record<
    LabSourceKind,
    { label: string; cls: string; Icon: typeof ShieldCheck; tip: string }
  > = {
    vulhub: {
      label: "vulhub 공식 재현",
      cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-800 dark:text-emerald-200",
      Icon: ShieldCheck,
      tip: "vulhub 프로젝트가 공식적으로 재현해 둔 환경 — 가장 신뢰도가 높습니다.",
    },
    generic: {
      label: "표준 실습 환경",
      cls: "border-neutral-600 bg-neutral-700/30 text-neutral-700 dark:text-neutral-300",
      Icon: FlaskConical,
      tip: "취약점 유형(예: XSS, RCE)별로 미리 만들어 둔 표준 환경입니다.",
    },
    synthesized: {
      label: "AI 합성 환경",
      cls: "border-amber-500/40 bg-amber-500/10 text-amber-800 dark:text-amber-200",
      Icon: Sparkles,
      tip: "이 CVE 전용으로 AI가 만든 환경 — 결과가 정확하면 👍 로 알려주세요.",
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
          ? `${m.tip} 이전 실행에서 페이로드가 작동함이 확인되어 결과를 즉시 재생합니다.`
          : `${m.tip} 첫 실행에서 실제 발현 여부를 확인합니다.`
      }
    >
      <m.Icon className="h-3 w-3" />
      {m.label}
      {verified && <span className="ml-0.5 text-emerald-700 dark:text-emerald-300">· 검증됨</span>}
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
    cls: "border-rose-500/40 bg-rose-500/10 text-rose-800 dark:text-rose-200",
  },
  rce: {
    label: "RCE · 셸 명령 실행",
    cls: "border-red-500/40 bg-red-500/10 text-red-800 dark:text-red-200",
  },
  sqli: {
    label: "SQLi · 쿼리 합성",
    cls: "border-orange-500/40 bg-orange-500/10 text-orange-800 dark:text-orange-200",
  },
  ssti: {
    label: "SSTI · 템플릿 평가",
    cls: "border-purple-500/40 bg-purple-500/10 text-purple-200",
  },
  "path-traversal": {
    label: "Path Traversal · 임의 파일 읽기",
    cls: "border-cyan-500/40 bg-cyan-500/10 text-cyan-800 dark:text-cyan-200",
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
    cls: "border-fuchsia-500/40 bg-fuchsia-500/10 text-fuchsia-800 dark:text-fuchsia-200",
  },
};

// 인터랙티브 PTY/단발 exec 는 너무 조잡해서 PR 10-O 에서 제거.
// 대신 ContainerAccessHelper 가 사용자가 자기 터미널에서 사용할
// `docker exec -it` 명령을 그대로 보여주고 클립보드 복사 한 번으로
// 진짜 셸에 붙도록 안내. WebSocket PTY 의 모든 헷갈림을 우회.
function ContainerAccessHelper({ containerName }: { containerName: string }) {
  const [copied, setCopied] = useState(false);
  const cmd = `docker exec -it ${containerName} sh`;
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(cmd);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable in insecure contexts; ignore */
    }
  };
  return (
    <div className="mt-3 rounded border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-surface-2 p-3 text-xs">
      <div className="mb-2 flex items-center gap-1.5 text-neutral-700 dark:text-neutral-300">
        <span className="font-medium">컨테이너 접속</span>
        <span className="text-neutral-500">— 호스트 터미널에서 실행</span>
      </div>
      <div className="flex items-center gap-2">
        <code className="flex-1 select-all overflow-x-auto rounded border border-neutral-200 dark:border-neutral-800 bg-neutral-900 px-2 py-1.5 font-mono text-[11px] text-emerald-700 dark:text-emerald-300">
          {cmd}
        </code>
        <button
          type="button"
          onClick={onCopy}
          className="inline-flex items-center gap-1 rounded border border-neutral-700 px-2 py-1 text-[11px] text-neutral-700 dark:text-neutral-300 hover:border-neutral-500 hover:text-neutral-900 dark:hover:text-neutral-100"
        >
          {copied ? <Check className="h-3 w-3 text-emerald-600 dark:text-emerald-400" /> : <Copy className="h-3 w-3" />}
          {copied ? "복사됨" : "복사"}
        </button>
      </div>
      <p className="mt-2 text-[11px] text-neutral-500">
        bash 가 있으면 <span className="font-mono">sh</span> 대신{" "}
        <span className="font-mono">bash</span> 로 바꿔 사용하세요. 컨테이너 종료 시
        세션도 자동으로 닫힙니다.
      </p>
    </div>
  );
}


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
      title={`표준 실습 환경 분류: ${labKind}`}
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
    <div className="mt-2 rounded border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-surface-2/40">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center justify-between gap-2 px-3 py-2 text-left text-xs text-neutral-700 dark:text-neutral-300 hover:text-neutral-900 dark:hover:text-neutral-100"
      >
        <span>다른 합성 환경으로 시작하기</span>
        <span className="text-neutral-500">{open ? "▴" : "▾"}</span>
      </button>
      {open && (
        <div className="border-t border-neutral-200 dark:border-neutral-800 px-3 py-2">
          {list.isLoading && (
            <p className="text-xs text-neutral-500">불러오는 중…</p>
          )}
          {list.error && (
            <p className="text-xs text-amber-700 dark:text-amber-300">
              불러오기 실패: {(list.error as Error).message}
            </p>
          )}
          {list.data && list.data.candidates.length === 0 && (
            <p className="text-xs text-neutral-500">대체할 합성 환경이 없습니다.</p>
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
                        : "bg-white dark:bg-surface-1 text-neutral-700 dark:text-neutral-300",
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
                            준비중
                          </span>
                        )}
                        {!c.isPlaceholder && c.verified && (
                          <span className="rounded border border-emerald-500/40 bg-emerald-500/10 px-1.5 text-[9px] text-emerald-800 dark:text-emerald-200">
                            검증됨
                          </span>
                        )}
                        {c.degraded && (
                          <span className="rounded border border-rose-500/40 bg-rose-500/10 px-1.5 text-[9px] text-rose-800 dark:text-rose-200">
                            정확도 낮음
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
                      <span className="text-[10px] uppercase text-amber-800 dark:text-amber-200">사용중</span>
                    ) : c.isPlaceholder || !c.verified ? (
                      <span className="text-[10px] text-neutral-600">실행 불가</span>
                    ) : (
                      <button
                        type="button"
                        disabled={pinning}
                        onClick={() => onPick(c.mappingId)}
                        className="rounded border border-neutral-600 px-2 py-0.5 text-[10px] font-medium text-neutral-800 dark:text-neutral-200 hover:border-neutral-400 hover:text-neutral-900 dark:hover:text-neutral-100 disabled:opacity-40"
                      >
                        {pinning ? "…" : "이 환경으로 시작"}
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


// ErrorBox / NoticeBox now live in components/ui/feedback-box.tsx so
// every panel renders the same shape. Re-imported below via the named
// imports at the top of this file.


function VerdictBadge({ ok, confidence }: { ok: boolean; confidence: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide",
        ok
          ? "border border-emerald-500/40 bg-emerald-500/10 text-emerald-800 dark:text-emerald-200"
          : "border border-amber-500/40 bg-amber-500/10 text-amber-800 dark:text-amber-200",
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
            className="inline-flex items-center gap-1 rounded border border-sky-500/40 bg-sky-500/10 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide text-sky-800 dark:text-sky-200"
            title="이전에 검증된 페이로드를 그대로 재실행했습니다 — AI 호출 없이 즉시 결과 표시."
          >
            <RefreshCw className="h-3 w-3" />
            저장된 페이로드 재사용
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
          AI 판정 결과
        </div>
        <p className="mt-1 text-sm text-neutral-800 dark:text-neutral-200">{verdict.summary}</p>
        {verdict.evidence && (
          <p className="mt-1 text-xs text-neutral-400">판단 근거: {verdict.evidence}</p>
        )}
        {verdict.nextStep && (
          <p className="mt-1 text-xs text-neutral-400">
            추천 다음 단계: {verdict.nextStep}
          </p>
        )}
        <p className="mt-1 text-[10px] uppercase tracking-wide text-neutral-600">
          자동 분석 신호: {verdict.heuristicSignal}
        </p>
      </div>

      <div>
        <div className="text-[10px] font-semibold uppercase tracking-wider text-neutral-500">
          실제로 보낸 페이로드
        </div>
        <pre className="mt-1 overflow-x-auto rounded border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-surface-2 p-2 font-mono text-[11px] text-neutral-900 dark:text-neutral-100">
          {adapted.payload}
        </pre>
        {adapted.rationale && (
          <p className="mt-1 text-[11px] text-neutral-500">
            AI 가 이 페이로드를 선택한 이유: {adapted.rationale}
          </p>
        )}
      </div>

      <div>
        <div className="text-[10px] font-semibold uppercase tracking-wider text-neutral-500">
          서버 응답 본문 (앞부분{exchange.bodyTruncated ? ", 일부 잘림" : ""})
        </div>
        <pre className="mt-1 max-h-64 overflow-auto rounded border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-surface-2 p-2 font-mono text-[11px] text-neutral-900 dark:text-neutral-100">
          {exchange.body || "(빈 응답)"}
        </pre>
      </div>
    </div>
  );
}

// Per-CVE persisted state — sessionId + lastResult survive navigation
// away & back so the user doesn't lose context. Cleared when the session
// is stopped or expires.
const SESSION_KEY_PREFIX = "kestrel:sandbox-session:";
const RESULT_KEY_PREFIX = "kestrel:sandbox-result:";

function readPersisted<T>(key: string): T | null {
  if (typeof window === "undefined") return null;
  const raw = window.localStorage.getItem(key);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

function writePersisted(key: string, value: unknown): void {
  if (typeof window === "undefined") return;
  if (value == null) {
    window.localStorage.removeItem(key);
  } else {
    window.localStorage.setItem(key, JSON.stringify(value));
  }
}

export function SandboxPanel({ cveId }: { cveId: string }) {
  const qc = useQueryClient();
  const sessionKey = SESSION_KEY_PREFIX + cveId;
  const resultKey = RESULT_KEY_PREFIX + cveId;

  const [sessionId, setSessionId] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<SandboxExecResponse | null>(null);

  // Hydrate from localStorage on mount (per cveId). Defers to next tick
  // so SSR/CSR mismatch doesn't cause hydration warnings.
  useEffect(() => {
    setSessionId(readPersisted<string>(sessionKey));
    setLastResult(readPersisted<SandboxExecResponse>(resultKey));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cveId]);

  // Persist whenever state changes.
  useEffect(() => {
    writePersisted(sessionKey, sessionId);
  }, [sessionKey, sessionId]);
  useEffect(() => {
    writePersisted(resultKey, lastResult);
  }, [resultKey, lastResult]);

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
    retry: false,
  });

  // Stale-session cleanup — persisted sessionId from a previous visit
  // may already be reaped on the server (TTL ~30 min). Clear local state
  // so the panel returns to its "start a new session" form instead of
  // showing a permanent error.
  useEffect(() => {
    const e = sessionQuery.error as ApiError | undefined;
    if (e && e.status === 404 && sessionId) {
      setSessionId(null);
      setLastResult(null);
    }
  }, [sessionQuery.error, sessionId]);

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

  // Manual cooldown reset (PR 10-N) — DELETE the placeholder row that's
  // gating the 24h timer, then immediately re-enter the synthesis flow.
  // Idempotent server-side; UI just clears local state and retries.
  const resetCooldown = async () => {
    try {
      await api.resetSynthCooldown(cveId);
    } catch {
      // Best-effort; if the reset failed (rare) we still try the
      // synthesis — the backend will just answer cooldown again and
      // the user sees the same NoticeBox.
    }
    setSynthLog([]);
    setSynthError(null);
    void startSynthesis();
  };

  // PR 10-S: re-run verify only on the previously-built image. Skips
  // LLM call + docker build, so transient wait_ready/HTTP-500 retries
  // cost zero LLM tokens + ~5s instead of full 60-90s synthesis.
  const resumeVerify = async () => {
    setSynthError(null);
    setSynthRunning(true);
    try {
      const res = await api.resumeSynthVerify(cveId);
      if (res.verified) {
        // Sandbox session can now spawn off the cached mapping
        start.mutate(undefined);
      } else {
        setSynthError(res.error ?? "verify 재개 실패");
      }
    } catch (e) {
      setSynthError((e as Error).message);
    } finally {
      setSynthRunning(false);
    }
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
          <FlaskConical className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
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
              이 CVE 를 안전하게 재현해 볼 수 있는 격리된 실습 환경을 띄웁니다.
              AI가 페이로드를 환경에 맞춰 자동 조정한 뒤 실행해 주므로 별도
              세팅 없이 바로 결과를 확인할 수 있습니다. 환경은 외부 인터넷이
              차단되며 30분 뒤 자동으로 정리됩니다.
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
            <Loader2 className="h-4 w-4 animate-spin text-emerald-600 dark:text-emerald-400" />
            실습 환경 준비 중…
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
              <div className="flex items-center gap-1.5 text-amber-800 dark:text-amber-200">
                <Sparkles className="h-3.5 w-3.5" />
                <span className="font-medium">아직 준비된 실습 환경이 없습니다</span>
              </div>
              <p className="text-amber-100/90">{noLabDetail.message}</p>
              <p className="text-amber-100/60">
                AI에게 이 CVE 전용 환경을 만들어 달라고 요청할 수 있습니다.
                AI 사용량이 발생하고 1~2분 정도 빌드 시간이 걸립니다. 합성에
                실패하면 같은 CVE 에 대해 24시간 동안 재시도가 자동으로
                보류됩니다.
              </p>
              <div className="flex gap-2 pt-1">
                <Button
                  type="button"
                  onClick={startSynthesis}
                  size="md"
                  className="bg-amber-500 text-black hover:bg-amber-400"
                >
                  <Sparkles className="mr-1.5 h-4 w-4" />
                  AI에게 환경 합성 요청
                </Button>
                <Button
                  type="button"
                  onClick={() => start.reset()}
                  size="md"
                  variant="ghost"
                  className="text-amber-800 dark:text-amber-200/70"
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
              <div className="flex items-center gap-1.5 text-rose-800 dark:text-rose-200">
                <ShieldAlert className="h-3.5 w-3.5" />
                <span className="font-medium">
                  다른 사용자들이 부정확하다고 평가한 환경입니다
                </span>
              </div>
              <p className="text-rose-100/90">{noLabDetail.message}</p>
              <p className="text-rose-100/70">
                현재 평가 — 👍 {noLabDetail.feedbackUp ?? 0} · 👎{" "}
                {noLabDetail.feedbackDown ?? 0}. 이 환경은 자동으로 선택되지
                않으며, 새로 합성하면 평가 기록이 비어 있는 새 환경으로
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
                    AI에게 새 환경 합성 요청
                  </Button>
                )}
                <Button
                  type="button"
                  onClick={() => start.reset()}
                  size="md"
                  variant="ghost"
                  className="text-rose-800 dark:text-rose-200/70"
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
            onResetCooldown={resetCooldown}
            onResumeVerify={resumeVerify}
          />
        )}

        {startError && !noLabDetail && (
          <ErrorBox
            title="샌드박스 시작 실패"
            message={startError.message}
            hint={
              isKeyMissing
                ? "AI 키가 필요한 단계가 있을 수 있습니다. 설정에서 활성 키를 확인하세요."
                : undefined
            }
            actions={
              <>
                {isKeyMissing && (
                  <FeedbackBoxButton href="/settings">설정으로 이동</FeedbackBoxButton>
                )}
                <FeedbackBoxButton onClick={() => start.mutate(undefined)}>
                  <RefreshCw className="h-3 w-3" />
                  다시 시도
                </FeedbackBoxButton>
              </>
            }
          />
        )}

        {session && (
          <div className="space-y-3">
            <div className="rounded border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-surface-2 p-3 text-xs">
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={cn(
                    "inline-flex items-center rounded px-2 py-0.5 font-medium uppercase tracking-wide",
                    session.status === "running"
                      ? "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                      : session.status === "failed"
                      ? "bg-rose-500/15 text-rose-700 dark:text-rose-300"
                      : "bg-neutral-700/40 text-neutral-700 dark:text-neutral-300",
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
                    className="inline-flex items-center gap-1 rounded border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-[10px] font-medium tracking-wide text-amber-800 dark:text-amber-200"
                    title="이 CVE 에 대해 AI가 만든 환경이 여러 개 있습니다. 현재 가장 정확하다고 평가된 환경을 사용 중이며, 👎 평가가 쌓이면 다음 후보로 자동 전환됩니다."
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
                <p className="mt-2 flex items-start gap-1.5 text-amber-800 dark:text-amber-200/90">
                  <Sparkles className="mt-0.5 h-3 w-3 shrink-0 text-amber-700 dark:text-amber-300" />
                  <span>{session.lab.digest}</span>
                </p>
              )}
              {session.lab?.degraded && (
                <p className="mt-2 flex items-start gap-1.5 text-rose-700 dark:text-rose-300">
                  <ShieldAlert className="mt-0.5 h-3 w-3 shrink-0" />
                  <span>
                    이 환경은 다른 사용자 평가로 정확도가 낮다고 표시되어
                    있습니다 — 다음 실행 시 다른 환경이 자동 선택됩니다.
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
                  공격 대상 주소 (격리 네트워크 내부 전용): {session.targetUrl}
                </p>
              )}
              {session.lab?.injectionPoints && session.lab.injectionPoints.length > 0 && (
                <details className="mt-2">
                  <summary className="cursor-pointer text-neutral-400 hover:text-neutral-800 dark:hover:text-neutral-200">
                    공격 입력 지점 {session.lab.injectionPoints.length}개
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
              {session.status === "running" && session.containerName && (
                <ContainerAccessHelper containerName={session.containerName} />
              )}
              {session.error && (
                <p className="mt-2 text-rose-700 dark:text-rose-300">오류: {session.error}</p>
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
                  {session.verified ? "검증된 페이로드 재실행" : "AI 페이로드 자동 조정 + 공격 실행"}
                </Button>
                {session.verified && (
                  <Button
                    type="button"
                    onClick={() => exec.mutate({ force: true })}
                    disabled={exec.isPending}
                    size="md"
                    variant="ghost"
                    title="저장된 페이로드를 무시하고 AI에게 다른 기법으로 새로 만들도록 요청합니다."
                  >
                    <RefreshCw className="mr-1.5 h-4 w-4" />
                    페이로드 새로 생성
                  </Button>
                )}
                <span className="text-[11px] text-neutral-500">
                  {session.verified
                    ? "이전 실행에서 검증된 페이로드 — AI 호출 없이 즉시 재실행"
                    : "AI가 페이로드를 환경에 맞게 조정해 보내고, 응답을 분석해 성공/실패를 판정합니다."}
                </span>
              </div>
            )}

            {execError && (
              <ErrorBox
                title="실행 실패"
                message={execError.message}
                actions={
                  <FeedbackBoxButton onClick={() => exec.mutate(undefined)}>
                    <RefreshCw className="h-3 w-3" />
                    다시 시도
                  </FeedbackBoxButton>
                }
              />
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
  onResetCooldown,
  onResumeVerify,
}: {
  log: SynthLogEntry[];
  running: boolean;
  error: string | null;
  onCancel: () => void;
  onRetry: () => void;
  onResetCooldown: () => void;
  onResumeVerify: () => void;
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
    <div className="space-y-3 rounded border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-surface-2 p-3 text-xs">
      <div className="flex items-center justify-between border-b border-neutral-200 dark:border-neutral-800 pb-2">
        <div className="flex items-center gap-1.5 text-amber-800 dark:text-amber-200">
          <Sparkles className="h-3.5 w-3.5" />
          <span className="font-medium">AI 환경 합성 진행 상황</span>
        </div>
        {running && (
          <Button
            type="button"
            onClick={onCancel}
            size="sm"
            variant="ghost"
            className="h-7 px-2 text-neutral-700 dark:text-neutral-300 hover:text-neutral-900 dark:hover:text-neutral-100"
          >
            진행 화면 닫기
          </Button>
        )}
        {!running && (failed || verifyFailed) && (
          <Button
            type="button"
            onClick={onRetry}
            size="sm"
            variant="ghost"
            className="h-7 px-2 text-amber-800 dark:text-amber-200 hover:text-amber-100"
          >
            <RefreshCw className="mr-1 h-3 w-3" />
            재시도
          </Button>
        )}
      </div>

      <ul className="space-y-2">
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
                    <XCircle className="h-3.5 w-3.5 text-rose-600 dark:text-rose-400" />
                  ) : (
                    <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
                  )
                ) : isCurrent ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-amber-700 dark:text-amber-300" />
                ) : (
                  <Circle className="h-3.5 w-3.5 text-neutral-600" />
                )}
              </span>
              <div className="flex-1">
                <div
                  className={cn(
                    "font-medium",
                    done
                      ? isFailedHere
                        ? "text-rose-800 dark:text-rose-200"
                        : "text-emerald-800 dark:text-emerald-200"
                      : isCurrent
                        ? "text-amber-800 dark:text-amber-200"
                        : "text-neutral-700 dark:text-neutral-300",
                  )}
                >
                  {PHASE_LABEL[phase] ?? phase}
                </div>
                {entry?.message && (
                  <div
                    className={cn(
                      "mt-0.5 break-words",
                      isFailedHere
                        ? "text-rose-800 dark:text-rose-200"
                        : isCurrent
                          ? "text-amber-100"
                          : "text-neutral-400",
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

      {error && (seen.has("cooldown") ? (
        <NoticeBox
          title="잠시 합성이 보류되어 있습니다"
          message={error}
          hint="이전 합성이 실패해 같은 CVE 에 대해 24시간 동안 자동 재시도가 멈춰 있습니다. 지금 바로 다시 시도하려면 '재시도 보류 해제' 를 누르세요."
          size="sm"
          actions={
            <>
              <FeedbackBoxButton tone="notice" onClick={onResetCooldown}>
                <RefreshCw className="h-3 w-3" />
                재시도 보류 해제
              </FeedbackBoxButton>
              <FeedbackBoxButton tone="notice" onClick={onRetry}>
                다시 시도
              </FeedbackBoxButton>
            </>
          }
        />
      ) : seen.has("cached_hit") ? (
        <NoticeBox title="이미 검증된 환경을 그대로 사용합니다" message={error} size="sm" />
      ) : (
        <ErrorBox
          title="합성 실패"
          message={error}
          hint={
            verifyFailed
              ? "환경 이미지는 이미 만들어져 있습니다. '검증만 다시 시도' 로 AI 호출/빌드 없이 몇 초 만에 재검증할 수 있습니다."
              : undefined
          }
          size="sm"
          actions={
            <>
              {verifyFailed && (
                <FeedbackBoxButton onClick={onResumeVerify}>
                  <RefreshCw className="h-3 w-3" />
                  검증만 다시 시도
                </FeedbackBoxButton>
              )}
              <FeedbackBoxButton onClick={onRetry}>
                <RefreshCw className="h-3 w-3" />
                처음부터 다시
              </FeedbackBoxButton>
            </>
          }
        />
      ))}

      {running && (
        <p className="text-[11px] text-amber-800 dark:text-amber-200/60">
          이 화면을 닫아도 백그라운드 합성은 계속 진행돼 결과가 자동으로 저장됩니다.
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
        이 환경 정확도
      </span>
      <button
        type="button"
        onClick={() => onVote("up")}
        disabled={pending}
        className={cn(
          "inline-flex items-center gap-1 rounded border px-1.5 py-0.5 transition",
          myVote === "up"
            ? "border-emerald-500/60 bg-emerald-500/15 text-emerald-800 dark:text-emerald-200"
            : "border-neutral-700 hover:border-emerald-500/40 hover:text-emerald-800 dark:hover:text-emerald-200",
          pending && "opacity-50",
        )}
        title="페이로드와 입력 지점이 이 CVE 와 정확히 일치합니다"
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
            ? "border-rose-500/60 bg-rose-500/15 text-rose-800 dark:text-rose-200"
            : "border-neutral-700 hover:border-rose-500/40 hover:text-rose-800 dark:hover:text-rose-200",
          pending && "opacity-50",
        )}
        title="잘못된 환경 — 다른 CVE 를 모사했거나 실제로 작동하지 않습니다"
      >
        <ThumbsDown className="h-3 w-3" />
        {down}
      </button>
      {myVote && (
        <span className="text-neutral-500">다시 누르면 평가가 변경됩니다</span>
      )}
    </div>
  );
}
