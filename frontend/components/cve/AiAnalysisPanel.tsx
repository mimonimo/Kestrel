"use client";

import {
  Check,
  Copy,
  Download,
  Globe,
  History,
  Loader2,
  Lock,
  RotateCcw,
  Send,
  Sparkles,
  Trash2,
  Users,
  X,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { ApiError, api, type AiAnalysisResponse, type AnalysisSummary } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { recordAnalysisFailure, recordAnalysisHistory } from "@/lib/analysis-history";
import { clearRunning, markRunning, readRunningAnalyses } from "@/lib/analysis-running";
import { appendQaTurn, clearQaHistory, useQaHistory } from "@/lib/analysis-qa";
import { clearRunningQa, markRunningQa, readRunningQa } from "@/lib/qa-running";
import { downloadAnalysisMarkdown } from "@/lib/analysis-report";
import { formatRelativeKo } from "@/lib/format";
import { MarkdownLite } from "@/components/ui/markdown-lite";
import { CopyLinkButton } from "@/components/ui/copy-link-button";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { ErrorBox, FeedbackBoxButton } from "@/components/ui/feedback-box";
import { cn } from "@/lib/utils";

// Per-CVE cache for the most recent AI analysis result. Survives
// navigation away & back so the user can revisit a previous analysis
// without re-burning a Claude credit on the same vulnerability.
const ANALYSIS_KEY_PREFIX = "kestrel:ai-analysis:";

interface CachedAnalysis {
  result: AiAnalysisResponse;
  timestamp: number; // epoch ms
}

function readCachedAnalysis(cveId: string): CachedAnalysis | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(ANALYSIS_KEY_PREFIX + cveId);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as CachedAnalysis;
    if (!parsed?.result || typeof parsed.timestamp !== "number") return null;
    return parsed;
  } catch {
    return null;
  }
}

function writeCachedAnalysis(cveId: string, result: AiAnalysisResponse): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(
      ANALYSIS_KEY_PREFIX + cveId,
      JSON.stringify({ result, timestamp: Date.now() }),
    );
  } catch {
    // localStorage quota exceeded — silently skip; the in-memory result
    // is still available.
  }
}

function detectLanguage(source: string): string {
  const s = source.trim();
  if (/^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+\s+HTTP\//m.test(s)) return "http";
  if (/^\s*curl\b/m.test(s)) return "bash";
  if (/^\s*(?:msf\d?|use\s+(?:exploit|auxiliary)\/)/m.test(s)) return "msf";
  if (/^\s*(?:id|name):/m.test(s) && /\bmatchers\b|\brequests\b/.test(s)) return "nuclei";
  if (/^\s*(?:import\s+\w+|from\s+\w+\s+import|def\s+\w+\()/m.test(s)) return "python";
  if (/[#$]\s*\w+|(?:^|\n)(?:\$|#)\s/m.test(s) || /\|\s*sh\b/.test(s)) return "bash";
  return "text";
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // ignore — clipboard may be unavailable in insecure contexts
    }
  };
  return (
    <button
      type="button"
      onClick={onCopy}
      className={cn(
        "inline-flex items-center gap-1 rounded px-2 py-1 text-[11px] transition-colors",
        copied
          ? "text-emerald-700 dark:text-emerald-300"
          : "text-neutral-400 hover:bg-neutral-200 hover:text-neutral-900 dark:hover:bg-surface-3 dark:hover:text-neutral-100",
      )}
      aria-label="페이로드 복사"
    >
      {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
      {copied ? "복사됨" : "복사"}
    </button>
  );
}

function CodeBlock({ source }: { source: string }) {
  const language = useMemo(() => detectLanguage(source), [source]);
  const lines = useMemo(() => source.replace(/\n$/, "").split("\n"), [source]);

  return (
    <div className="overflow-hidden rounded-lg border border-neutral-200 bg-neutral-50 dark:border-neutral-800 dark:bg-surface-2">
      <div className="flex items-center justify-between border-b border-neutral-200 bg-white px-3 py-1.5 dark:border-neutral-800 dark:bg-surface-3">
        <span className="font-mono text-[10px] uppercase tracking-wider text-neutral-600 dark:text-neutral-400">
          {language}
        </span>
        <CopyButton text={source} />
      </div>
      <pre className="px-0 py-3 text-xs leading-relaxed text-neutral-800 dark:text-neutral-100">
        <code className="block font-mono">
          {lines.map((line, i) => (
            <div key={i} className="flex items-start">
              <span className="sticky left-0 shrink-0 select-none bg-neutral-50 pl-3 pr-3 pt-0.5 text-right font-mono text-[10px] text-neutral-500 dark:bg-surface-2 dark:text-neutral-600">
                {String(i + 1).padStart(2, " ")}
              </span>
              <span className="min-w-0 flex-1 whitespace-pre-wrap break-all pr-4">
                {line || " "}
              </span>
            </div>
          ))}
        </code>
      </pre>
    </div>
  );
}

// AI 분석 실패를 상황별로 사람이 읽기 좋은 제목·설명·힌트로 변환.
// 원시 error.message 를 그대로 노출하던 것을 대체 — 운영자가 다음에 뭘
// 해야 하는지(설정/재시도/대기) 가 바로 보이도록.
function describeAnalysisError(
  err: Error | null | undefined,
): { title: string; message: string; hint?: string; settings?: boolean } {
  if (!err) return { title: "분석 요청 실패", message: "" };
  const status = err instanceof ApiError ? err.status : 0;
  const raw = (err.message || "").trim();
  if (status === 400) {
    return {
      title: "AI 자격증명이 아직 설정되지 않았어요",
      message: "분석을 실행하려면 설정에서 AI 모델과 API 키를 먼저 등록해 주세요.",
      hint: raw || undefined,
      settings: true,
    };
  }
  if (status === 401) {
    return { title: "로그인이 필요해요", message: "AI 심층 분석은 로그인 후 이용할 수 있어요." };
  }
  if (status === 429) {
    return {
      title: "잠시 후 다시 시도해 주세요",
      message: "짧은 시간에 분석 요청이 많이 들어왔어요. 잠깐 기다렸다가 다시 분석해 주세요.",
    };
  }
  if (status === 0 || status >= 500) {
    return {
      title: "분석을 완료하지 못했어요",
      message: "AI 분석 서버가 일시적으로 응답하지 않았어요. 잠시 후 다시 시도하면 대부분 정상 동작합니다.",
      hint: raw || undefined,
    };
  }
  return {
    title: "분석 요청 실패",
    message: raw || "알 수 없는 오류로 분석을 마치지 못했어요. 다시 시도해 주세요.",
  };
}

export function AiAnalysisPanel({ cveId }: { cveId: string }) {
  const qc = useQueryClient();
  const { user, loading: authLoading } = useAuth();
  // Cached analysis for this CVE. Auto-rendered when the user revisits
  // the CVE — no extra click required (the "N분 전 분석" chip in the
  // header is the cue that it's a cached, not freshly-run, result).
  const [cached, setCached] = useState<CachedAnalysis | null>(null);

  useEffect(() => {
    setCached(readCachedAnalysis(cveId));
  }, [cveId]);

  // ``useQuery`` (instead of ``useMutation``) so the in-flight request
  // state lives in the shared QueryClient cache and survives component
  // unmount/remount when the user navigates away and back. Previously
  // a mutation was component-local — leaving the CVE detail page mid-
  // analysis dropped the "분석 중" state and the panel reset to the
  // initial form when the user returned.
  //
  // enabled=false means the query never auto-fetches; only manual
  // ``refetch()`` triggers it. gcTime=Infinity keeps the cached state
  // for the lifetime of the QueryClient (i.e., the whole session).
  const analyze = useQuery<AiAnalysisResponse, Error>({
    queryKey: ["ai-analysis", cveId],
    queryFn: () => api.analyzeCve(cveId),
    enabled: false,
    staleTime: Infinity,
    gcTime: Infinity,
    retry: false,
  });

  // Persist successful result + push to global history.
  useEffect(() => {
    if (!analyze.data) return;
    writeCachedAnalysis(cveId, analyze.data);
    setCached({ result: analyze.data, timestamp: Date.now() });
    recordAnalysisHistory({
      cveId,
      attackMethod: analyze.data.attackMethod,
      payloadCount: analyze.data.payloadExamples.length,
      mitigationCount: analyze.data.mitigations.length,
    });
  }, [analyze.data, cveId]);

  // Clear the persisted "running" marker only when the analysis truly
  // settles (success OR error). Doing this in queryFn's finally caused
  // a race: TanStack Query aborts the queryFn on component unmount /
  // refresh, which fired finally → cleared the marker → broke the
  // refresh-persistence we'd just added.
  useEffect(() => {
    if (analyze.data || analyze.error) {
      clearRunning(cveId);
    }
  }, [analyze.data, analyze.error, cveId]);

  // ── 서버 분석 히스토리 (이 CVE 의 저장된 분석들 — 공개 + 본인 비공개) ──
  // localStorage 캐시만 보던 기존 방식은 다른 기기·다른 사용자·캐시 비움 시
  // 기록을 못 봤다. 서버에서 직접 목록을 불러와 여러 번 분석한 기록을 관리한다.
  const historyQ = useQuery({
    queryKey: ["cve-analyses", cveId, "mine"],
    queryFn: () => api.listCveAnalyses(cveId, true),
    staleTime: 30_000,
  });
  // 안전장치: 서버가 mine=true 로 본인 것만 주지만, 클라이언트에서도
  // 에이전트/타인 분석을 한 번 더 걸러 '내 분석 기록'에 절대 섞이지 않게 한다.
  const history: AnalysisSummary[] = (historyQ.data?.items ?? []).filter(
    (a) => !a.author.isAgent && (!user || !a.author.username || a.author.username === user.username),
  );
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [historyOpen, setHistoryOpen] = useState(false);
  useEffect(() => setSelectedId(null), [cveId]);
  useEffect(() => setHistoryOpen(false), [cveId]);
  // 방금 실행한 결과가 없고 저장된 기록이 있으면 최신 기록을 자동 표시.
  useEffect(() => {
    if (selectedId || analyze.data) return;
    if (history.length > 0) setSelectedId(history[0].id);
  }, [history, selectedId, analyze.data]);
  const savedDetailQ = useQuery({
    queryKey: ["analysis-record", selectedId],
    queryFn: () => api.getAnalysisRecord(selectedId!),
    enabled: !!selectedId,
    staleTime: 60_000,
  });

  const runAnalysis = () => {
    // 로그인 필수 — 비로그인이면 /login 으로 보내고 분석 후 돌아오기.
    if (authLoading) return;
    if (!user) {
      if (typeof window !== "undefined") {
        const next = window.location.pathname + window.location.search;
        window.location.href = `/login?next=${encodeURIComponent(next)}`;
      }
      return;
    }
    // Synchronously mirror "running" BEFORE refetch so a refresh fired
    // within the same tick still finds the marker on next load.
    markRunning(cveId);
    // 명시적 then/finally 로 결과 처리 — useEffect 기반은 컴포넌트
    // unmount(다른 페이지 이동) 후에는 발화하지 않아 "활동 센터 진입 전엔
    // 영원히 분석 중" 버그가 있었음. refetch promise 의 then 은 unmount
    // 와 무관하게 실행되므로 record + clearRunning 이 보장됩니다.
    analyze
      .refetch()
      .then((res) => {
        if (res.data) {
          writeCachedAnalysis(cveId, res.data);
          recordAnalysisHistory({
            cveId,
            attackMethod: res.data.attackMethod,
            payloadCount: res.data.payloadExamples.length,
            mitigationCount: res.data.mitigations.length,
          });
          // 새 기록을 서버 히스토리에 반영 + 방금 결과를 선택 상태로.
          qc.invalidateQueries({ queryKey: ["cve-analyses", cveId] });
          if (res.data.analysisId) setSelectedId(res.data.analysisId);
        } else if (res.error) {
          // 분석 실패 — 활동센터에서 빨간 톤으로 표시. 사용자가 페이지를 떠나
          // unmount 된 상태여도 promise 의 then 은 실행되므로 보장.
          const msg = res.error instanceof Error ? res.error.message : "분석에 실패했습니다.";
          recordAnalysisFailure(cveId, msg);
        }
      })
      .catch((err) => {
        // refetch 자체가 throw 한 케이스 (network 끊김 등). 한 번 더 안전망.
        const msg = err instanceof Error ? err.message : "분석에 실패했습니다.";
        recordAnalysisFailure(cveId, msg);
      })
      .finally(() => {
        clearRunning(cveId);
      });
  };

  // Auto-resume: if the user refreshed mid-analysis (so the in-memory
  // query state was wiped but the persisted "running" entry survives)
  // re-trigger the request on mount. Without this the FloatingDock pill
  // would say "분석 중" forever until the 10-min prune kicks in.
  useEffect(() => {
    const stillRunning = readRunningAnalyses().some((e) => e.cveId === cveId);
    if (stillRunning && !analyze.data && !analyze.isFetching && !analyze.error) {
      analyze.refetch();
    }
    // intentionally only on cveId mount — repeated checks would loop
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cveId]);

  // Display priority: live result first, then cached. So `data` is
  // non-null any time the user has either just analyzed OR analyzed
  // this CVE in a previous visit — revisit never falls back to the
  // "분석 요청" form when content is available.
  // 표시 우선순위:
  //  · 방금 실행한 구조화 결과(showingFresh) → 구조화 뷰 + 후속 Q&A
  //  · 선택된 저장 기록(viewingSaved) → Markdown 렌더 + 후속 Q&A
  //  · 둘 다 없으면 요청 CTA
  const fresh = analyze.data ?? null;
  const showingFresh = fresh != null && (selectedId == null || selectedId === fresh.analysisId);
  const viewingSaved = !showingFresh && !!selectedId;
  const hasContent = showingFresh || viewingSaved;
  const selectedMeta = history.find((h) => h.id === selectedId) ?? null;
  const error = analyze.error;
  const isRunning = analyze.isFetching;
  const errInfo = describeAnalysisError(error);
  void qc;
  void cached;

  // ── 커뮤니티 공유 토글 — 본인 기록을 공개/비공개 전환 (분석 직후 바로 공유) ──
  const currentRecordId = showingFresh ? fresh?.analysisId ?? null : selectedId;
  const isOwn =
    showingFresh || (!!selectedMeta && !!user && selectedMeta.author.username === user.username);
  const isPublic = selectedMeta?.visibility === "public";
  const shareMut = useMutation({
    mutationFn: (visibility: "public" | "private") =>
      api.updateAnalysisRecord(currentRecordId!, { visibility }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["cve-analyses", cveId] });
      qc.invalidateQueries({ queryKey: ["community-analyses"] });
      qc.invalidateQueries({ queryKey: ["cve-community-analyses", cveId] });
      if (currentRecordId) qc.invalidateQueries({ queryKey: ["analysis-record", currentRecordId] });
    },
  });

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Sparkles className="h-4 w-4 text-violet-600 dark:text-violet-400" />
          <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-600 dark:text-neutral-500">
            AI 심층 분석
          </h2>
          {history.length > 0 && (
            <button
              type="button"
              onClick={() => setHistoryOpen(true)}
              className="inline-flex items-center gap-1 rounded-full bg-violet-50 px-2 py-0.5 text-[10px] font-medium text-violet-700 transition-colors hover:bg-violet-100 dark:bg-violet-500/15 dark:text-violet-200 dark:hover:bg-violet-500/25"
              title={`이 CVE 의 저장된 분석 ${history.length}건 — 클릭하여 기록 보기·공유`}
            >
              <History className="h-3 w-3" />
              분석 기록 {history.length}건
            </button>
          )}
        </div>
        {hasContent && !isRunning && (
          <div className="flex flex-wrap items-center justify-end gap-1">
            {showingFresh && fresh && (
              <button
                type="button"
                onClick={() =>
                  downloadAnalysisMarkdown({
                    cveId,
                    result: fresh,
                    qa: [],
                  })
                }
                className="inline-flex items-center gap-1 rounded-full px-2 py-1 text-xs text-neutral-600 transition-colors hover:bg-neutral-100 hover:text-neutral-900 dark:text-neutral-400 dark:hover:bg-surface-2 dark:hover:text-neutral-100"
                title="분석 결과와 Q&A 를 Markdown 으로 내려받기"
              >
                <Download className="h-3 w-3" />
                리포트 다운로드
              </button>
            )}
            {/* 커뮤니티 공유 토글 — 본인 기록만. 분석 직후 한 번에 공개. */}
            {isOwn && currentRecordId && (
              isPublic ? (
                <>
                  <CopyLinkButton path={`/analyses/${currentRecordId}`} label="링크" />
                  <button
                    type="button"
                    onClick={() => shareMut.mutate("private")}
                    disabled={shareMut.isPending}
                    className="inline-flex items-center gap-1 rounded-full border border-emerald-300 bg-emerald-50 px-2.5 py-1 text-xs font-medium text-emerald-700 transition-colors hover:bg-emerald-100 disabled:opacity-50 dark:border-emerald-500/40 dark:bg-emerald-500/15 dark:text-emerald-300"
                    title="커뮤니티 분석 피드에 공개 중 — 누르면 비공개로 전환"
                  >
                    {shareMut.isPending ? (
                      <Loader2 className="h-3 w-3 animate-spin" />
                    ) : (
                      <Globe className="h-3 w-3" />
                    )}
                    공유 중
                  </button>
                </>
              ) : (
                <button
                  type="button"
                  onClick={() => shareMut.mutate("public")}
                  disabled={shareMut.isPending}
                  className="inline-flex items-center gap-1 rounded-full bg-violet-600 px-2.5 py-1 text-xs font-medium text-white transition-colors hover:bg-violet-500 disabled:opacity-50"
                  title="이 분석을 커뮤니티 분석 피드에 공개"
                >
                  {shareMut.isPending ? (
                    <Loader2 className="h-3 w-3 animate-spin" />
                  ) : (
                    <Users className="h-3 w-3" />
                  )}
                  커뮤니티에 공유
                </button>
              )
            )}
            {!!user && (
              <button
                type="button"
                onClick={() => runAnalysis()}
                className="inline-flex items-center gap-1 rounded-full px-2 py-1 text-xs text-neutral-600 transition-colors hover:bg-neutral-100 hover:text-neutral-900 dark:text-neutral-400 dark:hover:bg-surface-2 dark:hover:text-neutral-100"
              >
                <RotateCcw className="h-3 w-3" />
                다시 분석
              </button>
            )}
          </div>
        )}
      </CardHeader>
      <CardContent className="space-y-4">
        {/* 분석 히스토리는 헤더의 "분석 기록" 버튼 → 팝업(AnalysisHistoryModal)에서 관리. */}


        {!hasContent && !isRunning && !error && (
          <div className="flex flex-col items-start gap-3">
            <p className="text-sm text-neutral-700 dark:text-neutral-400">
              공격 시나리오 · 재현 가능한 PoC 페이로드 · 즉시 적용 가능한 차단 패치를
              한 번에 받아 보세요. 보안 운영팀이 그대로 점검·티켓팅에 쓸 수 있는
              형태로 정리해 드립니다.
            </p>
            {!authLoading && !user ? (
              <AiAnalysisLoginGate cveId={cveId} />
            ) : (
              <Button
                type="button"
                onClick={() => runAnalysis()}
                size="md"
                className="rounded-full bg-violet-600 text-white shadow-sm shadow-violet-600/20 hover:bg-violet-700 hover:shadow-md hover:shadow-violet-600/30 dark:bg-violet-500 dark:text-white dark:hover:bg-violet-400"
              >
                <Sparkles className="mr-1.5 h-4 w-4" />
                AI 심층 분석 요청
              </Button>
            )}
          </div>
        )}

        {isRunning && <RunningIndicator cveId={cveId} />}

        {error && (
          <ErrorBox
            title={errInfo.title}
            message={errInfo.message}
            hint={errInfo.hint}
            actions={
              <>
                {errInfo.settings && (
                  <FeedbackBoxButton href="/settings">설정으로 이동</FeedbackBoxButton>
                )}
                <FeedbackBoxButton onClick={() => runAnalysis()}>
                  <RotateCcw className="h-3 w-3" />
                  다시 시도
                </FeedbackBoxButton>
              </>
            }
          />
        )}

        {showingFresh && fresh && (
          <div className="space-y-5">
            <section>
              <h3 className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-neutral-600 dark:text-neutral-500">
                공격 기법
              </h3>
              <p className="whitespace-pre-line text-sm leading-relaxed text-neutral-800 dark:text-neutral-200">
                {fresh.attackMethod}
              </p>
            </section>

            <section>
              <h3 className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-neutral-600 dark:text-neutral-500">
                예시 페이로드 ({fresh.payloadExamples.length}종)
              </h3>
              <div className="space-y-3">
                {fresh.payloadExamples.map((p, i) => (
                  <div key={i} className="space-y-1">
                    <div className="text-[11px] font-medium text-neutral-500 dark:text-neutral-500">
                      #{i + 1}
                    </div>
                    <CodeBlock source={p} />
                  </div>
                ))}
              </div>
            </section>

            <section>
              <h3 className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-neutral-600 dark:text-neutral-500">
                패치 / 대응 항목 ({fresh.mitigations.length}개)
              </h3>
              <ul className="space-y-2">
                {fresh.mitigations.map((item, i) => (
                  <li
                    key={i}
                    className="rounded-lg border border-neutral-200 bg-neutral-50 p-3 text-sm leading-relaxed text-neutral-800 dark:border-neutral-800 dark:bg-surface-2 dark:text-neutral-200"
                  >
                    <span className="mr-2 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-violet-500/15 text-[11px] font-semibold text-violet-700 dark:text-violet-300">
                      {i + 1}
                    </span>
                    <span className="whitespace-pre-line break-words align-middle">{item}</span>
                  </li>
                ))}
              </ul>
            </section>

            <FollowUpThread cveId={cveId} prior={fresh} />

            <p className="text-[11px] text-neutral-500">
              ※ AI 생성 결과는 참고용입니다. 실제 대응 전에 반드시 전문가 검토를 거치세요.
            </p>
          </div>
        )}

        {viewingSaved &&
          (savedDetailQ.isPending ? (
            <div className="flex items-center gap-2 text-sm text-neutral-600 dark:text-neutral-500">
              <Loader2 className="h-4 w-4 animate-spin" /> 저장된 분석을 불러오는 중…
            </div>
          ) : savedDetailQ.isError ? (
            <ErrorBox
              title="분석을 불러오지 못했습니다"
              message="비공개로 전환됐거나 삭제됐을 수 있어요."
            />
          ) : savedDetailQ.data ? (
            <div className="space-y-5">
              <MarkdownLite source={savedDetailQ.data.resultMd} />
              <FollowUpThread cveId={cveId} prior={null} />
              <p className="text-[11px] text-neutral-500">
                ※ AI 생성 결과는 참고용입니다. 실제 대응 전에 반드시 전문가 검토를 거치세요.
              </p>
            </div>
          ) : null)}

        {historyOpen && (
          <AnalysisHistoryModal
            cveId={cveId}
            items={history}
            currentUsername={user?.username ?? null}
            selectedId={selectedId}
            onView={(id) => {
              qc.removeQueries({ queryKey: ["ai-analysis", cveId] });
              setSelectedId(id);
              setHistoryOpen(false);
            }}
            onShared={() => {
              qc.invalidateQueries({ queryKey: ["cve-analyses", cveId] });
              qc.invalidateQueries({ queryKey: ["community-analyses"] });
              qc.invalidateQueries({ queryKey: ["cve-community-analyses", cveId] });
            }}
            onClose={() => setHistoryOpen(false)}
          />
        )}
      </CardContent>
    </Card>
  );
}

// ─────────────────────── Running indicator (elapsed) ─────────────────

function RunningIndicator({ cveId }: { cveId: string }) {
  // 분석 시작 시각을 localStorage 의 markRunning entry 에서 읽어 새로고침해도
  // elapsed 가 0 으로 리셋되지 않게. entry 없으면 fallback 으로 현재 시각.
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    const computeT0 = () => {
      const entry = readRunningAnalyses().find((e) => e.cveId === cveId);
      return entry?.startedAt ?? Date.now();
    };
    let t0 = computeT0();
    setElapsed(Math.floor((Date.now() - t0) / 1000));
    const id = window.setInterval(() => {
      if (t0 === Date.now()) {
        // 첫 mark 가 막 도착했으면 다시 읽음
        t0 = computeT0();
      }
      setElapsed(Math.floor((Date.now() - t0) / 1000));
    }, 1000);
    return () => window.clearInterval(id);
  }, [cveId]);
  const hint =
    elapsed < 60
      ? "잠시만 기다려 주세요…"
      : elapsed < 120
        ? "거의 다 됐어요. 응답을 받아오는 중입니다."
        : "응답이 길어지고 있어요. 토큰을 마지막까지 받아오는 중입니다.";
  return (
    <div className="rounded-lg border border-violet-200 bg-violet-50/50 p-4 dark:border-violet-500/30 dark:bg-violet-500/5">
      <div className="flex items-center gap-2 text-sm font-medium text-violet-900 dark:text-violet-200">
        <Loader2 className="h-4 w-4 animate-spin" />
        AI 가 취약점을 분석 중입니다
        <span className="ml-1 tabular-nums text-[12px] text-violet-700 dark:text-violet-300">
          ({elapsed}s)
        </span>
      </div>
      <p className="mt-1.5 text-[11px] text-violet-800 dark:text-violet-300/80">{hint}</p>
    </div>
  );
}

// ─────────────────────── Follow-up Q&A thread ─────────────────────────

function FollowUpThread({ cveId, prior }: { cveId: string; prior: AiAnalysisResponse | null }) {
  const { user } = useAuth();
  const { turns } = useQaHistory(cveId);
  const [question, setQuestion] = useState("");
  // 진행 중인 질문 텍스트 — 새로고침 / 컴포넌트 unmount 후에도 입력란
  // placeholder 위쪽 카드로 시각 표시. 마운트 시 self-mutate 으로 재호출.
  const [inFlightQuestion, setInFlightQuestion] = useState<string | null>(null);
  const [elapsed, setElapsed] = useState(0);

  const ask = useMutation({
    mutationFn: async (q: string) => {
      setInFlightQuestion(q);
      markRunningQa(cveId, q);
      try {
        const res = await api.askFollowup({
          cveId,
          question: q,
          prior: prior ?? undefined,
          history: turns.map((t) => ({ question: t.question, answer: t.answer })),
        });
        appendQaTurn(cveId, { question: q, answer: res.answer });
        return res.answer;
      } finally {
        clearRunningQa(cveId);
        setInFlightQuestion(null);
      }
    },
    onSuccess: () => setQuestion(""),
  });

  // 마운트 시 진행 중인 질문이 있으면 자동으로 다시 요청 — 새로고침해도
  // "분석 하던게 사라졌다" 느낌이 나지 않게.
  useEffect(() => {
    const r = readRunningQa(cveId);
    if (r && !ask.isPending && !inFlightQuestion) {
      ask.mutate(r.question);
    }
    // mount-only for this cveId
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cveId]);

  // elapsed 카운터 — startedAt 기반이라 새로고침해도 시간 유지.
  useEffect(() => {
    if (!ask.isPending) {
      setElapsed(0);
      return;
    }
    const r = readRunningQa(cveId);
    const t0 = r?.startedAt ?? Date.now();
    setElapsed(Math.floor((Date.now() - t0) / 1000));
    const id = window.setInterval(
      () => setElapsed(Math.floor((Date.now() - t0) / 1000)),
      1000,
    );
    return () => window.clearInterval(id);
  }, [ask.isPending, cveId]);

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const q = question.trim();
    if (!q || ask.isPending) return;
    ask.mutate(q);
  };

  return (
    <section className="rounded-lg border border-neutral-200 bg-neutral-50/60 p-3 dark:border-neutral-800 dark:bg-surface-2/40">
      <header className="mb-2 flex items-center justify-between">
        <h3 className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-violet-700 dark:text-violet-300">
          <Sparkles className="h-3 w-3" />
          추가 질문 ({turns.length})
        </h3>
        <div className="flex items-center gap-1">
          {turns.length > 0 && (
            <>
              {prior && (
                <button
                  type="button"
                  onClick={() =>
                    downloadAnalysisMarkdown({
                      cveId,
                      result: prior,
                      qa: turns,
                    })
                  }
                  className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] text-neutral-600 hover:bg-neutral-200 hover:text-neutral-900 dark:text-neutral-400 dark:hover:bg-surface-3 dark:hover:text-neutral-100"
                  title="분석 결과 + 이 Q&A 를 Markdown 으로 다운로드"
                >
                  <Download className="h-3 w-3" />
                  저장
                </button>
              )}
              <button
                type="button"
                onClick={() => {
                  if (confirm("이 CVE 의 모든 추가 질문 기록을 지우시겠습니까?")) {
                    clearQaHistory(cveId);
                  }
                }}
                className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] text-neutral-600 hover:bg-neutral-200 hover:text-rose-700 dark:text-neutral-400 dark:hover:bg-surface-3 dark:hover:text-rose-300"
                title="질문 기록 지우기"
              >
                <Trash2 className="h-3 w-3" />
              </button>
            </>
          )}
        </div>
      </header>

      {turns.length > 0 && (
        <ul className="mb-3 space-y-3">
          {turns.map((t, i) => (
            <li key={i} className="space-y-1.5">
              <div className="rounded-md bg-white px-3 py-2 text-[12px] text-neutral-900 shadow-sm dark:bg-surface-1 dark:text-neutral-100">
                <div className="mb-1 text-[9px] font-semibold uppercase tracking-wider text-neutral-500 dark:text-neutral-500">
                  Q{i + 1}
                </div>
                <p className="whitespace-pre-line">{t.question}</p>
              </div>
              <div className="rounded-md border border-violet-200 bg-violet-50/50 px-3 py-2 text-[12px] leading-relaxed text-neutral-800 dark:border-violet-500/30 dark:bg-violet-500/10 dark:text-neutral-200">
                <div className="mb-1 text-[9px] font-semibold uppercase tracking-wider text-violet-700 dark:text-violet-300">
                  Answer
                </div>
                <p className="whitespace-pre-line">{t.answer}</p>
              </div>
            </li>
          ))}
        </ul>
      )}

      {/* 진행 중 — 새로고침에도 유지, 자동 재호출 */}
      {ask.isPending && inFlightQuestion && (
        <div className="mb-3 space-y-1.5">
          <div className="rounded-md bg-white px-3 py-2 text-[12px] text-neutral-900 shadow-sm dark:bg-surface-1 dark:text-neutral-100">
            <div className="mb-1 text-[9px] font-semibold uppercase tracking-wider text-neutral-500 dark:text-neutral-500">
              Q{turns.length + 1}
            </div>
            <p className="whitespace-pre-line">{inFlightQuestion}</p>
          </div>
          <div className="rounded-md border border-violet-300 bg-violet-50 px-3 py-2 text-[12px] text-violet-900 dark:border-violet-500/40 dark:bg-violet-500/15 dark:text-violet-200">
            <div className="flex items-center gap-1.5 text-[11px] font-medium">
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              답변 생성 중…
              <span className="ml-1 tabular-nums text-violet-700 dark:text-violet-300">
                ({elapsed}s)
              </span>
            </div>
          </div>
        </div>
      )}

      {ask.error && (
        <p className="mb-2 text-[11px] text-rose-700 dark:text-rose-300">
          {(ask.error as Error).message || "질문 처리에 실패했어요."}
        </p>
      )}

      {user ? (
        <form onSubmit={onSubmit} className="flex items-start gap-2">
          <textarea
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            rows={2}
            maxLength={2000}
            disabled={ask.isPending}
            placeholder="예: 두 번째 페이로드의 WAF 우회 부분을 더 자세히 설명해 주세요"
            className="flex-1 resize-none rounded-md border border-neutral-300 bg-white px-3 py-2 text-[12px] text-neutral-900 placeholder:text-neutral-500 focus:border-violet-500 focus:outline-none dark:border-neutral-700 dark:bg-surface-1 dark:text-neutral-100"
          />
          <Button
            type="submit"
            size="sm"
            disabled={!question.trim() || ask.isPending}
            className="shrink-0 rounded-full bg-violet-600 text-white hover:bg-violet-700 disabled:opacity-50 dark:bg-violet-500 dark:hover:bg-violet-400"
          >
            {ask.isPending ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Send className="h-3.5 w-3.5" />
            )}
            질문
          </Button>
        </form>
      ) : (
        <InlineLoginGate label="추가 질문" />
      )}
    </section>
  );
}

// AI 심층 분석 미실행 상태에서 비로그인 사용자에게 보여줄 큰 게이트.
// 단순히 버튼을 숨기는 대신 "왜 로그인이 필요한지" 한 줄 설명까지 — 보안
// 운영자가 분석을 본인 계정에 영구 저장한다는 가치 제안을 함께 전달.
function AiAnalysisLoginGate({ cveId }: { cveId: string }) {
  const next = encodeURIComponent(`/cve/${cveId}`);
  return (
    <div className="flex w-full flex-col items-start gap-2 rounded-lg border border-dashed border-violet-300 bg-violet-50/60 p-4 dark:border-violet-500/40 dark:bg-violet-500/10">
      <p className="text-sm text-neutral-900 dark:text-neutral-100">
        <span className="font-medium">AI 심층 분석</span> 은 로그인 후 이용할 수 있어요.
      </p>
      <p className="text-xs text-neutral-700 dark:text-neutral-300">
        분석 결과가 본인 계정에 저장돼 언제든 다시 열어볼 수 있고, 커뮤니티에
        공개하면 다른 보안 운영자에게도 도움이 됩니다.
      </p>
      <a
        href={`/login?next=${next}`}
        className="mt-1 inline-flex items-center gap-1.5 rounded-full bg-violet-600 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-violet-500 dark:bg-violet-500 dark:hover:bg-violet-400"
      >
        <Sparkles className="h-3 w-3" />
        로그인하고 분석하기
      </a>
    </div>
  );
}

// 작은 인라인 게이트 — Q&A / 댓글 등 비로그인 사용자가 마주칠 작성 영역에서 공통 사용.
function InlineLoginGate({ label }: { label: string }) {
  const next =
    typeof window !== "undefined"
      ? `?next=${encodeURIComponent(window.location.pathname + window.location.search)}`
      : "";
  return (
    <div className="flex flex-col items-start gap-1.5 rounded-md border border-dashed border-neutral-300 bg-neutral-50 p-3 text-[11px] dark:border-neutral-700 dark:bg-surface-1">
      <span className="text-neutral-700 dark:text-neutral-300">
        <span className="font-medium">{label}</span> 은 로그인 후 이용할 수 있어요.
      </span>
      <a
        href={`/login${next}`}
        className="inline-flex items-center gap-1 rounded-full bg-violet-600 px-2.5 py-1 font-medium text-white transition-colors hover:bg-violet-500 dark:bg-violet-500 dark:hover:bg-violet-400"
      >
        로그인하기
      </a>
    </div>
  );
}


// ─────────────────────── 분석 기록 팝업 ───────────────────────
// 여러 번 분석한 기록을 팝업으로 보고, 마음에 드는 하나를 골라(기본=최신)
// 하단에서 커뮤니티에 공유한다.
function AnalysisHistoryModal({
  cveId,
  items,
  currentUsername,
  selectedId,
  onView,
  onShared,
  onClose,
}: {
  cveId: string;
  items: AnalysisSummary[];
  currentUsername: string | null;
  selectedId: string | null;
  onView: (id: string) => void;
  onShared: () => void;
  onClose: () => void;
}) {
  // 기본 선택 = 현재 보고 있는 기록, 없으면 최신(목록 첫 항목).
  const [picked, setPicked] = useState<string | null>(selectedId ?? items[0]?.id ?? null);
  const current = items.find((it) => it.id === picked) ?? null;
  const isOwn = !!current && !!currentUsername && current.author.username === currentUsername;
  const isPublic = current?.visibility === "public";

  const share = useMutation({
    mutationFn: (visibility: "public" | "private") => api.updateAnalysisRecord(picked!, { visibility }),
    onSuccess: () => onShared(),
  });

  if (typeof document === "undefined") return null;
  return createPortal(
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/50 px-4" onClick={onClose} role="dialog" aria-modal="true">
      <div onClick={(e) => e.stopPropagation()} className="flex max-h-[85vh] w-full max-w-lg flex-col overflow-hidden rounded-2xl border border-neutral-200 bg-white shadow-xl dark:border-neutral-800 dark:bg-surface-1">
        <div className="flex items-center justify-between border-b border-neutral-200 px-5 py-3 dark:border-neutral-800">
          <h2 className="flex items-center gap-2 text-sm font-semibold text-neutral-900 dark:text-neutral-100">
            <History className="h-4 w-4 text-violet-500" /> 분석 기록 <span className="font-normal text-neutral-400">{items.length}</span>
          </h2>
          <button type="button" onClick={onClose} aria-label="닫기" className="rounded-full p-1 text-neutral-500 hover:bg-neutral-100 dark:hover:bg-surface-2"><X className="h-4 w-4" /></button>
        </div>

        <p className="px-5 pt-3 text-[11px] leading-relaxed text-neutral-500 dark:text-neutral-400">
          여러 번 분석한 기록입니다. 가장 마음에 드는 분석을 골라 하단에서 커뮤니티에 공유하세요. 기본값은 가장 최근 분석입니다.
        </p>

        <ul className="flex-1 space-y-1.5 overflow-y-auto px-5 py-3">
          {items.map((it, i) => {
            const active = picked === it.id;
            return (
              <li key={it.id}>
                <button
                  type="button"
                  onClick={() => setPicked(it.id)}
                  className={cn(
                    "flex w-full items-start gap-2 rounded-lg border px-3 py-2 text-left transition-colors",
                    active
                      ? "border-violet-400 bg-violet-50 dark:border-violet-500/50 dark:bg-violet-500/10"
                      : "border-neutral-200 hover:border-violet-300 dark:border-neutral-800 dark:hover:border-violet-500/40",
                  )}
                >
                  <span className={cn("mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full border", active ? "border-violet-500 bg-violet-500 text-white" : "border-neutral-300 dark:border-neutral-600")}>
                    {active && <Check className="h-2.5 w-2.5" />}
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-1.5 text-xs">
                      <span className="font-medium text-neutral-800 dark:text-neutral-200">{it.author.nickname || it.author.username}</span>
                      {i === 0 && <span className="rounded-full bg-sky-100 px-1.5 py-0.5 text-[9px] font-semibold text-sky-700 dark:bg-sky-500/15 dark:text-sky-200">최신</span>}
                      <span className={cn("inline-flex items-center gap-0.5 rounded-full px-1.5 py-0.5 text-[9px] font-medium", it.visibility === "public" ? "bg-emerald-100 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300" : "bg-neutral-100 text-neutral-500 dark:bg-surface-2 dark:text-neutral-400")}>
                        {it.visibility === "public" ? <><Globe className="h-2.5 w-2.5" /> 공개</> : <><Lock className="h-2.5 w-2.5" /> 비공개</>}
                      </span>
                      <span className="ml-auto tabular-nums text-[10px] text-neutral-400">{formatRelativeKo(it.createdAt)}</span>
                    </div>
                    {it.attackMethod && <p className="mt-1 line-clamp-2 text-[11px] text-neutral-500 dark:text-neutral-400">{it.attackMethod}</p>}
                    <div className="mt-1 flex gap-2 text-[10px] text-neutral-400">
                      <span>페이로드 {it.payloadCount}</span>
                      <span>완화 {it.mitigationCount}</span>
                    </div>
                  </div>
                </button>
              </li>
            );
          })}
        </ul>

        <div className="border-t border-neutral-200 px-5 py-3 dark:border-neutral-800">
          <div className="flex items-center justify-between gap-2">
            <button
              type="button"
              onClick={() => picked && onView(picked)}
              disabled={!picked}
              className="rounded-full border border-neutral-300 px-3 py-1.5 text-xs font-medium text-neutral-700 hover:bg-neutral-100 disabled:opacity-50 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-surface-2"
            >
              이 분석 보기
            </button>
            {isOwn ? (
              isPublic ? (
                <button
                  type="button"
                  onClick={() => share.mutate("private")}
                  disabled={share.isPending}
                  className="inline-flex items-center gap-1.5 rounded-full border border-emerald-300 bg-emerald-50 px-4 py-1.5 text-xs font-medium text-emerald-700 hover:bg-emerald-100 disabled:opacity-50 dark:border-emerald-500/40 dark:bg-emerald-500/15 dark:text-emerald-300"
                >
                  {share.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Globe className="h-3.5 w-3.5" />} 공유 중 — 비공개 전환
                </button>
              ) : (
                <button
                  type="button"
                  onClick={() => share.mutate("public")}
                  disabled={share.isPending || !picked}
                  className="inline-flex items-center gap-1.5 rounded-full bg-violet-600 px-4 py-1.5 text-xs font-semibold text-white hover:bg-violet-500 disabled:opacity-50"
                >
                  {share.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Users className="h-3.5 w-3.5" />} 이 분석 공유
                </button>
              )
            ) : (
              <span className="text-[11px] text-neutral-400">본인 분석만 공유할 수 있습니다.</span>
            )}
          </div>
          {share.isError && <p className="mt-2 text-[11px] text-rose-600 dark:text-rose-300">{(share.error as Error).message || "공유 처리에 실패했습니다."}</p>}
        </div>
      </div>
    </div>,
    document.body,
  );
}
