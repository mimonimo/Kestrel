"use client";

import { Check, Clock, Copy, Loader2, RotateCcw, Sparkles } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useMutation } from "@tanstack/react-query";

import { ApiError, api, type AiAnalysisResponse } from "@/lib/api";
import { recordAnalysisHistory } from "@/lib/analysis-history";
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

function formatAnalysisAge(epochMs: number): string {
  const diff = Date.now() - epochMs;
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "방금";
  if (mins < 60) return `${mins}분 전`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}시간 전`;
  const days = Math.floor(hours / 24);
  return `${days}일 전`;
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
          : "text-neutral-400 hover:bg-surface-3 hover:text-neutral-900 dark:hover:text-neutral-100",
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
      <pre className="overflow-x-auto px-0 py-3 text-xs leading-relaxed text-neutral-800 dark:text-neutral-100">
        <code className="block font-mono">
          {lines.map((line, i) => (
            <div key={i} className="flex">
              <span className="sticky left-0 select-none bg-neutral-50 pl-3 pr-3 text-right font-mono text-[10px] text-neutral-500 dark:bg-surface-2 dark:text-neutral-600">
                {String(i + 1).padStart(2, " ")}
              </span>
              <span className="whitespace-pre pr-4">{line || " "}</span>
            </div>
          ))}
        </code>
      </pre>
    </div>
  );
}

export function AiAnalysisPanel({ cveId }: { cveId: string }) {
  // Cached analysis for this CVE. Auto-rendered when the user revisits
  // the CVE — no extra click required (the "N분 전 분석" chip in the
  // header is the cue that it's a cached, not freshly-run, result).
  const [cached, setCached] = useState<CachedAnalysis | null>(null);

  useEffect(() => {
    setCached(readCachedAnalysis(cveId));
  }, [cveId]);

  const analyze = useMutation<AiAnalysisResponse, Error>({
    mutationFn: () => api.analyzeCve(cveId),
    onSuccess: (result) => {
      writeCachedAnalysis(cveId, result);
      setCached({ result, timestamp: Date.now() });
      // Append to the global cross-CVE analysis history (drives the
      // "분석 기록 보기" floating button popover).
      recordAnalysisHistory({
        cveId,
        attackMethod: result.attackMethod,
        payloadCount: result.payloadExamples.length,
        mitigationCount: result.mitigations.length,
      });
    },
  });

  // Display priority: live mutation result first, then cached. So
  // `data` is non-null any time the user has either just analyzed OR
  // analyzed this CVE in a previous visit — meaning revisiting the CVE
  // never falls back to the "분석 요청" form when there's content to show.
  const data = analyze.data ?? cached?.result ?? null;
  const isFromCache = analyze.data == null && cached != null;
  const error = analyze.error;
  const isKeyMissing = error instanceof ApiError && error.status === 400;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Sparkles className="h-4 w-4 text-violet-600 dark:text-violet-400" />
          <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-600 dark:text-neutral-500">
            AI 심층 분석
          </h2>
          {isFromCache && cached && (
            <span
              className="inline-flex items-center gap-1 rounded-full bg-neutral-100 px-1.5 py-0.5 text-[10px] text-neutral-700 dark:bg-surface-2 dark:text-neutral-400"
              title={`마지막 분석: ${new Date(cached.timestamp).toLocaleString("ko-KR")}`}
            >
              <Clock className="h-3 w-3" />
              {formatAnalysisAge(cached.timestamp)} 분석
            </span>
          )}
        </div>
        {data && !analyze.isPending && (
          <button
            type="button"
            onClick={() => analyze.mutate()}
            className="inline-flex items-center gap-1 rounded-full px-2 py-1 text-xs text-neutral-600 transition-colors hover:bg-neutral-100 hover:text-neutral-900 dark:text-neutral-400 dark:hover:bg-surface-2 dark:hover:text-neutral-100"
          >
            <RotateCcw className="h-3 w-3" />
            다시 분석
          </button>
        )}
      </CardHeader>
      <CardContent className="space-y-4">
        {!data && !analyze.isPending && !error && (
          <div className="flex flex-col items-start gap-3">
            <p className="text-sm text-neutral-700 dark:text-neutral-400">
              공격 시나리오 · 재현 가능한 PoC 페이로드 · 즉시 적용 가능한 차단
              패치를 한 번에. 보안 운영팀이 그대로 점검·티켓팅에 쓸 수 있는
              형태로 정리됩니다.
            </p>
            <Button
              type="button"
              onClick={() => analyze.mutate()}
              size="md"
              className="rounded-full bg-violet-600 text-white shadow-sm shadow-violet-600/20 hover:bg-violet-700 hover:shadow-md hover:shadow-violet-600/30 dark:bg-violet-500 dark:text-white dark:hover:bg-violet-400"
            >
              <Sparkles className="mr-1.5 h-4 w-4" />
              AI 심층 분석 요청
            </Button>
          </div>
        )}

        {analyze.isPending && (
          <div className="flex items-center gap-2 py-4 text-sm text-neutral-700 dark:text-neutral-400">
            <Loader2 className="h-4 w-4 animate-spin text-violet-600 dark:text-violet-400" />
            AI 가 취약점을 분석 중입니다…
          </div>
        )}

        {error && (
          <ErrorBox
            title="분석 요청 실패"
            message={error.message}
            actions={
              <>
                {isKeyMissing && (
                  <FeedbackBoxButton href="/settings">설정으로 이동</FeedbackBoxButton>
                )}
                <FeedbackBoxButton onClick={() => analyze.mutate()}>
                  <RotateCcw className="h-3 w-3" />
                  다시 시도
                </FeedbackBoxButton>
              </>
            }
          />
        )}

        {data && (
          <div className="space-y-5">
            <section>
              <h3 className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-neutral-600 dark:text-neutral-500">
                공격 기법
              </h3>
              <p className="whitespace-pre-line text-sm leading-relaxed text-neutral-800 dark:text-neutral-200">
                {data.attackMethod}
              </p>
            </section>

            <section>
              <h3 className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-neutral-600 dark:text-neutral-500">
                예시 페이로드 ({data.payloadExamples.length}종)
              </h3>
              <div className="space-y-3">
                {data.payloadExamples.map((p, i) => (
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
                패치 / 대응 항목 ({data.mitigations.length}개)
              </h3>
              <ul className="space-y-2">
                {data.mitigations.map((item, i) => (
                  <li
                    key={i}
                    className="rounded-lg border border-neutral-200 bg-neutral-50 p-3 text-sm leading-relaxed text-neutral-800 dark:border-neutral-800 dark:bg-surface-2 dark:text-neutral-200"
                  >
                    <span className="mr-2 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-violet-500/15 text-[11px] font-semibold text-violet-700 dark:text-violet-300">
                      {i + 1}
                    </span>
                    <span className="whitespace-pre-line align-middle">{item}</span>
                  </li>
                ))}
              </ul>
            </section>

            <p className="text-[11px] text-neutral-500">
              ※ AI 생성 결과는 참고용이며, 실제 대응 전에는 반드시 전문가 검토가 필요합니다.
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
