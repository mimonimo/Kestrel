"use client";

import { AlertCircle, Loader2, RotateCcw, Sparkles } from "lucide-react";
import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import Link from "next/link";

import { ApiError, api, type AiAnalysisResponse } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";

export function AiAnalysisPanel({ cveId }: { cveId: string }) {
  const [checked, setChecked] = useState<Record<number, boolean>>({});

  const analyze = useMutation<AiAnalysisResponse, Error>({
    mutationFn: () => api.analyzeCve(cveId),
    onSuccess: () => setChecked({}),
  });

  const data = analyze.data;
  const error = analyze.error;
  const isKeyMissing = error instanceof ApiError && error.status === 400;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Sparkles className="h-4 w-4 text-violet-400" />
          <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-500">
            AI 심층 분석
          </h2>
        </div>
        {data && !analyze.isPending && (
          <button
            type="button"
            onClick={() => analyze.mutate()}
            className="inline-flex items-center gap-1 text-xs text-neutral-500 hover:text-neutral-200"
          >
            <RotateCcw className="h-3 w-3" />
            다시 분석
          </button>
        )}
      </CardHeader>
      <CardContent className="space-y-4">
        {!data && !analyze.isPending && !error && (
          <div className="flex flex-col items-start gap-2">
            <p className="text-sm text-neutral-400">
              LLM을 활용해 공격 기법·페이로드 예시·대응 방안을 생성합니다. 설정 페이지에서
              등록한 제공자·모델·API 키가 사용됩니다.
            </p>
            <Button
              type="button"
              onClick={() => analyze.mutate()}
              size="md"
              className="mt-1"
            >
              <Sparkles className="mr-1.5 h-4 w-4" />
              AI 심층 분석 요청
            </Button>
          </div>
        )}

        {analyze.isPending && (
          <div className="flex items-center gap-2 py-4 text-sm text-neutral-400">
            <Loader2 className="h-4 w-4 animate-spin text-violet-400" />
            AI가 취약점을 분석 중입니다…
          </div>
        )}

        {error && (
          <div className="space-y-2 rounded-md border border-red-500/30 bg-red-500/10 p-3">
            <div className="flex items-center gap-1.5 text-sm font-medium text-red-300">
              <AlertCircle className="h-4 w-4" />
              분석 요청 실패
            </div>
            <p className="text-xs text-red-200/90">{error.message}</p>
            <div className="flex items-center gap-2 pt-1">
              {isKeyMissing && (
                <Link
                  href="/settings"
                  className="inline-flex items-center rounded border border-neutral-700 bg-surface-2 px-2 py-1 text-xs text-neutral-200 hover:bg-surface-3"
                >
                  설정 페이지로 이동
                </Link>
              )}
              <button
                type="button"
                onClick={() => analyze.mutate()}
                className="text-xs text-neutral-400 underline hover:text-neutral-200"
              >
                다시 시도
              </button>
            </div>
          </div>
        )}

        {data && (
          <div className="space-y-5">
            <section>
              <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-neutral-500">
                공격 기법
              </h3>
              <p className="whitespace-pre-line text-sm leading-relaxed text-neutral-200">
                {data.attackMethod}
              </p>
            </section>

            <section>
              <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-neutral-500">
                페이로드 예시
              </h3>
              <pre className="overflow-x-auto rounded-md border border-neutral-800 bg-surface-2 p-3 text-xs leading-relaxed text-neutral-100">
                <code className="font-mono whitespace-pre">{data.payloadExample}</code>
              </pre>
            </section>

            <section>
              <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-neutral-500">
                대응 방안 체크리스트
              </h3>
              <ul className="space-y-2">
                {data.mitigation.map((item, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm">
                    <input
                      type="checkbox"
                      id={`mitigation-${i}`}
                      checked={!!checked[i]}
                      onChange={(e) =>
                        setChecked((prev) => ({ ...prev, [i]: e.target.checked }))
                      }
                      className="mt-0.5 h-4 w-4 flex-shrink-0 cursor-pointer accent-violet-500"
                    />
                    <label
                      htmlFor={`mitigation-${i}`}
                      className={
                        checked[i]
                          ? "cursor-pointer text-neutral-500 line-through"
                          : "cursor-pointer text-neutral-200"
                      }
                    >
                      {item}
                    </label>
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
