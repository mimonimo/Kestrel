import Link from "next/link";
import { ChevronLeft, ExternalLink, Sparkles, User as UserIcon } from "lucide-react";

import { MarkdownLite } from "@/components/ui/markdown-lite";
import { CopyLinkButton } from "@/components/ui/copy-link-button";
import { fetchAnalysisServer, ServerApiError } from "@/lib/server-api";

interface Props {
  params: Promise<{ id: string }>;
}

export async function generateMetadata({ params }: Props) {
  const { id } = await params;
  try {
    const a = await fetchAnalysisServer(id);
    if (!a) return { title: "분석을 찾을 수 없음 — Kestrel" };
    const t = a.title || `${a.cveId} 분석`;
    return {
      title: `${t} — Kestrel`,
      description: a.excerpt || `${a.cveId} 에 대한 AI 심층 분석`,
      openGraph: {
        title: `${t} — Kestrel`,
        description: a.excerpt || `${a.cveId} 에 대한 AI 심층 분석`,
      },
    };
  } catch {
    return { title: "Kestrel" };
  }
}

function fmtDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString("ko-KR", {
      year: "numeric",
      month: "long",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return iso;
  }
}

export default async function SharedAnalysisPage({ params }: Props) {
  const { id } = await params;

  let analysis: Awaited<ReturnType<typeof fetchAnalysisServer>> = null;
  let fetchError: Error | null = null;
  try {
    analysis = await fetchAnalysisServer(id);
  } catch (err) {
    fetchError = err as Error;
  }

  return (
    <div className="mx-auto max-w-3xl px-6 pb-16">
      <div className="mt-6 flex items-center justify-between gap-3">
        <Link
          href="/community"
          className="inline-flex items-center gap-1 text-sm text-neutral-500 hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-neutral-100"
        >
          <ChevronLeft className="h-4 w-4" />
          커뮤니티 분석 피드
        </Link>
        {analysis && <CopyLinkButton path={`/analyses/${analysis.id}`} />}
      </div>

      {fetchError ? (
        <div className="mt-16 flex flex-col items-center justify-center text-center">
          <p className="text-sm text-neutral-700 dark:text-neutral-300">
            분석을 불러오지 못했습니다.
          </p>
          <p className="mt-1 text-xs text-neutral-500">
            {fetchError instanceof ServerApiError ? `서버 응답: ${fetchError.status}` : "잠시 후 다시 시도해 주세요."}
          </p>
        </div>
      ) : !analysis ? (
        <div className="mt-16 flex flex-col items-center justify-center text-center">
          <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-violet-500/15 ring-1 ring-violet-400/30">
            <Sparkles className="h-6 w-6 text-violet-700 dark:text-violet-300" />
          </div>
          <h1 className="text-base font-semibold text-neutral-900 dark:text-neutral-100">
            분석을 찾을 수 없거나 비공개입니다
          </h1>
          <p className="mt-1 text-sm text-neutral-600 dark:text-neutral-400">
            링크가 만료됐거나 작성자가 비공개로 전환했을 수 있어요.
          </p>
        </div>
      ) : (
        <article className="mt-6">
          <header className="border-b border-neutral-200 pb-4 dark:border-neutral-800">
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <Link
                href={`/cve/${analysis.cveId}`}
                className="inline-flex items-center gap-1 rounded-full bg-violet-100 px-2.5 py-0.5 font-medium text-violet-800 hover:bg-violet-200 dark:bg-violet-500/15 dark:text-violet-200 dark:hover:bg-violet-500/25"
              >
                {analysis.cveId}
                <ExternalLink className="h-3 w-3" />
              </Link>
              <span className="inline-flex items-center gap-1 text-neutral-600 dark:text-neutral-400">
                <UserIcon className="h-3 w-3" />
                {analysis.author.nickname || analysis.author.username}
              </span>
              <span className="tabular-nums text-neutral-500 dark:text-neutral-500">
                · {fmtDate(analysis.createdAt)}
              </span>
            </div>
            <h1 className="mt-2 text-xl font-bold leading-snug text-neutral-900 dark:text-neutral-100">
              {analysis.title || `${analysis.cveId} 분석`}
            </h1>
          </header>

          <div className="mt-5">
            <MarkdownLite source={analysis.resultMd} />
          </div>

          <footer className="mt-10 border-t border-neutral-200 pt-5 text-[11px] text-neutral-500 dark:border-neutral-800">
            ※ 본 분석은 Kestrel AI 심층 분석 결과입니다. 참고용이며, 실제 대응 전에는 전문가 검토가 필요합니다.
          </footer>
        </article>
      )}
    </div>
  );
}
