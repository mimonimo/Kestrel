import Link from "next/link";
import { ExternalLink, X } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { AiAnalysisPanel } from "./AiAnalysisPanel";
import { BookmarkButton } from "./BookmarkButton";
import { ShareButton } from "./ShareButton";
import { SeverityBadge } from "./SeverityBadge";
import { SourceBadgeCluster } from "./SourceBadgeCluster";
import { TicketControl } from "./TicketControl";
import { CommentThread } from "@/components/community/CommentThread";
import { formatDate } from "@/lib/utils";
import { decodeCvssVector } from "@/lib/cvss";
import type { Vulnerability } from "@/lib/types";

function hostOf(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return "";
  }
}

export function CveDetail({ vuln }: { vuln: Vulnerability }) {
  const scoreLabel =
    typeof vuln.cvssScore === "number" && Number.isFinite(vuln.cvssScore)
      ? vuln.cvssScore.toFixed(1)
      : "—";
  const decoded = decodeCvssVector(vuln.cvssVector);
  const metrics = vuln.enrichment?.metrics ?? [];
  const weaknesses = vuln.enrichment?.weaknesses ?? [];
  const richRefs = vuln.enrichment?.references ?? [];

  return (
    <article className="relative mx-auto max-w-7xl space-y-6 px-6 py-8">
      <Link
        href="/"
        aria-label="상세 닫기"
        className="absolute right-0 top-4 inline-flex h-9 w-9 items-center justify-center rounded-full border border-neutral-300 bg-white text-neutral-600 hover:border-neutral-500 hover:text-neutral-900 dark:border-neutral-800 dark:bg-surface-1 dark:text-neutral-400 dark:hover:border-neutral-600 dark:hover:text-neutral-100"
      >
        <X className="h-4 w-4" />
      </Link>

      <header className="space-y-3 pr-12">
        <div className="flex flex-wrap items-center gap-3">
          <span className="font-mono text-sm font-semibold text-neutral-500">{vuln.cveId}</span>
          <SeverityBadge severity={vuln.severity} score={vuln.cvssScore} />
          <SourceBadgeCluster sources={vuln.sources ?? [vuln.source]} size="md" />
          <BookmarkButton cveId={vuln.cveId} size="md" stopPropagation={false} />
          <ShareButton cveId={vuln.cveId} size="md" stopPropagation={false} />
          <span className="text-xs text-neutral-500">게시일: {formatDate(vuln.publishedAt)}</span>
          <span className="text-xs text-neutral-500">수정일: {formatDate(vuln.modifiedAt)}</span>
        </div>
        <h1 className="text-2xl font-bold leading-tight text-neutral-100">{vuln.title}</h1>
        {vuln.types.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {vuln.types.map((t) => (
              <Badge key={t} variant="secondary">
                {t}
              </Badge>
            ))}
          </div>
        )}
      </header>

      <Card>
        <CardHeader>
          <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-500">CVSS</h2>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-baseline gap-3">
            <span className="text-3xl font-bold text-neutral-100">{scoreLabel}</span>
            <span className="text-sm uppercase text-neutral-400">{vuln.severity ?? "unknown"}</span>
          </div>
          {decoded.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {decoded.map((m) => (
                <span
                  key={m.key}
                  className="inline-flex items-center gap-1 rounded-full bg-neutral-100 px-2 py-0.5 text-[11px] dark:bg-surface-2"
                  title={m.label}
                >
                  <span className="text-neutral-500 dark:text-neutral-500">{m.label}</span>
                  <span className="font-medium text-neutral-800 dark:text-neutral-200">{m.value}</span>
                </span>
              ))}
            </div>
          )}
          {vuln.cvssVector ? (
            <code className="block break-all font-mono text-xs text-neutral-500">
              {vuln.cvssVector}
            </code>
          ) : (
            <p className="text-xs text-neutral-600">CVSS 벡터 정보 없음</p>
          )}
          {metrics.length > 0 && (
            <div className="space-y-1 border-t border-neutral-200 pt-2 dark:border-neutral-800">
              {metrics.map((m, i) => (
                <div key={i} className="flex flex-wrap items-center gap-2 text-[11px] text-neutral-500 dark:text-neutral-400">
                  <span className="rounded bg-neutral-200/70 px-1.5 py-0.5 font-mono dark:bg-surface-3">
                    CVSS {m.version}
                  </span>
                  {m.baseScore != null && (
                    <span className="font-semibold text-neutral-800 dark:text-neutral-200">{m.baseScore.toFixed(1)}</span>
                  )}
                  {m.baseSeverity && <span className="uppercase">{m.baseSeverity}</span>}
                  {m.exploitMaturity && <span>· 악용성숙도 {m.exploitMaturity}</span>}
                  {m.exploitabilityScore != null && <span>· 악용성 {m.exploitabilityScore}</span>}
                  {m.impactScore != null && <span>· 영향도 {m.impactScore}</span>}
                  {m.source && <span className="text-neutral-400 dark:text-neutral-500">· {m.source}</span>}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {weaknesses.length > 0 && (
        <Card>
          <CardHeader>
            <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-500">
              약점 (CWE)
            </h2>
          </CardHeader>
          <CardContent>
            <ul className="flex flex-wrap gap-2">
              {weaknesses.map((w) => (
                <li key={w.cweId}>
                  <a
                    href={w.url ?? `https://cwe.mitre.org/`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 rounded-lg border border-neutral-200 px-2.5 py-1 text-xs transition-colors hover:border-sky-400 dark:border-neutral-800 dark:hover:border-sky-500/50"
                  >
                    <span className="font-mono font-semibold text-neutral-800 dark:text-neutral-100">{w.cweId}</span>
                    {w.name && <span className="text-neutral-500 dark:text-neutral-400">{w.name}</span>}
                    <ExternalLink className="h-3 w-3 text-neutral-400" />
                  </a>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-500">상세 설명</h2>
        </CardHeader>
        <CardContent>
          <p className="whitespace-pre-line text-sm leading-relaxed text-neutral-300">
            {vuln.description || "설명이 제공되지 않았습니다."}
          </p>
        </CardContent>
      </Card>

      <AiAnalysisPanel cveId={vuln.cveId} />

      {vuln.affectedProducts.length > 0 && (
        <Card>
          <CardHeader>
            <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-500">
              영향받는 제품·버전
            </h2>
          </CardHeader>
          <CardContent>
            <ul className="divide-y divide-neutral-800">
              {vuln.affectedProducts.map((p, i) => (
                <li key={i} className="flex items-center justify-between gap-3 py-2 text-sm">
                  <div>
                    <span className="font-medium text-neutral-100">
                      {p.vendor} {p.product}
                    </span>
                    {p.versionRange && (
                      <span className="ml-2 font-mono text-neutral-500">{p.versionRange}</span>
                    )}
                  </div>
                  <Badge variant="outline" className="uppercase">
                    {p.osFamily}
                  </Badge>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      {(richRefs.length > 0 || vuln.references.length > 0) && (
        <Card>
          <CardHeader>
            <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-500">
              참고 자료{" "}
              <span className="font-normal text-neutral-400">
                {(richRefs.length || vuln.references.length).toLocaleString("ko-KR")}
              </span>
            </h2>
          </CardHeader>
          <CardContent>
            {richRefs.length > 0 ? (
              <ul className="space-y-2.5">
                {richRefs.map((ref, i) => (
                  <li key={i} className="flex flex-col gap-1">
                    <a
                      href={ref.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 break-all text-sm text-blue-400 hover:text-blue-300 hover:underline"
                    >
                      {ref.url}
                      <ExternalLink className="h-3 w-3 flex-shrink-0" />
                    </a>
                    <div className="flex flex-wrap items-center gap-1.5">
                      {hostOf(ref.url) && (
                        <span className="rounded bg-neutral-100 px-1.5 py-0.5 text-[10px] font-medium text-neutral-600 dark:bg-surface-2 dark:text-neutral-400">
                          {hostOf(ref.url)}
                        </span>
                      )}
                      {ref.tags.map((t) => (
                        <span
                          key={t}
                          className="rounded-full bg-sky-100 px-1.5 py-0.5 text-[10px] font-medium text-sky-800 dark:bg-sky-500/15 dark:text-sky-200"
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <ul className="space-y-2">
                {vuln.references.map((ref, i) => (
                  <li key={i}>
                    <a
                      href={ref.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 break-all text-sm text-blue-400 hover:text-blue-300 hover:underline"
                    >
                      <span className="text-xs font-semibold uppercase text-neutral-500">
                        [{ref.type}]
                      </span>
                      {ref.url}
                      <ExternalLink className="h-3 w-3 flex-shrink-0" />
                    </a>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      )}

      <TicketControl cveId={vuln.cveId} />

      <CommentThread vulnerabilityId={vuln.id} />

      <footer className="border-t border-neutral-800 pt-8">
        <p className="break-all text-xs text-neutral-500">
          출처:{" "}
          <a
            href={vuln.sourceUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="underline hover:text-neutral-300"
          >
            {vuln.sourceUrl}
          </a>
        </p>
      </footer>
    </article>
  );
}
