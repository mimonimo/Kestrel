import Link from "next/link";
import { ExternalLink, X } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { BookmarkButton } from "./BookmarkButton";
import { SeverityBadge } from "./SeverityBadge";
import { TicketControl } from "./TicketControl";
import { CommentThread } from "@/components/community/CommentThread";
import { formatDate } from "@/lib/utils";
import type { Vulnerability } from "@/lib/types";

export function CveDetail({ vuln }: { vuln: Vulnerability }) {
  const scoreLabel =
    typeof vuln.cvssScore === "number" && Number.isFinite(vuln.cvssScore)
      ? vuln.cvssScore.toFixed(1)
      : "—";

  return (
    <article className="relative mx-auto max-w-4xl space-y-6 py-8">
      <Link
        href="/"
        aria-label="상세 닫기"
        className="absolute right-0 top-4 inline-flex h-9 w-9 items-center justify-center rounded-full border border-neutral-800 bg-surface-1 text-neutral-400 hover:border-neutral-600 hover:text-neutral-100"
      >
        <X className="h-4 w-4" />
      </Link>

      <header className="space-y-3 pr-12">
        <div className="flex flex-wrap items-center gap-3">
          <span className="font-mono text-sm font-semibold text-neutral-500">{vuln.cveId}</span>
          <SeverityBadge severity={vuln.severity} score={vuln.cvssScore} />
          <BookmarkButton cveId={vuln.cveId} size="md" stopPropagation={false} />
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
        <CardContent className="space-y-1.5">
          <div className="flex items-baseline gap-3">
            <span className="text-3xl font-bold text-neutral-100">{scoreLabel}</span>
            <span className="text-sm uppercase text-neutral-400">{vuln.severity ?? "unknown"}</span>
          </div>
          {vuln.cvssVector ? (
            <code className="block break-all font-mono text-xs text-neutral-500">
              {vuln.cvssVector}
            </code>
          ) : (
            <p className="text-xs text-neutral-600">CVSS 벡터 정보 없음</p>
          )}
        </CardContent>
      </Card>

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

      {vuln.references.length > 0 && (
        <Card>
          <CardHeader>
            <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-500">
              참고 자료
            </h2>
          </CardHeader>
          <CardContent>
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
